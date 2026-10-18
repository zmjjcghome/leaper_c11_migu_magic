package com.leapermagic.magic;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.util.Log;
import android.database.Cursor;
import android.os.Environment;
import android.provider.OpenableColumns;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";
    
    // 密钥库配置
    private static final String KEYSTORE_FILENAME = "autosign.keystore";
    private static final String KEYSTORE_PASSWORD = "changeit";
    private static final String KEY_ALIAS = "autosign_alias";
    private static final String KEY_PASSWORD = "changeit";
    private static final int KEY_SIZE = 2048;
    private static final int VALIDITY_DAYS = 10950; // 30年有效期

    private final Context context;

    public interface SignLogCallback {
        void onLog(String message);
    }

    private SignLogCallback logCallback;
    
    // 提前持有BC Provider的单例，避免重复注册
    private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();

    static {
        // 先移除重复的BC Provider，再重新注册，确保它在Provider列表中是唯一且可用的
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(BC_PROVIDER);
    }

    public ApkSignerUtil(Context context) {
        this.context = context.getApplicationContext();
    }

    public ApkSignerUtil(Context context, SignLogCallback callback) {
        this(context);
        this.logCallback = callback;
    }

    public void setLogCallback(SignLogCallback callback) {
        this.logCallback = callback;
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        if (logCallback != null) logCallback.onLog(msg);
    }

    /**
     * 核心重签名方法，支持V1+V2+V3全版本签名
     */
    public boolean resignApk(ContentResolver contentResolver, Uri apkUri, File outputFile) {
        log("========== 签名开始 ==========");
        try {
            // 1. 加载/生成标准BKS密钥库
            KeyStore keyStore = getOrCreateKeyStore();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray());
            Certificate[] certChain = keyStore.getCertificateChain(KEY_ALIAS);
            
            if (privateKey == null || certChain == null || certChain.length == 0) {
                throw new IllegalStateException("无法从密钥库加载密钥或证书");
            }
            
            X509Certificate cert = (X509Certificate) certChain[0];
            log("使用密钥别名: " + KEY_ALIAS);
            log("证书主体: " + cert.getSubjectDN());

            // 2. 准备输出目录与临时输入文件
            if (outputFile.getParentFile() != null && !outputFile.getParentFile().exists()) {
                outputFile.getParentFile().mkdirs();
            }
            if (outputFile.exists()) outputFile.delete();

            File inputApk = copyUriToTempFile(contentResolver, apkUri);
            if (inputApk == null || !inputApk.exists() || inputApk.length() == 0) {
                log("❌ 无法读取输入 APK");
                return false;
            }
            log("输入文件大小: " + inputApk.length() + " bytes");

            // 3. 修复类型不匹配：手动转换为List<X509Certificate>
            List<X509Certificate> x509CertList = new ArrayList<>();
            for (Certificate c : certChain) {
                if (c instanceof X509Certificate) {
                    x509CertList.add((X509Certificate) c);
                }
            }
            
            // 构建签名配置
            ApkSigner.SignerConfig signerConfig = new ApkSigner.SignerConfig.Builder(
                    "AutoSign", 
                    privateKey, 
                    x509CertList
            ).build();

            // 4. 启用V1+V2+V3全签名方案，兼容全版本Android
            ApkSigner apkSigner = new ApkSigner.Builder(Collections.singletonList(signerConfig))
                    .setInputApk(inputApk)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .build();

            // 5. 执行签名
            apkSigner.sign();
            log("ApkSigner.sign() 执行完成");

            // 6. 验证签名结果
            boolean success = outputFile.exists() && outputFile.length() > 0;
            if (success) {
                log("✅ 签名成功: " + outputFile.getAbsolutePath());
                verifyApkSignature(outputFile);
            } else {
                log("❌ 签名失败：输出文件为空或不存在");
            }

            // 清理临时文件
            if (inputApk.exists()) inputApk.delete();
            
            return success;

        } catch (Exception e) {
            log("❌ 签名异常: " + e.getMessage());
            Log.e(TAG, "签名详细错误", e);
            return false;
        }
    }

    /**
     * 获取或创建标准BKS密钥库，修复X.509 not found异常
     */
    private synchronized KeyStore getOrCreateKeyStore() throws Exception {
        File ksFile = new File(context.getFilesDir(), KEYSTORE_FILENAME);
        // 明确指定使用已注册的BC单例实例，避免动态查找Provider失败
        KeyStore keyStore = KeyStore.getInstance("BKS", BC_PROVIDER);

        if (ksFile.exists()) {
            try (FileInputStream fis = new FileInputStream(ksFile)) {
                keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
            }
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                log("密钥库存在但别名缺失，重新生成密钥");
                generateNewKey(keyStore, ksFile);
            } else {
                log("加载现有密钥库");
            }
        } else {
            log("创建新的 BKS 密钥库");
            keyStore.load(null, null);
            generateNewKey(keyStore, ksFile);
        }
        
        return keyStore;
    }

    /**
     * 生成新RSA密钥对并保存到密钥库
     */
    private void generateNewKey(KeyStore keyStore, File ksFile) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(KEY_SIZE);
        KeyPair kp = kpg.generateKeyPair();

        X509Certificate cert = generateSelfSignedCert(kp);
        
        keyStore.setKeyEntry(
                KEY_ALIAS, 
                kp.getPrivate(), 
                KEY_PASSWORD.toCharArray(), 
                new Certificate[]{cert}
        );

        try (FileOutputStream fos = new FileOutputStream(ksFile)) {
            keyStore.store(fos, KEYSTORE_PASSWORD.toCharArray());
        }
        log("新密钥对已生成并保存");
    }

    /**
     * 修复X.509 not found：显式指定CertificateFactory使用BC Provider
     */
    private X509Certificate generateSelfSignedCert(KeyPair kp) throws Exception {
        org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name("CN=AutoSign, OU=Dev, O=AutoSign, C=CN");
        java.math.BigInteger serial = java.math.BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter = new Date(System.currentTimeMillis() + (long) VALIDITY_DAYS * 86400000L);
        
        org.bouncycastle.cert.X509v3CertificateBuilder certBuilder = 
                new org.bouncycastle.cert.X509v3CertificateBuilder(
                        subject, serial, notBefore, notAfter, subject, 
                        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded())
                );
        
        // 不强制指定Provider，让Android系统自动选择最优签名实现
        org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                .build(kp.getPrivate());
        
        org.bouncycastle.cert.X509CertificateHolder certHolder = certBuilder.build(signer);
        
        // 关键修复：显式指定X.509 CertificateFactory使用BC Provider，彻底避免X.509 not found
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC_PROVIDER);
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
    }

    /**
     * 验证APK签名有效性
     */
    private void verifyApkSignature(File apkFile) {
        try {
            ApkVerifier.Result result = new ApkVerifier.Builder(apkFile).build().verify();
            if (result.isVerified()) {
                log("✅ APK 签名验证通过");
            } else {
                log("❌ APK 签名验证失败");
                for (ApkVerifier.IssueWithParams issue : result.getErrors()) {
                    log("错误详情: " + issue);
                }
            }
        } catch (Exception e) {
            log("验证过程出错: " + e.getMessage());
        }
    }

    /**
     * 从Uri复制APK到临时文件
     */
    private File copyUriToTempFile(ContentResolver cr, Uri uri) throws IOException {
        InputStream is = cr.openInputStream(uri);
        if (is == null) return null;
        
        File tempFile = File.createTempFile("apk_input_", ".apk", context.getCacheDir());
        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            byte[] buffer = new byte[8192];
            int len;
            while ((len = is.read(buffer)) != -1) {
                fos.write(buffer, 0, len);
            }
        } finally {
            is.close();
        }
        return tempFile;
    }
    
    /**
     * 生成签名后APK的输出路径
     */
    public static File getOutputFile(Context context, Uri sourceUri) {
        String fileName = "signed_app.apk";
        if (sourceUri != null && sourceUri.getPath() != null) {
            String path = sourceUri.getPath();
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash != -1) {
                String name = path.substring(lastSlash + 1);
                if (name.endsWith(".apk")) {
                    fileName = name.replace(".apk", "_signed.apk");
                } else {
                    fileName = name + "_signed.apk";
                }
            }
        }
        
        File dir = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
        if (dir == null) dir = context.getFilesDir();
        File outputDir = new File(dir, "SignedApks");
        if (!outputDir.exists()) outputDir.mkdirs();
        
        return new File(outputDir, fileName);
    }

    public static File generateOutputFile(Context context, Uri uri) {
        if (uri == null) return null;

        String name = getFileName(context, uri);
        if (name == null) name = "unknown.apk";
        
        File outputDir;
        if (Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState())) {
            outputDir = new File(context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), "SignedApk");
        } else {
            outputDir = new File(context.getFilesDir(), "SignedApk");
        }
        
        if (!outputDir.exists()) outputDir.mkdirs();
        return new File(outputDir, insertResigned(name));
    }

    private static String getFileName(Context ctx, Uri uri) {
        String name = null;
        if (ContentResolver.SCHEME_CONTENT.equals(uri.getScheme())) {
            try (Cursor c = ctx.getContentResolver().query(uri, null, null, null, null)) {
                if (c != null && c.moveToFirst()) {
                    int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (idx >= 0) name = c.getString(idx);
                }
            } catch (Exception ignored) {}
        }
        if (name == null && uri.getPath() != null) {
            String path = uri.getPath();
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash != -1) {
                name = path.substring(lastSlash + 1);
            } else {
                name = path;
            }
        }
        return (name != null && !name.isEmpty()) ? name : "unsigned.apk";
    }

    private static String insertResigned(String name) {
        int dot = name.lastIndexOf('.');
        if (dot > 0) {
            return name.substring(0, dot) + "_resigned" + name.substring(dot);
        }
        return name + "_resigned.apk";
    }
}
