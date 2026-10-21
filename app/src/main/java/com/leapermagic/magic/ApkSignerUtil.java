package com.leapermagic.magic;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.os.Environment;
import android.util.Log;
import android.database.Cursor;
import android.os.Environment;
import android.provider.OpenableColumns;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
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
     * 核心重签名方法，支持V1+V2+V3+V4全版本签名
     */
    public boolean resignApk(ContentResolver contentResolver, Uri apkUri, File outputFile) {
        log("========== 签名开始 ==========");
        try {
            // 1. 加载/自动生成标准BKS密钥库与签名证书
            KeyStore keyStore = getOrCreateKeyStore();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray());
            Certificate[] certChain = keyStore.getCertificateChain(KEY_ALIAS);
            
            if (privateKey == null || certChain == null || certChain.length == 0) {
                throw new IllegalStateException("无法从密钥库加载密钥或证书");
            }
            
            X509Certificate cert = (X509Certificate) certChain[0];
            log("使用密钥别名: " + KEY_ALIAS);
            log("证书主体: " + cert.getSubjectDN());
            log("证书有效期至: " + cert.getNotAfter());

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

            // 3. 转换证书链为 List<X509Certificate>
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

            // V4签名输出路径
            File v4OutputFile = new File(outputFile.getAbsolutePath() + ".v4");

            // 4. 启用V1+V2+V3+V4全签名方案，兼容全版本Android
            ApkSigner apkSigner = new ApkSigner.Builder(Collections.singletonList(signerConfig))
                    .setInputApk(inputApk)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setV4SigningEnabled(true)
                    .setV4SignatureOutputFile(v4OutputFile)
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

            // 清理临时输入文件
            if (inputApk.exists()) {
                inputApk.delete();
            }
            
            return success;

        } catch (Exception e) {
            log("❌ 签名异常: " + e.getMessage());
            Log.e(TAG, "签名详细错误", e);
            return false;
        }
    }

    /**
     * 获取或创建标准BKS密钥库，支持自动生成自签名证书
     */
    public synchronized KeyStore getOrCreateKeyStore() throws Exception {
        File ksFile = new File(context.getFilesDir(), KEYSTORE_FILENAME);
        KeyStore keyStore = KeyStore.getInstance("BKS", BC_PROVIDER);

        if (ksFile.exists()) {
            try (FileInputStream fis = new FileInputStream(ksFile)) {
                keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
            }
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                log("密钥库存在但别名缺失，重新生成密钥证书");
                generateNewKey(keyStore, ksFile);
            } else {
                log("加载现有BKS密钥库成功");
            }
        } else {
            log("创建新的 BKS 密钥库");
            keyStore.load(null, null);
            generateNewKey(keyStore, ksFile);
        }
        
        return keyStore;
    }

    /**
     * 强制重新生成签名证书和密钥对
     */
    public synchronized boolean forceRegenerateKeyStore() {
        try {
            File ksFile = new File(context.getFilesDir(), KEYSTORE_FILENAME);
            if (ksFile.exists()) {
                ksFile.delete();
            }
            KeyStore keyStore = KeyStore.getInstance("BKS", BC_PROVIDER);
            keyStore.load(null, null);
            generateNewKey(keyStore, ksFile);
            log("✅ 成功重新生成签名证书与密钥库");
            return true;
        } catch (Exception e) {
            log("❌ 重新生成密钥库失败: " + e.getMessage());
            Log.e(TAG, "generateKeyStore error", e);
            return false;
        }
    }

    /**
     * 生成新RSA密钥对与X.509自签名证书并保存到密钥库
     */
    private void generateNewKey(KeyStore keyStore, File ksFile) throws Exception {
        log("正在生成 " + KEY_SIZE + " 位 RSA 密钥对...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC_PROVIDER);
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
        log("新密钥对与自签名证书已成功保存至: " + ksFile.getAbsolutePath());
    }

    /**
     * 使用 BouncyCastle 生成 X.509 自签名证书
     */
    private X509Certificate generateSelfSignedCert(KeyPair kp) throws Exception {
        X500Name subject = new X500Name("CN=AutoSigner, OU=Development, O=LeaperMagic, C=CN");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L); // 提前一天防止时差问题
        Date notAfter = new Date(System.currentTimeMillis() + (long) VALIDITY_DAYS * 86400000L);
        
        X509v3CertificateBuilder certBuilder = 
                new X509v3CertificateBuilder(
                        subject, serial, notBefore, notAfter, subject, 
                        SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded())
                );
        
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BC_PROVIDER)
                .build(kp.getPrivate());
        
        X509CertificateHolder certHolder = certBuilder.build(signer);
        
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC_PROVIDER);
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
    }

    /**
     * 获取当前签名证书详细信息（可用于UI展示）
     */
    public String getCertificateDetails() {
        try {
            KeyStore keyStore = getOrCreateKeyStore();
            Certificate cert = keyStore.getCertificate(KEY_ALIAS);
            if (cert instanceof X509Certificate) {
                X509Certificate x509 = (X509Certificate) cert;
                StringBuilder sb = new StringBuilder();
                sb.append("签发者 (Issuer): ").append(x509.getIssuerDN()).append("\n");
                sb.append("主体 (Subject): ").append(x509.getSubjectDN()).append("\n");
                sb.append("序列号 (Serial): ").append(x509.getSerialNumber()).append("\n");
                sb.append("生效日期: ").append(x509.getNotBefore()).append("\n");
                sb.append("失效日期: ").append(x509.getNotAfter()).append("\n");
                sb.append("签名算法: ").append(x509.getSigAlgName());
                return sb.toString();
            }
        } catch (Exception e) {
            log("获取证书详情失败: " + e.getMessage());
        }
        return "暂无有效证书信息";
    }

    /**
     * 验证APK签名有效性
     */
    private void verifyApkSignature(File apkFile) {
        try {
            ApkVerifier.Result result = new ApkVerifier.Builder(apkFile).build().verify();
            if (result.isVerified()) {
                log("✅ APK 签名验证通过 (支持 V1/V2/V3/V4)");
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
