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
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";
    
    // 密钥库配置
    private static final String KEYSTORE_FILENAME = "autosign.keystore";
    private static final String KEYSTORE_PASSWORD = "changeit"; // 生产环境应更复杂或动态生成
    private static final String KEY_ALIAS = "autosign_alias";
    private static final String KEY_PASSWORD = "changeit";
    private static final int KEY_SIZE = 2048;
    private static final int VALIDITY_DAYS = 10950; // 30年

    private final Context context;

    public interface SignLogCallback {
        void onLog(String message);
    }

    private SignLogCallback logCallback;

    static {
        // 注册 Bouncy Castle Provider，用于支持 BKS 格式
        Security.addProvider(new BouncyCastleProvider());
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
     * 核心方法：对 APK 进行重签名
     */
    public boolean resignApk(ContentResolver contentResolver, Uri apkUri, File outputFile) {
        log("========== 签名开始 ==========");
        try {
            // 1. 确保密钥库存在并获取密钥
            KeyStore keyStore = getOrCreateKeyStore();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray());
            Certificate[] certChain = keyStore.getCertificateChain(KEY_ALIAS);
            
            if (privateKey == null || certChain == null || certChain.length == 0) {
                throw new IllegalStateException("无法从密钥库加载密钥或证书");
            }
            
            X509Certificate cert = (X509Certificate) certChain[0];
            log("使用密钥别名: " + KEY_ALIAS);
            log("证书主体: " + cert.getSubjectDN());

            // 2. 准备输入文件
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

            // 3. 配置 ApkSigner
            // 注意：ApkSigner 需要 List<Certificate> 而不是数组
            java.util.List<Certificate> certList = java.util.Arrays.asList(certChain);
            
            ApkSigner.SignerConfig signerConfig = new ApkSigner.SignerConfig.Builder(
                    "AutoSign", 
                    privateKey, 
                    certList
            ).build();

            ApkSigner apkSigner = new ApkSigner.Builder(Collections.singletonList(signerConfig))
                    .setInputApk(inputApk)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(true)  // 兼容旧版本
                    .setV2SigningEnabled(true)  // Android 7.0+ 必需
                    .setV3SigningEnabled(false) // 可选，通常 V2 足够
                    .build();

            // 4. 执行签名
            apkSigner.sign();
            log("ApkSigner.sign() 执行完成");

            // 5. 验证结果
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
     * 获取或创建标准的 BKS 密钥库
     */
    private synchronized KeyStore getOrCreateKeyStore() throws Exception {
        File ksFile = new File(context.getFilesDir(), KEYSTORE_FILENAME);
        KeyStore keyStore = KeyStore.getInstance("BKS", "BC");

        if (ksFile.exists()) {
            // 加载现有密钥库
            try (FileInputStream fis = new FileInputStream(ksFile)) {
                keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
            }
            // 验证别名是否存在
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                log("密钥库存在但别名缺失，重新生成密钥");
                generateNewKey(keyStore, ksFile);
            } else {
                log("加载现有密钥库");
            }
        } else {
            // 创建新密钥库
            log("创建新的 BKS 密钥库");
            keyStore.load(null, null);
            generateNewKey(keyStore, ksFile);
        }
        
        return keyStore;
    }

    /**
     * 生成新的 RSA 密钥对并存入密钥库
     */
    private void generateNewKey(KeyStore keyStore, File ksFile) throws Exception {
        // 使用 KeyPairGenerator 生成标准 RSA 密钥
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(KEY_SIZE);
        KeyPair kp = kpg.generateKeyPair();

        // 生成自签名证书 (使用简单的 Java API，不依赖 BC 的复杂构建器以避免 Provider 问题)
        // 注意：为了简化，这里使用 sun.security 的替代方案或者简单的自签名逻辑
        // 由于 Android 上生成自签名证书较复杂，我们使用一个简化的方法：
        // 实际上，ApkSigner 只需要一个有效的 X509Certificate。
        // 我们可以使用 Bouncy Castle 来生成这个证书，但只用于初始生成，之后存储在 KS 中。
        
        X509Certificate cert = generateSelfSignedCert(kp);
        
        // 存入密钥库
        keyStore.setKeyEntry(
                KEY_ALIAS, 
                kp.getPrivate(), 
                KEY_PASSWORD.toCharArray(), 
                new Certificate[]{cert}
        );

        // 保存密钥库到文件
        try (FileOutputStream fos = new FileOutputStream(ksFile)) {
            keyStore.store(fos, KEYSTORE_PASSWORD.toCharArray());
        }
        log("新密钥对已生成并保存");
    }

    /**
     * 使用 Bouncy Castle 生成自签名证书 (仅用于初始化密钥库)
     * 这里我们尽量使用标准 JCA，如果必须用 BC，确保不冲突
     */
    private X509Certificate generateSelfSignedCert(KeyPair kp) throws Exception {
        // 为了避开 BC Provider 的签名算法查找问题，我们使用 Android 原生的 CertificateFactory 
        // 但 Android 原生不支持直接生成自签名证书。
        // 因此，我们必须使用 BC 来生成证书对象，但签名时使用标准算法名称。
        
        // 引入 BC 的证书生成器
        org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name("CN=AutoSign, OU=Dev, O=AutoSign, C=CN");
        java.math.BigInteger serial = java.math.BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter = new Date(System.currentTimeMillis() + (long) VALIDITY_DAYS * 86400000L);
        
        org.bouncycastle.cert.X509v3CertificateBuilder certBuilder = 
                new org.bouncycastle.cert.X509v3CertificateBuilder(
                        subject, serial, notBefore, notAfter, subject, 
                        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded())
                );
        
        // 关键点：使用 "SHA256withRSA" 并且不指定 Provider，让 JCA 自动选择
        // 在 Android 上，这通常会路由到 AndroidOpenSSL 或 Conscrypt，它们支持 RSA 签名
        org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                .build(kp.getPrivate());
        
        org.bouncycastle.cert.X509CertificateHolder certHolder = certBuilder.build(signer);
        
        // 转换为 Java 标准 Certificate
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                .setProvider("BC") // 这里仅用于转换格式，不涉及签名运算
                .getCertificate(certHolder);
    }

    /**
     * 验证 APK 签名
     */
    private void verifyApkSignature(File apkFile) {
        try {
            ApkVerifier.Result result = new ApkVerifier.Builder(apkFile).build().verify();
            if (result.isVerified()) {
                log("✅ APK 签名验证通过");
            } else {
                log("❌ APK 签名验证失败");
                for (ApkVerifier.IssueWithParams issue : result.getErrors()) {
                    log("错误: " + issue);
                }
            }
        } catch (Exception e) {
            log("验证过程出错: " + e.getMessage());
        }
    }

    /**
     * 将 Uri 复制到临时文件
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
     * 获取输出文件路径
     */
    public static File getOutputFile(Context context, Uri sourceUri) {
        String fileName = "signed_app.apk";
        if (sourceUri != null) {
            String path = sourceUri.getPath();
            if (path != null) {
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
        }
        
        File dir = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
        if (dir == null) {
            dir = context.getFilesDir();
        }
        File outputDir = new File(dir, "SignedApks");
        if (!outputDir.exists()) outputDir.mkdirs();
        
        return new File(outputDir, fileName);
    }
}
