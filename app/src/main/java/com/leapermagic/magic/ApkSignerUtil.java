package com.leapermagic.magic;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Environment;
import android.provider.OpenableColumns;
import android.util.Log;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";
    
    private static final String PRIVATE_KEY_FILE = "autosign_private.key";
    private static final String CERT_FILE = "autosign_cert.crt";
    
    private static final int KEY_SIZE = 2048;
    private static final int VALIDITY_DAYS = 10950; // 30年有效期

    private final Context context;

    public interface SignLogCallback {
        void onLog(String message);
    }

    private SignLogCallback logCallback;

    static {
        // 确保 BC Provider 优先注册并命名为 "BC"
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    public ApkSignerUtil(Context context) {
        this.context = context.getApplicationContext();
        ensureProvider();
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

    private static void ensureProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    /**
     * 核心重签名方法
     */
    public boolean resignApk(ContentResolver contentResolver, Uri apkUri, File outputFile) {
        log("========== 签名开始 ==========");
        File inputApk = null;
        try {
            ensureProvider();
            
            KeyPair keyPair = getOrCreateKeyPair();
            X509Certificate cert = getOrCreateCertificate(keyPair);
            
            PrivateKey privateKey = keyPair.getPrivate();
            if (privateKey == null || cert == null) {
                throw new IllegalStateException("无法加载或生成签名密钥");
            }
            
            log("证书主体: " + cert.getSubjectDN());

            if (outputFile.getParentFile() != null && !outputFile.getParentFile().exists()) {
                outputFile.getParentFile().mkdirs();
            }
            if (outputFile.exists()) outputFile.delete();

            inputApk = copyUriToTempFile(contentResolver, apkUri);
            if (inputApk == null || !inputApk.exists() || inputApk.length() == 0) {
                log("❌ 无法读取输入 APK");
                return false;
            }
            log("输入文件大小: " + inputApk.length() + " bytes");

            List<X509Certificate> x509CertList = new ArrayList<>();
            x509CertList.add(cert);
            
            ApkSigner.SignerConfig signerConfig = new ApkSigner.SignerConfig.Builder(
                    "AutoSign", 
                    privateKey, 
                    x509CertList
            ).build();

            ApkSigner apkSigner = new ApkSigner.Builder(Collections.singletonList(signerConfig))
                    .setInputApk(inputApk)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setMinSdkVersion(24) 
                    .build();

            apkSigner.sign();
            log("ApkSigner.sign() 执行完成");

            boolean success = outputFile.exists() && outputFile.length() > 0;
            if (success) {
                log("✅ 签名成功: " + outputFile.getAbsolutePath());
                verifyApkSignature(outputFile);
            } else {
                log("❌ 签名失败：输出文件为空或不存在");
            }

            return success;

        } catch (Exception e) {
            log("❌ 签名异常: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            Log.e(TAG, "签名详细错误", e);
            return false;
        } finally {
            if (inputApk != null && inputApk.exists()) {
                inputApk.delete();
            }
        }
    }

    /**
     * 获取或生成 RSA 密钥对（显式指定使用字符串 "BC" 提供者）
     */
    private KeyPair getOrCreateKeyPair() throws Exception {
        File keyFile = new File(context.getFilesDir(), PRIVATE_KEY_FILE);
        
        if (keyFile.exists()) {
            try {
                byte[] keyBytes = readFileToBytes(keyFile);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
                PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
                
                File certFile = new File(context.getFilesDir(), CERT_FILE);
                if (certFile.exists()) {
                    PublicKey pubKey = getCertificatePublicKey(certFile);
                    if (pubKey != null) {
                        log("加载现有签名密钥对成功");
                        return new KeyPair(pubKey, privateKey);
                    }
                }
            } catch (Exception e) {
                log("密钥文件损坏，重新生成: " + e.getMessage());
                keyFile.delete();
                new File(context.getFilesDir(), CERT_FILE).delete();
            }
        }

        log("生成新的 RSA 密钥对");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(KEY_SIZE);
        KeyPair kp = kpg.generateKeyPair();

        try (FileOutputStream fos = new FileOutputStream(keyFile)) {
            fos.write(kp.getPrivate().getEncoded());
        }
        
        return kp;
    }

    /**
     * 获取或生成 X509 证书
     */
    private X509Certificate getOrCreateCertificate(KeyPair kp) throws Exception {
        File certFile = new File(context.getFilesDir(), CERT_FILE);
        if (certFile.exists()) {
            try (FileInputStream fis = new FileInputStream(certFile)) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
                return (X509Certificate) cf.generateCertificate(fis);
            } catch (Exception e) {
                certFile.delete();
            }
        }

        log("生成新的自签名证书");
        X509Certificate cert = generateSelfSignedCert(kp);
        try (FileOutputStream fos = new FileOutputStream(certFile)) {
            fos.write(cert.getEncoded());
        }
        return cert;
    }

    private PublicKey getCertificatePublicKey(File certFile) {
        try (FileInputStream fis = new FileInputStream(certFile)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
            return cert.getPublicKey();
        } catch (Exception e) {
            return null;
        }
    }

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
        
        org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(kp.getPrivate());
        
        org.bouncycastle.cert.X509CertificateHolder certHolder = certBuilder.build(signer);
        
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
    }

    private byte[] readFileToBytes(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            return bos.toByteArray();
        }
    }

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

    private File copyUriToTempFile(ContentResolver cr, Uri uri) throws IOException {
        InputStream is = null;
        if ("file".equalsIgnoreCase(uri.getScheme())) {
            File f = new File(uri.getPath());
            if (f.exists()) {
                is = new FileInputStream(f);
            }
        }
        if (is == null) {
            is = cr.openInputStream(uri);
        }
        if (is == null) return null;
        
        File tempFile = File.createTempFile("apk_input_", ".apk", context.getCacheDir());
        try (InputStream in = is; FileOutputStream fos = new FileOutputStream(tempFile)) {
            byte[] buffer = new byte[8192];
            int len;
            while ((len = in.read(buffer)) != -1) {
                fos.write(buffer, 0, len);
            }
        }
        return tempFile;
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
