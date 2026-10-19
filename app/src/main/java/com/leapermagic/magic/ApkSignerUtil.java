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

import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";
    
    // 使用对象序列化持久化密钥对文件名
    private static final String KEYPAIR_FILENAME = "autosign_keypair.dat";
    
    private static final int KEY_SIZE = 2048;
    private static final int VALIDITY_DAYS = 10950; // 30年有效期

    // 内存缓存，避免频繁读写文件
    private static KeyPair cachedKeyPair = null;
    private static X509Certificate cachedCert = null;

    private final Context context;

    public interface SignLogCallback {
        void onLog(String message);
    }

    private SignLogCallback logCallback;

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
     * 核心重签名方法
     */
    public boolean resignApk(ContentResolver contentResolver, Uri apkUri, File outputFile) {
        log("========== 签名开始 ==========");
        File inputApk = null;
        try {
            KeyPair keyPair = getOrGeneratePersistentKeyPair();
            X509Certificate cert = getOrGenerateCertificate(keyPair);
            
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
            Throwable cause = e.getCause();
            String detail = cause != null ? (cause.getClass().getSimpleName() + " - " + cause.getMessage()) : e.getMessage();
            log("❌ 签名异常: " + e.getClass().getSimpleName() + " - " + detail);
            Log.e(TAG, "签名详细错误", e);
            return false;
        } finally {
            if (inputApk != null && inputApk.exists()) {
                inputApk.delete();
            }
        }
    }

    /**
     * 获取或生成持久化的 RSA 密钥对（使用 Java 对象序列化保存，完美保留所有 CRT 加速参数）
     */
    private synchronized KeyPair getOrGeneratePersistentKeyPair() {
        if (cachedKeyPair != null) {
            return cachedKeyPair;
        }

        File keyFile = new File(context.getFilesDir(), KEYPAIR_FILENAME);
        if (keyFile.exists()) {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(keyFile))) {
                cachedKeyPair = (KeyPair) ois.readObject();
                if (cachedKeyPair != null && cachedKeyPair.getPrivate() != null && cachedKeyPair.getPublic() != null) {
                    log("✅ 成功从本地加载持久化密钥对");
                    return cachedKeyPair;
                }
            } catch (Exception e) {
                log("⚠️ 加载持久化密钥文件失败，将重新生成: " + e.getMessage());
                keyFile.delete();
            }
        }

        log("🔑 正在生成新的 RSA 密钥对并持久化...");
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(KEY_SIZE);
            cachedKeyPair = kpg.generateKeyPair();

            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(keyFile))) {
                oos.writeObject(cachedKeyPair);
            }
            log("✅ 新密钥对已成功持久化保存");
            return cachedKeyPair;
        } catch (Exception e) {
            log("❌ 生成或保存密钥对失败: " + e.getMessage());
            return null;
        }
    }

    /**
     * 获取或生成 X509 证书（基于持有的 KeyPair 在内存中生成）
     */
    private synchronized X509Certificate getOrGenerateCertificate(KeyPair kp) throws Exception {
        if (cachedCert != null) {
            return cachedCert;
        }
        log("正在生成自签名证书...");
        cachedCert = generateSelfSignedCert(kp);
        return cachedCert;
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
                .build(kp.getPrivate());
        
        org.bouncycastle.cert.X509CertificateHolder certHolder = certBuilder.build(signer);
        
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
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
