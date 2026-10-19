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
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";
    
    // 使用 Android 系统原生的 PKCS12 格式持久化，彻底杜绝 BKS/PKCS12 not found 异常
    private static final String KEYSTORE_FILENAME = "autosign_secure.p12";
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
     * 核心重签名方法：支持 V1 + V2 + V3 全版本签名
     */
    public boolean resignApk(ContentResolver contentResolver, Uri apkUri, File outputFile) {
        log("========== 签名开始 (V1+V2+V3) ==========");
        File inputApk = null;
        try {
            // 1. 获取或创建持久化的 KeyStore 密钥对
            KeyStore keyStore = getOrCreateKeyStore();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray());
            Certificate[] certChain = keyStore.getCertificateChain(KEY_ALIAS);
            
            if (privateKey == null || certChain == null || certChain.length == 0) {
                throw new IllegalStateException("无法从密钥库加载密钥或证书");
            }
            
            X509Certificate cert = (X509Certificate) certChain[0];
            log("证书主体: " + cert.getSubjectDN());

            // 2. 准备输出目录与临时输入文件
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

            // 3. 构建证书链列表
            List<X509Certificate> x509CertList = new ArrayList<>();
            for (Certificate c : certChain) {
                if (c instanceof X509Certificate) {
                    x509CertList.add((X509Certificate) c);
                }
            }
            
            ApkSigner.SignerConfig signerConfig = new ApkSigner.SignerConfig.Builder(
                    "AutoSign", 
                    privateKey, 
                    x509CertList
            ).build();

            // 4. 完美开启 V1 + V2 + V3 全版本签名
            ApkSigner apkSigner = new ApkSigner.Builder(Collections.singletonList(signerConfig))
                    .setInputApk(inputApk)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true) // 完美支持 V3 签名
                    .setMinSdkVersion(24) 
                    .build();

            apkSigner.sign();
            log("ApkSigner.sign() 执行完成");

            // 5. 验证签名结果
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
     * 获取或创建持久化的 PKCS12 密钥库（使用系统默认实现，绝不报 not found）
     */
    private synchronized KeyStore getOrCreateKeyStore() throws Exception {
        File ksFile = new File(context.getFilesDir(), KEYSTORE_FILENAME);
        // 使用系统默认的 PKCS12 容器，完全不依赖第三方 Provider 的 KeyStore 扩展
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        if (ksFile.exists()) {
            try (FileInputStream fis = new FileInputStream(ksFile)) {
                keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
                if (keyStore.containsAlias(KEY_ALIAS)) {
                    log("✅ 成功加载持久化 PKCS12 密钥库");
                    return keyStore;
                }
            } catch (Exception e) {
                log("⚠️ 密钥库加载失败，将重新创建: " + e.getMessage());
                ksFile.delete();
            }
        }

        log("🔑 正在创建新的 PKCS12 密钥库并生成自签名证书...");
        keyStore.load(null, null);

        // 使用系统默认 RSA 生成器（绝对不会报 NoSuchAlgorithmException）
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(KEY_SIZE);
        KeyPair kp = kpg.generateKeyPair();

        // 生成自签名 X509 证书
        X509Certificate cert = generateSelfSignedCert(kp);

        // 存入密钥库
        keyStore.setKeyEntry(
                KEY_ALIAS,
                kp.getPrivate(),
                KEY_PASSWORD.toCharArray(),
                new Certificate[]{cert}
        );

        // 持久化保存到文件
        try (FileOutputStream fos = new FileOutputStream(ksFile)) {
            keyStore.store(fos, KEYSTORE_PASSWORD.toCharArray());
        }

        log("✅ 新 PKCS12 密钥库已成功持久化保存");
        return keyStore;
    }

    /**
     * 生成自签名 X509 证书
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
        
        // 使用系统默认签名器构建器（不指定 provider，完美避免 SHA256WITHRSA 找不到异常）
        org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                .build(kp.getPrivate());
        
        org.bouncycastle.cert.X509CertificateHolder certHolder = certBuilder.build(signer);
        
        // 使用系统默认 CertificateFactory
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
    }

    /**
     * 验证 APK 签名有效性
     */
    private void verifyApkSignature(File apkFile) {
        try {
            ApkVerifier.Result result = new ApkVerifier.Builder(apkFile).build().verify();
            if (result.isVerified()) {
                log("✅ APK 签名验证通过 (V1+V2+V3)");
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
     * 复制文件到临时文件
     */
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
