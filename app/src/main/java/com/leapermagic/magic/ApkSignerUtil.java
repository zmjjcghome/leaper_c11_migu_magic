package com.leapermagic.magic;

import android.content.ContentResolver;
import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.util.Base64;
import android.util.Log;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;

import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

import javax.security.auth.x500.X500Principal;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";

    private static final String PREFS_NAME = "apk_signer_keystore";
    private static final String KEY_PRIVATE_KEY = "private_key_pkcs8";
    private static final String KEY_CERTIFICATE = "certificate_x509";

    private static final int CERT_VALIDITY_DAYS = 10950;
    private static final String CERT_DN =
            "CN=AutoSign, OU=Development, O=AutoSign, L=Unknown, ST=Unknown, C=CN";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int KEY_SIZE = 2048;

    private final Context context;
    private final SharedPreferences keystorePrefs;

    private PrivateKey cachedPrivateKey;
    private X509Certificate cachedCertificate;

    public interface SignLogCallback {
        void onLog(String message);
    }

    private SignLogCallback logCallback;

    // ==================== 构造函数 ====================

    public ApkSignerUtil(Context context) {
        this.context = context.getApplicationContext();
        this.keystorePrefs = this.context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public ApkSignerUtil(Context context, SignLogCallback callback) {
        this(context);
        this.logCallback = callback;
    }

    public void setLogCallback(SignLogCallback callback) {
        this.logCallback = callback;
    }

    // ==================== 日志 ====================

    private void log(String msg) {
        Log.d(TAG, msg);
        if (logCallback != null) {
            logCallback.onLog(msg);
        }
    }

    // ================================================================
    //  公开方法
    // ================================================================

    public boolean hasExistingCertificate() {
        return keystorePrefs.contains(KEY_PRIVATE_KEY)
                && keystorePrefs.contains(KEY_CERTIFICATE);
    }

    public String getCertificateInfo() {
        try {
            X509Certificate cert = getOrLoadCertificate();
            if (cert == null) return null;
            StringBuilder sb = new StringBuilder();
            sb.append("Subject: ").append(cert.getSubjectDN().getName()).append("\n");
            sb.append("有效期至: ").append(cert.getNotAfter()).append("\n");
            sb.append("序列号: ").append(cert.getSerialNumber().toString(16));
            return sb.toString();
        } catch (Exception e) {
            Log.e(TAG, "getCertificateInfo error", e);
            return null;
        }
    }

    public void deleteExistingCertificate() {
        keystorePrefs.edit()
                .remove(KEY_PRIVATE_KEY)
                .remove(KEY_CERTIFICATE)
                .apply();
        cachedPrivateKey = null;
        cachedCertificate = null;
        log("已删除存储的签名证书");
    }

    public boolean resignApk(ContentResolver contentResolver, Uri apkUri, File outputFile) {
        log("========== 开始重新签名 APK (V1+V2+V3) ==========");
        log("源APK: " + apkUri);
        log("输出: " + outputFile.getAbsolutePath());

        try {
            log("加载签名证书...");
            KeyPair keyPair = getOrCreateKeyPair();
            X509Certificate cert = getOrCreateCertificate(keyPair);
            log("证书: " + cert.getSubjectDN().getName());
            log("有效期至: " + cert.getNotAfter());

            File parent = outputFile.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            if (outputFile.exists()) {
                outputFile.delete();
            }

            log("读取原始APK...");
            File tempInput = copyUriToTempFile(contentResolver, apkUri);
            if (tempInput == null) {
                log("无法读取原始APK");
                return false;
            }
            long inputSize = tempInput.length();
            log("原始APK大小: " + inputSize + " bytes (" + (inputSize / 1024) + " KB)");

            log("执行 V1+V2+V3 签名...");
            signApkWithGoogleLib(tempInput, outputFile, keyPair.getPrivate(), cert);

            boolean success = outputFile.exists() && outputFile.length() > 0;
            if (success) {
                log("========== 签名成功 ==========");
                log("输出大小: " + outputFile.length() + " bytes (" + (outputFile.length() / 1024) + " KB)");
                verifySignature(outputFile);
            } else {
                log("========== 签名失败：输出文件为空或不存在 ==========");
            }

            if (tempInput.exists()) tempInput.delete();

            return success;

        } catch (Exception e) {
            log("签名异常: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            Log.e(TAG, "签名异常", e);
            return false;
        }
    }

    public static File generateOutputFile(Uri apkUri) {
        if (apkUri == null) return null;

        File originalFile = resolveFileFromUri(apkUri);
        if (originalFile != null && originalFile.getParentFile() != null) {
            String newName = insertResignedBeforeExtension(originalFile.getName());
            return new File(originalFile.getParentFile(), newName);
        }

        String path = apkUri.getPath();
        if (path == null || path.isEmpty()) return null;
        return new File(insertResignedBeforeExtension(path));
    }

    // ================================================================
    //  使用 Google apksig 库签名（新 API）
    // ================================================================

    private void signApkWithGoogleLib(File inputFile, File outputFile,
                                       PrivateKey privateKey, X509Certificate cert) throws Exception {
        ApkSigner.SignerConfig signerConfig = new ApkSigner.SignerConfig.Builder(
                "AutoSign",
                privateKey,
                Collections.singletonList(cert))
                .build();

        ApkSigner apkSigner = new ApkSigner.Builder(Collections.singletonList(signerConfig))
                .setInputApk(inputFile)
                .setOutputApk(outputFile)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .setCreatedBy("AutoSign-1.0 (Android)")
                .build();

        apkSigner.sign();
    }

    private void verifySignature(File apkFile) {
        try {
            ApkVerifier verifier = new ApkVerifier.Builder(apkFile).build();
            ApkVerifier.Result result = verifier.verify();
            if (result.isVerified()) {
                log("签名验证: 通过");
                if (result.isVerifiedUsingV1Scheme()) log("  V1 (JAR签名): OK");
                if (result.isVerifiedUsingV2Scheme()) log("  V2 (APK Signature v2): OK");
                if (result.isVerifiedUsingV3Scheme()) log("  V3 (APK Signature v3): OK");
            } else {
                log("签名验证: 失败");
                for (ApkVerifier.IssueWithParams issue : result.getErrors()) {
                    log("  " + issue);
                }
            }
        } catch (Exception e) {
            log("签名验证异常: " + e.getMessage());
        }
    }

    // ================================================================
    //  密钥和证书持久化
    // ================================================================

    private synchronized KeyPair getOrCreateKeyPair() throws Exception {
        PrivateKey pk = getOrLoadPrivateKey();
        if (pk != null) {
            X509Certificate cert = getOrLoadCertificate();
            if (cert != null) {
                log("从存储加载现有密钥对");
                return new KeyPair(cert.getPublicKey(), pk);
            }
        }

        log("生成新RSA密钥对 (" + KEY_SIZE + "位)...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(KEY_SIZE, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        keystorePrefs.edit()
                .putString(KEY_PRIVATE_KEY,
                        Base64.encodeToString(kp.getPrivate().getEncoded(), Base64.NO_WRAP))
                .apply();

        cachedPrivateKey = kp.getPrivate();
        log("密钥对已生成并存储");
        return kp;
    }

    private synchronized X509Certificate getOrCreateCertificate(KeyPair keyPair) throws Exception {
        X509Certificate existing = getOrLoadCertificate();
        if (existing != null) {
            try {
                existing.checkValidity();
                log("现有证书在有效期内");
                return existing;
            } catch (Exception e) {
                log("证书已过期，重新生成");
            }
        }

        log("生成新自签名证书...");
        X509Certificate newCert = generateCertificate(keyPair);

        keystorePrefs.edit()
                .putString(KEY_CERTIFICATE,
                        Base64.encodeToString(newCert.getEncoded(), Base64.NO_WRAP))
                .apply();

        cachedCertificate = newCert;
        log("证书已生成并存储");
        return newCert;
    }

    private PrivateKey getOrLoadPrivateKey() {
        if (cachedPrivateKey != null) return cachedPrivateKey;

        String b64 = keystorePrefs.getString(KEY_PRIVATE_KEY, null);
        if (b64 == null) return null;

        try {
            byte[] bytes = Base64.decode(b64, Base64.NO_WRAP);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            cachedPrivateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(bytes));
            return cachedPrivateKey;
        } catch (Exception e) {
            Log.e(TAG, "加载私钥失败", e);
            keystorePrefs.edit().remove(KEY_PRIVATE_KEY).apply();
            return null;
        }
    }

    private X509Certificate getOrLoadCertificate() {
        if (cachedCertificate != null) {
            try {
                cachedCertificate.checkValidity();
                return cachedCertificate;
            } catch (Exception e) {
                cachedCertificate = null;
            }
        }

        String b64 = keystorePrefs.getString(KEY_CERTIFICATE, null);
        if (b64 == null) return null;

        try {
            byte[] bytes = Base64.decode(b64, Base64.NO_WRAP);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cachedCertificate = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(bytes));
            return cachedCertificate;
        } catch (Exception e) {
            Log.e(TAG, "加载证书失败", e);
            keystorePrefs.edit().remove(KEY_CERTIFICATE).apply();
            return null;
        }
    }

    // ================================================================
    //  证书生成（BouncyCastle）
    // ================================================================

    private X509Certificate generateCertificate(KeyPair keyPair) throws Exception {
        long now = System.currentTimeMillis();

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal(CERT_DN),
                new BigInteger(64, new SecureRandom()),
                new Date(now - 86400000L),
                new Date(now + CERT_VALIDITY_DAYS * 86400000L),
                new X500Principal(CERT_DN),
                keyPair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    // ================================================================
    //  文件工具
    // ================================================================

    private static File resolveFileFromUri(Uri uri) {
        if (uri == null) return null;
        String path = uri.getPath();
        if (path == null) return null;

        File f = new File(path);
        if (f.exists()) return f;

        for (String p : new String[]{
                "/storage/emulated/0/", "/sdcard/", "/storage/self/primary/"
        }) {
            if (path.startsWith(p)) return new File(path);
        }

        if (path.startsWith("/document/")) {
            String[] parts = path.split(":");
            if (parts.length >= 2) {
                File candidate = new File("/storage/emulated/0/" + parts[parts.length - 1]);
                if (candidate.exists()) return candidate;
            }
        }
        return null;
    }

    private static String insertResignedBeforeExtension(String fileName) {
        if (fileName == null || fileName.isEmpty()) return "resigned.apk";

        int lastSep = Math.max(fileName.lastIndexOf('/'), fileName.lastIndexOf('\\'));
        String dir = "";
        String base = fileName;
        if (lastSep >= 0) {
            dir = fileName.substring(0, lastSep + 1);
            base = fileName.substring(lastSep + 1);
        }

        int lastDot = base.lastIndexOf('.');
        if (lastDot > 0) {
            base = base.substring(0, lastDot) + "_resigned" + base.substring(lastDot);
        } else {
            base = base + "_resigned";
        }
        return dir + base;
    }

    private File copyUriToTempFile(ContentResolver cr, Uri uri) throws IOException {
        InputStream is = null;
        try {
            is = cr.openInputStream(uri);
            if (is == null) throw new IOException("无法打开Uri: " + uri);

            File tmp = File.createTempFile("apk_input_", ".apk", context.getCacheDir());
            try (FileOutputStream fos = new FileOutputStream(tmp)) {
                byte[] buf = new byte[8192];
                int len;
                while ((len = is.read(buf)) != -1) {
                    fos.write(buf, 0, len);
                }
            }
            return tmp;
        } finally {
            if (is != null) {
                try { is.close(); } catch (IOException ignored) {}
            }
        }
    }
}
