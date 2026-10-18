package com.leapermagic.magic;

import android.content.ContentResolver;
import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.util.Base64;
import android.util.Log;
import android.database.Cursor;
import android.os.Environment;
import android.provider.MediaStore;
import android.provider.OpenableColumns;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.lang.reflect.Method;
import javax.security.auth.x500.X500Principal;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";

    private static final String PREFS_NAME = "apk_signer_keystore";
    private static final String KEY_PRIVATE_KEY = "private_key_pkcs8";
    private static final String KEY_CERTIFICATE = "certificate_x509";

    private static final int CERT_VALIDITY_DAYS = 10950;
    private static final String CERT_DN =
            "CN=AutoSign, OU=Development, O=AutoSign, L=Unknown, ST=Unknown, C=CN";
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
            log("证书有效期至: " + cert.getNotAfter());
            log("证书公钥算法: " + cert.getPublicKey().getAlgorithm());
            log("私钥算法: " + keyPair.getPrivate().getAlgorithm());

            // ---- 签名前校验：用证书公钥验签一段测试数据 ----
            try {
                Signature verifySig = Signature.getInstance("SHA256withRSA");
                verifySig.initSign(keyPair.getPrivate());
                verifySig.update("test".getBytes());
                byte[] testSig = verifySig.sign();
                verifySig.initVerify(cert.getPublicKey());
                verifySig.update("test".getBytes());
                boolean ok = verifySig.verify(testSig);
                log("密钥对校验: " + (ok ? "通过 ✅" : "失败 ❌"));
                if (!ok) {
                    log("私钥与证书不匹配！请删除证书重试。");
                    deleteExistingCertificate();
                    return false;
                }
            } catch (Exception e) {
                log("密钥对校验异常: " + e.getMessage());
                Log.e(TAG, "keypair check", e);
            }

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

            // 快速校验 APK 是否是有效 ZIP
            if (!isValidApk(tempInput)) {
                log("❌ 无效的 APK 文件（ZIP 头校验失败）");
                tempInput.delete();
                return false;
            }
            log("APK ZIP 头校验通过");

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

    public static File generateOutputFile(Context context, Uri apkUri) {
        if (apkUri == null) return null;

        File originalFile = resolveFileFromUri(apkUri);
        if (originalFile != null && originalFile.exists() && originalFile.getParentFile() != null) {
            String newName = insertResignedBeforeExtension(originalFile.getName());
            return new File(originalFile.getParentFile(), newName);
        }

        String realPath = getRealPathFromUri(context, apkUri);
        if (realPath != null) {
            File f = new File(realPath);
            if (f.getParentFile() != null) {
                String newName = insertResignedBeforeExtension(f.getName());
                return new File(f.getParentFile(), newName);
            }
        }

        String fileName = getFileNameFromUri(context, apkUri);
        if (fileName == null) fileName = "unknown.apk";
        String newName = insertResignedBeforeExtension(fileName);
        return new File(Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOWNLOADS), newName);
    }

    private static String getRealPathFromUri(Context context, Uri uri) {
        String path = null;
        if (ContentResolver.SCHEME_CONTENT.equals(uri.getScheme())) {
            try (Cursor cursor = context.getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int idx = cursor.getColumnIndex(MediaStore.MediaColumns.DATA);
                    if (idx >= 0 && !cursor.isNull(idx)) {
                        path = cursor.getString(idx);
                    } else {
                        int displayIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                        if (displayIdx >= 0) {
                            path = cursor.getString(displayIdx);
                        }
                    }
                }
            } catch (Exception ignored) {}
        }
        return path;
    }

    private static String getFileNameFromUri(Context context, Uri uri) {
        String name = null;
        if (ContentResolver.SCHEME_CONTENT.equals(uri.getScheme())) {
            try (Cursor cursor = context.getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (idx >= 0) name = cursor.getString(idx);
                }
            } catch (Exception ignored) {}
        }
        if (name == null && uri.getPath() != null) {
            name = new File(Uri.decode(uri.getPath())).getName();
        }
        return name != null ? name : "unsigned.apk";
    }

    // ================================================================
    //  签名
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
                .setV2SigningEnabled(false)   // 先只开 V1，排他法定位问题
                .setV3SigningEnabled(false)
                .setCreatedBy("AutoSign-1.0 (Android)")
                .build();

        apkSigner.sign();
        log("sign() 调用完成，无异常抛出");
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

    private boolean isValidApk(File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] header = new byte[4];
            if (fis.read(header) != 4) return false;
            // PK.. = 0x50 0x4B
            return header[0] == 0x50 && header[1] == 0x4B;
        } catch (Exception e) {
            return false;
        }
    }

    // ================================================================
    //  密钥/证书持久化
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

        log("生成新自签名证书（纯 Android API，无 BouncyCastle）...");
        X509Certificate newCert = generateCertificateNative(keyPair);

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
    //  纯 Android API 生成自签名证书（不需要 BouncyCastle）
    // ================================================================

    private X509Certificate generateCertificateNative(KeyPair keyPair) throws Exception {
        // Android 有 sun.security.x509 内部类可用
        // 它是 @hide 但运行时存在，反射调用
        Class<?> certInfoClass = Class.forName("sun.security.x509.CertificateX509CertInfo");
        Class<?> x509Class    = Class.forName("sun.security.x509.X509CertImpl");
        Class<?> issuerClass  = Class.forName("sun.security.x509.X500Name");
        Class<?> algoIdClass  = Class.forName("sun.security.x509.AlgorithmId");
        Class<?> keyIdClass   = Class.forName("sun.security.x509.CertificateX509Key");
        Class<?> validityClass= Class.forName("sun.security.x509.CertificateValidity");
        Class<?> serialClass  = Class.forName("sun.security.x509.CertificateSerialNumber");
        Class<?> issuerNameClass = Class.forName("sun.security.x509.CertificateIssuerName");
        Class<?>> subNameClass= Class.forName("sun.security.x509.CertificateSubjectName");
        Class<?> signerClass  = Class.forName("sun.security.x509.X509CertImpl");

        long now = System.currentTimeMillis();

        Object issuerName = issuerClass.getConstructor(String.class).newInstance(CERT_DN);
        Object subjectName = issuerName;

        Object serialNum = serialClass.getConstructor(int.class)
                .newInstance(new BigInteger(64, new SecureRandom()).intValue() & 0x7FFFFFFF);

        Object validity = validityClass.getConstructor(Date.class, Date.class)
                .newInstance(new Date(now - 86400000L),
                             new Date(now + CERT_VALIDITY_DAYS * 86400000L));

        Object algoId = algoIdClass.getMethod("get", String.class).invoke(null, "SHA256withRSA");
        Object keyInfo = keyIdClass.getConstructor(PublicKey.class).newInstance(keyPair.getPublic());

        Object info = certInfoClass.newInstance();
        certInfoClass.getMethod("set", String.class, Object.class).invoke(info, "version", 
                Class.forName("sun.security.x509.CertificateVersion")
                        .getConstructor(int.class).newInstance(2));
        certInfoClass.getMethod("set", String.class, Object.class).invoke(info, "serialNumber", serialNum);
        certInfoClass.getMethod("set", String.class, Object.class).invoke(info, "algorithmID", algoId);
        certInfoClass.getMethod("set", String.class, Object.class).invoke(info, "issuer", issuerName);
        certInfoClass.getMethod("set", String.class, Object.class).invoke(info, "validity", validity);
        certInfoClass.getMethod("set", String.class, Object.class).invoke(info, "subject", subjectName);
        certInfoClass.getMethod("set", String.class, Object.class).invoke(info, "key", keyInfo);

        // 签名
        Object certForSign = x509Class.getConstructor(certInfoClass).newInstance(info);
        Method signMethod = x509Class.getMethod("sign", PrivateKey.class, String.class);
        signMethod.invoke(certForSign, keyPair.getPrivate(), "SHA256withRSA");

        byte[] encoded = (byte[]) x509Class.getMethod("getEncoded").invoke(certForSign);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoded));
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
