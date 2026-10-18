package com.leapermagic.magic;

import android.content.ContentResolver;
import android.content.Context;
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
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import android.content.SharedPreferences;
import javax.security.auth.x500.X500Principal;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";

    private static final String PREFS_NAME = "apk_signer_keystore";
    private static final String KEY_MODULUS  = "rsa_modulus";
    private static final String KEY_PRIV_EXP = "rsa_private_exp";
    private static final String KEY_PUB_EXP  = "rsa_public_exp";

    private static final int CERT_VALIDITY_DAYS = 10950;
    private static final String CERT_CN = "AutoSign";
    private static final int KEY_SIZE = 2048;

    private final Context context;
    private final SharedPreferences keystorePrefs;

    private PrivateKey cachedPrivateKey;
    private X509Certificate cachedCertificate;

    public interface SignLogCallback {
        void onLog(String message);
    }

    private SignLogCallback logCallback;

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
        if (logCallback != null) logCallback.onLog(msg);
    }

    // ==================== 公开 ====================

    public boolean hasExistingCertificate() {
        return keystorePrefs.contains(KEY_MODULUS);
    }

    public String getCertificateInfo() {
        try {
            // X509Certificate cert = getOrLoadCertificate();
            X509Certificate cert = loadCertificate();
            if (cert == null) return null;
            return "Subject: " + cert.getSubjectDN().getName()
                    + "\n有效期至: " + cert.getNotAfter()
                    + "\n序列号: " + cert.getSerialNumber().toString(16);
        } catch (Exception e) {
            return null;
        }
    }

    public void deleteExistingCertificate() {
        keystorePrefs.edit()
                .remove(KEY_MODULUS)
                .remove(KEY_PRIV_EXP)
                .remove(KEY_PUB_EXP)
                .apply();
        cachedPrivateKey = null;
        cachedCertificate = null;
    }

    public boolean resignApk(ContentResolver contentResolver, Uri apkUri, File outputFile) {
        log("========== 签名开始 ==========");
        try {
            // 1. 加载/生成密钥和证书
            KeyPair keyPair = getOrCreateKeyPair();
            X509Certificate cert = getOrCreateCertificate(keyPair);
            log("证书: " + cert.getSubjectDN());
            log("算法: " + keyPair.getPrivate().getAlgorithm() + " " + KEY_SIZE);

            // 2. 准备文件
            if (outputFile.getParentFile() != null) outputFile.getParentFile().mkdirs();
            if (outputFile.exists()) outputFile.delete();

            File input = copyUriToTempFile(contentResolver, apkUri);
            if (input == null || !isValidApk(input)) {
                log("❌ 无法读取 APK");
                return false;
            }
            log("输入: " + input.length() + " bytes");

            // 3. 签名
            ApkSigner.SignerConfig config = new ApkSigner.SignerConfig.Builder(
                    "AutoSign", keyPair.getPrivate(), Collections.singletonList(cert)).build();

            ApkSigner signer = new ApkSigner.Builder(Collections.singletonList(config))
                    .setInputApk(input)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(false)
                    .build();

            signer.sign();
            log("sign() 完成");

            boolean ok = outputFile.exists() && outputFile.length() > 0;
            log(ok ? "✅ 签名成功" : "❌ 输出为空");
            if (ok) verifySig(outputFile);
            if (input.exists()) input.delete();
            return ok;

        } catch (Exception e) {
            log("❌ " + e.getClass().getSimpleName() + ": " + e.getMessage());
            Log.e(TAG, "签名异常", e);
            return false;
        }
    }

    // ==================== 密钥生成 / 加载 ====================

    private synchronized KeyPair getOrCreateKeyPair() throws Exception {
        KeyPair existing = loadKeyPair();
        if (existing != null) {
            log("使用已存储密钥");
            return existing;
        }

        log("生成 RSA " + KEY_SIZE + " 密钥...");
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(KEY_SIZE, new SecureRandom());
        KeyPair kp = gen.generateKeyPair();

        // 存 RSA 参数
        java.security.interfaces.RSAPrivateKey priv = 
                (java.security.interfaces.RSAPrivateKey) kp.getPrivate();
        java.security.interfaces.RSAPublicKey pub = 
                (java.security.interfaces.RSAPublicKey) kp.getPublic();

        keystorePrefs.edit()
                .putString(KEY_MODULUS,  Base64.encodeToString(pub.getModulus().toByteArray(),   Base64.NO_WRAP))
                .putString(KEY_PUB_EXP,   Base64.encodeToString(pub.getPublicExponent().toByteArray(), Base64.NO_WRAP))
                .putString(KEY_PRIV_EXP,  Base64.encodeToString(priv.getPrivateExponent().toByteArray(), Base64.NO_WRAP))
                .apply();

        cachedPrivateKey = kp.getPrivate();
        return kp;
    }

    private KeyPair loadKeyPair() {
        String modB64  = keystorePrefs.getString(KEY_MODULUS, null);
        String pubB64  = keystorePrefs.getString(KEY_PUB_EXP, null);
        String privB64 = keystorePrefs.getString(KEY_PRIV_EXP, null);
        if (modB64 == null || pubB64 == null || privB64 == null) return null;

        try {
            BigInteger mod  = new BigInteger(1, Base64.decode(modB64,  Base64.NO_WRAP));
            BigInteger pub  = new BigInteger(1, Base64.decode(pubB64,  Base64.NO_WRAP));
            BigInteger priv = new BigInteger(1, Base64.decode(privB64, Base64.NO_WRAP));

            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey  pubKey  = kf.generatePublic(new RSAPublicKeySpec(mod, pub));
            PrivateKey privKey = kf.generatePrivate(new RSAPrivateKeySpec(mod, priv));

            KeyPair kp = new KeyPair(pubKey, privKey);
            cachedPrivateKey = privKey;
            return kp;
        } catch (Exception e) {
            Log.e(TAG, "加载密钥失败", e);
            deleteExistingCertificate();
            return null;
        }
    }

    private synchronized X509Certificate getOrCreateCertificate(KeyPair kp) throws Exception {
        X509Certificate existing = loadCertificate();
        if (existing != null) {
            try {
                existing.checkValidity();
                return existing;
            } catch (Exception ignored) {}
        }
        return generateCertificateFor(kp);
    }

    private X509Certificate loadCertificate() {
        if (cachedCertificate != null) {
            try { cachedCertificate.checkValidity(); return cachedCertificate; }
            catch (Exception e) { cachedCertificate = null; }
        }
        return null;
    }

    // ==================== 自签名证书生成 ====================

    /**
     * 使用 sun.security.tools.keytool.CertAndKeyGen（Android 内部类）
     */
    @SuppressWarnings("unchecked")
    private X509Certificate generateCertificateFor(KeyPair kp) throws Exception {
        log("生成自签名证书...");

        // CertAndKeyGen 在 Android 运行时可用（来自 sun.*）
        Class<?> cakgClass = Class.forName("sun.security.tools.keytool.CertAndKeyGen");
        Object cakg = cakgClass.getConstructor(String.class, String.class)
                .newInstance("RSA", "SHA256WithRSA");

        // 设置随机数
        cakgClass.getMethod("setRandom", SecureRandom.class).invoke(cakg, new SecureRandom());

        // 生成证书
        cakgClass.getMethod("generate", int.class).invoke(cakg, KEY_SIZE);

        // getSelfCertificate
        long firstDate = System.currentTimeMillis() - 86400000L;
        long lastDate  = firstDate + CERT_VALIDITY_DAYS * 86400000L;

        X500Principal principal = new X500Principal("CN=" + CERT_CN + ", OU=Dev, O=AutoSign, L=SH, ST=SH, C=CN");

        X509Certificate[] chain = (X509Certificate[]) cakgClass
                .getMethod("getSelfCertificate", X500Principal.class, long.class)
                .invoke(cakg, principal, lastDate);

        X509Certificate cert = chain[0];
        cachedCertificate = cert;
        log("证书生成完毕, 有效期至: " + cert.getNotAfter());
        return cert;
    }

    // ==================== 验证 ====================

    private void verifySig(File apk) {
        try {
            ApkVerifier.Result r = new ApkVerifier.Builder(apk).build().verify();
            log("验证: " + (r.isVerified() ? "通过" : "失败"));
        } catch (Exception e) {
            log("验证异常: " + e.getMessage());
        }
    }

    private boolean isValidApk(File f) {
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] h = new byte[4];
            return fis.read(h) == 4 && h[0] == 0x50 && h[1] == 0x4B;
        } catch (Exception e) { return false; }
    }

    // ==================== 文件工具 ====================

    private File copyUriToTempFile(ContentResolver cr, Uri uri) throws Exception {
        InputStream is = cr.openInputStream(uri);
        if (is == null) return null;
        File tmp = File.createTempFile("apk_", ".apk", context.getCacheDir());
        try (FileOutputStream fos = new FileOutputStream(tmp)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) fos.write(buf, 0, n);
        }
        is.close();
        return tmp;
    }

    // ==================== generateOutputFile ====================

    public static File generateOutputFile(Context context, Uri uri) {
        if (uri == null) return null;

        File f = resolveFileFromUri(uri);
        if (f != null && f.exists() && f.getParentFile() != null)
            return new File(f.getParentFile(), insertResigned(f.getName()));

        String path = getRealPath(context, uri);
        if (path != null) {
            File pf = new File(path);
            if (pf.getParentFile() != null)
                return new File(pf.getParentFile(), insertResigned(pf.getName()));
        }

        String name = getFileName(context, uri);
        if (name == null) name = "unknown.apk";
        return new File(Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOWNLOADS), insertResigned(name));
    }

    private static String getRealPath(Context ctx, Uri uri) {
        if (!ContentResolver.SCHEME_CONTENT.equals(uri.getScheme())) return null;
        try (Cursor c = ctx.getContentResolver().query(uri, null, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(MediaStore.MediaColumns.DATA);
                if (idx >= 0 && !c.isNull(idx)) return c.getString(idx);
                idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx >= 0) return c.getString(idx);
            }
        } catch (Exception ignored) {}
        return null;
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
        if (name == null && uri.getPath() != null)
            name = new File(Uri.decode(uri.getPath())).getName();
        return name != null ? name : "unsigned.apk";
    }

    private static File resolveFileFromUri(Uri uri) {
        if (uri == null) return null;
        String path = uri.getPath();
        if (path == null) return null;
        File f = new File(path);
        if (f.exists()) return f;
        if (path.startsWith("/document/")) {
            String[] parts = path.split(":");
            if (parts.length >= 2) {
                File c = new File("/storage/emulated/0/" + parts[parts.length - 1]);
                if (c.exists()) return c;
            }
        }
        return null;
    }

    private static String insertResigned(String name) {
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) + "_resigned" + name.substring(dot) : name + "_resigned";
    }
}
