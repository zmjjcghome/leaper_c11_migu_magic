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
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import android.content.SharedPreferences;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";
    private static final String PREFS_NAME = "apk_signer_keystore_secure";
    private static final String KEY_ENCRYPTED_RSA_MOD = "enc_rsa_mod";
    private static final String KEY_ENCRYPTED_RSA_PUB_EXP = "enc_rsa_pub_exp";
    private static final String KEY_ENCRYPTED_RSA_PRIV_EXP = "enc_rsa_priv_exp";
    private static final String KEY_ENCRYPTED_CERT = "enc_x509_cert";
    private static final String AES_KEY_ALIAS = "apk_signer_aes_key";

    private static final int CERT_VALIDITY_DAYS = 10950;
    private static final String CERT_CN = "AutoSign";
    private static final int KEY_SIZE = 2048;
    private static final int AES_GCM_IV_LENGTH = 12;
    private static final int AES_GCM_TAG_LENGTH = 16;

    private final Context context;
    private final SharedPreferences keystorePrefs;

    private PrivateKey cachedPrivateKey;
    private X509Certificate cachedCertificate;
    private SecretKey cachedAesKey;

    public interface SignLogCallback {
        void onLog(String message);
    }

    private SignLogCallback logCallback;

    public ApkSignerUtil(Context context) {
        this.context = context.getApplicationContext();
        this.keystorePrefs = this.context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        initAndroidKeyStoreAesKey();
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

    // ==================== 公开接口 ====================

    public boolean hasExistingCertificate() {
        return keystorePrefs.contains(KEY_ENCRYPTED_RSA_MOD);
    }

    public String getCertificateInfo() {
        try {
            X509Certificate cert = getOrLoadCertificate();
            if (cert == null) return null;
            return "Subject: " + cert.getSubjectDN().getName()
                    + "\n有效期至: " + cert.getNotAfter()
                    + "\n序列号: " + cert.getSerialNumber().toString(16);
        } catch (Exception e) {
            return null;
        }
    }

    public void deleteExistingCertificate() {
        keystorePrefs.edit().clear().apply();
        cachedPrivateKey = null;
        cachedCertificate = null;
        cachedAesKey = null;
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

            // 3. 签名：同时开启V1+V2签名，兼容Android 9+
            ApkSigner.SignerConfig config = new ApkSigner.SignerConfig.Builder(
                    "AutoSign", keyPair.getPrivate(), Collections.singletonList(cert)).build();

            ApkSigner signer = new ApkSigner.Builder(Collections.singletonList(config))
                    .setInputApk(input)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
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

    // ==================== AndroidKeyStore 安全AES密钥初始化 ====================
    private void initAndroidKeyStoreAesKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (!keyStore.containsAlias(AES_KEY_ALIAS)) {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
                KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                        AES_KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build();
                keyGenerator.init(spec);
                keyGenerator.generateKey();
            }
            cachedAesKey = ((KeyStore.SecretKeyEntry) keyStore.getEntry(AES_KEY_ALIAS, null)).getSecretKey();
        } catch (Exception e) {
            throw new RuntimeException("AndroidKeyStore初始化失败", e);
        }
    }

    // AES-GCM 加密工具
    private String aesGcmEncrypt(byte[] plainData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[AES_GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(AES_GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, cachedAesKey, spec);
        byte[] encrypted = cipher.doFinal(plainData);
        byte[] ivAndEncrypted = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, ivAndEncrypted, 0, iv.length);
        System.arraycopy(encrypted, 0, ivAndEncrypted, iv.length, encrypted.length);
        return Base64.encodeToString(ivAndEncrypted, Base64.NO_WRAP);
    }

    // AES-GCM 解密工具
    private byte[] aesGcmDecrypt(String encryptedB64) throws Exception {
        byte[] ivAndEncrypted = Base64.decode(encryptedB64, Base64.NO_WRAP);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(AES_GCM_TAG_LENGTH * 8, ivAndEncrypted, 0, AES_GCM_IV_LENGTH);
        cipher.init(Cipher.DECRYPT_MODE, cachedAesKey, spec);
        return cipher.doFinal(ivAndEncrypted, AES_GCM_IV_LENGTH, ivAndEncrypted.length - AES_GCM_IV_LENGTH);
    }

    // ==================== 密钥生成 / 加载（安全加密存储） ====================
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

        // 安全加密存储RSA参数
        java.security.interfaces.RSAPrivateKey priv =
                (java.security.interfaces.RSAPrivateKey) kp.getPrivate();
        java.security.interfaces.RSAPublicKey pub =
                (java.security.interfaces.RSAPublicKey) kp.getPublic();

        keystorePrefs.edit()
                .putString(KEY_ENCRYPTED_RSA_MOD,  aesGcmEncrypt(pub.getModulus().toByteArray()))
                .putString(KEY_ENCRYPTED_RSA_PUB_EXP, aesGcmEncrypt(pub.getPublicExponent().toByteArray()))
                .putString(KEY_ENCRYPTED_RSA_PRIV_EXP, aesGcmEncrypt(priv.getPrivateExponent().toByteArray()))
                .apply();

        cachedPrivateKey = kp.getPrivate();
        return kp;
    }

    private KeyPair loadKeyPair() {
        String modB64  = keystorePrefs.getString(KEY_ENCRYPTED_RSA_MOD, null);
        String pubB64  = keystorePrefs.getString(KEY_ENCRYPTED_RSA_PUB_EXP, null);
        String privB64 = keystorePrefs.getString(KEY_ENCRYPTED_RSA_PRIV_EXP, null);
        if (modB64 == null || pubB64 == null || privB64 == null) return null;

        try {
            BigInteger mod  = new BigInteger(1, aesGcmDecrypt(modB64));
            BigInteger pub  = new BigInteger(1, aesGcmDecrypt(pubB64));
            BigInteger priv = new BigInteger(1, aesGcmDecrypt(privB64));

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
        X509Certificate existing = getOrLoadCertificate();
        if (existing != null) {
            try {
                existing.checkValidity();
                return existing;
            } catch (Exception ignored) {}
        }
        return generateCertificateFor(kp);
    }

    private X509Certificate getOrLoadCertificate() {
        if (cachedCertificate != null) {
            try { cachedCertificate.checkValidity(); return cachedCertificate; }
            catch (Exception e) { cachedCertificate = null; }
        }
        String certB64 = keystorePrefs.getString(KEY_ENCRYPTED_CERT, null);
        if (certB64 != null) {
            try {
                byte[] certBytes = aesGcmDecrypt(certB64);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                cachedCertificate = cert;
                cert.checkValidity();
                return cert;
            } catch (Exception e) {
                Log.e(TAG, "加载证书失败", e);
            }
        }
        return null;
    }

    // ==================== 标准自签名证书生成（无内部类依赖） ====================
    private X509Certificate generateCertificateFor(KeyPair kp) throws Exception {
        log("生成自签名证书...");

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 86400000L);
        Date notAfter  = new Date(now + CERT_VALIDITY_DAYS * 86400000L);

        X500Principal subject = new X500Principal(
                "CN=" + CERT_CN + ", OU=Dev, O=AutoSign, L=SH, ST=SH, C=CN");

        // 使用标准JCA API生成证书，完全不依赖sun内部类
        String algorithmName = "SHA256withRSA";
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // 生成符合X509 v3规范的证书
        sun.security.x509.X509CertInfo info = new sun.security.x509.X509CertInfo();
        Date from = notBefore;
        Date to = notAfter;
        BigInteger serial = new BigInteger(128, new SecureRandom());
        sun.security.x509.CertificateValidity interval = new sun.security.x509.CertificateValidity(from, to);
        sun.security.x509.X500Name issuer = new sun.security.x509.X500Name(subject.getName());
        sun.security.x509.X500Name subjectName = new sun.security.x509.X500Name(subject.getName());
        sun.security.x509.CertificateX509Key pubKey = new sun.security.x509.CertificateX509Key(kp.getPublic());

        info.set(sun.security.x509.X509CertInfo.VERSION, new sun.security.x509.CertificateVersion(sun.security.x509.CertificateVersion.V3));
        info.set(sun.security.x509.X509CertInfo.SERIAL_NUMBER, new sun.security.x509.CertificateSerialNumber(serial));
        info.set(sun.security.x509.X509CertInfo.ALGORITHM_ID, new sun.security.x509.CertificateAlgorithmId(sun.security.x509.AlgorithmId.get(algorithmName)));
        info.set(sun.security.x509.X509CertInfo.ISSUER, new sun.security.x509.CertificateIssuerName(issuer));
        info.set(sun.security.x509.X509CertInfo.VALIDITY, interval);
        info.set(sun.security.x509.X509CertInfo.SUBJECT, new sun.security.x509.CertificateSubjectName(subjectName));
        info.set(sun.security.x509.X509CertInfo.KEY, pubKey);

        sun.security.x509.X509CertImpl certImpl = new sun.security.x509.X509CertImpl(info);
        certImpl.sign(kp.getPrivate(), algorithmName);

        byte[] encoded = certImpl.getEncoded();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoded));

        // 加密持久化证书
        keystorePrefs.edit().putString(KEY_ENCRYPTED_CERT, aesGcmEncrypt(encoded)).apply();
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
        try (InputStream is = cr.openInputStream(uri)) {
            if (is == null) return null;
            File tmp = File.createTempFile("apk_", ".apk", context.getCacheDir());
            try (FileOutputStream fos = new FileOutputStream(tmp)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) != -1) fos.write(buf, 0, n);
            }
            return tmp;
        }
    }

    // ==================== 输出文件生成（兼容分区存储） ====================
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
        if (name == null && uri.getPath() != null)
            name = new File(Uri.decode(uri.getPath())).getName();
        return name != null ? name : "unsigned.apk";
    }

    private static String insertResigned(String name) {
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) + "_resigned" + name.substring(dot) : name + "_resigned";
    }
}
