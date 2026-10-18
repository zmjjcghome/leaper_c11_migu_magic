
package com.leapermagic.magic;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.util.Base64;
import android.util.Log;
import android.database.Cursor;
import android.os.Environment;
import android.provider.OpenableColumns;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import android.content.SharedPreferences;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";
    private static final String PREFS_NAME = "apk_signer_keystore_secure";
    
    // 存储键名
    private static final String KEY_ENCRYPTED_RSA_MOD = "enc_rsa_mod";
    private static final String KEY_ENCRYPTED_RSA_PUB_EXP = "enc_rsa_pub_exp";
    private static final String KEY_ENCRYPTED_RSA_PRIV_EXP = "enc_rsa_priv_exp";
    private static final String KEY_ENCRYPTED_CERT = "enc_x509_cert";
    private static final String AES_KEY_ALIAS = "apk_signer_aes_key";

    private static final int CERT_VALIDITY_DAYS = 10950; // 30年
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

    static {
        // 注册 Bouncy Castle Provider
        Security.addProvider(new BouncyCastleProvider());
    }

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
            Log.e(TAG, "获取证书信息失败", e);
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
            log("证书主体: " + cert.getSubjectDN());
            log("密钥算法: " + keyPair.getPrivate().getAlgorithm() + " " + KEY_SIZE);

            // 2. 准备文件
            if (outputFile.getParentFile() != null && !outputFile.getParentFile().exists()) {
                outputFile.getParentFile().mkdirs();
            }
            if (outputFile.exists()) outputFile.delete();

            File input = copyUriToTempFile(contentResolver, apkUri);
            if (input == null || !isValidApk(input)) {
                log("❌ 无法读取或无效的 APK");
                return false;
            }
            log("输入文件大小: " + input.length() + " bytes");

            // 3. 配置签名器：开启 V1 + V2 签名以兼容 Android 9+
            ApkSigner.SignerConfig config = new ApkSigner.SignerConfig.Builder(
                    "AutoSign", keyPair.getPrivate(), Collections.singletonList(cert)).build();

            ApkSigner signer = new ApkSigner.Builder(Collections.singletonList(config))
                    .setInputApk(input)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false) // Android 9+ V2足够，V3可选
                    .build();

            signer.sign();
            log("ApkSigner.sign() 执行完成");

            boolean ok = outputFile.exists() && outputFile.length() > 0;
            log(ok ? "✅ 签名成功" : "❌ 输出文件为空");
            
            if (ok) {
                verifySig(outputFile);
            }
            
            // 清理临时文件
            if (input.exists()) input.delete();
            return ok;

        } catch (Exception e) {
            log("❌ 签名异常: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            Log.e(TAG, "签名详细异常", e);
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
                log("AndroidKeyStore AES密钥生成成功");
            }
            KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry(AES_KEY_ALIAS, null);
            if (entry != null) {
                cachedAesKey = entry.getSecretKey();
            } else {
                throw new RuntimeException("无法从AndroidKeyStore获取AES密钥");
            }
        } catch (Exception e) {
            throw new RuntimeException("AndroidKeyStore初始化失败", e);
        }
    }

    // AES-GCM 加密工具
    private String aesGcmEncrypt(byte[] plainData) throws Exception {
        if (cachedAesKey == null) initAndroidKeyStoreAesKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[AES_GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(AES_GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, cachedAesKey, spec);
        byte[] encrypted = cipher.doFinal(plainData);
        
        // IV + Ciphertext
        byte[] ivAndEncrypted = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, ivAndEncrypted, 0, iv.length);
        System.arraycopy(encrypted, 0, ivAndEncrypted, iv.length, encrypted.length);
        return Base64.encodeToString(ivAndEncrypted, Base64.NO_WRAP);
    }

    // AES-GCM 解密工具
    private byte[] aesGcmDecrypt(String encryptedB64) throws Exception {
        if (cachedAesKey == null) initAndroidKeyStoreAesKey();
        byte[] ivAndEncrypted = Base64.decode(encryptedB64, Base64.NO_WRAP);
        if (ivAndEncrypted.length < AES_GCM_IV_LENGTH) {
            throw new IllegalArgumentException("Invalid encrypted data length");
        }
        byte[] iv = Arrays.copyOfRange(ivAndEncrypted, 0, AES_GCM_IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(ivAndEncrypted, AES_GCM_IV_LENGTH, ivAndEncrypted.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(AES_GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, cachedAesKey, spec);
        return cipher.doFinal(ciphertext);
    }

    // ==================== 密钥生成 / 加载（安全加密存储） ====================
    private synchronized KeyPair getOrCreateKeyPair() throws Exception {
        KeyPair existing = loadKeyPair();
        if (existing != null) {
            log("使用已存储的RSA密钥对");
            return existing;
        }

        log("生成新的 RSA " + KEY_SIZE + " 密钥对...");
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(KEY_SIZE, new SecureRandom());
        KeyPair kp = gen.generateKeyPair();

        // 提取参数并加密存储
        java.security.interfaces.RSAPrivateKey priv = (java.security.interfaces.RSAPrivateKey) kp.getPrivate();
        java.security.interfaces.RSAPublicKey pub = (java.security.interfaces.RSAPublicKey) kp.getPublic();

        keystorePrefs.edit()
                .putString(KEY_ENCRYPTED_RSA_MOD, aesGcmEncrypt(pub.getModulus().toByteArray()))
                .putString(KEY_ENCRYPTED_RSA_PUB_EXP, aesGcmEncrypt(pub.getPublicExponent().toByteArray()))
                .putString(KEY_ENCRYPTED_RSA_PRIV_EXP, aesGcmEncrypt(priv.getPrivateExponent().toByteArray()))
                .apply();

        cachedPrivateKey = kp.getPrivate();
        return kp;
    }

    private KeyPair loadKeyPair() {
        String modB64 = keystorePrefs.getString(KEY_ENCRYPTED_RSA_MOD, null);
        String pubB64 = keystorePrefs.getString(KEY_ENCRYPTED_RSA_PUB_EXP, null);
        String privB64 = keystorePrefs.getString(KEY_ENCRYPTED_RSA_PRIV_EXP, null);
        
        if (modB64 == null || pubB64 == null || privB64 == null) return null;

        try {
            BigInteger mod = new BigInteger(1, aesGcmDecrypt(modB64));
            BigInteger pubExp = new BigInteger(1, aesGcmDecrypt(pubB64));
            BigInteger privExp = new BigInteger(1, aesGcmDecrypt(privB64));

            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pubKey = kf.generatePublic(new RSAPublicKeySpec(mod, pubExp));
            PrivateKey privKey = kf.generatePrivate(new RSAPrivateKeySpec(mod, privExp));

            KeyPair kp = new KeyPair(pubKey, privKey);
            cachedPrivateKey = privKey;
            return kp;
        } catch (Exception e) {
            Log.e(TAG, "加载密钥失败，可能数据损坏或密钥不匹配", e);
            deleteExistingCertificate(); // 清除损坏的数据
            return null;
        }
    }

    private synchronized X509Certificate getOrCreateCertificate(KeyPair kp) throws Exception {
        X509Certificate existing = getOrLoadCertificate();
        if (existing != null) {
            try {
                existing.checkValidity();
                // 简单校验公钥是否匹配当前加载的私钥对应的公钥
                if (existing.getPublicKey().equals(kp.getPublic())) {
                    log("使用已存储且有效的证书");
                    return existing;
                } else {
                    log("证书公钥与当前密钥不匹配，重新生成证书");
                }
            } catch (Exception ignored) {
                log("证书已过期或无效，重新生成");
            }
        }
        return generateCertificateWithBC(kp);
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
        
        String certB64 = keystorePrefs.getString(KEY_ENCRYPTED_CERT, null);
        if (certB64 != null) {
            try {
                byte[] certBytes = aesGcmDecrypt(certB64);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                cachedCertificate = cert;
                return cert;
            } catch (Exception e) {
                Log.e(TAG, "加载持久化证书失败", e);
            }
        }
        return null;
    }

    // ==================== 使用 Bouncy Castle 生成自签名证书 ====================
    private X509Certificate generateCertificateWithBC(KeyPair keyPair) throws Exception {
        log("使用 Bouncy Castle 生成自签名 X.509 v3 证书...");

        // 1. 准备证书基本信息
        BigInteger serialNumber = new BigInteger(128, new SecureRandom());
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L); // 提前一天生效，避免时钟偏差
        Date notAfter = new Date(System.currentTimeMillis() + (long) CERT_VALIDITY_DAYS * 86400000L);
        
        // 主题名称 (Subject DN) - Issuer 和 Subject 相同因为是自签名
        X500Name subject = new X500Name("CN=" + CERT_CN + ", OU=Dev, O=AutoSign, L=SH, ST=SH, C=CN");
        
        // 2. 构建证书主体
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(
                keyPair.getPublic().getEncoded()
        );

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                subject,          // Issuer
                serialNumber,
                notBefore,
                notAfter,
                subject,          // Subject
                publicKeyInfo
        );

        // 3. 添加基本约束扩展 (非CA证书)
        certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.basicConstraints, 
                true, 
                new BasicConstraints(false)
        );

        // 4. 使用私钥对证书进行签名
        // SHA256withRSA 是 Android APK 签名的标准且安全的算法
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        signerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME); 
        
        // 5. 生成证书对象
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);

        X509Certificate certificate = converter.getCertificate(
                certBuilder.build(signerBuilder.build(keyPair.getPrivate()))
        );

        // 6. 加密并持久化证书
        byte[] encoded = certificate.getEncoded();
        keystorePrefs.edit().putString(KEY_ENCRYPTED_CERT, aesGcmEncrypt(encoded)).apply();
        
        cachedCertificate = certificate;
        log("证书生成完毕, 有效期至: " + certificate.getNotAfter());
        return certificate;
    }

    // ==================== 验证 ====================
    private void verifySig(File apk) {
        try {
            ApkVerifier.Result r = new ApkVerifier.Builder(apk).build().verify();
            if (r.isVerified()) {
                log("✅ APK 签名验证通过");
            } else {
                log("❌ APK 签名验证失败");
                for (ApkVerifier.IssueWithParams issue : r.getErrors()) {
                    log("错误详情: " + issue);
                }
            }
        } catch (Exception e) {
            log("验证过程异常: " + e.getMessage());
        }
    }

    private boolean isValidApk(File f) {
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] h = new byte[4];
            int read = fis.read(h);
            // ZIP 文件头 PK..
            return read == 4 && h[0] == 0x50 && h[1] == 0x4B;
        } catch (Exception e) { 
            return false; 
        }
    }

    // ==================== 文件工具 ====================
    private File copyUriToTempFile(ContentResolver cr, Uri uri) throws Exception {
        try (InputStream is = cr.openInputStream(uri)) {
            if (is == null) return null;
            // 在缓存目录创建临时文件
            File tmp = File.createTempFile("apk_unsigned_", ".apk", context.getCacheDir());
            try (FileOutputStream fos = new FileOutputStream(tmp)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) != -1) {
                    fos.write(buf, 0, n);
                }
            }
            return tmp;
        }
    }

    // ==================== 输出文件生成（兼容分区存储） ====================
    public static File generateOutputFile(Context context, Uri uri) {
        if (uri == null) return null;

        String name = getFileName(context, uri);
        if (name == null) name = "unknown.apk";
        
        // 优先使用应用专属外部存储目录，无需权限且兼容性好
        File outputDir;
        if (Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState())) {
            outputDir = new File(context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), "SignedApk");
        } else {
            //  fallback to internal files dir if external storage is not available
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
