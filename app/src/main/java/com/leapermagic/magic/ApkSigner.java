package com.leapermagic.magic;

import android.content.ContentResolver;
import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.util.Base64;
import android.util.Log;

import com.android.apksig.ApkSignerEngine;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;

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
import java.util.jar.*;

import javax.security.auth.x500.X500Principal;

/**
 * APK 重新签名工具类
 *
 * 基于 Google 官方 apksig 库，同时支持 V1（JAR签名）、V2、V3 签名。
 * 使用 BouncyCastle 生成自签名 X509 证书。
 * 密钥和证书持久化存储在 SharedPreferences 中，确保每次签名使用相同证书。
 */
public class ApkSigner {

    private static final String TAG = "ApkSigner";

    // ==================== SharedPreferences 存储 key ====================
    private static final String PREFS_NAME = "apk_signer_keystore";
    private static final String KEY_PRIVATE_KEY = "private_key_pkcs8";
    private static final String KEY_CERTIFICATE = "certificate_x509";

    // ==================== 签名常量 ====================
    private static final int CERT_VALIDITY_DAYS = 10950; // 约30年
    private static final String CERT_DN = "CN=AutoSign, OU=AutoSign, O=AutoSign, L=Unknown, ST=Unknown, C=CN";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int KEY_SIZE = 2048;

    // ==================== 实例字段 ====================

    private final Context context;
    private final SharedPreferences keystorePrefs;

    private PrivateKey cachedPrivateKey;
    private X509Certificate cachedCertificate;

    /**
     * 日志回调接口
     */
    public interface SignLogCallback {
        void onLog(String message);
    }

    private SignLogCallback logCallback;

    // ==================== 构造函数 ====================

    public ApkSigner(Context context) {
        this.context = context.getApplicationContext();
        this.keystorePrefs = this.context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public ApkSigner(Context context, SignLogCallback callback) {
        this(context);
        this.logCallback = callback;
    }

    public void setLogCallback(SignLogCallback callback) {
        this.logCallback = callback;
    }

    // ==================== 日志辅助 ====================

    private void log(String msg) {
        Log.d(TAG, msg);
        if (logCallback != null) {
            logCallback.onLog(msg);
        }
    }

    // ================================================================
    //  公开方法
    // ================================================================

    /**
     * 检查是否已有存储的签名证书
     */
    public boolean hasExistingCertificate() {
        return keystorePrefs.contains(KEY_PRIVATE_KEY)
                && keystorePrefs.contains(KEY_CERTIFICATE);
    }

    /**
     * 获取已存储的证书信息
     */
    public String getCertificateInfo() {
        try {
            X509Certificate cert = getOrLoadCertificate();
            if (cert == null) return null;
            StringBuilder sb = new StringBuilder();
            sb.append("Subject: ").append(cert.getSubjectDN().getName()).append("\n");
            sb.append("有效期至: ").append(cert.getNotAfter().toString()).append("\n");
            sb.append("序列号: ").append(cert.getSerialNumber().toString(16));
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 删除已存储的证书，下次签名时会重新生成
     */
    public void deleteExistingCertificate() {
        keystorePrefs.edit()
                .remove(KEY_PRIVATE_KEY)
                .remove(KEY_CERTIFICATE)
                .apply();
        cachedPrivateKey = null;
        cachedCertificate = null;
        log("已删除存储的签名证书");
    }

    /**
     * 对指定的 APK 执行重新签名（V1 + V2 + V3）
     *
     * @param contentResolver ContentResolver
     * @param apkUri          原始APK的Uri
     * @param outputFile      签名后输出的目标文件
     * @return 签名是否成功
     */
    public boolean resignApk(ContentResolver contentResolver, Uri apkUri, File outputFile) {
        log("========== 开始重新签名 APK (V1+V2+V3) ==========");
        log("源APK: " + apkUri);
        log("输出: " + outputFile.getAbsolutePath());

        try {
            // Step 1: 获取或生成密钥对和证书
            log("加载签名证书...");
            KeyPair keyPair = getOrCreateKeyPair();
            X509Certificate cert = getOrCreateCertificate(keyPair);
            log("证书: " + cert.getSubjectDN().getName());
            log("有效期至: " + cert.getNotAfter());

            // Step 2: 确保输出目录存在
            File parent = outputFile.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            if (outputFile.exists()) {
                outputFile.delete();
            }

            // Step 3: 读取原始APK到临时文件（apksig库需要DataSource）
            log("读取原始APK...");
            File tempInputFile = copyUriToTempFile(contentResolver, apkUri);
            if (tempInputFile == null) {
                log("无法读取原始APK");
                return false;
            }
            long inputSize = tempInputFile.length();
            log("原始APK大小: " + inputSize + " bytes");

            // Step 4: 使用 apksig 库进行签名
            log("执行签名 (V1+V2+V3)...");
            signWithApkSig(tempInputFile, outputFile, keyPair.getPrivate(), cert);

            // Step 5: 验证结果
            boolean success = outputFile.exists() && outputFile.length() > 0;
            if (success) {
                log("========== 签名成功 ==========");
                log("输出大小: " + outputFile.length() + " bytes");
            } else {
                log("========== 签名失败 ==========");
            }

            // 清理临时文件
            if (tempInputFile.exists()) {
                tempInputFile.delete();
            }

            return success;

        } catch (Exception e) {
            log("签名异常: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            Log.e(TAG, "签名异常", e);
            return false;
        }
    }

    /**
     * 根据原始APK的Uri生成签名后的输出文件路径
     * 在原文件名基础上增加 "_resigned" 字样，放在同目录下
     */
    public static File generateOutputFile(Uri apkUri) {
        if (apkUri == null) return null;

        File originalFile = resolveFileFromUri(apkUri);
        if (originalFile != null && originalFile.getParentFile() != null) {
            String name = originalFile.getName();
            String newName = insertResignedBeforeExtension(name);
            return new File(originalFile.getParentFile(), newName);
        }

        String path = apkUri.getPath();
        if (path == null || path.isEmpty()) return null;
        String newPath = insertResignedBeforeExtension(path);
        return new File(newPath);
    }

    // ================================================================
    //  核心签名方法（使用 apksig 库）
    // ================================================================

    /**
     * 使用 Google apksig 库执行 V1+V2+V3 签名
     */
    private void signWithApkSig(File inputFile, File outputFile,
                                 PrivateKey privateKey, X509Certificate cert) throws Exception {
        // 构建签名配置
        ApkSignerEngine.SignerConfig signerConfig =
                new ApkSignerEngine.SignerConfig.Builder(
                        "AutoSign",
                        privateKey,
                        Collections.singletonList(cert))
                        .build();

        // 创建签名引擎，启用 V1, V2, V3
        // minSdkVersion 14 确保启用 V1（兼容老设备）
        // 也可以明确指定哪些签名方案
        ApkSignerEngine signerEngine = new ApkSignerEngine.Builder(Collections.singletonList(signerConfig))
                .setMinSdkVersion(24)      // V2 从 API 24 开始
                .setV1SigningEnabled(true)  // 启用 V1 (JAR签名)
                .setV2SigningEnabled(true)  // 启用 V2 (APK Signature Scheme v2)
                .setV3SigningEnabled(true)  // 启用 V3 (APK Signature Scheme v3)
                .setCreatedBy("AutoSign-1.0 (Android)")
                .build();

        // 执行签名
        try (DataSource inputDataSource = DataSources.asDataSource(inputFile);
             ApkSignerEngine.OutputApkSigningBlockRequestor outputApkSigningBlockRequestor =
                     new ApkSignerEngine.OutputApkSigningBlockRequestor() {
                         @Override
                         public byte[] getOutputApkSigningBlock() {
                             // 不需要自定义额外的 signing block，返回空
                             return new byte[0];
                         }
                     }) {

            // 使用 ApkSignerEngine 签名
            signWithEngine(signerEngine, inputDataSource, outputFile);
        }
    }

    /**
     * 使用 ApkSignerEngine 执行实际签名并输出到文件
     */
    private void signWithEngine(ApkSignerEngine engine, DataSource input,
                                 File outputFile) throws Exception {
        // 创建一个临时的输出文件（因为签名过程涉及ZIP操作）
        File tempOutputFile = new File(outputFile.getParentFile(),
                outputFile.getName() + ".tmp");

        try {
            // 打开输入
            ApkSignerEngine.InputApk inputApk = engine.openInputApk(input);

            // 获取输出流
            try (FileOutputStream fos = new FileOutputStream(tempOutputFile)) {
                // 写入输出APK
                ApkSignerEngine.OutputApk outputApk = engine.openOutputApk(
                        inputApk, fos);

                // 复制所有ZIP条目（除了签名相关），同时签名
                byte[] buffer = new byte[65536];
                ApkSignerEngine.InputJarEntry inputEntry;
                while ((inputEntry = inputApk.nextEntry()) != null) {
                    String entryName = inputEntry.getName();

                    // 跳过旧的签名文件
                    if (isOldSignatureFile(entryName)) {
                        log("跳过旧签名文件: " + entryName);
                        continue;
                    }

                    ApkSignerEngine.OutputJarEntry outputEntry =
                            outputApk.outputJarEntry(entryName);

                    // 复制数据
                    try (InputStream entryStream = inputEntry.getInputStream()) {
                        int len;
                        while ((len = entryStream.read(buffer)) != -1) {
                            outputEntry.write(buffer, 0, len);
                        }
                    }
                    outputEntry.close();
                }

                outputApk.close();
                inputApk.close();
            }

            // 重命名临时文件
            if (tempOutputFile.exists()) {
                if (outputFile.exists()) {
                    outputFile.delete();
                }
                boolean renamed = tempOutputFile.renameTo(outputFile);
                if (!renamed) {
                    // 如果rename失败，复制
                    copyFile(tempOutputFile, outputFile);
                    tempOutputFile.delete();
                }
                log("签名完成");
            } else {
                throw new IOException("临时输出文件不存在");
            }

        } finally {
            if (tempOutputFile.exists()) {
                tempOutputFile.delete();
            }
        }
    }

    /**
     * 判断是否为旧的签名文件
     */
    private boolean isOldSignatureFile(String entryName) {
        if (!entryName.startsWith("META-INF/")) {
            return false;
        }
        String upper = entryName.toUpperCase();
        return upper.equals("META-INF/MANIFEST.MF") ||
                upper.endsWith(".SF") ||
                upper.endsWith(".RSA") ||
                upper.endsWith(".DSA") ||
                upper.endsWith(".EC");
    }

    // ================================================================
    //  密钥和证书持久化管理
    // ================================================================

    private synchronized KeyPair getOrCreateKeyPair() throws Exception {
        PrivateKey privateKey = getOrLoadPrivateKey();
        if (privateKey != null) {
            log("从存储加载现有私钥");
            X509Certificate cert = getOrLoadCertificate();
            if (cert != null) {
                return new KeyPair(cert.getPublicKey(), privateKey);
            }
        }

        log("生成新RSA密钥对 (" + KEY_SIZE + "位)...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(KEY_SIZE, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        // 持久化私钥
        byte[] pkcs8 = keyPair.getPrivate().getEncoded();
        keystorePrefs.edit()
                .putString(KEY_PRIVATE_KEY, Base64.encodeToString(pkcs8, Base64.NO_WRAP))
                .apply();

        cachedPrivateKey = keyPair.getPrivate();
        log("密钥对已生成并存储");
        return keyPair;
    }

    private synchronized X509Certificate getOrCreateCertificate(KeyPair keyPair) throws Exception {
        X509Certificate existingCert = getOrLoadCertificate();
        if (existingCert != null) {
            try {
                existingCert.checkValidity();
                log("现有证书在有效期内");
                return existingCert;
            } catch (Exception e) {
                log("证书已过期，生成新证书");
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
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            cachedPrivateKey = kf.generatePrivate(spec);
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
    //  证书生成（使用 BouncyCastle）
    // ================================================================

    /**
     * 使用 BouncyCastle 生成自签名 X509 证书
     */
    private X509Certificate generateCertificate(KeyPair keyPair) throws Exception {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 86400000L);
        Date notAfter = new Date(now + CERT_VALIDITY_DAYS * 86400000L);

        X500Principal subject = new X500Principal(CERT_DN);
        BigInteger serial = new BigInteger(64, new SecureRandom());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,          // issuer
                serial,           // serial
                notBefore,        // notBefore
                notAfter,         // notAfter
                subject,          // subject
                keyPair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(signer));
    }

    // ================================================================
    //  Uri 解析和文件操作
    // ================================================================

    /**
     * 从Uri解析File对象
     */
    private static File resolveFileFromUri(Uri uri) {
        if (uri == null) return null;
        String path = uri.getPath();
        if (path == null) return null;

        File file = new File(path);
        if (file.exists()) return file;

        for (String prefix : new String[]{
                "/storage/emulated/0/", "/sdcard/", "/storage/self/primary/"
        }) {
            if (path.startsWith(prefix)) return new File(path);
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

    /**
     * 将ContentProvider中的Uri内容复制到临时文件
     */
    private File copyUriToTempFile(ContentResolver cr, Uri uri) throws IOException {
        InputStream is = cr.openInputStream(uri);
        if (is == null) {
            throw new IOException("无法打开Uri: " + uri);
        }

        File tempFile = File.createTempFile("apk_input_", ".apk",
                context.getCacheDir());

        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            byte[] buf = new byte[8192];
            int len;
            while ((len = is.read(buf)) != -1) {
                fos.write(buf, 0, len);
            }
            fos.flush();
        } finally {
            is.close();
        }

        return tempFile;
    }

    private void copyFile(File src, File dst) throws IOException {
        try (FileInputStream fis = new FileInputStream(src);
             FileOutputStream fos = new FileOutputStream(dst)) {
            byte[] buf = new byte[8192];
            int len;
            while ((len = fis.read(buf)) != -1) {
                fos.write(buf, 0, len);
            }
            fos.flush();
        }
    }
}
