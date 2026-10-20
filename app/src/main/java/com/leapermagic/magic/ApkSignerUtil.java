package com.leapermagic.magic;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.util.Log;

import com.android.apksig.ApkSigner;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";
    private static final String KEYSTORE_NAME = "debug.keystore"; // 恢复标准的 keystore 后缀
    private static final String KEY_ALIAS = "androiddebugkey";
    private static final char[] KEY_PASSWORD = "android".toCharArray();

    static {
        try {
            Security.removeProvider("BC");
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private final Context context;
    private SignLogCallback logCallback;

    public interface SignLogCallback {
        void onLog(String message);
    }

    public ApkSignerUtil(Context context) {
        this.context = context;
    }

    public void setLogCallback(SignLogCallback logCallback) {
        this.logCallback = logCallback;
    }

    private void log(String message) {
        Log.d(TAG, message);
        if (logCallback != null) {
            logCallback.onLog(message);
        }
    }

    /**
     * 生成重签名后的输出 APK 文件路径
     */
    public static File generateOutputFile(Context context, Uri uri) {
        try {
            String fileName = "signed_" + System.currentTimeMillis() + ".apk";
            File dir = context.getExternalFilesDir(null);
            if (dir == null) {
                dir = context.getFilesDir();
            }
            File signedDir = new File(dir, "signed_apk");
            if (!signedDir.exists()) {
                signedDir.mkdirs();
            }
            return new File(signedDir, fileName);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 重新签名 APK
     * 1. 支持 Android 9+ (API 28+)
     * 2. 同时启用 V1、V2、V3 签名方案
     */
    public boolean resignApk(ContentResolver resolver, Uri inputUri, File outputFile) {
        File inputTempFile = null;
        try {
            log("正在准备输入 APK 文件...");
            inputTempFile = File.createTempFile("input_to_sign_", ".apk", context.getCacheDir());

            // 将 Uri 内容复制到临时文件供签名读取
            try (InputStream in = resolver.openInputStream(inputUri);
                 FileOutputStream out = new FileOutputStream(inputTempFile)) {
                if (in == null) {
                    log("错误: 无法打开输入 APK 的 InputStream");
                    return false;
                }
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
                out.flush();
            }
            log("输入 APK 临时文件准备就绪: " + inputTempFile.getAbsolutePath());

            // 检查或通过 Java 代码自动生成 Keystore
            log("正在加载或动态生成签名密钥...");
            KeyStore keyStore = getOrCreateAndLoadKeyStore();
            if (keyStore == null) {
                log("错误: 无法加载或生成签名 Keystore");
                return false;
            }

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, KEY_PASSWORD);
            if (privateKey == null) {
                log("错误: 未能在 Keystore 中找到私钥，别名: " + KEY_ALIAS);
                return false;
            }

            X509Certificate cert = (X509Certificate) keyStore.getCertificate(KEY_ALIAS);
            if (cert == null) {
                log("错误: 未能在 Keystore 中找到证书，别名: " + KEY_ALIAS);
                return false;
            }

            log("密钥加载成功，正在配置 ApkSigner...");

            // 构建签名者配置
            ApkSigner.SignerConfig signerConfig = new ApkSigner.SignerConfig.Builder(
                    "CERT", privateKey, Collections.singletonList(cert)
            ).build();

            // 配置 ApkSigner 构建器：同时开启 V1, V2, V3 签名，显式指定最小支持版本 28 (Android 9+)
            ApkSigner.Builder builder = new ApkSigner.Builder(Collections.singletonList(signerConfig))
                    .setInputApk(inputTempFile)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(true)  // V1 签名
                    .setV2SigningEnabled(true)  // V2 签名
                    .setV3SigningEnabled(true); // V3 签名 (Android 9+)

            log("开始执行多版本 (V1/V2/V3) 签名算法...");
            builder.build().sign();

            log("APK 重新签名成功！\n输出文件: " + outputFile.getAbsolutePath());
            return true;

        } catch (Exception e) {
            String detailMsg = e.getMessage();
            Throwable cause = e.getCause();
            while (cause != null) {
                detailMsg += " -> 根因: " + cause.getMessage();
                cause = cause.getCause();
            }
            log("异常: 重新签名失败 - " + detailMsg);
            e.printStackTrace();
            if (outputFile != null && outputFile.exists()) {
                outputFile.delete();
            }
            return false;
        } finally {
            if (inputTempFile != null && inputTempFile.exists()) {
                inputTempFile.delete();
            }
        }
    }

    /**
     * 获取或通过 Java 代码动态生成 Keystore（使用 BouncyCastle 提供的 PKCS12 引擎）
     */
    private KeyStore getOrCreateAndLoadKeyStore() {
        try {
            File localKeystoreFile = new File(context.getFilesDir(), KEYSTORE_NAME);
            BouncyCastleProvider bcProvider = new BouncyCastleProvider();

            // 如果本地文件不存在，直接通过 Java 代码动态生成
            if (!localKeystoreFile.exists()) {
                log("本地未检测到 Keystore，正在通过 BouncyCastle 动态生成...");
                boolean generated = generateAndSaveKeystore(localKeystoreFile, bcProvider);
                if (!generated) {
                    return null;
                }
            } else {
                log("检测到本地已存在 Keystore，正在校验: " + localKeystoreFile.getAbsolutePath());
                try {
                    // 【关键修复】显式传入 bcProvider 实例，使用 BouncyCastle 自带的 PKCS12 引擎
                    KeyStore testStore = KeyStore.getInstance("PKCS12", bcProvider);
                    try (FileInputStream fis = new FileInputStream(localKeystoreFile)) {
                        testStore.load(fis, KEY_PASSWORD);
                    }
                    if (!testStore.containsAlias(KEY_ALIAS)) {
                        log("本地 Keystore 缺少别名，重新生成...");
                        localKeystoreFile.delete();
                        generateAndSaveKeystore(localKeystoreFile, bcProvider);
                    }
                } catch (Exception e) {
                    log("本地 Keystore 损坏，重新生成...");
                    localKeystoreFile.delete();
                    generateAndSaveKeystore(localKeystoreFile, bcProvider);
                }
            }

            // 加载最终的 KeyStore
            KeyStore keyStore = KeyStore.getInstance("PKCS12", bcProvider);
            try (FileInputStream fis = new FileInputStream(localKeystoreFile)) {
                keyStore.load(fis, KEY_PASSWORD);
            }
            return keyStore;

        } catch (Exception e) {
            log("加载或生成 Keystore 异常: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 核心：纯 Java 代码生成符合 apksig 规范的自签名 Keystore 文件
     */
    private boolean generateAndSaveKeystore(File keystoreFile, BouncyCastleProvider bcProvider) {
        try {
            log("1/3: 正在生成 2048 位 RSA 密钥对...");
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            log("2/3: 正在生成自签名证书...");
            long now = System.currentTimeMillis();
            Date startDate = new Date(now - 86400000L * 7); // 7天前开始生效
            Date endDate = new Date(now + 30L * 365L * 86400000L); // 有效期 30 年
            BigInteger serialNumber = BigInteger.valueOf(now);

            X500Name subjectAndIssuer = new X500Name("CN=Android Debug, O=Android, C=US");

            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo pubKeyInfo = 
                    org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    subjectAndIssuer,
                    serialNumber,
                    startDate,
                    endDate,
                    subjectAndIssuer,
                    pubKeyInfo
            );

            // 必须添加 KeyUsage 权限扩展，否则 apksig 会拒绝签名
            KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
            certBuilder.addExtension(Extension.keyUsage, true, keyUsage);

            ContentSigner contentSigner = new StandardRsaContentSigner(keyPair.getPrivate());
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);

            byte[] certBytes = certHolder.getEncoded();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));

            log("3/3: 正在创建 PKCS12 格式的 Keystore 并持久化保存...");
            // 【关键修复】使用 BouncyCastle 的 PKCS12 引擎，彻底摆脱系统限制
            KeyStore keyStore = KeyStore.getInstance("PKCS12", bcProvider);
            keyStore.load(null, null);
            keyStore.setKeyEntry(KEY_ALIAS, keyPair.getPrivate(), KEY_PASSWORD, new java.security.cert.Certificate[]{cert});

            // 写入本地文件
            try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
                keyStore.store(fos, KEY_PASSWORD);
            }

            log("Keystore 动态生成成功！保存路径: " + keystoreFile.getAbsolutePath());
            return true;

        } catch (Exception e) {
            log("动态生成 Keystore 失败: " + e.getMessage());
            e.printStackTrace();
            if (keystoreFile.exists()) {
                keystoreFile.delete();
            }
            return false;
        }
    }

    /**
     * 原生轻量级 ContentSigner 实现类
     */
    private static class StandardRsaContentSigner implements ContentSigner {
        private final PrivateKey privateKey;
        private final ByteArrayOutputStream stream = new ByteArrayOutputStream();
        private final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption);

        public StandardRsaContentSigner(PrivateKey privateKey) {
            this.privateKey = privateKey;
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return algorithmIdentifier;
        }

        @Override
        public OutputStream getOutputStream() {
            return stream;
        }

        @Override
        public byte[] getSignature() {
            try {
                byte[] dataToSign = stream.toByteArray();
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(privateKey);
                signature.update(dataToSign);
                return signature.sign();
            } catch (Exception e) {
                throw new RuntimeException("StandardRsaContentSigner 签名出错: " + e.getMessage(), e);
            }
        }
    }
}
