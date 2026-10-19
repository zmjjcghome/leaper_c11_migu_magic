package com.leapermagic.magic;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.util.Log;

import com.android.apksig.ApkSigner;

import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.Extension;
import org.spongycastle.asn1.x509.KeyUsage;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";
    private static final String KEYSTORE_NAME = "debug.keystore";
    private static final String KEY_ALIAS = "androiddebugkey";
    private static final char[] KEY_PASSWORD = "android".toCharArray();

    // 动态注册 SpongyCastle 提供者
    static {
        try {
            Security.removeProvider("SC");
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

            // 加载或自动生成本地 Keystore
            log("正在加载签名密钥...");
            KeyStore keyStore = loadDebugKeyStore();
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

            // 配置 ApkSigner 构建器：同时开启 V1, V2, V3 签名
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
     * 加载本地 Keystore
     */
    private KeyStore loadDebugKeyStore() {
        File localKeystoreFile = new File(context.getFilesDir(), KEYSTORE_NAME);

        // 如果本地已存在 keystore，先校验有效性
        if (localKeystoreFile.exists()) {
            try {
                log("检测到本地已存在 Keystore，正在校验有效性: " + localKeystoreFile.getAbsolutePath());
                KeyStore keyStore = KeyStore.getInstance("PKCS12", "SC");
                try (FileInputStream fis = new FileInputStream(localKeystoreFile)) {
                    keyStore.load(fis, KEY_PASSWORD);
                }
                if (keyStore.containsAlias(KEY_ALIAS) && keyStore.getCertificate(KEY_ALIAS) != null) {
                    log("本地 Keystore 校验通过！");
                    return keyStore;
                } else {
                    log("本地 Keystore 无效或损坏，删除旧文件并重新生成...");
                    localKeystoreFile.delete();
                }
            } catch (Exception e) {
                log("读取本地 Keystore 异常 (" + e.getMessage() + ")，删除坏文件并重新生成...");
                localKeystoreFile.delete();
            }
        }

        // 初始化/重新生成本地 Keystore
        log("正在初始化全新的本地 Keystore...");
        boolean initialized = false;

        // 1. 尝试从 assets 复制
        try (InputStream is = context.getAssets().open(KEYSTORE_NAME);
             FileOutputStream fos = new FileOutputStream(localKeystoreFile)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) != -1) {
                fos.write(buffer, 0, read);
            }
            fos.flush();
            initialized = true;
            log("已成功从 assets 复制 debug.keystore。");
        } catch (Exception e) {
            log("assets 中无 debug.keystore，正在通过 SpongyCastle 自动生成全新证书...");
        }

        // 2. 自动生成全新合格证书
        if (!initialized) {
            boolean generated = generateAndSaveKeystore(localKeystoreFile);
            if (!generated) {
                return null;
            }
        }

        // 加载最新生成的 KeyStore
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "SC");
            try (FileInputStream fis = new FileInputStream(localKeystoreFile)) {
                keyStore.load(fis, KEY_PASSWORD);
            }
            return keyStore;
        } catch (Exception e) {
            log("加载生成的 Keystore 失败: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 使用 SpongyCastle 自动生成符合 apksig 规范的 KeyStore
     */
    private boolean generateAndSaveKeystore(File keystoreFile) {
        try {
            log("正在生成 2048 位 RSA 密钥对...");
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            log("正在生成符合 apksig 规范的自签名 X.509 证书...");
            long now = System.currentTimeMillis();
            Date startDate = new Date(now - 86400000L * 7); // 7天前开始生效
            Date endDate = new Date(now + 30L * 365L * 86400000L); // 30年有效期
            BigInteger serialNumber = BigInteger.valueOf(now);

            X500Name subjectAndIssuer = new X500Name("CN=Android Debug, O=Android, C=US");

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    subjectAndIssuer,
                    serialNumber,
                    startDate,
                    endDate,
                    subjectAndIssuer,
                    keyPair.getPublic()
            );

            // 添加数字签名与密钥加密权限
            KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
            certBuilder.addExtension(Extension.keyUsage, true, keyUsage);

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("SC")
                    .build(keyPair.getPrivate());

            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider("SC")
                    .getCertificate(certHolder);

            // 创建 PKCS12 KeyStore，提供者指定为 "SC" (SpongyCastle)
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "SC");
            keyStore.load(null, null);
            keyStore.setKeyEntry(KEY_ALIAS, keyPair.getPrivate(), KEY_PASSWORD, new java.security.cert.Certificate[]{cert});

            // 保存文件
            try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
                keyStore.store(fos, KEY_PASSWORD);
            }
            log("自动生成 Keystore 成功并已保存至: " + keystoreFile.getAbsolutePath());
            return true;

        } catch (Exception e) {
            log("自动生成 Keystore 异常: " + e.getMessage());
            e.printStackTrace();
            if (keystoreFile.exists()) {
                keystoreFile.delete();
            }
            return false;
        }
    }
}
