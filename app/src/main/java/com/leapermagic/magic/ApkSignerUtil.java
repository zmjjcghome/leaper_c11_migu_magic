package com.leapermagic.magic;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.util.Log;

import com.android.apksig.ApkSigner;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";
    private static final String KEYSTORE_NAME = "debug.keystore";
    private static final String KEY_ALIAS = "androiddebugkey";
    private static final char[] KEY_PASSWORD = "android".toCharArray();

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

            log("密钥加载成功，正在配置 ApkSigner (apksig 8.2.2 兼容版)...");

            // 适配 apksig 8.2.2 的构建方式
            ApkSigner.SignerConfig signerConfig = new ApkSigner.SignerConfig.Builder(
                    "CERT", privateKey, Collections.singletonList(cert)
            ).build();

            // 配置 ApkSigner 构建器：同时开启 V1、V2、V3 签名
            ApkSigner.Builder builder = new ApkSigner.Builder(Collections.singletonList(signerConfig))
                    .setInputApk(inputTempFile)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(true) // V1 签名
                    .setV2SigningEnabled(true) // V2 签名
                    .setV3SigningEnabled(true); // V3 签名 (Android 9+)

            log("开始执行多版本签名算法...");
            builder.build().sign();

            log("APK 重新签名成功！\n输出文件: " + outputFile.getAbsolutePath());
            return true;

        } catch (Exception e) {
            log("异常: 重新签名失败 - " + e.getMessage());
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
     * 加载本地 Keystore：
     * 1. 如果本地文件不存在，先尝试从 assets 复制；
     * 2. 如果 assets 也没有，则通过代码自动生成一个新的 Keystore 文件；
     * 3. 后续所有签名均从该本地文件读取。
     */
    private KeyStore loadDebugKeyStore() {
        try {
            File localKeystoreFile = new File(context.getFilesDir(), KEYSTORE_NAME);

            // 如果本地没有 keystore 文件，进行初始化
            if (!localKeystoreFile.exists()) {
                log("本地未找到 keystore 文件，正在初始化...");
                boolean initialized = false;

                // 尝试从 assets 复制
                try (InputStream is = context.getAssets().open(KEYSTORE_NAME);
                     FileOutputStream fos = new FileOutputStream(localKeystoreFile)) {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = is.read(buffer)) != -1) {
                        fos.write(buffer, 0, read);
                    }
                    fos.flush();
                    initialized = true;
                    log("已成功从 assets 复制 debug.keystore 到本地存储。");
                } catch (Exception e) {
                    log("assets 中未找到 debug.keystore，将通过代码自动生成...");
                }

                // 如果 assets 也没有，自动生成
                if (!initialized) {
                    boolean generated = generateAndSaveKeystore(localKeystoreFile);
                    if (!generated) {
                        return null;
                    }
                }
            } else {
                log("从本地路径读取 Keystore: " + localKeystoreFile.getAbsolutePath());
            }

            // 从本地文件加载 KeyStore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(localKeystoreFile)) {
                keyStore.load(fis, KEY_PASSWORD);
            }
            return keyStore;

        } catch (Exception e) {
            log("加载 Keystore 失败: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 当本地和 assets 均无 keystore 时，自动生成一个新的 keystore 文件
     */
    private boolean generateAndSaveKeystore(File keystoreFile) {
        try {
            log("正在生成 2048 位 RSA 密钥对...");
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            log("正在生成自签名 X.509 证书 (有效期 30 年)...");
            X509Certificate cert;
            try {
                // 使用 Android 内置的 BouncyCastle 动态生成自签名证书
                Class<?> genClass = Class.forName("com.android.org.bouncycastle.x509.X509V3CertificateGenerator");
                Object certGen = genClass.getDeclaredConstructor().newInstance();

                genClass.getMethod("setSerialNumber", BigInteger.class)
                        .invoke(certGen, BigInteger.valueOf(System.currentTimeMillis()));
                
                X500Principal issuer = new X500Principal("CN=Android Debug, O=Android, C=US");
                genClass.getMethod("setIssuerDN", X500Principal.class).invoke(certGen, issuer);
                genClass.getMethod("setNotBefore", Date.class).invoke(certGen, new Date(System.currentTimeMillis() - 86400000L));
                genClass.getMethod("setNotAfter", Date.class).invoke(certGen, new Date(System.currentTimeMillis() + 30L * 365L * 86400000L));
                genClass.getMethod("setSubjectDN", X500Principal.class).invoke(certGen, issuer);
                genClass.getMethod("setPublicKey", java.security.PublicKey.class).invoke(certGen, keyPair.getPublic());
                genClass.getMethod("setSignatureAlgorithm", String.class).invoke(certGen, "SHA256WithRSAEncryption");

                cert = (X509Certificate) genClass.getMethod("generate", PrivateKey.class)
                        .invoke(certGen, keyPair.getPrivate());
            } catch (Exception e) {
                log("生成自签名证书错误: " + e.getMessage());
                return false;
            }

            if (cert == null) {
                log("错误: 生成的自签名证书为空");
                return false;
            }

            // 创建 PKCS12 类型的 Keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry(KEY_ALIAS, keyPair.getPrivate(), KEY_PASSWORD, new java.security.cert.Certificate[]{cert});

            // 保存到本地文件
            try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
                keyStore.store(fos, KEY_PASSWORD);
            }
            log("自动生成 Keystore 成功并已保存至: " + keystoreFile.getAbsolutePath());
            return true;

        } catch (Exception e) {
            log("自动生成 Keystore 异常: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
}
