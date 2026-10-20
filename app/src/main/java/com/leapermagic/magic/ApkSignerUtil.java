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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.Date;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";
    private static final String KEY_FILE_NAME = "signing_private.key";
    private static final String CERT_FILE_NAME = "signing_cert.crt";

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

            // 获取或动态生成签名密钥对与证书
            log("正在加载或动态生成签名密钥...");
            PrivateKey privateKey = loadOrGeneratePrivateKey();
            X509Certificate cert = loadOrGenerateCertificate(privateKey);

            if (privateKey == null || cert == null) {
                log("错误: 无法获取有效的私钥或证书");
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
                    .setV3SigningEnabled(false)  // V3 签名 (Android 9+)
                    .setMinSdkVersion(28);     // 【关键修复】显式指定最小支持版本，防止 V3 签名块解析清单失败

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
     * 加载私钥，如果本地不存在则自动生成并保存
     */
    private PrivateKey loadOrGeneratePrivateKey() {
        try {
            File keyFile = new File(context.getFilesDir(), KEY_FILE_NAME);
            File certFile = new File(context.getFilesDir(), CERT_FILE_NAME);

            // 如果文件已存在，直接从本地二进制读取
            if (keyFile.exists() && certFile.exists()) {
                log("检测到本地已存在签名文件，正在加载...");
                byte[] keyBytes = readFileBytes(keyFile);
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return kf.generatePrivate(spec);
            }

            // 如果不存在，自动生成全新的密钥对与证书
            log("本地未检测到签名文件，正在自动生成全新密钥对...");
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // 保存私钥字节
            writeFileBytes(keyFile, keyPair.getPrivate().getEncoded());

            // 生成并保存证书字节
            X509Certificate cert = generateSelfSignedCert(keyPair);
            writeFileBytes(certFile, cert.getEncoded());

            log("新签名文件已成功生成并持久化。");
            return keyPair.getPrivate();

        } catch (Exception e) {
            log("加载或生成私钥异常: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 加载证书，如果不存在则由私钥重新生成
     */
    private X509Certificate loadOrGenerateCertificate(PrivateKey privateKey) {
        try {
            File certFile = new File(context.getFilesDir(), CERT_FILE_NAME);
            if (certFile.exists()) {
                byte[] certBytes = readFileBytes(certFile);
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
            }
            return null;
        } catch (Exception e) {
            log("加载证书异常: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 生成自签名 X.509 证书
     */
    private X509Certificate generateSelfSignedCert(KeyPair keyPair) throws Exception {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now - 86400000L * 7); // 7天前
        Date endDate = new Date(now + 30L * 365L * 86400000L); // 30年有效期
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

        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
        certBuilder.addExtension(Extension.keyUsage, true, keyUsage);

        ContentSigner contentSigner = new StandardRsaContentSigner(keyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(contentSigner);

        byte[] certBytes = certHolder.getEncoded();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
    }

    private byte[] readFileBytes(File file) throws Exception {
        try (FileInputStream fis = new FileInputStream(file);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, read);
            }
            return bos.toByteArray();
        }
    }

    private void writeFileBytes(File file, byte[] data) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
            fos.flush();
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
