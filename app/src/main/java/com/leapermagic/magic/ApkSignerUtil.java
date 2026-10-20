package com.leapermagic.magic;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.util.Log;
import android.database.Cursor;
import android.os.Environment;
import android.provider.OpenableColumns;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";

    // 密钥库配置
    private static final String KEYSTORE_FILENAME = "autosign.p12";
    private static final String KEYSTORE_PASSWORD = "changeit";
    private static final String KEY_ALIAS = "autosign_alias";

    private final Context context;
    private SignLogCallback logCallback;

    // 【核心修复 1】：提前持有 BC Provider，用于 apksig 底层加密算法
    private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();

    static {
        // 注册 BC Provider，apksig 的 V2/V3 签名强依赖它
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(BC_PROVIDER);
    }

    public ApkSignerUtil(Context context) {
        this.context = context.getApplicationContext();
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

    /**
     * 核心重签名方法，支持 V1+V2+V3 全版本签名
     */
    public boolean resignApk(ContentResolver contentResolver, Uri apkUri, File outputFile) {
        log("========== 签名开始 ==========");
        try {
            // 1. 确保 p12 密钥库已就绪
            if (!ensureKeystoreExtracted()) {
                log("❌ 无法获取有效的签名密钥库");
                return false;
            }

            File p12File = new File(context.getFilesDir(), KEYSTORE_FILENAME);

            // 【核心修复 2】：使用 Android 系统默认 Provider 加载 PKCS12
            // 绝对不要写 KeyStore.getInstance("PKCS12", BC_PROVIDER)，Android 会报 not found
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(p12File)) {
                keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
            }

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, KEYSTORE_PASSWORD.toCharArray());
            Certificate[] certChain = keyStore.getCertificateChain(KEY_ALIAS);

            if (privateKey == null || certChain == null || certChain.length == 0) {
                throw new IllegalStateException("无法从密钥库加载密钥或证书");
            }

            X509Certificate cert = (X509Certificate) certChain[0];
            log("使用密钥别名: " + KEY_ALIAS);
            log("证书主体: " + cert.getSubjectDN());

            // 2. 准备输出目录与临时输入文件
            if (outputFile.getParentFile() != null && !outputFile.getParentFile().exists()) {
                outputFile.getParentFile().mkdirs();
            }
            if (outputFile.exists()) outputFile.delete();

            File inputApk = copyUriToTempFile(contentResolver, apkUri);
            if (inputApk == null || !inputApk.exists() || inputApk.length() == 0) {
                log("❌ 无法读取输入 APK");
                return false;
            }
            log("输入文件大小: " + inputApk.length() + " bytes");

            // 3. 构建签名配置
            List<X509Certificate> x509CertList = new ArrayList<>();
            for (Certificate c : certChain) {
                if (c instanceof X509Certificate) {
                    x509CertList.add((X509Certificate) c);
                }
            }

            ApkSigner.SignerConfig signerConfig = new ApkSigner.SignerConfig.Builder(
                    "AutoSign",
                    privateKey,
                    x509CertList
            ).build();

            // 4. 启用 V1+V2+V3 全签名方案并执行
            ApkSigner apkSigner = new ApkSigner.Builder(Collections.singletonList(signerConfig))
                    .setInputApk(inputApk)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .build();

            apkSigner.sign();
            log("ApkSigner.sign() 执行完成");

            // 5. 验证签名结果
            boolean success = outputFile.exists() && outputFile.length() > 0;
            if (success) {
                log("✅ 签名成功: " + outputFile.getAbsolutePath());
                verifyApkSignature(outputFile);
            } else {
                log("❌ 签名失败：输出文件为空或不存在");
            }

            // 清理临时文件
            if (inputApk.exists()) inputApk.delete();
            return success;

        } catch (Exception e) {
            log("❌ 签名异常: " + e.getMessage());
            if (e.getCause() != null) {
                log("❌ 异常原因 (Cause): " + e.getCause().getMessage());
            }
            Log.e(TAG, "签名详细错误", e);
            return false;
        }
    }

    /**
     * 检查并从 assets 中提取 p12 密钥库到 filesDir
     */
    private synchronized boolean ensureKeystoreExtracted() {
        File p12File = new File(context.getFilesDir(), KEYSTORE_FILENAME);
        if (p12File.exists()) return true;

        log("本地密钥库不存在，正在从 assets 释放...");
        try (InputStream in = context.getAssets().open(KEYSTORE_FILENAME);
             OutputStream out = new FileOutputStream(p12File)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            log("✅ 密钥库释放成功: " + p12File.getAbsolutePath());
            return true;
        } catch (Exception e) {
            log("❌ 释放密钥库失败: " + e.getMessage());
            Log.e(TAG, "Extract keystore error", e);
            return false;
        }
    }

    /**
     * 验证 APK 签名有效性
     */
    private void verifyApkSignature(File apkFile) {
        try {
            ApkVerifier.Result result = new ApkVerifier.Builder(apkFile).build().verify();
            if (result.isVerified()) {
                log("✅ APK 签名验证通过");
            } else {
                log("❌ APK 签名验证失败");
                for (ApkVerifier.IssueWithParams issue : result.getErrors()) {
                    log("错误详情: " + issue);
                }
            }
        } catch (Exception e) {
            log("验证过程出错: " + e.getMessage());
        }
    }

    /**
     * 从 Uri 复制 APK 到临时文件
     */
    private File copyUriToTempFile(ContentResolver cr, Uri uri) throws IOException {
        InputStream is = cr.openInputStream(uri);
        if (is == null) return null;

        File tempFile = File.createTempFile("apk_input_", ".apk", context.getCacheDir());
        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            byte[] buffer = new byte[8192];
            int len;
            while ((len = is.read(buffer)) != -1) {
                fos.write(buffer, 0, len);
            }
        } finally {
            is.close();
        }
        return tempFile;
    }

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
        if (name == null && uri.getPath() != null) {
            String path = uri.getPath();
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash != -1) name = path.substring(lastSlash + 1);
            else name = path;
        }
        return (name != null && !name.isEmpty()) ? name : "unsigned.apk";
    }

    private static String insertResigned(String name) {
        int dot = name.lastIndexOf('.');
        if (dot > 0) return name.substring(0, dot) + "_resigned" + name.substring(dot);
        return name + "_resigned.apk";
    }

    public interface SignLogCallback {
        void onLog(String message);
    }
}
