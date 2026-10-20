package com.leapermagic.magic;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.util.Log;
import android.database.Cursor;
import android.os.Environment;
import android.provider.OpenableColumns;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ApkSignerUtil {

    private static final String TAG = "ApkSignerUtil";
    
    private final Context context;

    public interface SignLogCallback {
        void onLog(String message);
    }

    private SignLogCallback logCallback;

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
     * 核心重签名方法，支持V1+V2+V3全版本签名
     */
    public boolean resignApk(ContentResolver contentResolver, Uri apkUri, File outputFile) {
        log("========== 签名开始 ==========");
        try {
            // 1. 确保通过 Rust 成功生成或加载私钥与证书
            if (!ensureCertificateGenerated()) {
                log("❌ 无法获取有效的签名证书和私钥");
                return false;
            }

            File keyFile = new File(context.getFilesDir(), "private_key.der");
            File certFile = new File(context.getFilesDir(), "cert.der");

            PrivateKey privateKey = loadPrivateKey(keyFile);
            X509Certificate cert = loadCertificate(certFile);

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

            List<X509Certificate> x509CertList = new ArrayList<>();
            x509CertList.add(cert);
            
            // 构建签名配置
            ApkSigner.SignerConfig signerConfig = new ApkSigner.SignerConfig.Builder(
                    "AutoSign", 
                    privateKey, 
                    x509CertList
            ).build();

            // 3. 启用V1+V2+V3全签名方案
            ApkSigner apkSigner = new ApkSigner.Builder(Collections.singletonList(signerConfig))
                    .setInputApk(inputApk)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .build();

            // 4. 执行签名
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

            // 清理临时输入文件
            if (inputApk.exists()) inputApk.delete();
            
            return success;

        } catch (Exception e) {
            log("❌ 签名异常: " + e.getMessage());
            Log.e(TAG, "签名详细错误", e);
            return false;
        }
    }

    /**
     * 检查或调用 Rust 可执行程序生成证书与私钥
     */
    private synchronized boolean ensureCertificateGenerated() {
        File keyFile = new File(context.getFilesDir(), "private_key.der");
        File certFile = new File(context.getFilesDir(), "cert.der");

        if (keyFile.exists() && certFile.exists()) {
            return true;
        }

        log("本地证书不存在，正在调用 Rust 生成器...");
        try {
            String abi = getPrimaryAbi();
            log("当前设备架构 ABI: " + abi);

            String assetPath = "bin/" + abi + "/cert_generator";
            File execFile = new File(context.getFilesDir(), "cert_generator");

            // 从 assets 中复制对应的可执行文件到 cache 目录
            try (InputStream in = context.getAssets().open(assetPath);
                 OutputStream out = new FileOutputStream(execFile)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
            }

            // 赋予执行权限
            if (!execFile.setExecutable(true, false)) {
                log("⚠️ 警告：赋予可执行权限失败");
            }

            // 执行 Rust 二进制程序，输出路径指定为 context.getFilesDir()
            String outputDir = context.getFilesDir().getAbsolutePath();
            ProcessBuilder pb = new ProcessBuilder(execFile.getAbsolutePath(), outputDir);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            // 读取 Rust 执行日志
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    log("[Rust] " + line);
                }
            }

            int exitCode = process.waitFor();
            execFile.delete(); // 清理临时可执行文件

            return exitCode == 0 && keyFile.exists() && certFile.exists();
        } catch (Exception e) {
            log("❌ 执行 Rust 证书生成器失败: " + e.getMessage());
            Log.e(TAG, "Rust exec error", e);
            return false;
        }
    }

    private String getPrimaryAbi() {
        String[] abis = Build.SUPPORTED_ABIS;
        if (abis == null || abis.length == 0) {
            return "armeabi-v7a";
        }
        String abi = abis[0].toLowerCase();
        if (abi.contains("arm64") || abi.contains("aarch64")) {
            return "arm64-v8a";
        } else if (abi.contains("x86_64")) {
            return "x86_64";
        } else {
            return "armeabi-v7a";
        }
    }

    private PrivateKey loadPrivateKey(File keyFile) throws Exception {
        byte[] keyBytes = readAllBytes(keyFile);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private X509Certificate loadCertificate(File certFile) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(certFile)) {
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    private byte[] readAllBytes(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            return bos.toByteArray();
        }
    }

    /**
     * 验证APK签名有效性
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
     * 从Uri复制APK到临时文件
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
