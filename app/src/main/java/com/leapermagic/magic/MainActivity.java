package com.leapermagic.magic;

import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInstaller;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.Editable;
import android.text.TextWatcher;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Field;

public class MainActivity extends AppCompatActivity {

    private static final String PREFS_NAME = "leapermagic_magic_prefs";
    private static final String KEY_TARGET_PATH = "target_path";
    private static final String DEFAULT_PATH =
            "/storage/self/primary/Android/data/com.leapmotor.appcenter/files/download/com.migu.car.music.apk";

    // ====== 新增：绕过安装所需的常量 ======
    private static final String DEX_SOURCE_PATH = "/data/local/tmp/Api64Installer.dex";
    private static final String INSTALLER_CLASS = "com.lipu.install.Api64Installer";
    private static final int INSTALL_REASON_ENTERPRISE_POLICY = 0x40; // INSTALL_REASON_ENTERPRISE_POLICY

    private Uri selectedApkUri;
    private String targetPath;
    private boolean isMonitoring = false;
    private Thread monitorThread;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private SharedPreferences prefs;

    private TextView tvSelectedApk;
    private EditText etTargetPath;
    private Button btnToggleMonitor;
    private Button btnShellInstall; // 新增：Shell 安装按钮
    private TextView tvStatus;

    private ActivityResultLauncher<Intent> selectApkLauncher;
    private ActivityResultLauncher<Intent> manageStorageLauncher;

    private final Handler saveHandler = new Handler(Looper.getMainLooper());
    private final Runnable saveRunnable = () -> savePath(etTargetPath.getText().toString().trim());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);

        tvSelectedApk = findViewById(R.id.tv_selected_apk);
        etTargetPath = findViewById(R.id.et_target_path);
        btnToggleMonitor = findViewById(R.id.btn_toggle_monitor);
        btnShellInstall = findViewById(R.id.btn_shell_install); // 需要在布局中新增此按钮
        tvStatus = findViewById(R.id.tv_status);

        String savedPath = prefs.getString(KEY_TARGET_PATH, "");
        if (!savedPath.isEmpty()) {
            etTargetPath.setText(savedPath);
        } else {
            etTargetPath.setText(DEFAULT_PATH);
        }

        etTargetPath.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override
            public void afterTextChanged(Editable s) {
                saveHandler.removeCallbacks(saveRunnable);
                saveHandler.postDelayed(saveRunnable, 500);
            }
        });

        selectApkLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                        selectedApkUri = result.getData().getData();
                        tvSelectedApk.setText("已选择: " + selectedApkUri.getPath());
                    }
                });

        manageStorageLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        if (Environment.isExternalStorageManager()) {
                            Toast.makeText(this, "存储权限已授予", Toast.LENGTH_SHORT).show();
                        }
                    }
                });

        findViewById(R.id.btn_select_apk).setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("application/vnd.android.package-archive");
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            selectApkLauncher.launch(Intent.createChooser(intent, "选择 APK 文件"));
        });

        btnToggleMonitor.setOnClickListener(v -> {
            if (isMonitoring) {
                stopMonitoring();
            } else {
                startMonitoring();
            }
        });

        // ====== 新增：Shell 安装按钮点击事件 ======
        btnShellInstall.setOnClickListener(v -> performShellInstall());

        checkPermissions();
    }

    // ============================================================
    // 新增功能：通过 shell context 绕过 PMS 白名单和签名检查安装 APK
    // ============================================================

    /**
     * 核心方法：将 APK 通过 shell context 安装，绕过 PMS 白名单和签名检查
     * 
     * 原理：
     * 1. 将内嵌的 classes.dex（Api64Installer.dex）push 到 /data/local/tmp/
     * 2. 通过 app_process 在 shell context 下运行 Api64Installer
     * 3. Api64Installer 内部使用 PackageInstaller + setInstallReason(0x40) + 反射修改 installFlags
     *    从而绕过 PMS（PackageManagerService）的白名单和签名校验
     */
    private void performShellInstall() {
        if (selectedApkUri == null) {
            Toast.makeText(this, "请先选择要安装的 APK", Toast.LENGTH_SHORT).show();
            return;
        }

        // 先把 APK 复制到 /data/local/tmp/
        String destApkPath = "/data/local/tmp/install_target.apk";

        tvStatus.setText("正在准备绕过安装...");
        new Thread(() -> {
            try {
                // Step 1: 释放内嵌的 classes.dex -> Api64Installer.dex 到 /data/local/tmp/
                if (!pushDexToDataLocalTmp()) {
                    uiHandler.post(() -> {
                        tvStatus.setText("DEX 释放失败");
                        Toast.makeText(MainActivity.this, "Api64Installer.dex 释放失败", Toast.LENGTH_SHORT).show();
                    });
                    return;
                }

                // Step 2: 复制目标 APK 到 /data/local/tmp/
                if (!copyApkTo(destApkPath)) {
                    uiHandler.post(() -> {
                        tvStatus.setText("APK 复制失败");
                        Toast.makeText(MainActivity.this, "APK 复制到 /data/local/tmp/ 失败", Toast.LENGTH_SHORT).show();
                    });
                    return;
                }

                uiHandler.post(() -> tvStatus.setText("正在执行绕过安装..."));

                // Step 3: 执行 app_process 命令，在 shell context 下调用 Api64Installer
                // 该 Installer 内部使用 PackageInstaller + setInstallReason(0x40) + 反射修改 installFlags
                String result = executeShellInstall(destApkPath);

                uiHandler.post(() -> {
                    tvStatus.setText("安装结果: " + result);
                    Toast.makeText(MainActivity.this, "安装完成: " + result, Toast.LENGTH_LONG).show();
                });

            } catch (Exception e) {
                uiHandler.post(() -> {
                    tvStatus.setText("安装异常: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "安装失败: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                });
            }
        }).start();
    }

    /**
     * 从 APK 的 assets 或 raw 资源中提取内嵌的 classes.dex，
     * 重命名为 Api64Installer.dex 并 push 到 /data/local/tmp/
     */
    private boolean pushDexToDataLocalTmp() {
        try {
            // 方式一：如果 dex 放在 assets 目录
            // InputStream dexStream = getAssets().open("classes.dex");

            // 方式二：如果 dex 放在 res/raw 目录（如 raw/api64_installer_dex）
            // 此处以 assets 为例，开发者可按实际情况调整
            InputStream dexStream = getAssets().open("classes.dex");

            File destFile = new File("/data/local/tmp/Api64Installer.dex");

            // 如果已存在则先删除
            if (destFile.exists()) {
                destFile.delete();
            }

            try (FileOutputStream fos = new FileOutputStream(destFile)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = dexStream.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                }
                fos.flush();
            }
            dexStream.close();

            // 设置可执行权限
            destFile.setReadable(true, false);
            destFile.setWritable(true, false);

            return destFile.exists() && destFile.length() > 0;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 将用户选择的 APK 复制到指定路径
     */
    private boolean copyApkTo(String destPath) {
        try {
            File destFile = new File(destPath);
            if (destFile.exists()) {
                destFile.delete();
            }

            try (InputStream inputStream = getContentResolver().openInputStream(selectedApkUri);
                 FileOutputStream outputStream = new FileOutputStream(destFile)) {
                if (inputStream == null) return false;

                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
                outputStream.flush();
            }
            return destFile.exists() && destFile.length() > 0;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 执行 shell 命令：
     * export CLASSPATH=/data/local/tmp/Api64Installer.dex
     * app_process /system/framework com.lipu.install.Api64Installer /data/local/tmp/xxx.apk
     * 
     * Api64Installer 内部会：
     * 1. 获取 PackageInstaller 实例
     * 2. 调用 setInstallReason(INSTALL_REASON_ENTERPRISE_POLICY) 即 0x40
     * 3. 反射修改 installFlags，绕过 PMS 白名单和签名检查
     */
    private String executeShellInstall(String apkPath) {
        StringBuilder output = new StringBuilder();
        try {
            // 构建命令：
            // export CLASSPATH=/data/local/tmp/Api64Installer.dex && 
            // app_process /system/framework com.lipu.install.Api64Installer /data/local/tmp/install_target.apk
            String[] cmd = {
                "sh",
                "-c",
                "export CLASSPATH=" + DEX_SOURCE_PATH + " && " +
                "app_process /system/framework " + INSTALLER_CLASS + " " + apkPath
            };

            Process process = Runtime.getRuntime().exec(cmd);

            // 读取标准输出
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            // 读取错误输出
            try (BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = errorReader.readLine()) != null) {
                    output.append("[ERR] ").append(line).append("\n");
                }
            }

            process.waitFor();
            int exitCode = process.exitValue();
            output.insert(0, "ExitCode=" + exitCode + " | ");

        } catch (Exception e) {
            output.append("Exception: ").append(e.getMessage());
        }

        String result = output.toString().trim();
        return result.isEmpty() ? "Success (no output)" : result;
    }

    // ============================================================
    // 备选方案：直接在 Java 层通过反射绕过安装限制（需要系统权限）
    // 如果 app_process 方案不可用，可以尝试此方法
    // ============================================================

    /**
     * 备选：直接在 Android Java 层使用 PackageInstaller + 反射绕过
     * 注意：此方法需要系统级权限（system UID 或 root），普通 App 无法直接调用
     */
    @SuppressWarnings("unused")
    private void performDirectBypassInstall(String apkPath) {
        try {
            // 获取 PackageInstaller
            PackageInstaller packageInstaller = getPackageManager().getPackageInstaller();

            PackageInstaller.SessionParams params =
                    new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);

            // === 核心：反射设置 INSTALL_REASON = 0x40 (INSTALL_REASON_ENTERPRISE_POLICY) ===
            Field installReasonField = PackageInstaller.SessionParams.class.getDeclaredField("installReason");
            installReasonField.setAccessible(true);
            installReasonField.setInt(params, INSTALL_REASON_ENTERPRISE_POLICY);  // 0x40

            // === 核心：反射修改 installFlags，绕过白名单和签名检查 ===
            // 常见的绕过 flags（按需组合）：
            // INSTALL_ALLOW_TEST = 0x4          - 允许测试签名
            // INSTALL_REPLACE_EXISTING = 0x2    - 允许覆盖安装
            // INSTALL_ALLOW_DOWNGRADE = 0x80    - 允许降级
            // 0x40000000 (INSTALL_DISABLE_VERIFICATION) - 禁用签名验证（Android 内部 flag）
            Field installFlagsField = PackageInstaller.SessionParams.class.getDeclaredField("installFlags");
            installFlagsField.setAccessible(true);

            int bypassFlags = 0x4           // INSTALL_ALLOW_TEST

                            | 0x2           // INSTALL_REPLACE_EXISTING
                            | 0x80          // INSTALL_ALLOW_DOWNGRADE
                            | 0x40000000;   // INSTALL_DISABLE_VERIFICATION (绕过签名检查)
            installFlagsField.setInt(params, bypassFlags);

            // 设置 APK 文件大小
            File apkFile = new File(apkPath);
            params.setSize(apkFile.length());

            // 创建安装会话
            int sessionId = packageInstaller.createSession(params);
            PackageInstaller.Session session = packageInstaller.openSession(sessionId);

            // 写入 APK 数据
            try (InputStream in = new FileInputStream(apkFile);
                 OutputStream out = session.openWrite("package", 0, apkFile.length())) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
                session.fsync(out);
            }

            // 提交安装（传入 PendingIntent 接收结果）
            Intent intent = new Intent(this, MainActivity.class);
            // session.commit(PendingIntent.getBroadcast(...)); // 需要广播接收器

            session.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ============================================================
    // 以下为原有的文件替换监控功能（保持不变）
    // ============================================================

    private void savePath(String path) {
        if (!path.isEmpty() && !path.equals(prefs.getString(KEY_TARGET_PATH, ""))) {
            prefs.edit().putString(KEY_TARGET_PATH, path).apply();
        }
    }

    private void checkPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                intent.setData(Uri.parse("package:" + getPackageName()));
                manageStorageLauncher.launch(intent);
            }
        } else {
            if (checkSelfPermission(android.Manifest.permission.READ_EXTERNAL_STORAGE)
                    != android.content.pm.PackageManager.PERMISSION_GRANTED ||
                    checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE)
                            != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{
                        android.Manifest.permission.READ_EXTERNAL_STORAGE,
                        android.Manifest.permission.WRITE_EXTERNAL_STORAGE
                }, 200);
            }
        }
    }

    private void startMonitoring() {
        targetPath = etTargetPath.getText().toString().trim();
        if (targetPath.isEmpty()) {
            Toast.makeText(this, "请输入目标路径", Toast.LENGTH_SHORT).show();
            return;
        }
        if (selectedApkUri == null) {
            Toast.makeText(this, "请先选择 APK 文件", Toast.LENGTH_SHORT).show();
            return;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) {
            Toast.makeText(this, "请授予'所有文件访问权限'", Toast.LENGTH_SHORT).show();
            Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
            intent.setData(Uri.parse("package:" + getPackageName()));
            manageStorageLauncher.launch(intent);
            return;
        }
        isMonitoring = true;
        btnToggleMonitor.setText("停止监控");
        tvStatus.setText("正在监控目标路径...");
        Toast.makeText(this, "开始监控", Toast.LENGTH_SHORT).show();

        monitorThread = new Thread(() -> {
            File targetFile = new File(targetPath);
            File tempFile = new File(targetPath + ".tmp");
            try {
                copyToTempFile(tempFile);
                uiHandler.post(() -> {
                    tvStatus.setText("已准备替换文件，等待目标出现...");
                    Toast.makeText(MainActivity.this, "临时文件已准备好", Toast.LENGTH_SHORT).show();
                });
                while (isMonitoring) {
                    if (targetFile.exists()) {
                        replaceTargetWithTemp(targetFile, tempFile);
                        break;
                    }
                    Thread.sleep(500);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                uiHandler.post(() -> {
                    Toast.makeText(MainActivity.this, "错误: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                    tvStatus.setText("监控出错");
                });
            } finally {
                uiHandler.post(() -> {
                    if (isMonitoring) {
                        stopMonitoringFromBackground();
                    }
                });
            }
        });
        monitorThread.start();
    }

    private void stopMonitoring() {
        isMonitoring = false;
        if (monitorThread != null) {
            monitorThread.interrupt();
        }
        if (targetPath != null && !targetPath.isEmpty()) {
            File tempFile = new File(targetPath + ".tmp");
            if (tempFile.exists()) {
                tempFile.delete();
            }
        }
        btnToggleMonitor.setText("开始监控");
        tvStatus.setText("监控已停止");
    }

    private void stopMonitoringFromBackground() {
        isMonitoring = false;
        btnToggleMonitor.setText("开始监控");
        tvStatus.setText("替换完成");
        Toast.makeText(this, "文件替换已完成", Toast.LENGTH_SHORT).show();
    }

    private void copyToTempFile(File tempFile) throws Exception {
        File parent = tempFile.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
        if (tempFile.exists() && !tempFile.delete()) {
            throw new Exception("无法删除旧临时文件");
        }
        try (InputStream inputStream = getContentResolver().openInputStream(selectedApkUri);
             FileOutputStream outputStream = new FileOutputStream(tempFile)) {
            if (inputStream == null) {
                throw new Exception("无法读取 APK 文件");
            }
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            outputStream.flush();
        }
    }

    private void replaceTargetWithTemp(File targetFile, File tempFile) {
        if (!tempFile.exists()) {
            uiHandler.post(() -> Toast.makeText(MainActivity.this, "临时文件不存在", Toast.LENGTH_SHORT).show());
            return;
        }
        if (targetFile.exists() && !targetFile.delete()) {
            uiHandler.post(() -> Toast.makeText(MainActivity.this, "无法删除目标文件", Toast.LENGTH_SHORT).show());
            return;
        }
        boolean renamed = tempFile.renameTo(targetFile);
        if (renamed) {
            uiHandler.post(() -> Toast.makeText(MainActivity.this, "替换成功", Toast.LENGTH_SHORT).show());
        } else {
            copyTempToTargetFallback(targetFile, tempFile);
        }
    }

    private void copyTempToTargetFallback(File targetFile, File tempFile) {
        try (InputStream inputStream = new FileInputStream(tempFile);
             FileOutputStream outputStream = new FileOutputStream(targetFile)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            outputStream.flush();
            if (tempFile.exists()) {
                tempFile.delete();
            }
            uiHandler.post(() -> Toast.makeText(MainActivity.this, "替换成功", Toast.LENGTH_SHORT).show());
        } catch (Exception e) {
            uiHandler.post(() -> Toast.makeText(MainActivity.this, "替换失败: " + e.getMessage(), Toast.LENGTH_SHORT).show());
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        stopMonitoring();
    }
}
