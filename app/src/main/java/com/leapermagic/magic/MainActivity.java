package com.leapermagic.magic;

import android.content.Intent;
import android.content.SharedPreferences;
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
import java.io.IOException;

public class MainActivity extends AppCompatActivity {

    private static final String PREFS_NAME = "leapermagic_magic_prefs";
    private static final String KEY_TARGET_PATH = "target_path";
    private static final String DEFAULT_PATH =
            "/storage/self/primary/Android/data/com.leapmotor.appcenter/files/download/com.migu.car.music.apk";

    // ====== Shell 绕过安装常量 ======
    private static final String[] DEX_CANDIDATE_PATHS = {
            "/data/local/tmp/Api64Installer.dex",
            "/data/data/com.leapermagic.magic/files/Api64Installer.dex",
            "/sdcard/Api64Installer.dex"
    };
    private static final String[] APK_CANDIDATE_PATHS = {
            "/data/local/tmp/install_target.apk",
            "/data/data/com.leapermagic.magic/files/install_target.apk",
            "/sdcard/install_target.apk"
    };
    private static final String INSTALLER_CLASS = "com.lipu.install.Api64Installer";
    /** 当前的 adbd 端口，-1 表示未连接 */
    private int adbdPort = -1;
    
    /** ADB 连接实例 */
    private AdbConnection adbConnection;
    
    private Uri selectedApkUri;
    private String targetPath;
    private boolean isMonitoring = false;
    private Thread monitorThread;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private SharedPreferences prefs;

    private TextView tvSelectedApk;
    private TextView tvLog;
    private EditText etTargetPath;
    private Button btnToggleMonitor;
    private Button btnPrepareFiles;    // 按钮1：复制 dex + apk
    private Button btnExecuteInstall;  // 按钮2：执行安装
    private TextView tvStatus;

    // 记录最终成功的路径
    private String actualDexPath = null;
    private String actualApkPath = null;

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
        tvLog = findViewById(R.id.tv_log);
        etTargetPath = findViewById(R.id.et_target_path);
        btnToggleMonitor = findViewById(R.id.btn_toggle_monitor);
        btnPrepareFiles = findViewById(R.id.btn_prepare_files);
        btnExecuteInstall = findViewById(R.id.btn_execute_install);
        tvStatus = findViewById(R.id.tv_status);

        // 初始状态：安装按钮不可用
        btnExecuteInstall.setEnabled(false);

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
                        // 重新选择 APK 后需要重新准备文件
                        actualDexPath = null;
                        actualApkPath = null;
                        btnExecuteInstall.setEnabled(false);
                        appendLog("已选择 APK，请点击'准备文件'");
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

        // ====== 按钮1：准备文件 ======
        btnPrepareFiles.setOnClickListener(v -> prepareFiles());

        // ====== 按钮2：执行安装 ======
        btnExecuteInstall.setOnClickListener(v -> executeInstall());

        checkPermissions();
    }
    
    /**
     * 初始化：自动检测 adbd 端口并建立连接
     * 在 onCreate 或用户点击某个按钮时调用
     */
    private void initAdbConnection() {
        //new Thread(() -> {
            appendLog("========== 开始检测 adbd ==========");
    
            // 自动检测端口
            adbdPort = AdbPortDetector.detect(-1, msg -> {
                runOnUiThread(() -> appendLog("[检测] " + msg));
            });
    
            if (adbdPort > 0) {
                appendLog("[成功] 找到 adbd 端口: " + adbdPort);
                // 建立持久连接
                try {
                    adbConnection = new AdbConnection();
                    adbConnection.connect("127.0.0.1", adbdPort, 5000);
                    appendLog("[成功] 已连接到 adbd (端口 " + adbdPort + ")");
                } catch (IOException e) {
                    appendLog("[失败] 连接 adbd 失败: " + e.getMessage());
                    adbdPort = -1;
                    adbConnection = null;
                }
            } else {
                appendLog("[失败] 未找到 adbd 监听端口");
                appendLog("[提示] 请在设置中开启无线调试 (Android 11+)");
                appendLog("[提示] 或通过 USB 执行: adb tcpip 5555");
            }
        //}).start();
    }
    
    // ============================================================
    // 日志辅助方法
    // ============================================================
    private void appendLog(String msg) {
        uiHandler.post(() -> {
            String current = tvLog.getText().toString();
            String timestamp = new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
                    .format(new java.util.Date());
            String newLine = "[" + timestamp + "] " + msg;
            if (current.isEmpty()) {
                tvLog.setText(newLine);
            } else {
                tvLog.setText(current + "\n" + newLine);
            }
        });
    }

    // ============================================================
    // 按钮1：准备文件（复制 DEX + APK）
    // ============================================================
    private void prepareFiles() {
        if (selectedApkUri == null) {
            Toast.makeText(this, "请先选择要安装的 APK", Toast.LENGTH_SHORT).show();
            return;
        }

        btnPrepareFiles.setEnabled(false);
        tvStatus.setText("正在准备文件...");
        appendLog("========== 开始准备文件 ==========");

        new Thread(() -> {
            // Step 1: 释放 DEX
            actualDexPath = pushDexWithFallback();
            if (actualDexPath == null) {
                uiHandler.post(() -> {
                    tvStatus.setText("DEX 释放失败，查看日志");
                    btnPrepareFiles.setEnabled(true);
                });
                return;
            }
            appendLog("DEX 释放成功 → " + actualDexPath);

            // Step 2: 复制 APK
            actualApkPath = copyApkWithFallback();
            if (actualApkPath == null) {
                uiHandler.post(() -> {
                    tvStatus.setText("APK 复制失败，查看日志");
                    btnPrepareFiles.setEnabled(true);
                });
                return;
            }
            appendLog("APK 复制成功 → " + actualApkPath);

            uiHandler.post(() -> {
                tvStatus.setText("文件准备完成，可执行安装");
                btnPrepareFiles.setEnabled(true);
                btnExecuteInstall.setEnabled(true);
                Toast.makeText(MainActivity.this, "文件准备完成", Toast.LENGTH_SHORT).show();
            });
        }).start();
    }

    /**
     * 尝试多个路径释放 DEX，返回成功写入的路径
     */
    private String pushDexWithFallback() {
        for (String path : DEX_CANDIDATE_PATHS) {
            appendLog("尝试释放 DEX → " + path);
            if (tryPushDex(path)) {
                return path;
            }
            appendLog("  ✗ 失败");
        }
        appendLog("所有 DEX 路径均写入失败！");
        return null;
    }

    private boolean tryPushDex(String destPath) {
        try {
            File destFile = new File(destPath);

            // 确保父目录存在
            File parent = destFile.getParentFile();
            if (parent != null && !parent.exists()) {
                boolean mkdirResult = parent.mkdirs();
                appendLog("  mkdirs " + parent.getAbsolutePath() + " → " + mkdirResult);
            }

            // 检查父目录是否可写
            if (parent != null && !parent.canWrite()) {
                appendLog("  父目录不可写: " + parent.getAbsolutePath());
                return false;
            }

            // 删除旧文件
            if (destFile.exists()) {
                boolean deleted = destFile.delete();
                appendLog("  删除旧文件 → " + deleted);
            }

            // 从 assets 读取
            InputStream dexStream = getAssets().open("classes.dex");
            if (dexStream == null) {
                appendLog("  assets/classes.dex 不存在！");
                return false;
            }

            int available = dexStream.available();
            appendLog("  assets/classes.dex 大小: " + available + " bytes");

            // 写入文件
            try (FileOutputStream fos = new FileOutputStream(destFile)) {
                byte[] buffer = new byte[8192];
                int bytesRead, total = 0;
                while ((bytesRead = dexStream.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    total += bytesRead;
                }
                fos.flush();
                appendLog("  写入 " + total + " bytes");
            }
            dexStream.close();

            // 设置权限
            destFile.setReadable(true, false);
            destFile.setExecutable(true, false);

            boolean success = destFile.exists() && destFile.length() > 0;
            appendLog("  最终: exists=" + destFile.exists() + ", size=" + destFile.length() + " → " + (success ? "✓" : "✗"));
            return success;

        } catch (Exception e) {
            appendLog("  异常: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 尝试多个路径复制 APK，返回成功写入的路径
     */
    private String copyApkWithFallback() {
        for (String path : APK_CANDIDATE_PATHS) {
            appendLog("尝试复制 APK → " + path);
            if (tryCopyApk(path)) {
                return path;
            }
            appendLog("  ✗ 失败");
        }
        appendLog("所有 APK 路径均写入失败！");
        return null;
    }

    private boolean tryCopyApk(String destPath) {
        try {
            File destFile = new File(destPath);

            // 确保父目录存在
            File parent = destFile.getParentFile();
            if (parent != null && !parent.exists()) {
                boolean mkdirResult = parent.mkdirs();
                appendLog("  mkdirs " + parent.getAbsolutePath() + " → " + mkdirResult);
            }

            // 检查父目录是否可写
            if (parent != null && !parent.canWrite()) {
                appendLog("  父目录不可写: " + parent.getAbsolutePath());
                return false;
            }

            // 删除旧文件
            if (destFile.exists()) {
                boolean deleted = destFile.delete();
                appendLog("  删除旧文件 → " + deleted);
            }

            // 从 URI 复制
            try (InputStream inputStream = getContentResolver().openInputStream(selectedApkUri);
                 FileOutputStream fos = new FileOutputStream(destFile)) {
                if (inputStream == null) {
                    appendLog("  ContentResolver.openInputStream 返回 null");
                    return false;
                }

                byte[] buffer = new byte[8192];
                int bytesRead, total = 0;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    total += bytesRead;
                }
                fos.flush();
                appendLog("  写入 " + total + " bytes");
            }

            destFile.setReadable(true, false);

            boolean success = destFile.exists() && destFile.length() > 0;
            appendLog("  最终: exists=" + destFile.exists() + ", size=" + destFile.length() + " → " + (success ? "✓" : "✗"));
            return success;

        } catch (Exception e) {
            appendLog("  异常: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    // ============================================================
    // 按钮2：执行安装
    // ============================================================
    private void executeInstall() {
        if (actualDexPath == null || actualApkPath == null) {
            Toast.makeText(this, "请先准备文件", Toast.LENGTH_SHORT).show();
            return;
        }

        btnExecuteInstall.setEnabled(false);
        tvStatus.setText("正在执行绕过安装...");
        appendLog("========== 开始执行安装 ==========");
        appendLog("DEX: " + actualDexPath);
        appendLog("APK: " + actualApkPath);

        new Thread(() -> {
            String result = executeShellInstall(actualDexPath, actualApkPath);

            uiHandler.post(() -> {
                tvStatus.setText("安装结果: " + result);
                btnExecuteInstall.setEnabled(true);
                Toast.makeText(MainActivity.this, "安装完成: " + result, Toast.LENGTH_LONG).show();
            });
        }).start();
    }

    /**
     * 执行：
     * export CLASSPATH=<dexPath>
     * app_process /system/framework com.lipu.install.Api64Installer <apkPath>
     *//**
     * 修改后的 executeShellInstall — 通过 ADB 以 shell UID 执行
     */
    private String executeShellInstall(String dexPath, String apkPath) {
        StringBuilder output = new StringBuilder();
    
        String cmd = "export CLASSPATH=" + dexPath + " && " +
                     "app_process /system/framework " + INSTALLER_CLASS + " " + apkPath;
        if (adbConnection == null ) {
            appendLog("========== 开始初始化adb ==========");
            initAdbConnection();
        }
        // 如果 ADB 连接可用，优先使用（shell UID 权限）
        if (adbConnection != null && adbdPort > 0) {
            appendLog("[ADB] 使用 adbd shell 执行 (UID=2000)");
            try {
                AdbConnection.ShellResult result = adbConnection.shell(cmd);
                output.append("ExitCode=").append(result.exitCode).append("\n");
                
                if (result.stdout != null && !result.stdout.isEmpty()) {
                    output.append("STDOUT:\n").append(result.stdout);
                }
                if (result.stderr != null && !result.stderr.isEmpty()) {
                    output.append("STDERR:\n").append(result.stderr);
                }
    
                appendLog("[ADB] 退出码: " + result.exitCode);
                if (result.isSuccess()) {
                    appendLog("[ADB] 安装命令执行成功");
                    File targetFile = new File(apkPath);
                    if (targetFile.exists()) {
                        if (targetFile.exists() && !targetFile.delete()) {
                            appendLog("[ADB] 无法删除temp apk文件:"+apkPath);
                        } else {
                            appendLog("[ADB] 成功删除temp apk文件:"+apkPath);
                        }
                    }
                } else {
                    appendLog("[ADB] 安装命令执行失败");
                }
    
                String finalResult = output.toString().trim();
                if (finalResult.isEmpty()) finalResult = "Success (no output)";
                return finalResult;
    
            } catch (IOException e) {
                appendLog("[ADB] 执行异常: " + e.getMessage());
                // ADB 连接可能已断开，回退到 sh
                appendLog("[ADB] 回退到普通 sh 执行...");
            }
        }
    
        // 回退：普通 sh -c 方式
        appendLog("[SH] 使用普通 sh 执行 (App UID)");
        try {
            String[] shCmd = { "sh", "-c", cmd };
            Process process = Runtime.getRuntime().exec(shCmd);
    
            // 读取输出（原逻辑）
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }
            try (BufferedReader errReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = errReader.readLine()) != null) {
                    output.append("[ERR] ").append(line).append("\n");
                }
            }
            process.waitFor();
            output.insert(0, "ExitCode=" + process.exitValue() + "\n");
    
        } catch (Exception e) {
            output.append("Exception: ").append(e.getMessage());
        }
    
        String result = output.toString().trim();
        if (result.isEmpty()) result = "Success (no output)";
        return result;
    }
    
    /**
     * 清理资源
     */
    private void closeAdbConnection() {
        if (adbConnection != null) {
            try {
                adbConnection.close();
            } catch (IOException ignored) {}
            adbConnection = null;
        }
    }



    // ============================================================
    // 备选方案：直接在 Java 层通过反射绕过安装限制（需要系统权限）
    // 如果 app_process 方案不可用，可以尝试此方法
    // ============================================================

    /**
     * 备选：直接在 Android Java 层使用 PackageInstaller + 反射绕过
     * 注意：此方法需要系统级权限（system UID 或 root），普通 App 无法直接调用
     */
    /****
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
**/
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
        closeAdbConnection();
    }
}
