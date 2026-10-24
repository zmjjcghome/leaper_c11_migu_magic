package com.leapermagic.magic;

import android.view.View;
import android.content.Intent;
import android.content.Context;
import android.content.pm.PackageManager;
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
import android.widget.ScrollView;
import android.widget.Toast;
import android.Manifest;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.appcompat.app.AlertDialog;

import java.net.Socket;
import java.net.InetSocketAddress;
import java.io.*;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class MainActivity extends AppCompatActivity {

    private static final String PREFS_NAME = "leapermagic_magic_prefs";
    private static final String KEY_TARGET_PATH = "target_path";
    private static final String DEFAULT_PATH =
            "/storage/self/primary/Android/data/com.leapmotor.appcenter/files/download/com.migu.car.music.apk";

    // ====== Shell 绕过安装常量 ======
    private static final String[] DEX_CANDIDATE_PATHS = {
            "/data/local/tmp/Api64Installer.dex"
    };
    private static final String[] APK_CANDIDATE_PATHS = {
            "/data/local/tmp/install_target.apk"
    };
    private static final String INSTALLER_CLASS = "com.lipu.install.Api64Installer";
    /** 当前的 adbd 端口，-1 表示未连接 */
    private int adbdPort = -1;
    
    /** ADB 连接实例 */
    //private AdbConnection adbConnection;
    private AdbClient.AdbConnection adbConnection;
    
    private Uri selectedApkUri;
    private String targetPath;
    private boolean isMonitoring = false;
    private Thread monitorThread;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private SharedPreferences prefs;

    private TextView tvSelectedApk;
    private TextView tvLog;
    private ScrollView tvLogScroll;
    private EditText etTargetPath;
    private Button btnToggleMonitor;
    private Button btnPrepareFiles;    // 按钮1：复制 dex + apk
    private Button btnExecuteInstall;  // 按钮2：执行安装
    private Button btnResignApk;       // 按钮3：重新签名
    // private Button btnInstallResigned; // 按钮4：安装重签名后的APK
    private TextView tvStatus;
    // 字段声明
    private ApkSignerUtil apkSignerUtil;
    
    // 记录最终成功的路径
    private String actualDexPath = null;
    private String actualApkPath = null;
    private File actualSignedApkFile = null;  // 改为File对象
    
    private ActivityResultLauncher<Intent> selectApkLauncher;
    private ActivityResultLauncher<Intent> manageStorageLauncher;

    private final Handler saveHandler = new Handler(Looper.getMainLooper());
    private final Runnable saveRunnable = () -> savePath(etTargetPath.getText().toString().trim());
    

    // 字段声明处添加
    private final AtomicBoolean isInitializingAdb = new AtomicBoolean(false);

    // ==================== 权限相关 ====================
    
    /**
     * Android 9+ 需要的所有权限
     */
    private static final String[] REQUIRED_PERMISSIONS = {
        // 网络权限（ADB通信必需）
        Manifest.permission.INTERNET,
        Manifest.permission.ACCESS_NETWORK_STATE,
        Manifest.permission.ACCESS_WIFI_STATE,
        Manifest.permission.CHANGE_WIFI_STATE,
        Manifest.permission.CHANGE_WIFI_MULTICAST_STATE,
        
        // 存储权限（读取/安装APK）
        Manifest.permission.READ_EXTERNAL_STORAGE,
        Manifest.permission.WRITE_EXTERNAL_STORAGE,
        
        // 安装权限
        // Manifest.permission.REQUEST_INSTALL_PACKAGES,
        
        // 设备信息
        //Manifest.permission.READ_PHONE_STATE,
    };
    
    /**
     * Android 11+ 需要的额外权限
     */
    private static final String[] ANDROID_11_PERMISSIONS = {
        Manifest.permission.MANAGE_EXTERNAL_STORAGE,
        // Manifest.permission.QUERY_ALL_PACKAGES,
    };
    
    /**
     * Android 13+ 的通知权限
     */
    private static final String[] ANDROID_13_PERMISSIONS = {
        // Manifest.permission.POST_NOTIFICATIONS,
    };
    // ==================== ActivityResult启动器 ====================
    
    /**
     * 常规权限请求启动器
     */
    private final ActivityResultLauncher<String[]> permissionLauncher = 
        registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(), 
            result -> {
                List<String> deniedPermissions = new ArrayList<>();
                for (Map.Entry<String, Boolean> entry : result.entrySet()) {
                    if (!entry.getValue()) {
                        deniedPermissions.add(entry.getKey());
                    }
                }
                
                if (deniedPermissions.isEmpty()) {
                    appendLog("✅ 所有权限已授予");
                    onPermissionsGranted();
                } else {
                    appendLog("⚠️ 部分权限被拒绝: " + deniedPermissions.size() + "项[" + String.join(", ", deniedPermissions)+"]");
                    // 对关键权限被拒绝给出提示
                    if (deniedPermissions.contains(Manifest.permission.INTERNET)) {
                        showPermissionDialog("网络权限被拒绝，ADB通信功能将无法使用");
                    }
                    if (deniedPermissions.contains(Manifest.permission.REQUEST_INSTALL_PACKAGES)) {
                        showPermissionDialog("安装权限被拒绝，无法安装APK");
                    }
                }
            });
    
    /**
     * 安装未知来源应用权限启动器
     */
    private final ActivityResultLauncher<Intent> installPermissionLauncher = 
        registerForActivityResult(new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    if (getPackageManager().canRequestPackageInstalls()) {
                        appendLog("✅ 安装未知应用权限已授予");
                    } else {
                        appendLog("⚠️ 安装未知应用权限未授予");
                        showPermissionDialog("需要安装未知应用权限才能安装APK");
                    }
                }
            });
    
    /**
     * 管理所有文件权限启动器（Android 11+）
     */
    private final ActivityResultLauncher<Intent> manageFilesPermissionLauncher = 
        registerForActivityResult(new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    if (Environment.isExternalStorageManager()) {
                        appendLog("✅ 管理所有文件权限已授予");
                    } else {
                        appendLog("⚠️ 管理所有文件权限未授予");
                    }
                }
            });
    // ============================================================
    // 设置日志监听（将AdbClient日志输出到UI）
    // ============================================================
    private void setupLogListener() {
        AdbClient.setLogListener(new AdbClient.LogListener() {
            @Override
            public void onLog(AdbClient.LogLevel level, String tag, String message) {
                String formattedMsg = String.format("[%s] %s: %s", level.tag, tag, message);
                appendLog(formattedMsg);
            }
        });
        
        appendLog("ADB客户端已就绪");
        appendLog("日志系统初始化完成");
    }
    
    /**
     * 示例1：端口检查
     */
    private void checkPort(String ip, int port) {
        new Thread(() -> {
            boolean open = AdbClient.checkAdbPort(ip, port, 3000);
            runOnUiThread(() -> {
                Toast.makeText(this, "端口" + port + ": " + (open ? "开放" : "关闭"), 
                               Toast.LENGTH_SHORT).show();
                appendLog("端口" + port + ": " + (open ? "开放" : "关闭"));
            });
        }).start();
    }
    
    /**
     * 示例2：连接ADB设备
     */
    private void connectToDevice(String ip, int port) {
        new Thread(() -> {
            AdbClient.AdbConnectionResult result = AdbClient.connect(ip, port);
            
            runOnUiThread(() -> {
                if (result.success) {
                    adbConnection = result.connection;
                    appendLog("连接成功: " + result.message);
                } else {
                    appendLog("连接失败: " + result.message);
                }
            });
        }).start();
    }
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);

        tvSelectedApk = findViewById(R.id.tv_selected_apk);
        tvLog = findViewById(R.id.tv_log);
        tvLogScroll = findViewById(R.id.tv_log_scroll);
        etTargetPath = findViewById(R.id.et_target_path);
        btnToggleMonitor = findViewById(R.id.btn_toggle_monitor);
        btnPrepareFiles = findViewById(R.id.btn_prepare_files);
        btnExecuteInstall = findViewById(R.id.btn_execute_install);
        btnResignApk = findViewById(R.id.btn_resign_apk);
        // btnInstallResigned = findViewById(R.id.btn_install_resigned);
        tvStatus = findViewById(R.id.tv_status);

        // 强制滚动条始终可见，不淡出
        tvLogScroll.setScrollbarFadingEnabled(false);
        tvLogScroll.setVerticalScrollBarEnabled(true);
        
        // 初始状态：重签名相关按钮不可用
        btnResignApk.setEnabled(false);
        // btnInstallResigned.setEnabled(false);
        
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
                        actualSignedApkFile = null;
                        btnExecuteInstall.setEnabled(false);
                        btnResignApk.setEnabled(true);
                        // btnInstallResigned.setEnabled(false);
                        appendLog("已选择 APK，可以进行重新签名或准备绕过安装");
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
        // ====== 按钮3：重新签名 ======
        btnResignApk.setOnClickListener(v -> resignSelectedApk());
        // ====== 按钮4：安装重签名后的APK ======
        // btnInstallResigned.setOnClickListener(v -> installResignedApk());
        
        // 初始化签名工具，设置日志回调
        // apkSignerUtil = new ApkSignerUtil(this, new ApkSignerUtil.SignLogCallback() {
        //     @Override
        //     public void onLog(String message) {
        //         appendLog("[签名] " + message);
        //     }
        // });
        apkSignerUtil = new ApkSignerUtil(this);
        apkSignerUtil.setLogCallback(new ApkSignerUtil.SignLogCallback() {
            @Override
            public void onLog(final String message) {
                runOnUiThread(() -> {
                    appendLog("[签名] " + message);
                });
            }
        });
        checkPermissions();
        checkAllPermissions();
        setupLogListener();
        
        initAdbConnection();
    }
    // ==================== 权限管理 ====================
    
    /**
     * 检查所有权限
     */
    private void checkAllPermissions() {
        appendLog("🔍 正在检查权限...");
        
        // 1. 收集需要请求的权限
        List<String> permissionsToRequest = new ArrayList<>();
        
        for (String permission : REQUIRED_PERMISSIONS) {
            if (ContextCompat.checkSelfPermission(this, permission) 
                    != PackageManager.PERMISSION_GRANTED) {
                permissionsToRequest.add(permission);
            }
        }
        
        // Android 11+ 额外权限
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            for (String permission : ANDROID_11_PERMISSIONS) {
                if (ContextCompat.checkSelfPermission(this, permission) 
                        != PackageManager.PERMISSION_GRANTED) {
                    // MANAGE_EXTERNAL_STORAGE 需要特殊处理
                    if (!Manifest.permission.MANAGE_EXTERNAL_STORAGE.equals(permission)) {
                        permissionsToRequest.add(permission);
                    }
                }
            }
        }
        
        // Android 13+ 通知权限
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            for (String permission : ANDROID_13_PERMISSIONS) {
                if (ContextCompat.checkSelfPermission(this, permission) 
                        != PackageManager.PERMISSION_GRANTED) {
                    permissionsToRequest.add(permission);
                }
            }
        }
        
        // 2. 请求权限
        if (!permissionsToRequest.isEmpty()) {
            appendLog("📋 需要请求 " + permissionsToRequest.size() + " 项权限[" + String.join(", ", permissionsToRequest)+"]");
            
            // 检查是否有"不再询问"的权限
            boolean hasDeniedForever = false;
            for (String permission : permissionsToRequest) {
                if (ActivityCompat.shouldShowRequestPermissionRationale(this, permission)) {
                    appendLog("ℹ️ 权限需要解释: " + getPermissionDisplayName(permission));
                } else if (ContextCompat.checkSelfPermission(this, permission) 
                        == PackageManager.PERMISSION_DENIED) {
                    hasDeniedForever = true;
                }
            }
            
            if (hasDeniedForever) {
                showGoToSettingsDialog();
            } else {
                permissionLauncher.launch(permissionsToRequest.toArray(new String[0]));
            }
        } else {
            appendLog("✅ 基础权限已满足");
            checkSpecialPermissions();
        }
    }
    
    /**
     * 检查特殊权限
     */
    private void checkSpecialPermissions() {
        // 安装未知应用权限（Android 8+）
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (!getPackageManager().canRequestPackageInstalls()) {
                appendLog("⚠️ 需要安装未知应用权限");
                requestInstallPermission();
                return;
            }
        }
        
        // 管理所有文件权限（Android 11+）
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                appendLog("⚠️ 需要管理所有文件权限");
                requestManageFilesPermission();
                return;
            }
        }
        
        // 修改系统设置权限
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (!Settings.System.canWrite(this)) {
                appendLog("ℹ️ 修改系统设置权限未授予（非必需）");
            }
        }
        
        appendLog("✅ 所有权限检查完毕");
        onPermissionsGranted();
    }
    
    /**
     * 权限授予后的回调
     */
    private void onPermissionsGranted() {
        appendLog("🎉 权限准备就绪，可以开始使用");
        // 自动扫描局域网设备
        appendLog("💡 点击[扫描网络]查找ADB设备");
    }
    
    /**
     * 请求安装权限
     */
    private void requestInstallPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Intent intent = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES);
            intent.setData(Uri.parse("package:" + getPackageName()));
            installPermissionLauncher.launch(intent);
        }
    }
    
    /**
     * 请求管理文件权限
     */
    private void requestManageFilesPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
            intent.setData(Uri.parse("package:" + getPackageName()));
            manageFilesPermissionLauncher.launch(intent);
        }
    }
    
    /**
     * 显示权限说明对话框
     */
    private void showPermissionDialog(String message) {
        new AlertDialog.Builder(this)
            .setTitle("权限说明")
            .setMessage(message)
            .setPositiveButton("去设置", (dialog, which) -> {
                Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivity(intent);
            })
            .setNegativeButton("取消", null)
            .show();
    }
    
    /**
     * 显示跳转设置对话框
     */
    private void showGoToSettingsDialog() {
        new AlertDialog.Builder(this)
            .setTitle("需要权限")
            .setMessage("部分权限被永久拒绝，请前往应用设置手动开启")
            .setPositiveButton("去设置", (dialog, which) -> {
                Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivity(intent);
            })
            .setNegativeButton("取消", (dialog, which) -> {
                appendLog("⚠️ 权限不足，功能可能受限");
            })
            .show();
    }
    
    /**
     * 获取权限的友好显示名称
     */
    private String getPermissionDisplayName(String permission) {
        switch (permission) {
            case Manifest.permission.INTERNET:
                return "网络访问";
            case Manifest.permission.ACCESS_NETWORK_STATE:
                return "网络状态";
            case Manifest.permission.ACCESS_WIFI_STATE:
                return "WiFi状态";
            case Manifest.permission.CHANGE_WIFI_STATE:
                return "WiFi控制";
            case Manifest.permission.READ_EXTERNAL_STORAGE:
                return "读取存储";
            case Manifest.permission.WRITE_EXTERNAL_STORAGE:
                return "写入存储";
            case Manifest.permission.REQUEST_INSTALL_PACKAGES:
                return "安装应用";
            case Manifest.permission.READ_PHONE_STATE:
                return "读取设备信息";
            case Manifest.permission.MANAGE_EXTERNAL_STORAGE:
                return "管理文件";
            case Manifest.permission.POST_NOTIFICATIONS:
                return "通知";
            default:
                return permission;
        }
    }
    /**
     * 初始化：自动检测 adbd 端口并建立连接
     * 在 onCreate 或用户点击某个按钮时调用
     */
    /**
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
    }*/
    
    /**
     * 初始化：自动检测 adbd 端口并建立连接
     */
    private void initAdbConnection() {
        // 防止并发重复初始化
        if (!isInitializingAdb.compareAndSet(false, true)) {
            return;
        }
    
        new Thread(() -> {
            try {
                if (adbConnection == null || adbConnection.isClosed()) {
                    // 1. 快速检查系统是否开启了 ADB 调试
                    try {
                        int adbEnabled = Settings.Global.getInt(getContentResolver(), Settings.Global.ADB_ENABLED, 0);
                        if (adbEnabled != 1) {
                            runOnUiThread(() -> {
                                appendLog("[提示] 系统未开启 ADB 调试，请在开发者选项中开启 USB/无线调试");
                            });
                            //return;
                        }
                    } catch (Exception ignored) {}
    
                    appendLog("========== 开始检测 adbd ==========");
            
                    // 自动检测端口
                    adbdPort = AdbPortDetector.detect(adbdPort > 0 ? adbdPort : -1, msg -> {
                        runOnUiThread(() -> appendLog("[检测] " + msg));
                    });
            
                    if (adbdPort > 0) {
                        appendLog("[成功] 找到 adbd 端口: " + adbdPort);
                        // 建立持久连接
                        AdbClient.AdbConnectionResult result = AdbClient.connect("127.0.0.1", adbdPort);
        
                        if (result.success) {
                            adbConnection = result.connection;
                            appendLog("连接成功: " + result.message);
                            appendLog("[成功] 已连接到 adbd (端口 " + adbdPort + "):" + result.message);
                        } else {
                            appendLog("[失败] 连接 adbd 失败: " + result.message);
                        }
                    } else {
                        appendLog("[失败] 未找到 adbd 监听端口");
                        appendLog("[提示] 请在设置中开启无线调试 (Android 11+)");
                        appendLog("[提示] 或通过 USB 执行: adb tcpip 5555");
                    }
                }
            } finally {
                isInitializingAdb.set(false);
            }
        }).start();
    }
    
    // ============================================================
    // 日志辅助方法
    // ============================================================
    private void appendLog(String msg) {
        uiHandler.post(() -> {

            String current = tvLog.getText().toString();
            String timestamp = new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
                    .format(new java.util.Date());
            String newLine = "[" + timestamp + "] " + msg + "\n";
            // 追加新文本后自动滚到底部
            tvLog.append(newLine);
            
            // 2. 关键步骤：使用 post 延迟执行滚动
            // 因为 setText/append 后，View 需要重新测量布局高度，
            // 立即调用 scrollTo 可能获取的是旧的高度，导致滚不到底。
            tvLogScroll.post(new Runnable() {
                @Override
                public void run() {
                    // 方法一：平滑滚动（推荐，体验更好）
                    tvLogScroll.fullScroll(View.FOCUS_DOWN);
                    
                    // 方法二：瞬间跳转到底部（如果不需要动画）
                    // tvLogScroll.scrollTo(0, tvLogScroll.getChildAt(0).getHeight());
                }
            });

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
        tvStatus.setText("正在通过 ADB 推送文件...");
        appendLog("========== 开始通过 ADB push 准备文件 ==========");
        
        // 确保 ADB 连接已建立
        if (adbdPort <= 0) {
            appendLog("ADB 端口未检测到，正在初始化 ADB 连接...");
            initAdbConnection();
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            if (adbdPort <= 0) {
                uiHandler.post(() -> {
                    tvStatus.setText("ADB 连接失败，请检查 ADB 调试是否开启");
                    btnPrepareFiles.setEnabled(true);
                    Toast.makeText(MainActivity.this, "ADB 连接失败，请检查设备连接", Toast.LENGTH_LONG).show();
                });
                return;
            }
        }


         new Thread(() -> {
            
            // ====== 建立单次 ADB 连接，DEX 和 APK 推送复用此连接 ======
            AdbClient.AdbConnection conn = null;
            try {
                // 1. 建立或复用 ADB 连接
                if (adbConnection == null || adbConnection.isClosed()) {
                    appendLog("正在建立 ADB 连接...");
                    AdbClient.AdbConnectionResult result = AdbClient.connect("127.0.0.1", adbdPort);
                    if (!result.success || result.connection == null) {
                        uiHandler.post(() -> {
                            tvStatus.setText("ADB 连接失败: " + result.message);
                            btnPrepareFiles.setEnabled(true);
                            Toast.makeText(MainActivity.this, "ADB 连接失败", Toast.LENGTH_LONG).show();
                        });
                        appendLog("ADB 连接失败: " + result.message);
                        return;
                    }
                    adbConnection = result.connection;
                    appendLog("ADB 连接已建立 ✓ | 端口=" + adbdPort + " | 单连接复用模式");
                } else {
                    appendLog("复用已有 ADB 连接 | 端口=" + adbdPort + " | 单连接复用模式");
                }
                conn = adbConnection;
    
                // 2. 检查 DEX 是否已推送并验证一致性
                String dexRemotePath = DEX_CANDIDATE_PATHS[0];
                appendLog("========== 检查 DEX 文件状态 ==========");
                
                // 先获取本地 DEX 大小（从 assets 读取）
                long localDexSize = 0;
                try (InputStream dexCheckStream = getAssets().open("classes.dex")) {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = dexCheckStream.read(buffer)) != -1) {
                        localDexSize += read;
                    }
                    appendLog("本地 DEX 文件大小: " + localDexSize + " bytes");
                } catch (IOException e) {
                    appendLog("读取本地 DEX 失败: " + e.getMessage());
                    uiHandler.post(() -> {
                        tvStatus.setText("读取 DEX 文件失败");
                        btnPrepareFiles.setEnabled(true);
                    });
                    return;
                }
    
                // 检查设备上的 DEX 文件是否存在及大小
                AdbClient.ShellResult statResult = AdbClient.executeShell(conn, 
                        "stat -c %s " + AdbClient.escapeShellArg(dexRemotePath));
                
                boolean dexExists = false;
                long remoteDexSize = 0;
                if (statResult.isSuccess()) {
                    try {
                        remoteDexSize = Long.parseLong(statResult.stdout.trim());
                        dexExists = (remoteDexSize > 0);
                        appendLog("设备 DEX 文件大小: " + remoteDexSize + " bytes");
                    } catch (NumberFormatException ignored) {
                        appendLog("无法解析 DEX 文件大小，将重新推送");
                    }
                } else {
                    appendLog("设备上 DEX 文件不存在或 stat 命令失败");
                }
    
                // 验证一致性：大小匹配则跳过推送
                if (dexExists && remoteDexSize == localDexSize) {
                    appendLog("DEX 文件已存在且大小一致 (" + localDexSize + " bytes)，跳过推送");
                    actualDexPath = dexRemotePath;
                } else {
                    appendLog("DEX 文件不存在或大小不一致 (本地=" + localDexSize + " 设备=" + remoteDexSize + ")，开始推送...");
                    
                    // 将 DEX 从 assets 保存到临时文件
                    String dexTempPath = saveDexToTempFile();
                    if (dexTempPath == null) {
                        uiHandler.post(() -> {
                            tvStatus.setText("DEX 临时文件保存失败");
                            btnPrepareFiles.setEnabled(true);
                        });
                        return;
                    }
                    
                    AdbClient.ShellResult cpResult = AdbClient.executeShell(conn, 
                            "cp \"" + dexTempPath + "\" \"" + dexRemotePath + "\"");

                    if (!cpResult.isSuccess()) {
                    
                        // 使用 AdbClient 新的文件路径推送方法（流式读取，不一次性加载到内存）
                        appendLog("调用 AdbClient.pushFile(conn, dexTempPath, " + dexRemotePath + ")...");
                        AdbClient.ShellResult dexPushResult = AdbClient.pushFile(conn, dexTempPath, dexRemotePath);
                        
                        if (!dexPushResult.isSuccess()) {
                            appendLog("DEX 推送失败: " + dexPushResult.stderr);
                            uiHandler.post(() -> {
                                tvStatus.setText("DEX 推送失败，查看日志");
                                btnPrepareFiles.setEnabled(true);
                            });
                            return;
                        }
                    }
                    
                    actualDexPath = dexRemotePath;
                    appendLog("DEX 推送成功 → " + actualDexPath);
                    
                    // 清理临时文件
                    new File(dexTempPath).delete();
                }
    
                // 3. 推送 APK（复用同一连接）
                String apkRemotePath = APK_CANDIDATE_PATHS[0];
                appendLog("========== 推送 APK 文件 ==========");
                
                // 获取 APK 实际文件路径
                String apkFilePath = getActualApkFilePath();
                if (apkFilePath == null) {
                    uiHandler.post(() -> {
                        tvStatus.setText("无法获取 APK 文件路径");
                        btnPrepareFiles.setEnabled(true);
                    });
                    return;
                }
                
                appendLog("APK 源路径: " + apkFilePath);
                File apkFile = new File(apkFilePath);
                appendLog("APK 文件大小: " + apkFile.length() + " bytes");

                Thread.sleep(500);
                
                AdbClient.ShellResult apkCpResult = AdbClient.executeShell(conn, 
                        "cp \"" + apkFilePath + "\" \"" + apkRemotePath + "\"");

                if (!apkCpResult.isSuccess()) {

                    // 使用 AdbClient 新的文件路径推送方法（流式读取，不一次性加载到内存）
                    appendLog("调用 AdbClient.pushFile(conn, apkFilePath, " + apkRemotePath + ")...");
                    AdbClient.ShellResult apkPushResult = AdbClient.pushFile(conn, apkFilePath, apkRemotePath);
                    
                    if (!apkPushResult.isSuccess()) {
                        appendLog("APK 推送失败: " + apkPushResult.stderr);
                        uiHandler.post(() -> {
                            tvStatus.setText("APK 推送失败，查看日志");
                            btnPrepareFiles.setEnabled(true);
                        });
                        return;
                    }
                }
                
                actualApkPath = apkRemotePath;
                appendLog("APK 推送成功 → " + actualApkPath);
    
                uiHandler.post(() -> {
                    tvStatus.setText("文件推送完成，可执行安装");
                    btnPrepareFiles.setEnabled(true);
                    btnExecuteInstall.setEnabled(true);
                    Toast.makeText(MainActivity.this, "文件准备完成", Toast.LENGTH_SHORT).show();
                });
                appendLog("========== 文件准备完成 ==========");
            } catch (Exception e) {
                appendLog("推送异常: " + e.getMessage());
                e.printStackTrace();
                uiHandler.post(() -> {
                    tvStatus.setText("推送异常: " + e.getMessage());
                    btnPrepareFiles.setEnabled(true);
                });
            } finally {
                // 统一关闭连接，释放资源
                if (conn != null) {
                    try {
                        appendLog("关闭 ADB 连接...");
                        conn.close();
                        appendLog("ADB 连接已关闭");
                    } catch (Exception e) {
                        appendLog("关闭连接异常: " + e.getMessage());
                    }
                }
            }
         }).start();
    }

    /**
     * 检查设备上文件是否存在及大小
     * @return 文件大小，-1 表示文件不存在或检查失败
     */
    private long checkFileOnDevice(AdbClient.AdbConnection conn, String filePath) {
        try {
            AdbClient.ShellResult result = AdbClient.executeShell(conn, 
                    "stat -c %s " + AdbClient.escapeShellArg(filePath));
            if (result.isSuccess()) {
                try {
                    return Long.parseLong(result.stdout.trim());
                } catch (NumberFormatException ignored) {
                    // stat 不可用，降级用 ls
                    AdbClient.ShellResult lsResult = AdbClient.executeShell(conn, 
                            "ls -la " + AdbClient.escapeShellArg(filePath));
                    if (lsResult.isSuccess()) {
                        String[] parts = lsResult.stdout.trim().split("\\s+");
                        if (parts.length >= 5) {
                            try {
                                return Long.parseLong(parts[4]);
                            } catch (NumberFormatException ignored2) {}
                        }
                    }
                }
            }
        } catch (Exception e) {
            appendLog("检查文件状态异常: " + e.getMessage());
        }
        return -1;
    }

    /**
     * 将 assets 中的 DEX 文件保存到外部存储临时文件
     * @return 临时文件路径，失败返回 null
     */
    private String saveDexToTempFile() {
        try {
            File externalDir = getExternalFilesDir(null);
            if (externalDir == null) {
                externalDir = getExternalCacheDir();
            }
            if (externalDir == null) {
                appendLog("无法获取外部存储目录");
                return null;
            }
            
            if (!externalDir.exists()) {
                externalDir.mkdirs();
            }
            
            String tempName = "dex_temp.dex";
            File tempFile = new File("/storage/emulated/0/Download/", tempName);
            
            InputStream dexStream = getAssets().open("classes.dex");
            if (dexStream == null) {
                appendLog("assets/classes.dex 不存在");
                return null;
            }
            
            java.io.FileOutputStream fos = new java.io.FileOutputStream(tempFile);
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = dexStream.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
            }
            fos.flush();
            fos.close();
            dexStream.close();
            
            appendLog("DEX 已保存到临时文件: " + tempFile.getAbsolutePath() + " (" + tempFile.length() + " bytes)");
            return tempFile.getAbsolutePath();
        } catch (Exception e) {
            appendLog("保存 DEX 临时文件失败: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 从 selectedApkUri 获取实际的文件路径
     * 支持 file:// 和 content:// 两种 URI
     * @return 文件路径，失败返回 null
     */
    private String getActualApkFilePath() {
        if (selectedApkUri == null) {
            appendLog("selectedApkUri 为 null");
            return null;
        }
        
               
        // 尝试直接从 URI 获取路径
        String uriPath = selectedApkUri.getPath();
        if (uriPath != null && uriPath.startsWith("/")) {
            File f = new File(uriPath);
            if (f.exists()) {
                appendLog("直接从 URI 获取路径成功: " + uriPath);
                return uriPath;
            }
        }
        
        // content:// URI 需要复制到临时文件
        appendLog("URI 不是直接文件路径，尝试复制到临时文件...");
        try {
            File externalDir = getExternalFilesDir(null);
            if (externalDir == null) {
                externalDir = getExternalCacheDir();
            }
            if (externalDir == null) {
                appendLog("无法获取外部存储目录");
                return null;
            }
            
            if (!externalDir.exists()) {
                externalDir.mkdirs();
            }
            
            // 从 URI 提取文件名
            String fileName = "apk_temp_.apk";
            
            File tempFile = new File("/storage/emulated/0/Download/", fileName);
            InputStream inputStream = getContentResolver().openInputStream(selectedApkUri);
            if (inputStream == null) {
                appendLog("ContentResolver.openInputStream 返回 null");
                return null;
            }
            
            java.io.FileOutputStream fos = new java.io.FileOutputStream(tempFile);
            byte[] buffer = new byte[8192];
            int bytesRead;
            long totalBytes = 0;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
                totalBytes += bytesRead;
            }
            fos.flush();
            fos.close();
            inputStream.close();
            
            appendLog("APK 已复制到临时文件: " + tempFile.getAbsolutePath() + " (" + totalBytes + " bytes)");
            return tempFile.getAbsolutePath();
        } catch (Exception e) {
            appendLog("复制 APK 临时文件失败: " + e.getMessage());
            e.printStackTrace();
            return null;
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

        //checkPort("127.0.0.1", 5555);
        // 然后再尝试连接
        //connectToDevice("127.0.0.1", 5555);
        if (adbConnection == null || adbConnection.isClosed()) {

            appendLog("正在建立 ADB 连接...");
            AdbClient.AdbConnectionResult result = AdbClient.connect("127.0.0.1", adbdPort);
            if (!result.success || result.connection == null) {
                uiHandler.post(() -> {
                    tvStatus.setText("ADB 连接失败: " + result.message);
                    btnPrepareFiles.setEnabled(true);
                    Toast.makeText(MainActivity.this, "ADB 连接失败", Toast.LENGTH_LONG).show();
                });
                appendLog("ADB 连接失败: " + result.message);
                return "ADB 连接失败";
            }
            adbConnection = result.connection;
            appendLog("ADB 连接已建立 ✓ | 端口=" + adbdPort + " | 单连接复用模式");


        }
        // 如果 ADB 连接可用，优先使用（shell UID 权限）
        if (adbConnection != null && adbdPort > 0) {
            appendLog("[ADB] 使用 adbd shell 执行 (UID=2000)");
            try {
                /** old execute
                AdbConnection.ShellResult result = adbConnection.shell(cmd);
                output.append("ExitCode=").append(result.exitCode).append("\n");
                
                if (result.stdout != null && !result.stdout.isEmpty()) {
                    output.append("STDOUT:\n").append(result.stdout);
                }
                if (result.stderr != null && !result.stderr.isEmpty()) {
                    output.append("STDERR:\n").append(result.stderr);
                }
                */
                //=====new shell execute =======
                AdbClient.ShellResult result = 
                        AdbClient.executeShell(adbConnection, cmd);
                appendLog("执行结果:\n" + result.toString());
    
                appendLog("[ADB] 退出码: " + result.exitCode);
                if (result.isSuccess()) {
                    appendLog("[ADB] 安装命令执行成功");

                    //File targetFile = new File(apkPath);
                    
                    if (AdbClient.executeShell(adbConnection, 
                    "rm -f " + AdbClient.escapeShellArg(apkPath)).isSuccess()) {
                        appendLog("[ADB] 成功删除temp apk文件:"+apkPath);
                    } else {
                        appendLog("[ADB] 无法删除temp apk文件:"+apkPath);
                    }
                    
                } else {
                    appendLog("[ADB] 安装命令执行失败");
                }
    
                String finalResult = output.toString().trim();
                if (finalResult.isEmpty()) finalResult = "Success (no output)";
                return finalResult;
    
            } catch (Exception e) {
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
            } catch (Exception ignored) {}
            adbConnection = null;
        }
    }

    /**
     * 从本地路径推送文件到设备
     */
    private void pushLocalFile(String ip, int port, String localPath, String remotePath) {
        String tag = "PushFile";
        appendLog(">>> 推送: " + localPath + " -> " + remotePath);
    
        new Thread(() -> {
            try {
                // 1. 读取本地文件
                File localFile = new File(localPath);
                if (!localFile.exists()) {
                    appendLog(">>> 推送: ✗ 本地文件不存在: " + localPath);
                    uiHandler.post(() -> {
                        tvStatus.setText(">>> 推送: 文件不存在");
                        btnExecuteInstall.setEnabled(true);
                        Toast.makeText(MainActivity.this, ">>> 推送: 文件不存在 ", Toast.LENGTH_LONG).show();
                    });
                    return;
                }
    
                byte[] data = new byte[(int) localFile.length()];
                try (FileInputStream fis = new FileInputStream(localFile)) {
                    int read = fis.read(data);
                    appendLog("读取本地: " + read + " bytes");
                }
    
                // 2. 推送到设备
                AdbClient.ShellResult pushResult = AdbClient.pushFile(
                    ip, port, data, remotePath);
    
                if (pushResult.isSuccess()) {
                    appendLog("✓ 推送成功");
    
                    // 3. 验证文件大小
                    AdbClient.ShellResult lsResult = AdbClient.executeShellOneShot(
                        ip, port,
                        "ls -la " + AdbClient.escapeShellArg(remotePath));
                    appendLog("文件信息: " + lsResult.stdout.trim());
    
                    // 4. 如果是APK，自动安装
                    // if (remotePath.endsWith(".apk")) {
                    //     appendLog(">>> 检测到APK，开始安装...");
                    //     AdbClient.ShellResult installResult = AdbClient.installApk(
                    //         ip, port, remotePath);
                    //     appendLog("安装结果: " + installResult.exitCode);
                    //     if (!installResult.stdout.isEmpty()) {
                    //         appendLog("STDOUT:\n" + installResult.stdout.trim());
                    //     }
                    //     if (!installResult.stderr.isEmpty()) {
                    //         appendLog("STDERR:\n" + installResult.stderr.trim());
                    //     }
                    // }
                    uiHandler.post(() -> {
                        tvStatus.setText(">>> 推送: 推送成功");
                        btnExecuteInstall.setEnabled(true);
                        Toast.makeText(MainActivity.this, ">>> 推送: 推送成功 ", Toast.LENGTH_LONG).show();
                    });
                } else {
                    appendLog(">>> 推送: ✗ 推送失败: " + pushResult.stderr);
                    
                    uiHandler.post(() -> {
                        tvStatus.setText(">>> 推送: 推送失败");
                        btnExecuteInstall.setEnabled(true);
                        Toast.makeText(MainActivity.this, ">>> 推送: 推送失败 ", Toast.LENGTH_LONG).show();
                    });
                }
    
            } catch (Exception e) {
                appendLog("✗ 异常: " + e.getMessage());
                uiHandler.post(() -> {
                    tvStatus.setText(">>> 推送: 异常: " + e.getMessage());
                    btnExecuteInstall.setEnabled(true);
                    Toast.makeText(MainActivity.this, ">>> 推送: 异常: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }
    
    // ============================================================
    // 按钮3：重新对APK签名（使用 ApkSigner 类）
    // ============================================================
    private void resignSelectedApk() {
        if (selectedApkUri == null) {
            Toast.makeText(this, "请先选择要签名的 APK", Toast.LENGTH_SHORT).show();
            return;
        }
        btnResignApk.setEnabled(false);
        tvStatus.setText("正在重新签名...");
        appendLog("========== 开始重新签名 APK ==========");
        new Thread(() -> {
            // 根据原始 APK Uri 生成输出文件路径
            actualSignedApkFile = ApkSignerUtil.generateOutputFile(this, selectedApkUri);
            if (actualSignedApkFile == null) {
                uiHandler.post(() -> {
                    
                    tvStatus.setText("无法确定输出路径");
                    btnResignApk.setEnabled(true);
                    Toast.makeText(MainActivity.this, "无法确定输出路径", Toast.LENGTH_SHORT).show();
                });
                return;
            }
            appendLog("输出文件: " + actualSignedApkFile.getAbsolutePath());
            // 调用 ApkSigner 执行签名
            boolean success = apkSignerUtil.resignApk(
                    getContentResolver(),
                    selectedApkUri,
                    actualSignedApkFile
            );
            uiHandler.post(() -> {
                if (success) {
                    selectedApkUri = Uri.fromFile(actualSignedApkFile);
                    
                    tvStatus.setText("签名完成 → " + actualSignedApkFile.getAbsolutePath());
                    tvSelectedApk.setText("已选择: " + actualSignedApkFile.getAbsolutePath());
                    btnResignApk.setEnabled(true);
                    // btnInstallResigned.setEnabled(true);
                    Toast.makeText(MainActivity.this,
                            "APK重新签名完成:\n" + actualSignedApkFile.getName() + ";已经重新选择为重签名的apk文件，可重新进行监控或者安装！",
                            Toast.LENGTH_LONG).show();
                    appendLog("APK重新签名完成:\n" + actualSignedApkFile.getName() + ";已经重新选择为重签名的apk文件，可重新进行监控或者安装！");
                } else {
                    tvStatus.setText("签名失败，查看日志");
                    btnResignApk.setEnabled(true);
                    Toast.makeText(MainActivity.this, "签名失败", Toast.LENGTH_SHORT).show();
                }
            });
        }).start();
    }
    // ============================================================
    // 按钮4：安装重签名后的APK
    // ============================================================
    /***
    private void installResignedApk() {
        if (actualSignedApkFile == null || !actualSignedApkFile.exists()) {
            Toast.makeText(this, "请先对APK重新签名", Toast.LENGTH_SHORT).show();
            return;
        }
        btnInstallResigned.setEnabled(false);
        tvStatus.setText("正在安装重签名后的APK...");
        appendLog("========== 开始安装重签名APK ==========");
        appendLog("APK路径: " + actualSignedApkFile.getAbsolutePath());
        new Thread(() -> {
            // 确保DEX文件存在
            if (actualDexPath == null) {
                // actualDexPath = pushDexWithFallback(); // 已废弃，使用 prepareFiles() 中的新逻辑
                if (actualDexPath == null) {
                    uiHandler.post(() -> {
                        tvStatus.setText("DEX准备失败");
                        btnInstallResigned.setEnabled(true);
                        Toast.makeText(MainActivity.this, "DEX文件准备失败", Toast.LENGTH_SHORT).show();
                    });
                    return;
                }
            }
            String result = executeShellInstall(actualDexPath, actualSignedApkFile.getAbsolutePath());
            uiHandler.post(() -> {
                tvStatus.setText("安装结果: " + result);
                btnInstallResigned.setEnabled(true);
                Toast.makeText(MainActivity.this, "安装完成: " + result, Toast.LENGTH_LONG).show();
            });
        }).start();
    }
    */

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
