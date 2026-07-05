package com.leapermagic.magic;

import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public class MainActivity extends AppCompatActivity {

    private Uri selectedApkUri;
    private String targetPath;
    private boolean isMonitoring = false;
    private Thread monitorThread;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());

    private TextView tvSelectedApk;
    private EditText etTargetPath;
    private Button btnToggleMonitor;
    private TextView tvStatus;

    private ActivityResultLauncher<Intent> selectApkLauncher;
    private ActivityResultLauncher<Intent> manageStorageLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tvSelectedApk = findViewById(R.id.tv_selected_apk);
        etTargetPath = findViewById(R.id.et_target_path);
        btnToggleMonitor = findViewById(R.id.btn_toggle_monitor);
        tvStatus = findViewById(R.id.tv_status);

        // 默认目标路径
        etTargetPath.setText("/storage/self/primary/Android/data/com.leapmotor.appcenter/files/download/com.migu.car.music.apk");

        // 注册选择 APK 文件的回调
        selectApkLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                        selectedApkUri = result.getData().getData();
                        tvSelectedApk.setText("已选择: " + selectedApkUri.getPath());
                    }
                });

        // 注册 Android 11+ 特殊权限回调
        manageStorageLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        if (Environment.isExternalStorageManager()) {
                            Toast.makeText(this, "已获得所有文件访问权限", Toast.LENGTH_SHORT).show();
                        }
                    }
                });

        // 选择 APK 按钮
        findViewById(R.id.btn_select_apk).setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("application/vnd.android.package-archive");
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            selectApkLauncher.launch(Intent.createChooser(intent, "选择 APK 文件"));
        });

        // 开始 / 停止监控按钮
        btnToggleMonitor.setOnClickListener(v -> {
            if (isMonitoring) {
                stopMonitoring();
            } else {
                startMonitoring();
            }
        });

        checkPermissions();
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
            Toast.makeText(this, "请先授予'所有文件访问权限'", Toast.LENGTH_SHORT).show();
            Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
            intent.setData(Uri.parse("package:" + getPackageName()));
            manageStorageLauncher.launch(intent);
            return;
        }

        isMonitoring = true;
        btnToggleMonitor.setText("停止监控");
        tvStatus.setText("状态：监控中...");
        Toast.makeText(this, "监控已开始", Toast.LENGTH_SHORT).show();

        monitorThread = new Thread(() -> {
            while (isMonitoring) {
                try {
                    File targetFile = new File(targetPath);
                    if (targetFile.exists()) {
                        deleteAndCopy(targetFile);
                        break;
                    }
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            uiHandler.post(() -> {
                if (isMonitoring) stopMonitoringFromBackground();
            });
        });
        monitorThread.start();
    }

    private void stopMonitoring() {
        isMonitoring = false;
        if (monitorThread != null) monitorThread.interrupt();
        btnToggleMonitor.setText("开始监控");
        tvStatus.setText("状态：待机");
    }

    private void stopMonitoringFromBackground() {
        isMonitoring = false;
        btnToggleMonitor.setText("开始监控");
        tvStatus.setText("状态：已完成替换");
        Toast.makeText(this, "文件已替换，监控停止", Toast.LENGTH_SHORT).show();
    }

    private void deleteAndCopy(File targetFile) {
        if (targetFile.delete()) {
            uiHandler.post(() -> Toast.makeText(MainActivity.this, "已删除原有文件", Toast.LENGTH_SHORT).show());
        } else {
            uiHandler.post(() -> Toast.makeText(MainActivity.this, "删除原有文件失败", Toast.LENGTH_SHORT).show());
            return;
        }
        try (InputStream inputStream = getContentResolver().openInputStream(selectedApkUri);
             FileOutputStream outputStream = new FileOutputStream(targetFile)) {
            if (inputStream == null) throw new Exception("无法打开文件");
            byte[] buffer = new byte[50];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            uiHandler.post(() -> Toast.makeText(MainActivity.this, "复制完成", Toast.LENGTH_SHORT).show());
        } catch (Exception e) {
            uiHandler.post(() -> Toast.makeText(MainActivity.this, "复制失败: " + e.getMessage(), Toast.LENGTH_SHORT).show());
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        stopMonitoring();
    }
}
