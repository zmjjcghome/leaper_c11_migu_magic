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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;

public class MainActivity extends AppCompatActivity {

    private static final String PREFS_NAME = "leapermagic_magic_prefs";
    private static final String KEY_TARGET_PATH = "target_path";
    private static final String DEFAULT_PATH =
            "/storage/self/primary/Android/data/com.leapmotor.appcenter/files/download/com.migu.car.music.apk";

    private Uri selectedApkUri;
    private String targetPath;
    private boolean isMonitoring = false;
    private Thread monitorThread;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private SharedPreferences prefs;

    private TextView tvSelectedApk;
    private EditText etTargetPath;
    private Button btnToggleMonitor;
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
                            Toast.makeText(this, "已获得所有文件访问权限", Toast.LENGTH_SHORT).show();
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

        checkPermissions();
    }

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
            Toast.makeText(this, "请先授予'所有文件访问权限'", Toast.LENGTH_SHORT).show();
            Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
            intent.setData(Uri.parse("package:" + getPackageName()));
            manageStorageLauncher.launch(intent);
            return;
        }

        isMonitoring = true;
        btnToggleMonitor.setText("停止监控");
        tvStatus.setText("状态：正在提前复制临时文件...");
        Toast.makeText(this, "开始准备临时文件", Toast.LENGTH_SHORT).show();

        monitorThread = new Thread(() -> {
            File targetFile = new File(targetPath);
            File tempFile = new File(targetPath + ".tmp");

            try {
                copyToTempFile(tempFile);

                uiHandler.post(() -> {
                    tvStatus.setText("状态：临时文件已准备好，监控中...");
                    Toast.makeText(MainActivity.this, "临时文件复制完成，开始监控目标文件", Toast.LENGTH_SHORT).show();
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
                    Toast.makeText(MainActivity.this, "操作失败: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                    tvStatus.setText("状态：失败");
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
        tvStatus.setText("状态：待机");
    }

    private void stopMonitoringFromBackground() {
        isMonitoring = false;
        btnToggleMonitor.setText("开始监控");
        tvStatus.setText("状态：已完成替换");
        Toast.makeText(this, "文件已替换，监控停止", Toast.LENGTH_SHORT).show();
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
                throw new Exception("无法打开源 APK 文件");
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
            uiHandler.post(() -> Toast.makeText(MainActivity.this, "删除原有文件失败", Toast.LENGTH_SHORT).show());
            return;
        }

        boolean renamed = tempFile.renameTo(targetFile);
        if (renamed) {
            uiHandler.post(() -> Toast.makeText(MainActivity.this, "替换完成", Toast.LENGTH_SHORT).show());
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

            uiHandler.post(() -> Toast.makeText(MainActivity.this, "替换完成", Toast.LENGTH_SHORT).show());
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
