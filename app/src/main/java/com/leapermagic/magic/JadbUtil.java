package com.leapermagic.magic;

import se.vidstige.jadb.JadbConnection;
import se.vidstige.jadb.JadbDevice;
import se.vidstige.jadb.RemoteFile;
import se.vidstige.jadb.JadbException;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * 基于 jadb 库的 ADB 客户端封装
 * 替代纯Java ADB协议实现，使用 jadb (https://github.com/vidstige/jadb) 作为底层通信库
 *
 * 依赖 (Gradle - Android项目):
 *   // 在 project-level build.gradle 中添加 Jitpack 仓库:
 *   // allprojects { repositories { maven { url 'https://jitpack.io' } } }
 *   // 在 app-level build.gradle 中添加依赖:
 *   implementation 'com.github.vidstige:jadb:v1.3.0'
 *
 * 依赖 (Maven):
 *   <repositories>
 *       <repository>
 *           <id>jitpack.io</id>
 *           <url>https://jitpack.io</url>
 *       </repository>
 *   </repositories>
 *   <dependency>
 *       <groupId>com.github.vidstige</groupId>
 *       <artifactId>jadb</artifactId>
 *       <version>v1.3.0</version>
 *   </dependency>
 *
 * 功能:
 *   - 端口检查与局域网设备扫描
 *   - ADB Shell命令执行（一次性/长连接）
 *   - 文件推送（支持大文件分块、进度回调）
 *   - 设备信息查询
 *   - APK安装
 *
 * 与纯Java实现的差异说明:
 *   1. jadb通过连接本地ADB Server (默认localhost:5037) 与设备通信，
 *      而非直接TCP连接到设备。因此需要先执行 adb connect <host>:<port> 建立连接。
 *   2. 不再需要手动实现CNXN握手、AUTH认证、消息帧编解码等底层协议。
 *   3. 文件推送使用 jadb 内置的 push/pull 方法，支持流式传输。
 *   4. 长连接通过复用 JadbDevice 实例实现。
 *
 * Android 注意事项:
 *   - jadb 依赖 Java SE 的 NIO 和并发包，在 Android 中可用（Android API 24+ 完全兼容）
 *   - 所有网络/I/O 操作必须在子线程执行，禁止在主线程（UI线程）调用
 *   - 确保设备已通过 adb connect <host>:<port> 连接到本机 ADB Server
 */
public class JadbUtil {

    // ==================== 常量定义 ====================

    private static final int ADB_DEFAULT_PORT = 5555;
    private static final int CONNECT_TIMEOUT = 5000;
    private static final int READ_TIMEOUT = 30000;
    private static final int SHELL_READ_TIMEOUT = 30; // 秒，用于读取shell输出流的超时

    // ==================== 日志接口 ====================

    /**
     * 日志级别
     */
    public enum LogLevel {
        DEBUG("D"),
        INFO("I"),
        WARN("W"),
        ERROR("E");

        final String tag;
        LogLevel(String tag) { this.tag = tag; }
    }

    /**
     * 日志监听器接口
     */
    public interface LogListener {
        void onLog(LogLevel level, String tag, String message);
    }

    /**
     * 默认日志监听器（输出到System.out/System.err）
     */
    public static final LogListener DEFAULT_LOG_LISTENER = new LogListener() {
        private final SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault());

        @Override
        public void onLog(LogLevel level, String tag, String message) {
            String timestamp = sdf.format(new Date());
            String line = String.format("[%s] [%s/%s] %s", timestamp, level.tag, tag, message);
            if (level == LogLevel.ERROR) {
                System.err.println(line);
            } else {
                System.out.println(line);
            }
        }
    };

    private static LogListener logListener = DEFAULT_LOG_LISTENER;

    /**
     * 设置全局日志监听器
     */
    public static void setLogListener(LogListener listener) {
        logListener = (listener != null) ? listener : DEFAULT_LOG_LISTENER;
    }

    /**
     * 获取当前日志监听器
     */
    public static LogListener getLogListener() {
        return logListener;
    }

    // 内部日志方法
    private static void log(LogLevel level, String tag, String msg) {
        if (logListener != null) {
            logListener.onLog(level, tag, msg);
        }
    }

    private static void logD(String tag, String msg) { log(LogLevel.DEBUG, tag, msg); }
    private static void logI(String tag, String msg) { log(LogLevel.INFO, tag, msg); }
    private static void logW(String tag, String msg) { log(LogLevel.WARN, tag, msg); }
    private static void logE(String tag, String msg) { log(LogLevel.ERROR, tag, msg); }
    private static void logE(String tag, String msg, Throwable t) {
        log(LogLevel.ERROR, tag, msg + " | " + t.getClass().getSimpleName() + ": " + t.getMessage());
    }

    /**
     * 辅助方法：格式化异常堆栈为字符串
     */
    public static String getStackTrace(Throwable t) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        t.printStackTrace(pw);
        pw.flush();
        return sw.toString();
    }

    // ==================== 内部类 ====================

    /**
     * ADB连接结果
     */
    public static class AdbConnectionResult {
        public final boolean success;
        public final String message;
        public final AdbConnection connection;

        public AdbConnectionResult(boolean success, String message, AdbConnection connection) {
            this.success = success;
            this.message = message;
            this.connection = connection;
        }

        @Override
        public String toString() {
            return success ? "SUCCESS: " + message : "FAILED: " + message;
        }
    }

    /**
     * Shell执行结果
     */
    public static class ShellResult {
        public final int exitCode;
        public final String stdout;
        public final String stderr;

        public ShellResult(int exitCode, String stdout, String stderr) {
            this.exitCode = exitCode;
            this.stdout = (stdout != null) ? stdout : "";
            this.stderr = (stderr != null) ? stderr : "";
        }

        public boolean isSuccess() {
            return exitCode == 0;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("ExitCode=").append(exitCode).append("\n");
            if (!stdout.isEmpty()) {
                sb.append("STDOUT:\n").append(stdout);
            }
            if (!stderr.isEmpty()) {
                sb.append("STDERR:\n").append(stderr);
            }
            return sb.toString();
        }
    }

    /**
     * ADB连接对象（封装jadb的JadbDevice）
     * 支持长连接场景下复用设备连接，多次执行命令
     */
    public static class AdbConnection implements Closeable {
        private final JadbConnection jadbConnection;
        private final JadbDevice device;
        private final String serial;
        private final String tag;
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private final long connectTime;

        AdbConnection(JadbConnection jadbConnection, JadbDevice device) {
            this.jadbConnection = jadbConnection;
            this.device = device;
            this.serial = device.getSerial();
            this.tag = "AdbConn[" + serial + "]";
            this.connectTime = System.currentTimeMillis();
            logI(tag, "连接已建立 | 设备=" + serial);
        }

        public String getSerial() { return serial; }
        public long getConnectTime() { return connectTime; }
        public boolean isClosed() { return closed.get(); }

        /**
         * 在长连接上执行Shell命令
         * 注意: jadb的executeShell返回InputStream，需要手动读取并转换为字符串
         *
         * @param command 要执行的shell命令
         * @return Shell执行结果
         */
        public ShellResult executeShell(String command) {
            if (closed.get()) {
                logE(tag, "连接已关闭，无法执行");
                return new ShellResult(-1, "", "连接已关闭");
            }

            String cmdPreview = command.substring(0, Math.min(200, command.length())).trim();
            logI(tag, "执行命令: '" + cmdPreview + "'");

            InputStream inputStream = null;
            try {
                // jadb vidstige: executeShell返回InputStream，需手动读取
                inputStream = device.executeShell(command);
                
                // 读取流内容（带超时）
                String output = readStreamWithTimeout(inputStream, SHELL_READ_TIMEOUT);
                logI(tag, "命令执行完成 | 输出长度=" + output.length());
                return new ShellResult(0, output, "");
            } catch (SocketTimeoutException e) {
                logE(tag, "命令执行超时", e);
                return new ShellResult(-1, "", "命令超时: " + e.getMessage());
            } catch (InterruptedIOException e) {
                logE(tag, "命令执行被中断", e);
                return new ShellResult(-1, "", "执行被中断: " + e.getMessage());
            } catch (IOException e) {
                logE(tag, "命令执行异常", e);
                return new ShellResult(-1, "", "执行异常: " + e.getMessage());
            } catch (JadbException e) {
                logE(tag, "jadb异常", e);
                return new ShellResult(-1, "", "jadb异常: " + e.getMessage());
            } finally {
                if (inputStream != null) {
                    try { inputStream.close(); } catch (IOException ignored) {}
                }
            }
        }

        /**
         * 推送文件到设备（长连接方式）
         * jadb vidstige: push需要RemoteFile对象作为目标路径
         *
         * @param data 文件数据
         * @param remotePath 远程路径
         * @return 执行结果
         */
        public ShellResult pushFile(byte[] data, String remotePath) {
            if (closed.get()) {
                logE(tag, "连接已关闭，无法推送文件");
                return new ShellResult(-1, "", "连接已关闭");
            }

            logI(tag, "推送文件 | 大小=" + data.length + " bytes | 目标=" + remotePath);

            try {
                // jadb vidstige: push(InputStream, long, int, RemoteFile)
                // 或者使用 push(File, RemoteFile) 重载
                ByteArrayInputStream bais = new ByteArrayInputStream(data);
                device.push(bais, System.currentTimeMillis(), 0644, new RemoteFile(remotePath));
                logI(tag, "文件推送完成 | 大小=" + data.length + " bytes");
                return new ShellResult(0, "", "");
            } catch (IOException e) {
                logE(tag, "文件推送失败", e);
                return new ShellResult(-1, "", "推送失败: " + e.getMessage());
            } catch (JadbException e) {
                logE(tag, "文件推送jadb异常", e);
                return new ShellResult(-1, "", "推送失败: " + e.getMessage());
            }
        }

        /**
         * 推送文件到设备（从文件路径，长连接方式）
         * jadb vidstige: push(File, RemoteFile)
         *
         * @param sourceFilePath 源文件路径
         * @param remotePath 远程路径
         * @return 执行结果
         */
        public ShellResult pushFile(String sourceFilePath, String remotePath) {
            if (closed.get()) {
                logE(tag, "连接已关闭，无法推送文件");
                return new ShellResult(-1, "", "连接已关闭");
            }

            File sourceFile = new File(sourceFilePath);
            if (!sourceFile.exists()) {
                logE(tag, "源文件不存在: " + sourceFilePath);
                return new ShellResult(-1, "", "源文件不存在: " + sourceFilePath);
            }

            logI(tag, "推送文件(从路径) | 大小=" + sourceFile.length() + " bytes | 源=" + sourceFilePath + " | 目标=" + remotePath);

            try {
                // jadb vidstige: push(File local, RemoteFile remote)
                device.push(sourceFile, new RemoteFile(remotePath));
                logI(tag, "文件推送完成 | 大小=" + sourceFile.length() + " bytes");
                return new ShellResult(0, "", "");
            } catch (IOException e) {
                logE(tag, "文件推送失败", e);
                return new ShellResult(-1, "", "推送失败: " + e.getMessage());
            } catch (JadbException e) {
                logE(tag, "文件推送jadb异常", e);
                return new ShellResult(-1, "", "推送失败: " + e.getMessage());
            }
        }

        /**
         * 从设备拉取文件
         * jadb vidstige: pull(RemoteFile, File)
         *
         * @param remotePath 设备端文件路径
         * @param localPath 本地保存路径
         * @return 执行结果
         */
        public ShellResult pullFile(String remotePath, String localPath) {
            if (closed.get()) {
                logE(tag, "连接已关闭，无法拉取文件");
                return new ShellResult(-1, "", "连接已关闭");
            }

            logI(tag, "拉取文件 | 源=" + remotePath + " | 目标=" + localPath);

            try {
                File localFile = new File(localPath);
                // 确保父目录存在
                if (localFile.getParentFile() != null) {
                    localFile.getParentFile().mkdirs();
                }
                // jadb vidstige: pull(RemoteFile remote, File local)
                device.pull(new RemoteFile(remotePath), localFile);
                logI(tag, "文件拉取完成 | 目标=" + localPath);
                return new ShellResult(0, "", "");
            } catch (IOException e) {
                logE(tag, "文件拉取失败", e);
                return new ShellResult(-1, "", "拉取失败: " + e.getMessage());
            } catch (JadbException e) {
                logE(tag, "文件拉取jadb异常", e);
                return new ShellResult(-1, "", "拉取失败: " + e.getMessage());
            }
        }

        /**
         * 读取InputStream内容，带超时控制
         */
        private String readStreamWithTimeout(InputStream stream, int timeoutSeconds) throws IOException {
            final BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8));
            final Timer timer = new Timer(true); // 守护线程
            final AtomicReference<IOException> timeoutException = new AtomicReference<>();
            
            timer.schedule(new TimerTask() {
                @Override
                public void run() {
                    try {
                        stream.close();
                        timeoutException.set(new SocketTimeoutException("读取超时: " + timeoutSeconds + "秒"));
                    } catch (IOException e) {
                        // 忽略关闭异常
                    }
                }
            }, timeoutSeconds * 1000);

            try {
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                return output.toString();
            } finally {
                timer.cancel();
                try { stream.close(); } catch (IOException ignored) {}
            }
        }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                long duration = System.currentTimeMillis() - connectTime;
                logI(tag, "关闭连接 | 持续时间=" + duration + "ms");
                // jadbConnection 不需要显式关闭，由GC回收
                // 但如果需要断开设备连接，可以调用:
                // jadbConnection.disconnect(device);
            }
        }

        /**
         * 获取底层的JadbDevice实例（高级用法）
         */
        public JadbDevice getDevice() {
            return device;
        }
    }

    // ==================== 端口检查 ====================

    /**
     * 检查ADB端口是否开放
     * @param host 目标主机IP
     * @param port ADB端口（默认5555）
     * @param timeoutMs 超时时间（毫秒）
     * @return 端口是否开放
     */
    public static boolean checkAdbPort(String host, int port, int timeoutMs) {
        String tag = "PortCheck[" + host + ":" + port + "]";
        logD(tag, "开始检查端口... | 超时=" + timeoutMs + "ms");

        long startTime = System.currentTimeMillis();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            long elapsed = System.currentTimeMillis() - startTime;
            logI(tag, "端口开放 | 耗时=" + elapsed + "ms");
            return true;
        } catch (Exception e) {
            long elapsed = System.currentTimeMillis() - startTime;
            logD(tag, "端口关闭/不可达 | 耗时=" + elapsed + "ms | " + e.getMessage());
            return false;
        }
    }

    /**
     * 批量检查端口
     * @param host 目标主机IP
     * @param ports 要检查的端口列表
     * @param timeoutMs 超时时间
     * @return 开放的端口列表
     */
    public static List<Integer> scanOpenPorts(String host, int[] ports, int timeoutMs) {
        String tag = "PortScan[" + host + "]";
        logI(tag, "开始扫描 " + ports.length + " 个端口...");

        List<Integer> openPorts = new ArrayList<>();

        for (int port : ports) {
            if (checkAdbPort(host, port, timeoutMs)) {
                openPorts.add(port);
            }
        }

        logI(tag, "扫描完成 | 开放端口=" + openPorts.size() + " | " + openPorts);
        return openPorts;
    }

    // ==================== ADB连接管理 ====================

    /**
     * 连接到ADB设备（通过ADB Server）
     * 注意：设备必须已经通过 adb connect <host>:<port> 连接到ADB Server
     *
     * @param host 目标主机IP（用于adb connect）
     * @param port ADB端口
     * @return 连接结果
     */
    public static AdbConnectionResult connect(String host, int port) {
        String tag = "Connect[" + host + ":" + port + "]";
        logI(tag, "========== 开始ADB连接 ==========");

        // 第一步：通过命令行连接设备到ADB Server
        // try {
        //     logD(tag, "步骤1: 执行 adb connect " + host + ":" + port);
        //     Process process = Runtime.getRuntime().exec(new String[]{"adb", "connect", host + ":" + port});
        //     int exitCode = process.waitFor();
        //     String output = new BufferedReader(new InputStreamReader(process.getInputStream())).readLine();
        //     logD(tag, "adb connect 输出: " + output + " | 退出码=" + exitCode);
        // } catch (IOException | InterruptedException e) {
        //     logE(tag, "adb connect 执行失败", e);
        //     return new AdbConnectionResult(false, "adb connect失败: " + e.getMessage(), null);
        // }

        // 第二步：通过jadb连接ADB Server并获取设备
        JadbConnection jadb = null;
        try {
            logD(tag, "步骤2: 连接ADB Server (localhost:5037)...");
            jadb = new JadbConnection(host, port);

            logD(tag, "步骤3: 获取设备列表...");
            List<JadbDevice> devices = jadb.getDevices();
            logD(tag, "已连接设备数: " + devices.size());

            // 查找目标设备
            JadbDevice targetDevice = null;
            for (JadbDevice device : devices) {
                if (device.getSerial().equals(host + ":" + port) ||
                    device.getSerial().contains(host)) {
                    targetDevice = device;
                    break;
                }
            }

            // 如果没找到精确匹配的设备，返回第一个可用设备
            if (targetDevice == null && !devices.isEmpty()) {
                targetDevice = devices.get(0);
                logW(tag, "未找到精确匹配的设备，使用第一个可用设备: " + targetDevice.getSerial());
            }

            if (targetDevice == null) {
                logE(tag, "未找到可用设备 | host=" + host + " port=" + port);
                return new AdbConnectionResult(false, "未找到可用设备", null);
            }

            logI(tag, "步骤4: 设备已选中 | serial=" + targetDevice.getSerial());
            AdbConnection conn = new AdbConnection(jadb, targetDevice);
            logI(tag, "========== 连接成功 ==========");
            return new AdbConnectionResult(true, "连接成功: " + targetDevice.getSerial(), conn);

        } catch (IOException e) {
            logE(tag, "连接ADB Server失败", e);
            return new AdbConnectionResult(false, "连接ADB Server失败: " + e.getMessage(), null);
        } catch (JadbException e) {
            logE(tag, "jadb连接异常", e);
            return new AdbConnectionResult(false, "jadb连接异常: " + e.getMessage(), null);
        } catch (Exception e) {
            logE(tag, "jadb连接异常", e);
            e.printStackTrace(); // 务必打印异常，看是否是 Connection Refused
            return new AdbConnectionResult(false, "jadb连接异常: " + e.getMessage(), null);
        }
    }

    /**
     * 直接连接ADB Server（不指定设备，用于设备列表查询）
     * @return JadbConnection实例
     */
    public static JadbConnection connectToServer() throws IOException, JadbException {
        logI("JadbServer", "连接ADB Server...");
        JadbConnection jadb = new JadbConnection();
        logI("JadbServer", "ADB Server连接成功");
        return jadb;
    }

    /**
     * 获取所有已连接的设备列表
     * @param jadb ADB Server连接
     * @return 设备列表
     */
    public static List<JadbDevice> getDeviceList(JadbConnection jadb) {
        try {
            List<JadbDevice> devices = jadb.getDevices();
            logI("DeviceList", "获取到 " + devices.size() + " 个设备");
            for (JadbDevice d : devices) {
                logD("DeviceList", "  - " + d.getSerial() + " | " + d.getState());
            }
            return devices;
        } catch (IOException e) {
            logE("DeviceList", "获取设备列表失败", e);
            return Collections.emptyList();
        } catch (JadbException e) {
            logE("DeviceList", "jadb异常", e);
            return Collections.emptyList();
        }
    }

    // ==================== Shell命令执行 ====================

    /**
     * 执行ADB Shell命令（一次性连接方式）
     * 每次调用都会创建新的连接，适合单次命令执行
     *
     * @param host 目标主机IP
     * @param port ADB端口
     * @param command Shell命令
     * @return Shell执行结果
     */
    public static ShellResult executeShellOneShot(String host, int port, String command) {
        String tag = "OneShot[" + host + ":" + port + "]";

        logI(tag, "一次性执行开始 | 命令='" + command.substring(0, Math.min(200, command.length())).trim() + "'");

        AdbConnectionResult result = connect(host, port);
        if (!result.success || result.connection == null) {
            logE(tag, "连接失败，无法执行命令 | " + result.message);
            return new ShellResult(-1, "", "连接失败: " + result.message);
        }

        try {
            ShellResult shellResult = result.connection.executeShell(command);
            logI(tag, "一次性执行完成 | exitCode=" + shellResult.exitCode);
            return shellResult;
        } finally {
            try { result.connection.close(); } catch (Exception ignored) {}
        }
    }

    /**
     * 执行ADB Shell命令（使用已建立的长连接）
     * 适合需要在同一连接上多次执行命令的场景
     *
     * @param connection ADB长连接对象
     * @param command 要执行的shell命令
     * @return Shell执行结果
     */
    public static ShellResult executeShell(AdbConnection connection, String command) {
        return connection.executeShell(command);
    }

    /**
     * 异步执行Shell命令
     * @param connection ADB长连接对象
     * @param command Shell命令
     * @return CompletableFuture包裹的ShellResult
     */
    public static CompletableFuture<ShellResult> executeShellAsync(AdbConnection connection, String command) {
        return CompletableFuture.supplyAsync(() -> connection.executeShell(command));
    }

    // ==================== 文件传输 ====================

    /**
     * 推送文件到设备（一次性连接方式）
     *
     * @param host 目标主机IP
     * @param port ADB端口
     * @param data 文件数据
     * @param remotePath 远程路径
     * @return 执行结果
     */
    public static ShellResult pushFile(String host, int port, byte[] data, String remotePath) {
        String tag = "Push[" + host + ":" + port + "]";
        logI(tag, "推送文件(一次性) | 大小=" + data.length + " bytes | 目标=" + remotePath);

        AdbConnectionResult result = connect(host, port);
        if (!result.success || result.connection == null) {
            logE(tag, "连接失败 | " + result.message);
            return new ShellResult(-1, "", "连接失败: " + result.message);
        }

        try {
            ShellResult pushResult = result.connection.pushFile(data, remotePath);
            if (pushResult.isSuccess()) {
                logI(tag, "文件推送完成 | 大小=" + data.length + " bytes");
            }
            return pushResult;
        } finally {
            try { result.connection.close(); } catch (Exception ignored) {}
        }
    }

    /**
     * 推送文件到设备（从文件路径，一次性连接方式）
     *
     * @param host 目标主机IP
     * @param port ADB端口
     * @param sourceFilePath 源文件路径
     * @param remotePath 远程路径
     * @return 执行结果
     */
    public static ShellResult pushFile(String host, int port, String sourceFilePath, String remotePath) {
        String tag = "Push[" + host + ":" + port + "]";
        File sourceFile = new File(sourceFilePath);
        logI(tag, "推送文件(从路径/一次性) | 大小=" + sourceFile.length() + " bytes | 源=" + sourceFilePath + " | 目标=" + remotePath);

        AdbConnectionResult result = connect(host, port);
        if (!result.success || result.connection == null) {
            logE(tag, "连接失败 | " + result.message);
            return new ShellResult(-1, "", "连接失败: " + result.message);
        }

        try {
            ShellResult pushResult = result.connection.pushFile(sourceFilePath, remotePath);
            if (pushResult.isSuccess()) {
                logI(tag, "文件推送完成 | 大小=" + sourceFile.length() + " bytes");
            }
            return pushResult;
        } finally {
            try { result.connection.close(); } catch (Exception ignored) {}
        }
    }

    /**
     * 推送文件到设备（使用已建立的长连接）
     * 适用于MainActivity已持有adbConnection实例的场景，避免重复建连
     *
     * @param connection 已建立的ADB连接
     * @param data 文件数据
     * @param remotePath 远程路径
     * @return 执行结果
     */
    public static ShellResult pushFile(AdbConnection connection, byte[] data, String remotePath) {
        return connection.pushFile(data, remotePath);
    }

    /**
     * 推送文件到设备（使用已建立的长连接，从文件路径）
     *
     * @param connection 已建立的ADB连接
     * @param sourceFilePath 源文件路径
     * @param remotePath 远程路径
     * @return 执行结果
     */
    public static ShellResult pushFile(AdbConnection connection, String sourceFilePath, String remotePath) {
        return connection.pushFile(sourceFilePath, remotePath);
    }

    /**
     * 从设备拉取文件
     *
     * @param connection ADB长连接
     * @param remotePath 设备端文件路径
     * @param localPath 本地保存路径
     * @return 执行结果
     */
    public static ShellResult pullFile(AdbConnection connection, String remotePath, String localPath) {
        return connection.pullFile(remotePath, localPath);
    }

    // ==================== 设备管理 ====================

    /**
     * 获取设备信息
     */
    public static String getDeviceInfo(String host, int port) {
        String tag = "DeviceInfo[" + host + ":" + port + "]";
        logI(tag, "获取设备信息...");

        ShellResult sdkResult = executeShellOneShot(host, port, "getprop ro.build.version.sdk");
        ShellResult modelResult = executeShellOneShot(host, port, "getprop ro.product.model");
        ShellResult brandResult = executeShellOneShot(host, port, "getprop ro.product.brand");
        ShellResult androidIdResult = executeShellOneShot(host, port, "settings get secure android_id");

        StringBuilder info = new StringBuilder();
        info.append("SDK: ").append(sdkResult.stdout.trim()).append("\n");
        info.append("Model: ").append(modelResult.stdout.trim()).append("\n");
        info.append("Brand: ").append(brandResult.stdout.trim()).append("\n");
        info.append("AndroidId: ").append(androidIdResult.stdout.trim()).append("\n");

        logI(tag, "设备信息获取完成:\n" + info.toString().trim());
        return info.toString();
    }

    /**
     * 安装APK
     */
    public static ShellResult installApk(String host, int port, String remoteApkPath) {
        logI("Install[" + host + ":" + port + "]", "安装APK: " + remoteApkPath);
        return executeShellOneShot(host, port,
            "pm install -r -d " + escapeShellArg(remoteApkPath));
    }

    /**
     * 卸载应用
     */
    public static ShellResult uninstallApp(String host, int port, String packageName) {
        logI("Uninstall[" + host + ":" + port + "]", "卸载应用: " + packageName);
        return executeShellOneShot(host, port,
            "pm uninstall " + escapeShellArg(packageName));
    }

    /**
     * 获取已安装应用列表
     */
    public static String getInstalledApps(String host, int port, boolean systemApps) {
        String flag = systemApps ? "" : " -3";
        return executeShellOneShot(host, port,
            "pm list packages" + flag).stdout;
    }

    // ==================== 工具方法 ====================

    /**
     * Shell参数转义
     */
    public static String escapeShellArg(String arg) {
        if (arg == null) return "''";
        return "'" + arg.replace("'", "'\\''") + "'";
    }

    /**
     * 扫描局域网ADB设备
     */
    public static List<String> scanLanDevices(String subnet, int timeoutMs) {
        String tag = "LanScan[" + subnet + ".0/24]";
        logI(tag, "开始扫描局域网ADB设备...");

        List<String> devices = new ArrayList<>();
        int[] commonPorts = {5555, 5556, 5557, 5558, 5559, 6666, 8888};

        int totalHosts = 254;
        int scannedHosts = 0;
        int progressStep = totalHosts / 10;

        for (int i = 1; i <= 254; i++) {
            final String host = subnet + "." + i;

            for (int port : commonPorts) {
                if (checkAdbPort(host, port, timeoutMs)) {
                    String device = host + ":" + port;
                    devices.add(device);
                    logI(tag, "发现设备: " + device);
                }
            }

            scannedHosts++;
            if (scannedHosts % progressStep == 0) {
                int percent = scannedHosts * 100 / totalHosts;
                logD(tag, "扫描进度: " + percent + "% (" + scannedHosts + "/" + totalHosts + ")");
            }
        }

        logI(tag, "扫描完成 | 发现设备=" + devices.size() + " | " + devices);
        return devices;
    }

    /**
     * 通过ADB Server连接设备（高级用法，返回JadbConnection供直接使用jadb API）
     * 适用于需要访问jadb高级功能（如屏幕捕获、输入模拟等）的场景
     *
     * @param deviceSerial 设备序列号（如 "192.168.1.100:5555"）
     * @return JadbDevice实例
     */
    public static JadbDevice connectToDevice(String deviceSerial) throws IOException, JadbException {
        logI("JadbDirect", "直接连接设备: " + deviceSerial);
        JadbConnection jadb = new JadbConnection();
        List<JadbDevice> devices = jadb.getDevices();

        for (JadbDevice device : devices) {
            if (device.getSerial().equals(deviceSerial)) {
                logI("JadbDirect", "设备已找到: " + deviceSerial);
                return device;
            }
        }

        throw new IOException("设备未连接: " + deviceSerial + " | 已连接设备: " +
            devices.stream().map(JadbDevice::getSerial).collect(Collectors.joining(", ")));
    }
}
