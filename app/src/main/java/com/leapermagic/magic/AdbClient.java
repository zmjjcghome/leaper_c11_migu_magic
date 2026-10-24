package com.leapermagic.magic;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;  // ← 新增

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * 纯Java实现的ADB客户端（带Debug Log）
 * 支持：端口检查、ADB Connect、ADB Shell执行
 * 目标：Android 9+
 */
public class AdbClient {

    // ==================== 常量定义 ====================
    
    private static final int ADB_DEFAULT_PORT = 5555;
    private static final int CONNECT_TIMEOUT = 5000;
    private static final int READ_TIMEOUT = 30000;
    
    // ADB协议命令
    private static final String CMD_CONNECT = "host:connect:%s:%d";
    private static final String CMD_TRACK_DEVICES = "host:track-devices";
    private static final String CMD_SHELL = "shell:%s";
    private static final String CMD_EXEC = "exec:%s";
    
    // ADB协议版本
    private static final int ADB_VERSION = 0x01000000;
    private static final int MAX_PAYLOAD = 256 * 1024; // 256KB
    
    // ADB消息类型
    private static final int AUTH_TOKEN = 1;
    private static final int AUTH_SIGNATURE = 2;
    private static final int AUTH_RSAPUBLICKEY = 3;
    
    private static final int CMD_OPEN = 0x4e45504f; // "OPEN"
    private static final int CMD_OKAY = 0x59414b4f;  // "OKAY"
    private static final int CMD_CLSE = 0x45534c43;  // "CLSE"
    private static final int CMD_WRTE = 0x45545257;  // "WRTE"
    
    // ==================== 新增/修改常量 ====================
    // ADB协议命令常量补充
    private static final int A_SYNC = 0x434e5953;  // "SYNC"
    private static final int A_CNXN = 0x4e584e43;  // "CNXN"
    private static final int A_AUTH = 0x48545541;  // "AUTH"
    private static final int A_OPEN = 0x4e45504f;  // "OPEN"
    private static final int A_OKAY = 0x59414b4f;  // "OKAY"
    private static final int A_CLSE = 0x45534c43;  // "CLSE"
    private static final int A_WRTE = 0x45545257;  // "WRTE"
    private static final int AUTH_TYPE_TOKEN = 1;
    private static final int AUTH_TYPE_SIGNATURE = 2;
    private static final int AUTH_TYPE_RSAPUBLICKEY = 3;

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
     * ADB连接对象
     */
    // ==================== 修复 AdbConnection 构造函数 ====================
    public static class AdbConnection implements Closeable {
        private final Socket socket;
        private final DataInputStream input;
        private final DataOutputStream output;
        private final String serial;
        private final String tag;
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private final long connectTime;
        private final AtomicInteger localIdCounter = new AtomicInteger(1);  // 新增
    
        AdbConnection(Socket socket, String serial,
                      DataInputStream input, DataOutputStream output) throws IOException {
            this.socket = socket;
            this.serial = serial;
            this.tag = "AdbConn[" + serial + "]";
            this.connectTime = System.currentTimeMillis();
            this.input = input;
            this.output = output;
            socket.setSoTimeout(READ_TIMEOUT);
            logI(tag, "连接已建立 | 本地端口=" + socket.getLocalPort());
        }
    
        /** 获取下一个 local-id */
        int nextLocalId() {
            return localIdCounter.getAndIncrement();
        }
    
        public String getSerial() { return serial; }
        public long getConnectTime() { return connectTime; }
        public boolean isClosed() { return closed.get() || socket.isClosed(); }
    
        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                long duration = System.currentTimeMillis() - connectTime;
                logI(tag, "关闭连接 | 持续时间=" + duration + "ms");
                try { socket.close(); } catch (Exception ignored) {}
            }
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
            logI(tag, "端口开放 ✓ | 耗时=" + elapsed + "ms");
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
    public static java.util.List<Integer> scanOpenPorts(String host, int[] ports, int timeoutMs) {
        String tag = "PortScan[" + host + "]";
        logI(tag, "开始扫描 " + ports.length + " 个端口...");
        
        java.util.List<Integer> openPorts = new java.util.ArrayList<>();
        
        for (int port : ports) {
            if (checkAdbPort(host, port, timeoutMs)) {
                openPorts.add(port);
            }
        }
        
        logI(tag, "扫描完成 | 开放端口=" + openPorts.size() + " | " + openPorts);
        return openPorts;
    }

    // ==================== ADB Connect ====================
    
    /**
     * ADB连接（完整协议实现）
     * @param host 目标主机IP
     * @param port ADB端口
     * @param keyPair RSA密钥对（用于认证，可为null自动生成）
     * @return 连接结果
     */
    // ==================== 修复连接方法 ====================
    /**
     * ADB连接（修复版）
     */
    public static AdbConnectionResult connect(String host, int port, KeyPair keyPair) {
        String tag = "Connect[" + host + ":" + port + "]";
        Socket socket = null;
        logI(tag, "========== 开始ADB连接 ==========");
        try {
            // 1. 建立TCP连接
            logD(tag, "步骤1/6: 建立TCP连接...");
            long t1 = System.currentTimeMillis();
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT);
            socket.setTcpNoDelay(true);
            socket.setSoTimeout(READ_TIMEOUT);
            long tcpTime = System.currentTimeMillis() - t1;
            logI(tag, "TCP连接成功 | 耗时=" + tcpTime + "ms | " +
                     socket.getLocalAddress().getHostAddress() + ":" + socket.getLocalPort() +
                     " -> " + host + ":" + port);
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
            // ============ 修复点1：先发送 CNXN 握手消息 ============
            logD(tag, "步骤2/6: 发送CNXN握手消息...");
            // CNXN格式: version(4字节) + maxdata(4字节) + "host::\0"
            String handshakePayload = "host::\0";
            sendAdbRawMessage(out, A_CNXN, ADB_VERSION, MAX_PAYLOAD, 
                              handshakePayload.getBytes(StandardCharsets.UTF_8), tag);
            logD(tag, "CNXN握手消息已发送 | version=0x" + Integer.toHexString(ADB_VERSION) + 
                       " | maxdata=" + MAX_PAYLOAD);
            // ============ 修复点2：读取握手响应 ============
            logD(tag, "步骤3/6: 等待握手响应...");
            AdbMessage response = readAdbMessageRaw(in, tag);
            if (response == null) {
                logE(tag, "握手失败：无响应");
                return new AdbConnectionResult(false, "握手无响应", null);
            }
            logD(tag, "收到握手响应 | command=0x" + Integer.toHexString(response.command).toUpperCase() +
                       " | arg0=" + response.arg0 + " | dataLen=" + response.dataLength);
            // ============ 修复点3：处理认证 ============
            if (response.command == A_AUTH) {
                int authType = response.arg0;
                logI(tag, "步骤4/6: 需要认证 | type=" + authType + 
                           " (" + (authType == AUTH_TYPE_TOKEN ? "TOKEN" : 
                                   authType == AUTH_TYPE_SIGNATURE ? "SIGNATURE" : 
                                   authType == AUTH_TYPE_RSAPUBLICKEY ? "RSAPUBLICKEY" : "UNKNOWN") + ")");
                if (keyPair == null) {
                    logD(tag, "生成新的RSA密钥对...");
                    long keyGenStart = System.currentTimeMillis();
                    keyPair = generateAdbKey();
                    long keyGenTime = System.currentTimeMillis() - keyGenStart;
                    logI(tag, "RSA密钥对生成完成 | 耗时=" + keyGenTime + "ms | 强度=2048位");
                }
                // 发送公钥
                logD(tag, "发送公钥...");
                byte[] publicKey = encodePublicKey(keyPair.getPublic());
                sendAdbRawMessage(out, A_AUTH, AUTH_TYPE_RSAPUBLICKEY, 0, publicKey, tag);
                logD(tag, "公钥已发送 | 大小=" + publicKey.length + " bytes");
                // 等待响应
                response = readAdbMessageRaw(in, tag);
                if (response == null) {
                    logE(tag, "认证失败：无响应");
                    try { socket.close(); } catch (Exception ignored) {}
                    return new AdbConnectionResult(false, "认证无响应", null);
                }
                logD(tag, "收到认证响应 | command=0x" + Integer.toHexString(response.command).toUpperCase() +
                           " | arg0=" + response.arg0);
                if (response.command == A_AUTH && response.arg0 == AUTH_TYPE_TOKEN) {
                    logD(tag, "收到认证令牌 | 长度=" + response.dataLength + " bytes");
                    // 签名令牌
                    byte[] token = response.payload;
                    long signStart = System.currentTimeMillis();
                    byte[] signature = signToken(token, keyPair);
                    long signTime = System.currentTimeMillis() - signStart;
                    logD(tag, "发送签名 | 大小=" + signature.length + " bytes | 签名耗时=" + signTime + "ms");
                    sendAdbRawMessage(out, A_AUTH, AUTH_TYPE_SIGNATURE, 0, signature, tag);
                    // 读取最终握手结果
                    response = readAdbMessageRaw(in, tag);
                    if (response == null) {
                        logE(tag, "签名后无响应");
                        try { socket.close(); } catch (Exception ignored) {}
                        return new AdbConnectionResult(false, "签名后无响应", null);
                    }
                }
            }
            // 检查握手是否成功（应该是 CNXN 响应）
            if (response.command == A_CNXN) {
                // 握手成功，设备已连接
                String deviceInfo = "";
                if (response.payload != null && response.payload.length > 0) {
                    deviceInfo = new String(response.payload, StandardCharsets.UTF_8).trim();
                }
                String serial = host + ":" + port;
                logI(tag, "握手成功 | 设备信息=" + deviceInfo);
                AdbConnection conn = new AdbConnection(socket, serial, in, out);
                logI(tag, "========== 连接成功 ✓ ==========");
                return new AdbConnectionResult(true, "连接成功: " + serial + 
                                               (deviceInfo.isEmpty() ? "" : " [" + deviceInfo + "]"), conn);
            } else {
                String msg = "未知错误";
                if (response.payload != null) {
                    msg = new String(response.payload, StandardCharsets.UTF_8).trim();
                }
                logE(tag, "握手失败 | command=0x" + Integer.toHexString(response.command).toUpperCase() +
                         " | msg=" + msg);
                try { socket.close(); } catch (Exception ignored) {}
                return new AdbConnectionResult(false, "握手失败: " + msg, null);
            }
        } catch (SocketTimeoutException e) {
            logE(tag, "连接超时", e);
            if (socket != null) try { socket.close(); } catch (Exception ignored) {}
            return new AdbConnectionResult(false, "连接超时: " + e.getMessage(), null);
        } catch (ConnectException e) {
            logE(tag, "连接被拒绝", e);
            if (socket != null) try { socket.close(); } catch (Exception ignored) {}
            return new AdbConnectionResult(false, "连接被拒绝: " + e.getMessage(), null);
        } catch (Exception e) {
            logE(tag, "连接异常", e);
            logD(tag, "异常堆栈:\n" + getStackTrace(e));
            if (socket != null) try { socket.close(); } catch (Exception ignored) {}
            return new AdbConnectionResult(false, "连接异常: " + e.getMessage(), null);
        }
    }
    // ==================== 新增：原始ADB消息读写 ====================
    /**
     * 发送原始ADB消息（用于CNXN/AUTH等）
     * 格式: command(4) + arg0(4) + arg1(4) + dataLength(4) + dataCrc32(4) + magic(4) + payload
     */
    private static void sendAdbRawMessage(DataOutputStream out, int command, int arg0, int arg1, 
                                           byte[] payload, String tag) throws IOException {
        int dataLength = (payload != null) ? payload.length : 0;
        int dataCrc32 = (payload != null && payload.length > 0) ? calculateCrc32(payload) : 0;
        int magic = command ^ 0xFFFFFFFF;
        if (dataLength > 512) {
            logD(tag, "发送RAW | cmd=0x" + Integer.toHexString(command).toUpperCase() +
                       " | arg0=0x" + Integer.toHexString(arg0) +
                       " | arg1=0x" + Integer.toHexString(arg1) +
                       " | dataLen=" + dataLength + " bytes");
        } else {
            String preview = (payload != null && payload.length > 0) ?
                new String(payload, 0, Math.min(payload.length, 64), StandardCharsets.UTF_8)
                    .replace("\0", "\\0").replace("\n", "\\n") : "";
            logD(tag, "发送RAW | cmd=0x" + Integer.toHexString(command).toUpperCase() +
                       " | arg0=0x" + Integer.toHexString(arg0) +
                       " | arg1=0x" + Integer.toHexString(arg1) +
                       " | dataLen=" + dataLength +
                       " | data='" + preview.substring(0, Math.min(300, preview.length())).trim() + (dataLength > 64 ? "..." : "") + "'");
        }
        ByteBuffer header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(command);
        header.putInt(arg0);
        header.putInt(arg1);
        header.putInt(dataLength);
        header.putInt(dataCrc32);
        header.putInt(magic);
        out.write(header.array());
        if (payload != null && payload.length > 0) {
            out.write(payload);
        }
        out.flush();
    }
    
    /**
     * 读取原始ADB消息
     * 使用 available() 检测是否有数据，避免死等
     *
     * 读取原始ADB消息（修复版 - 使用阻塞读取 + 超时重试）
     */
    private static AdbMessage readAdbMessageRaw(DataInputStream in, String tag) throws IOException {
        int maxWaitTime = 10000;  // 最多等10秒
        int pollInterval = 200;   // 每200ms检查一次
        int waited = 0;
        
        // 等待数据到达
        while (waited < maxWaitTime) {
            try {
                int available = in.available();
                if (available >= 24) {
                    break;  // 有完整头部
                }
            } catch (IOException e) {
                // socket 可能已关闭
                logW(tag, "available() 检查失败: " + e.getMessage());
                return null;
            }
            
            if (waited == 0) {
                logD(tag, "等待数据到达...");
            }
            
            try {
                Thread.sleep(pollInterval);
                waited += pollInterval;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logW(tag, "等待被中断");
                return null;
            }
        }
        
        if (waited >= maxWaitTime) {
            logE(tag, "等待数据超时 | 已等待=" + waited + "ms");
            return null;
        }
        
        // 使用 readFully 确保读满24字节
        try {
            byte[] header = new byte[24];
            in.readFully(header);
            
            AdbMessage msg = new AdbMessage();
            ByteBuffer buf = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
            msg.command = buf.getInt();
            msg.arg0 = buf.getInt();
            msg.arg1 = buf.getInt();
            msg.dataLength = buf.getInt();
            msg.dataCrc32 = buf.getInt();
            msg.magic = buf.getInt();
            
            // 验证magic
            int expectedMagic = msg.command ^ 0xFFFFFFFF;
            if (msg.magic != expectedMagic) {
                logE(tag, "Magic验证失败! | cmd=0x" + Integer.toHexString(msg.command).toUpperCase() +
                          " | 期望=0x" + Integer.toHexString(expectedMagic).toUpperCase() +
                          " | 实际=0x" + Integer.toHexString(msg.magic).toUpperCase());
                return null;
            }
            
            // 读取payload
            if (msg.dataLength > 0 && msg.dataLength <= MAX_PAYLOAD) {
                msg.payload = new byte[msg.dataLength];
                in.readFully(msg.payload);
            } else if (msg.dataLength > MAX_PAYLOAD) {
                logW(tag, "Payload过大 | dataLen=" + msg.dataLength + " | 跳过");
                long skipped = in.skip(msg.dataLength);
                logD(tag, "已跳过 " + skipped + " bytes");
                msg.payload = null;
            }
            
            // 日志
            String payloadPreview = "";
            if (msg.payload != null && msg.payload.length > 0) {
                payloadPreview = new String(msg.payload, 0, Math.min(msg.payload.length, 80), 
                                            StandardCharsets.UTF_8)
                    .replace("\0", "\\0").replace("\n", "\\n");
            }
            
            logD(tag, "收到RAW | cmd=0x" + Integer.toHexString(msg.command).toUpperCase() +
                       " | arg0=0x" + Integer.toHexString(msg.arg0) +
                       " | arg1=0x" + Integer.toHexString(msg.arg1) +
                       " | dataLen=" + msg.dataLength +
                       (payloadPreview.isEmpty() ? "" : " | data='" + payloadPreview + 
                        (msg.payload != null && msg.payload.length > 80 ? "..." : "") + "'"));
            
            return msg;
            
        } catch (EOFException e) {
            logW(tag, "读取消息: 意外EOF | " + e.getMessage());
            return null;
        } catch (SocketTimeoutException e) {
            logW(tag, "读取消息: 超时 | " + e.getMessage());
            return null;
        }
    }
    
    /**
     * 自动生成密钥对连接
     */
    public static AdbConnectionResult connect(String host, int port) {
        return connect(host, port, null);
    }

    // ==================== ADB Shell执行 ====================
    // ==================== 修改 executeShell 中的消息方法 ====================
    /**
     * Shell通道使用的消息（带 localId/remoteId）
     * 需要修改原来的 sendAdbMessage 来支持 arg0/arg1
     */
    private static void sendShellMessage(DataOutputStream out, int command, int arg0, int arg1, 
                                          byte[] payload, String tag) throws IOException {
        sendAdbRawMessage(out, command, arg0, arg1, payload, tag);
    }
    
    /**
     * 执行ADB Shell命令（使用已建立的连接）
     * @param connection ADB连接对象
     * @param command 要执行的shell命令
     * @return Shell执行结果
     */
    // ==================== 修改 executeShell ====================
    /**
     * 执行ADB Shell命令（修复版 - 正确管理 localId/remoteId）
     */
    public static ShellResult executeShell(AdbConnection connection, String command) {
        String tag = "Shell[" + connection.serial + "]";
    
        logI(tag, "========== 执行命令: '" + command.substring(0, Math.min(300, command.length())).trim() + "' ==========");
    
        try {
            if (connection.isClosed()) {
                logE(tag, "连接已关闭，无法执行");
                return new ShellResult(-1, "", "连接已关闭");
            }
    
            DataOutputStream out = connection.output;
            DataInputStream in = connection.input;
    
            // 使用递增的 local-id（从1开始，避免与系统冲突）
            int localId = connection.nextLocalId();
            
            // 1. 打开Shell通道
            // 格式: "shell:command\0" 或 "shell,arg1,arg2:command\0"（对于exec）
            String shellPayload = "shell:" + command + "\0";
            
            logD(tag, "步骤1: 打开Shell通道 | localId=" + localId + " | payload=" + 
                       shellPayload.replace("\0", "\\0").substring(0, Math.min(300, shellPayload.length())).trim());
            
            sendShellMessage(out, A_OPEN, localId, 0x00000000, 
                             shellPayload.getBytes(StandardCharsets.UTF_8), tag);
    
            // 2. 等待OKAY 或 CLSE
            logD(tag, "步骤2: 等待通道响应...");
            AdbMessage response = readAdbMessageRaw(in, tag);
            
            if (response == null) {
                logE(tag, "无法打开Shell通道：无响应（null）");
                return new ShellResult(-1, "", "无法打开Shell通道：无响应");
            }
            
            logD(tag, "收到通道响应 | cmd=0x" + Integer.toHexString(response.command).toUpperCase() +
                       " | arg0=" + response.arg0 + " | arg1=" + response.arg1);
    
            if (response.command == A_CLSE) {
                // 命令被立即拒绝
                String reason = "";
                if (response.payload != null) {
                    reason = new String(response.payload, StandardCharsets.UTF_8).trim();
                }
                logE(tag, "Shell通道被拒绝 | reason=" + reason);
                return new ShellResult(-1, "", "Shell被拒绝: " + reason);
            }
            
            if (response.command != A_OKAY) {
                logE(tag, "无法打开Shell通道 | 期望=OKAY | 实际=0x" + 
                          Integer.toHexString(response.command).toUpperCase());
                return new ShellResult(-1, "", 
                    "无法打开Shell通道: 0x" + Integer.toHexString(response.command));
            }
    
            int remoteId = response.arg0;
            // response.arg1 应该是我们的 localId
            logD(tag, "Shell通道已打开 ✓ | localId=" + localId + " | remoteId=" + remoteId);
    
            // 3. 读取输出数据
            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();
            boolean shellClosed = false;
            int writeCount = 0;
            long totalBytes = 0;
    
            logD(tag, "步骤3: 读取命令输出...");
    
            while (!shellClosed) {
                response = readAdbMessageRaw(in, tag);
                if (response == null) {
                    logW(tag, "读取到null消息，可能连接断开 | 已读取=" + writeCount + "块");
                    shellClosed = true;
                    break;
                }
    
                switch (response.command) {
                    case A_WRTE:
                        writeCount++;
                        String data = new String(response.payload, StandardCharsets.UTF_8);
                        stdout.append(data);
                        totalBytes += response.payload.length;
    
                        if (writeCount <= 3) {
                            logD(tag, "数据块#" + writeCount + " | 大小=" + response.payload.length +
                                       " bytes | 内容='" + 
                                       data.substring(0, Math.min(60, data.length()))
                                           .replace("\n", "\\n") + 
                                       (data.length() > 60 ? "..." : "") + "'");
                        } else if (writeCount % 100 == 0) {
                            logD(tag, "数据块#" + writeCount + " | 大小=" + response.payload.length +
                                       " bytes | 累计=" + totalBytes + " bytes");
                        }
    
                        // 发送OKAY确认（注意：arg0=remoteId, arg1=localId）
                        sendShellMessage(out, A_OKAY, localId, remoteId, null, tag);
                        break;
    
                    case A_CLSE:
                        // Shell远程关闭
                        shellClosed = true;
                        int closeRemoteId = response.arg0;
                        logD(tag, "Shell通道远程关闭 | remoteId=" + closeRemoteId + 
                                   " | 总数据块=" + writeCount + " | 总字节=" + totalBytes + " bytes");
                        
                        // 如果payload有内容，可能是退出码
                        if (response.payload != null && response.payload.length > 0) {
                            String closeData = new String(response.payload, StandardCharsets.UTF_8);
                            logD(tag, "关闭附带数据: " + closeData.trim());
                            stderr.append(closeData);
                        }
                        
                        // 发送CLSE确认
                        sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
                        break;
    
                    case A_OKAY:
                        // 就绪确认（可能在WRTE之前）
                        logD(tag, "收到OKAY | localId=" + response.arg0 + 
                                   " | remoteId=" + response.arg1);
                        break;
    
                    default:
                        if (response.payload != null && response.payload.length > 0) {
                            String extra = new String(response.payload, StandardCharsets.UTF_8);
                            logW(tag, "未知响应 | cmd=0x" + 
                                      Integer.toHexString(response.command).toUpperCase() +
                                      " | data=" + extra.substring(0, Math.min(100, extra.length())));
                            stderr.append("[UNKNOWN:").append(response.command).append("]").append(extra);
                        } else {
                            logW(tag, "未知响应 | cmd=0x" + 
                                      Integer.toHexString(response.command).toUpperCase());
                        }
                        break;
                }
            }
    
            // 4. 确保本地关闭
            sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
    
            String stdoutStr = stdout.toString();
            String stderrStr = stderr.toString();
    
            logI(tag, "========== 执行完成 | 数据块=" + writeCount + 
                     " | stdout=" + stdoutStr.length() + " bytes" +
                     " | stderr=" + stderrStr.length() + " bytes ==========");
    
            if (!stdoutStr.isEmpty() && stdoutStr.length() <= 300) {
                logD(tag, "STDOUT:\n" + stdoutStr.trim());
            } else if (!stdoutStr.isEmpty()) {
                logD(tag, "STDOUT(前300字符):\n" + 
                      stdoutStr.substring(0, Math.min(300, stdoutStr.length())).trim() + "...");
            }
    
            if (!stderrStr.isEmpty()) {
                logW(tag, "STDERR:\n" + stderrStr.trim());
            }
    
            return new ShellResult(0, stdoutStr, stderrStr);
    
        } catch (SocketTimeoutException e) {
            logE(tag, "Socket超时", e);
            return new ShellResult(-1, "", "Socket超时: " + e.getMessage());
        } catch (Exception e) {
            logE(tag, "执行异常", e);
            logD(tag, "异常堆栈:\n" + getStackTrace(e));
            return new ShellResult(-1, "", "执行异常: " + e.getMessage());
        }
    }
    
    /**
     * 执行ADB Shell命令（一次性连接）
     * @param host 目标主机IP
     * @param port ADB端口
     * @param command Shell命令
     * @return Shell执行结果
     */
    public static ShellResult executeShellOneShot(String host, int port, String command) {
        String tag = "OneShot[" + host + ":" + port + "]";
        
        logI(tag, "一次性执行开始 | 命令='" + command.substring(0, Math.min(300, command.length())).trim() + "'");
        
        AdbConnectionResult result = connect(host, port);
        if (!result.success || result.connection == null) {
            logE(tag, "连接失败，无法执行命令 | " + result.message);
            return new ShellResult(-1, "", "连接失败: " + result.message);
        }
        
        try (AdbConnection conn = result.connection) {
            ShellResult shellResult = executeShell(conn, command);
            logI(tag, "一次性执行完成 | exitCode=" + shellResult.exitCode);
            return shellResult;
        }
    }

    // ==================== ADB协议底层实现 ====================
    
    /**
     * ADB消息结构
     */
    private static class AdbMessage {
        int command;
        int arg0;
        int arg1;
        int dataLength;
        int dataCrc32;
        int magic;
        byte[] payload;
    }
    
    /**
     * 发送ADB消息（字符串payload）
     */
    private static void sendAdbMessage(DataOutputStream out, String payload, String tag) throws IOException {
        sendAdbMessage(out, CMD_OPEN, 0x00000000, 
                       payload.getBytes(StandardCharsets.UTF_8), tag);
    }
    
    /**
     * 发送ADB消息（byte[] payload）
     */
    private static void sendAdbMessage(DataOutputStream out, int command, byte[] payload, String tag) throws IOException {
        sendAdbMessage(out, command, 0x00000000, payload, tag);
    }
    
    /**
     * 发送完整的ADB消息
     */
    private static void sendAdbMessage(DataOutputStream out, int command, int arg0, byte[] payload, String tag) throws IOException {
        int dataLength = (payload != null) ? payload.length : 0;
        int dataCrc32 = (payload != null) ? calculateCrc32(payload) : 0;
        int magic = command ^ 0xFFFFFFFF;
        
        // 日志（大payload只记录摘要）
        if (dataLength > 512) {
            logD(tag, "发送消息 | cmd=0x" + Integer.toHexString(command).toUpperCase() + 
                       " | arg0=" + arg0 + " | dataLen=" + dataLength + " bytes | CRC=0x" + 
                       Integer.toHexString(dataCrc32).toUpperCase());
        } else {
            String payloadPreview = (payload != null && payload.length > 0) ? 
                new String(payload, 0, Math.min(payload.length, 64), StandardCharsets.UTF_8) : "";
            logD(tag, "发送消息 | cmd=0x" + Integer.toHexString(command).toUpperCase() + 
                       " | arg0=" + arg0 + " | dataLen=" + dataLength + " | data='" + payloadPreview + 
                       (dataLength > 64 ? "..." : "") + "'");
        }
        
        // 写入24字节头（小端字节序）
        ByteBuffer header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(command);
        header.putInt(arg0);
        header.putInt(0);  // arg1
        header.putInt(dataLength);
        header.putInt(dataCrc32);
        header.putInt(magic);
        
        out.write(header.array());
        
        // 写入payload
        if (payload != null && payload.length > 0) {
            out.write(payload);
        }
        
        out.flush();
    }
    
    /**
     * 读取ADB消息
     */
    private static AdbMessage readAdbMessage(DataInputStream in, String tag) throws IOException {
        try {
            AdbMessage msg = new AdbMessage();
            
            byte[] header = new byte[24];
            int bytesRead = in.read(header);
            if (bytesRead != 24) {
                if (bytesRead < 0) {
                    logW(tag, "读取消息头: EOF (连接可能已关闭)");
                } else {
                    logW(tag, "读取消息头: 不完整 | 期望=24 | 实际=" + bytesRead);
                }
                return null;
            }
            
            ByteBuffer buf = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
            msg.command = buf.getInt();
            msg.arg0 = buf.getInt();
            msg.arg1 = buf.getInt();
            msg.dataLength = buf.getInt();
            msg.dataCrc32 = buf.getInt();
            msg.magic = buf.getInt();
            
            // 验证magic
            int expectedMagic = msg.command ^ 0xFFFFFFFF;
            if (msg.magic != expectedMagic) {
                logE(tag, "Magic验证失败! | cmd=0x" + Integer.toHexString(msg.command).toUpperCase() +
                          " | 期望magic=0x" + Integer.toHexString(expectedMagic).toUpperCase() +
                          " | 实际magic=0x" + Integer.toHexString(msg.magic).toUpperCase());
                throw new IOException("ADB消息magic验证失败");
            }
            
            // 读取payload
            if (msg.dataLength > 0 && msg.dataLength <= MAX_PAYLOAD) {
                msg.payload = new byte[msg.dataLength];
                bytesRead = in.read(msg.payload);
                if (bytesRead != msg.dataLength) {
                    logW(tag, "Payload不完整 | 期望=" + msg.dataLength + " | 实际=" + bytesRead);
                    msg.payload = Arrays.copyOf(msg.payload, Math.max(0, bytesRead));
                }
            } else if (msg.dataLength > MAX_PAYLOAD) {
                logW(tag, "Payload过大 | dataLen=" + msg.dataLength + " | 限制=" + MAX_PAYLOAD);
            }
            
            // 记录消息摘要
            String payloadPreview = "";
            if (msg.payload != null && msg.payload.length > 0) {
                if (msg.payload.length <= 100) {
                    payloadPreview = new String(msg.payload, StandardCharsets.UTF_8).replace("\n", "\\n");
                } else {
                    payloadPreview = new String(msg.payload, 0, 100, StandardCharsets.UTF_8).replace("\n", "\\n") + "...";
                }
            }
            
            logD(tag, "收到消息 | cmd=0x" + Integer.toHexString(msg.command).toUpperCase() +
                       " | arg0=" + msg.arg0 + " | arg1=" + msg.arg1 +
                       " | dataLen=" + msg.dataLength + " | data='" + payloadPreview + "'");
            
            return msg;
            
        } catch (EOFException e) {
            logW(tag, "读取消息: 意外EOF");
            return null;
        } catch (SocketTimeoutException e) {
            logW(tag, "读取消息: 超时");
            throw e;
        }
    }
    
    /**
     * CRC32计算
     */
    private static int calculateCrc32(byte[] data) {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(data);
        return (int) crc.getValue();
    }

    // ==================== RSA密钥管理 ====================
    
    /**
     * 生成ADB RSA密钥对（2048位）
     */
    public static KeyPair generateAdbKey() {
        String tag = "RSA";
        try {
            logD(tag, "生成RSA 2048位密钥对...");
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            logI(tag, "RSA密钥对生成成功 | 算法=" + keyPair.getPublic().getAlgorithm());
            return keyPair;
        } catch (Exception e) {
            logE(tag, "生成密钥失败", e);
            throw new RuntimeException("生成密钥失败", e);
        }
    }
    
    /**
     * 编码公钥为ADB格式
     */
    private static byte[] encodePublicKey(PublicKey publicKey) {
        String tag = "RSA";
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey.getEncoded());
            String base64Key = Base64.getEncoder().withoutPadding()
                                     .encodeToString(spec.getEncoded());
            
            String loginName = "adbclient@android";
            String keyString = base64Key + "\0" + loginName + "\0";
            byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
            
            logD(tag, "公钥编码完成 | Base64长度=" + base64Key.length() + 
                       " | 总字节=" + keyBytes.length);
            
            ByteBuffer buf = ByteBuffer.allocate(keyBytes.length)
                                       .order(ByteOrder.LITTLE_ENDIAN);
            buf.put(keyBytes);
            
            return buf.array();
        } catch (Exception e) {
            logE(tag, "编码公钥失败", e);
            throw new RuntimeException("编码公钥失败", e);
        }
    }
    
    /**
     * 对认证令牌签名
     */
    private static byte[] signToken(byte[] token, KeyPair keyPair) {
        String tag = "RSA";
        try {
            logD(tag, "对令牌签名... | token长度=" + token.length);
            java.security.Signature signature = java.security.Signature.getInstance("SHA1withRSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(token);
            byte[] sig = signature.sign();
            logD(tag, "签名完成 | 签名长度=" + sig.length + " bytes");
            return sig;
        } catch (Exception e) {
            logE(tag, "签名失败", e);
            throw new RuntimeException("签名失败", e);
        }
    }

    // ==================== 便捷方法 ====================
    
    /**
     * 执行命令并直接返回字符串结果
     */
    public static String quickShell(String host, int port, String command) {
        ShellResult result = executeShellOneShot(host, port, command);
        if (result.isSuccess()) {
            return result.stdout;
        } else {
            return "ERROR[" + result.exitCode + "]: " + result.stderr;
        }
    }
    
    /**
     * 获取设备信息
     */
    public static String getDeviceInfo(String host, int port) {
        String tag = "DeviceInfo[" + host + ":" + port + "]";
        logI(tag, "获取设备信息...");
        
        StringBuilder info = new StringBuilder();
        
        ShellResult prop = executeShellOneShot(host, port, "getprop ro.build.version.sdk");
        info.append("SDK: ").append(prop.stdout.trim()).append("\n");
        
        ShellResult model = executeShellOneShot(host, port, "getprop ro.product.model");
        info.append("Model: ").append(model.stdout.trim()).append("\n");
        
        ShellResult brand = executeShellOneShot(host, port, "getprop ro.product.brand");
        info.append("Brand: ").append(brand.stdout.trim()).append("\n");
        
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
    
    // ==================== ADB SYNC 协议常量 ====================
    // SYNC 子协议命令（小端字节序）
    private static final int A_S_OKAY = 0x59414b4f;  // "OKAY"
    private static final int A_S_FAIL = 0x4c49414f;   // "FAIL"
    private static final int A_S_DONE = 0x454e4f44;   // "DONE"
    private static final int A_S_DATA = 0x41544144;   // "DATA"
    private static final int A_S_QUIT = 0x54495151;   // "QUIT"
    private static final int A_S_SEND = 0x444e4553;   // "SEND"
    
    // SYNC 协议消息头大小: id(4) + command(4) + arg0(4) + arg1(4) + data_length(4) + data_crc32(4) = 24 bytes
    private static final int SYNC_HEADER_SIZE = 24;
    
    // 文件传输分块大小（原始数据）- 控制在 MAX_PAYLOAD(256KB) 以内，无线ADB建议更小
    private static final int FILE_CHUNK_SIZE = 32 * 1024;  // 32KB 每块
    // 流式Shell推送块大小（无每块握手开销，可使用更大块）
    private static final int STREAM_SHELL_CHUNK_SIZE = 64 * 1024;  // 64KB 每块
    
    /**
     * 推送文件（优化版 - 自适应分块传输）
     * 小文件直接推送，大文件自动切换分块模式，避免单条命令过大导致超时
     * 
     * @param host 目标主机IP
     * @param port ADB端口
     * @param data 文件数据
     * @param remotePath 远程路径
     * @return 执行结果
     */
    /**
     * 推送文件到设备（自动选择最优策略）
     * 策略优先级: 流式Shell(最快) > 分块Shell(最可靠) > 直接Shell(小文件更快) > SYNC(备选)
     * 
     * @param host 目标主机IP
     * @param port ADB端口
     * @param data 文件数据
     * @param remotePath 远程路径
     * @return 执行结果
     */
    public static ShellResult pushFile(String host, int port, byte[] data, String remotePath) {
        String tag = "Push[" + host + ":" + port + "]";
        logI(tag, "推送文件 | 大小=" + data.length + " bytes | 目标=" + remotePath);
        
        // 建立单次连接，所有传输策略复用此连接
        AdbConnection connection = null;
        try {
            AdbConnectionResult connResult = connect(host, port);
            if (!connResult.success || connResult.connection == null) {
                logE(tag, "连接失败，无法推送文件 | " + connResult.message);
                return new ShellResult(-1, "", "连接失败: " + connResult.message);
            }
            connection = connResult.connection;
            logD(tag, "连接已建立，开始推送...");
            
            // 注意：SYNC协议在无线ADB上不稳定，部分设备不支持SYNC over wireless
            // 优先使用Shell方式推送，更可靠
            
            // 策略1: 单连接流式Shell推送（性能最优 - 只打开1次Shell通道）
            logD(tag, "策略1: 使用单连接流式Shell模式推送(" + data.length + " bytes)...");
            ShellResult streamResult = pushFileStreamShell(connection, data, remotePath);
            if (streamResult.isSuccess()) {
                if (verifyFileSize(connection, remotePath, data.length)) {
                    logI(tag, "流式Shell推送完成 | 大小=" + data.length + " bytes 验证通过");
                    return streamResult;
                }
                logW(tag, "流式Shell推送成功但大小验证失败");
                return new ShellResult(-1, "", "文件大小验证失败");
            }
            
            // 策略2: 分块Shell推送（复用同一个连接，最可靠）
            logD(tag, "策略2: 使用分块Shell模式推送(" + data.length + " bytes)...");
            ShellResult chunkResult = pushFileChunked(connection, data, remotePath);
            if (chunkResult.isSuccess()) {
                if (verifyFileSize(connection, remotePath, data.length)) {
                    logI(tag, "分块推送完成 | 大小=" + data.length + " bytes 验证通过");
                    return chunkResult;
                }
                logW(tag, "分块推送成功但大小验证失败");
                return new ShellResult(-1, "", "文件大小验证失败");
            }
            
            // 策略3: 小文件直接推送（更快）
            if (data.length <= 200 * 1024) {
                logD(tag, "策略3: 尝试直接Shell推送(小文件)...");
                ShellResult directResult = pushFileDirect(connection, data, remotePath);
                if (directResult.isSuccess()) {
                    if (verifyFileSize(connection, remotePath, data.length)) {
                        logI(tag, "直接推送完成 | 大小=" + data.length + " bytes 验证通过");
                        return directResult;
                    }
                    logW(tag, "直接推送成功但大小验证失败");
                }
            }
            
            // 策略4: 作为最后备选，尝试SYNC协议（部分设备可能支持）
            logD(tag, "策略4: 备选尝试SYNC原生协议推送...");
            ShellResult syncResult = pushFileSync(connection, data, remotePath);
            if (syncResult.isSuccess()) {
                logI(tag, "SYNC推送成功(备选) | 大小=" + data.length + " bytes");
                return syncResult;
            }
            
            logE(tag, "所有推送策略均失败");
            return new ShellResult(-1, "", "所有推送策略均失败");
            
        } catch (Exception e) {
            logE(tag, "推送异常", e);
            return new ShellResult(-1, "", "推送异常: " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.close();
            }
        }
    }
    
    /**
     * 推送文件到设备（使用已建立的ADB连接）
     * 适用于MainActivity已持有adbConnection实例的场景，避免重复建连
     * 
     * @param connection 已建立的ADB连接
     * @param data 文件数据
     * @param remotePath 远程路径
     * @return 执行结果
     */
    public static ShellResult pushFile(AdbConnection connection, byte[] data, String remotePath) {
        String tag = "Push[" + connection.serial + "]";
        logI(tag, "推送文件(复用连接) | 大小=" + data.length + " bytes | 目标=" + remotePath);
        
        try {
            // 注意：SYNC协议在无线ADB上不稳定，部分设备不支持SYNC over wireless
            // 优先使用Shell方式推送，更可靠
            
            // 策略1: 单连接流式Shell推送（性能最优 - 只打开1次Shell通道）
            logD(tag, "策略1: 使用单连接流式Shell模式推送(" + data.length + " bytes)...");
            ShellResult streamResult = pushFileStreamShell(connection, data, remotePath);
            if (streamResult.isSuccess()) {
                if (verifyFileSize(connection, remotePath, data.length)) {
                    logI(tag, "流式Shell推送完成 | 大小=" + data.length + " bytes 验证通过");
                    return streamResult;
                }
                logW(tag, "流式Shell推送成功但大小验证失败");
                return new ShellResult(-1, "", "文件大小验证失败");
            }
            
            // 策略2: 分块Shell推送（复用同一个连接，最可靠）
            logD(tag, "策略2: 使用分块Shell模式推送(" + data.length + " bytes)...");
            ShellResult chunkResult = pushFileChunked(connection, data, remotePath);
            if (chunkResult.isSuccess()) {
                if (verifyFileSize(connection, remotePath, data.length)) {
                    logI(tag, "分块推送完成 | 大小=" + data.length + " bytes 验证通过");
                    return chunkResult;
                }
                logW(tag, "分块推送成功但大小验证失败");
                return new ShellResult(-1, "", "文件大小验证失败");
            }
            
            // 策略3: 小文件直接推送（更快）
            if (data.length <= 200 * 1024) {
                logD(tag, "策略3: 尝试直接Shell推送(小文件)...");
                ShellResult directResult = pushFileDirect(connection, data, remotePath);
                if (directResult.isSuccess()) {
                    if (verifyFileSize(connection, remotePath, data.length)) {
                        logI(tag, "直接推送完成 | 大小=" + data.length + " bytes 验证通过");
                        return directResult;
                    }
                    logW(tag, "直接推送成功但大小验证失败");
                }
            }
            
            // 策略4: 作为最后备选，尝试SYNC协议（部分设备可能支持）
            logD(tag, "策略4: 备选尝试SYNC原生协议推送...");
            ShellResult syncResult = pushFileSync(connection, data, remotePath);
            if (syncResult.isSuccess()) {
                logI(tag, "SYNC推送成功(备选) | 大小=" + data.length + " bytes");
                return syncResult;
            }
            
            logE(tag, "所有推送策略均失败");
            return new ShellResult(-1, "", "所有推送策略均失败");
            
        } catch (Exception e) {
            logE(tag, "推送异常", e);
            return new ShellResult(-1, "", "推送异常: " + e.getMessage());
        }
    }
    
    /**
     * 直接推送（小文件专用 - 单次shell命令完成，复用已有连接）
     */
    private static ShellResult pushFileDirect(AdbConnection connection, byte[] data, String remotePath) {
        String tag = "PushDirect[" + connection.serial + "]";
        String base64Data = Base64.getEncoder().encodeToString(data);
        logD(tag, "Base64编码后大小=" + base64Data.length() + " chars");
        
        String cmd = "printf '%s' '" + base64Data + 
                     "' | base64 -d > " + escapeShellArg(remotePath);
        
        ShellResult result = executeShell(connection, cmd);
        logD(tag, "直接推送执行完成 | exitCode=" + result.exitCode);
        return result;
    }
    
    /**
     * 分块推送（大文件专用 - 逐块base64编码后写入，复用已有连接）
     * 关键优化：所有分块复用同一个AdbConnection，避免每次分块都重新握手
     * 
     * @param connection 已建立的ADB连接
     * @param data 文件数据
     * @param remotePath 远程路径
     * @return 执行结果
     */
    private static ShellResult pushFileChunked(AdbConnection connection, byte[] data, String remotePath) {
        String tag = "PushChunked[" + connection.serial + "]";
        final int CHUNK_SIZE = FILE_CHUNK_SIZE;
        
        // 先删除可能存在的旧文件
        ShellResult rmResult = executeShell(connection, 
                "rm -f " + escapeShellArg(remotePath));
        
        int totalChunks = (data.length + CHUNK_SIZE - 1) / CHUNK_SIZE;
        int offset = 0;
        int bytesWritten = 0;
        int failedChunks = 0;
        final int MAX_FAILED_CHUNKS = 5;
        
        logD(tag, "分块推送开始 | 总块数=" + totalChunks + " | 块大小=" + CHUNK_SIZE);
        
        for (int chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
            int chunkEnd = Math.min(offset + CHUNK_SIZE, data.length);
            byte[] chunk = java.util.Arrays.copyOfRange(data, offset, chunkEnd);
            
            // Base64编码当前块
            String base64Chunk = Base64.getEncoder().encodeToString(chunk);
            
            // 构建shell命令（使用>>追加模式写入）
            String cmd = "printf \'%s\' \'" + base64Chunk + 
                         "\' | base64 -d >> " + escapeShellArg(remotePath);
            
            // ★ 关键优化：使用executeShell(connection)复用已有连接，不再新建TCP连接
            ShellResult result = executeShell(connection, cmd);
            
            if (!result.isSuccess()) {
                failedChunks++;
                logE(tag, "块#" + chunkIndex + "写入失败 | offset=" + offset + 
                     " | 连续失败=" + failedChunks + " | " + result.stderr);
                
                if (failedChunks >= MAX_FAILED_CHUNKS) {
                    logE(tag, "连续失败过多(" + MAX_FAILED_CHUNKS + "次)，清理文件并退出");
                    executeShell(connection, "rm -f " + escapeShellArg(remotePath));
                    return new ShellResult(-1, "", "分块写入连续失败");
                }
                
                // 失败后等待重试
                try {
                    logD(tag, "等待2000ms后重试块#" + chunkIndex + "...");
                    Thread.sleep(2000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    executeShell(connection, "rm -f " + escapeShellArg(remotePath));
                    return new ShellResult(-1, "", "写入被中断");
                }
                
                // 不推进offset，重试当前块
                chunkIndex--;
                continue;
            }
            
            // 写入成功，重置失败计数
            failedChunks = 0;
            bytesWritten += chunk.length;
            offset = chunkEnd;
            
            // 打印进度
            if ((chunkIndex + 1) % 10 == 0 || chunkIndex == totalChunks - 1) {
                int percent = (int) ((double) bytesWritten / data.length * 100);
                logD(tag, "进度: " + (chunkIndex + 1) + "/" + totalChunks + "块 (" + 
                     percent + "%) | 已写=" + bytesWritten + "/" + data.length + " bytes");
            }
        }
        
        // 验证文件大小
        if (verifyFileSize(connection, remotePath, data.length)) {
            logI(tag, "分块推送完成 | 大小=" + data.length + " bytes 验证通过");
            return new ShellResult(0, "", "");
        } else {
            logE(tag, "文件大小验证失败 | 期望=" + data.length + " bytes");
            executeShell(connection, "rm -f " + escapeShellArg(remotePath));
            return new ShellResult(-1, "", "文件大小验证失败");
        }
    }
    

    /**
     * 【方案二】单连接流式Shell推送（性能最优 - 只打开1次Shell通道，持续写入）
     * 核心思想：打开一个Shell通道执行 base64 -d >> path，然后在同一个通道内持续发送Base64编码数据块
     * 性能提升：将N次Shell建连减少为1次，大幅降低ADB握手和进程创建开销
     * 
     * @param connection 已建立的ADB连接
     * @param data 文件数据
     * @param remotePath 远程路径
     * @return 执行结果
     */
    private static ShellResult pushFileStreamShell(AdbConnection connection, byte[] data, String remotePath)  throws IOException {
        String tag = "PushStreamShell[" + connection.serial + "]";
        logI(tag, "流式Shell推送开始 | 大小=" + data.length + " bytes | 目标=" + remotePath);
        
        DataOutputStream out = connection.output;
        DataInputStream in = connection.input;
        
        // 1. 打开Shell通道，执行 base64 -d >> remotePath
        int localId = connection.nextLocalId();
        String shellCmd = "base64 -d >> \"" + remotePath + "\"";
        
        logD(tag, "步骤1: 打开Shell通道执行: " + shellCmd);
        sendShellMessage(out, A_OPEN, localId, 0x00000000,
                ("shell:" + shellCmd + "\0").getBytes(StandardCharsets.UTF_8), tag);
        
        // 等待OKAY响应
        AdbMessage response = readAdbMessageRaw(in, tag);
        if (response == null || response.command != A_OKAY) {
            logE(tag, "Shell通道打开失败 | command=0x" + 
                 Integer.toHexString(response != null ? response.command : 0).toUpperCase());
            return new ShellResult(-1, "", "Shell通道打开失败");
        }
        
        int remoteId = response.arg0;
        logD(tag, "Shell通道已打开 | localId=" + localId + " | remoteId=" + remoteId);
        
        // 2. 流式发送Base64编码数据块
        int chunkSize = STREAM_SHELL_CHUNK_SIZE;
        int offset = 0;
        int bytesWritten = 0;
        long startTime = System.currentTimeMillis();
        
        logD(tag, "步骤2: 开始流式写入 | 块大小=" + chunkSize + " bytes");
        
        try {
            while (offset < data.length) {
                int chunkEnd = Math.min(offset + chunkSize, data.length);
                byte[] chunk = java.util.Arrays.copyOfRange(data, offset, chunkEnd);
                
                // Base64编码当前块
                String base64Chunk = Base64.getEncoder().encodeToString(chunk);
                byte[] base64Bytes = base64Chunk.getBytes(StandardCharsets.UTF_8);
                
                // 通过WRTE命令发送数据（设备端base64进程从stdin读取并解码写入文件）
                sendShellMessage(out, A_WRTE, localId, remoteId, base64Bytes, tag);
                
                // 读取设备响应（OKAY流控确认 或 WRTE stdout数据）
                boolean gotOkay = false;
                while (!gotOkay) {
                    response = readAdbMessageRaw(in, tag);
                    if (response == null) {
                        logE(tag, "流式写入中断: 无响应");
                        sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
                        return new ShellResult(-1, "", "流式写入中断");
                    }
                    
                    switch (response.command) {
                        case A_OKAY:
                            gotOkay = true;
                            break;
                        case A_WRTE:
                            String stdoutData = new String(response.payload, StandardCharsets.UTF_8);
                            if (!stdoutData.isEmpty()) {
                                logD(tag, "Shell stdout: " + stdoutData.trim().substring(0, Math.min(100, stdoutData.length())));
                            }
                            sendShellMessage(out, A_OKAY, localId, remoteId, null, tag);
                            break;
                        case A_CLSE:
                            logW(tag, "设备关闭Shell通道 | 已写=" + bytesWritten + " bytes");
                            if (bytesWritten >= data.length) {
                                logI(tag, "数据已全部发送，设备关闭通道视为成功");
                                return new ShellResult(0, "", "");
                            }
                            return new ShellResult(-1, "", "设备关闭Shell通道");
                        default:
                            logW(tag, "未知响应: 0x" + Integer.toHexString(response.command).toUpperCase());
                            break;
                    }
                }
                
                bytesWritten += chunk.length;
                offset = chunkEnd;
                
                // 打印进度
                if (offset % (32 * 1024) == 0 || offset == data.length) {
                    long elapsed = System.currentTimeMillis() - startTime;
                    int percent = (int) ((double) bytesWritten / data.length * 100);
                    double speed = bytesWritten / (double) (elapsed > 0 ? elapsed : 1) * 1000;
                    logD(tag, "流式进度: " + percent + "% | 已写=" + bytesWritten + "/" + data.length + 
                         " bytes | " + (int)speed + "KB/s | 耗时=" + elapsed + "ms");
                }
            }
        } catch (Exception e) {
            logE(tag, "流式写入异常", e);
            sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
            return new ShellResult(-1, "", "流式写入异常: " + e.getMessage());
        }
        
        // 3. 关闭Shell通道
        logD(tag, "步骤3: 关闭Shell通道...");
        sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
        
        // 4. 验证文件大小
        if (verifyFileSize(connection, remotePath, data.length)) {
            long elapsed = System.currentTimeMillis() - startTime;
            logI(tag, "流式Shell推送完成 | 大小=" + data.length + " bytes | 耗时=" + elapsed + "ms");
            return new ShellResult(0, "", "");
        } else {
            logE(tag, "文件大小验证失败 | 期望=" + data.length + " bytes");
            executeShell(connection, "rm -f " + escapeShellArg(remotePath));
            return new ShellResult(-1, "", "文件大小验证失败");
        }
    }
    
    /**
     * 【方案二】单连接流式Shell推送（从文件路径读取，避免大文件一次性加载到内存）
     * 核心思想：打开一个Shell通道执行 base64 -d >> path，然后通过同一个通道持续发送Base64编码数据块
     * 
     * @param connection 已建立的ADB连接
     * @param sourceFilePath 源文件路径
     * @param remotePath 远程路径
     * @return 执行结果
     */
    private static ShellResult pushFileStreamShellFromFile(AdbConnection connection, String sourceFilePath, String remotePath)  throws IOException {
        String tag = "PushStreamShellFile[" + connection.serial + "]";
        File sourceFile = new File(sourceFilePath);
        long fileSize = sourceFile.length();
        
        logI(tag, "流式Shell推送(从文件)开始 | 大小=" + fileSize + " bytes | 源=" + sourceFilePath + " | 目标=" + remotePath);
        
        DataOutputStream out = connection.output;
        DataInputStream in = connection.input;
        
        // 1. 打开Shell通道，执行 base64 -d >> remotePath
        int localId = connection.nextLocalId();
        String shellCmd = "base64 -d >> " + escapeShellArg(remotePath);
        
        logD(tag, "步骤1: 打开Shell通道执行: " + shellCmd);
        sendShellMessage(out, A_OPEN, localId, 0x00000000,
                ("shell:" + shellCmd + "\0").getBytes(StandardCharsets.UTF_8), tag);
        
        // 等待OKAY响应
        AdbMessage response = readAdbMessageRaw(in, tag);
        if (response == null || response.command != A_OKAY) {
            logE(tag, "Shell通道打开失败 | command=0x" + 
                 Integer.toHexString(response != null ? response.command : 0).toUpperCase());
            return new ShellResult(-1, "", "Shell通道打开失败");
        }
        
        int remoteId = response.arg0;
        logD(tag, "Shell通道已打开 | localId=" + localId + " | remoteId=" + remoteId);
        
        // 2. 流式读取文件并发送
        int chunkSize = STREAM_SHELL_CHUNK_SIZE;
        long bytesWritten = 0;
        long startTime = System.currentTimeMillis();
        FileInputStream fis = null;
        
        logD(tag, "步骤2: 开始流式读取并写入 | 块大小=" + chunkSize + " bytes");
        
        try {
            fis = new FileInputStream(sourceFile);
            byte[] readBuffer = new byte[chunkSize];
            int bytesRead;
            
            while ((bytesRead = fis.read(readBuffer)) != -1) {
                byte[] chunk = java.util.Arrays.copyOf(readBuffer, bytesRead);
                
                // Base64编码当前块
                String base64Chunk = Base64.getEncoder().encodeToString(chunk);
                byte[] base64Bytes = base64Chunk.getBytes(StandardCharsets.UTF_8);
                
                // 通过WRTE命令发送数据
                sendShellMessage(out, A_WRTE, localId, remoteId, base64Bytes, tag);
                
                // 读取设备响应（OKAY流控确认 或 WRTE stdout数据）
                boolean gotOkay = false;
                while (!gotOkay) {
                    response = readAdbMessageRaw(in, tag);
                    if (response == null) {
                        logE(tag, "流式写入中断: 无响应");
                        sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
                        return new ShellResult(-1, "", "流式写入中断");
                    }
                    
                    switch (response.command) {
                        case A_OKAY:
                            gotOkay = true;
                            break;
                        case A_WRTE:
                            String stdoutData = new String(response.payload, StandardCharsets.UTF_8);
                            if (!stdoutData.isEmpty()) {
                                logD(tag, "Shell stdout: " + stdoutData.trim().substring(0, Math.min(100, stdoutData.length())));
                            }
                            sendShellMessage(out, A_OKAY, localId, remoteId, null, tag);
                            break;
                        case A_CLSE:
                            logW(tag, "设备关闭Shell通道 | 已写=" + bytesWritten + " bytes");
                            if (bytesWritten >= fileSize) {
                                logI(tag, "数据已全部发送，设备关闭通道视为成功");
                                return new ShellResult(0, "", "");
                            }
                            return new ShellResult(-1, "", "设备关闭Shell通道");
                        default:
                            logW(tag, "未知响应: 0x" + Integer.toHexString(response.command).toUpperCase());
                            break;
                    }
                }
                
                bytesWritten += bytesRead;
                
                // 打印进度
                if (bytesWritten % (32 * 1024) == 0 || bytesWritten == fileSize) {
                    long elapsed = System.currentTimeMillis() - startTime;
                    int percent = (int) (bytesWritten * 100 / fileSize);
                    double speed = bytesWritten / (double) (elapsed > 0 ? elapsed : 1) * 1000;
                    logD(tag, "流式进度: " + percent + "% | 已写=" + bytesWritten + "/" + fileSize + 
                         " bytes | " + (int)speed + "KB/s | 耗时=" + elapsed + "ms");
                }
            }
        } catch (Exception e) {
            logE(tag, "流式写入异常", e);
            sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
            return new ShellResult(-1, "", "流式写入异常: " + e.getMessage());
        } finally {
            if (fis != null) {
                try { fis.close(); } catch (Exception ignored) {}
            }
        }
        
        // 3. 关闭Shell通道
        logD(tag, "步骤3: 关闭Shell通道...");
        sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
        
        // 4. 验证文件大小
        if (verifyFileSize(connection, remotePath, (int) Math.min(fileSize, Integer.MAX_VALUE))) {
            long elapsed = System.currentTimeMillis() - startTime;
            logI(tag, "流式Shell推送完成(从文件) | 大小=" + fileSize + " bytes | 耗时=" + elapsed + "ms");
            return new ShellResult(0, "", "");
        } else {
            logE(tag, "文件大小验证失败 | 期望=" + fileSize + " bytes");
            executeShell(connection, "rm -f " + escapeShellArg(remotePath));
            return new ShellResult(-1, "", "文件大小验证失败");
        }
    }

    /**
     * 通过ADB SYNC协议推送文件（最高效 - 原生协议，无Base64膨胀）
     * 需要已建立的AdbConnection，避免每次分块都重新握手
     * 
     * @param connection 已建立的ADB连接
     * @param data 文件数据
     * @param remotePath 远程路径
     * @return 执行结果
     */
    public static ShellResult pushFileSync(AdbConnection connection, byte[] data, String remotePath) {
        String tag = "PushSync[" + connection.serial + "]";
        logI(tag, "SYNC推送文件 | 大小=" + data.length + " bytes | 目标=" + remotePath);
        
        try {
            DataOutputStream out = connection.output;
            DataInputStream in = connection.input;
            
            // 1. 打开SYNC通道
            int localId = connection.nextLocalId();
            String syncTarget = "sync\0";
            logD(tag, "步骤1: 打开SYNC通道...");
            
            sendShellMessage(out, A_OPEN, localId, 0x00000000,
                    syncTarget.getBytes(StandardCharsets.UTF_8), tag);
            
            // 等待通道打开响应
            AdbMessage response = readAdbMessageRaw(in, tag);
            if (response == null || response.command != A_OKAY) {
                logE(tag, "SYNC通道打开失败 | command=0x" + 
                     Integer.toHexString(response != null ? response.command : 0).toUpperCase());
                return new ShellResult(-1, "", "SYNC通道打开失败");
            }
            
            int remoteId = response.arg0;
            logD(tag, "SYNC通道已打开 | localId=" + localId + " | remoteId=" + remoteId);
            
            // 2. 发送SEND命令（文件名 + 模式）
            String fileName = remotePath.substring(remotePath.lastIndexOf('/') + 1);
            String sendCommand = "SEND\0" + remotePath + "\0" + "100644" + "\0";
            logD(tag, "步骤2: 发送SEND命令 | 文件=" + fileName);
            
            // 构建SYNC消息: id(4) + command(4) + arg0(4) + arg1(4) + data_length(4) + data_crc32(4) + payload
            byte[] sendPayload = sendCommand.getBytes(StandardCharsets.UTF_8);
            int sendCrc = calculateCrc32(sendPayload);
            byte[] sendMsg = buildSyncMessage(A_S_SEND, 0, 0, sendPayload.length, sendCrc, sendPayload);
            
            sendShellMessage(out, A_WRTE, localId, remoteId, sendMsg, tag);
            
            // 等待OKAY
            response = readAdbMessageRaw(in, tag);
            if (response == null || response.command != A_OKAY) {
                logE(tag, "SEND命令失败 | command=0x" + 
                     Integer.toHexString(response != null ? response.command : 0).toUpperCase());
                // 发送QUIT清理
                sendShellMessage(out, A_WRTE, localId, remoteId, 
                        buildSyncMessage(A_S_QUIT, 0, 0, 0, 0, null), tag);
                sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
                return new ShellResult(-1, "", "SEND命令失败");
            }
            logD(tag, "SEND命令已确认");
            
            // 3. 分块发送文件数据
            int chunkSize = Math.min(FILE_CHUNK_SIZE, MAX_PAYLOAD - 64); // 留头空间
            int totalChunks = (data.length + chunkSize - 1) / chunkSize;
            int offset = 0;
            int bytesWritten = 0;
            long startTime = System.currentTimeMillis();
            
            logD(tag, "步骤3: 发送文件数据 | 块大小=" + chunkSize + " | 总块数=" + totalChunks);
            
            for (int chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
                int chunkEnd = Math.min(offset + chunkSize, data.length);
                byte[] chunk = java.util.Arrays.copyOfRange(data, offset, chunkEnd);
                
                // 构建DATA消息
                int chunkCrc = calculateCrc32(chunk);
                byte[] dataMsg = buildSyncMessage(A_S_DATA, 0, 0, chunk.length, chunkCrc, chunk);
                
                sendShellMessage(out, A_WRTE, localId, remoteId, dataMsg, tag);
                
                // 等待OKAY确认
                response = readAdbMessageRaw(in, tag);
                if (response == null || response.command != A_OKAY) {
                    logE(tag, "DATA块#" + chunkIndex + "确认失败 | command=0x" + 
                         Integer.toHexString(response != null ? response.command : 0).toUpperCase());
                    // 发送QUIT清理
                    sendShellMessage(out, A_WRTE, localId, remoteId, 
                            buildSyncMessage(A_S_QUIT, 0, 0, 0, 0, null), tag);
                    sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
                    return new ShellResult(-1, "", "DATA传输失败: 块#" + chunkIndex);
                }
                
                bytesWritten += chunk.length;
                offset = chunkEnd;
                
                if ((chunkIndex + 1) % 10 == 0 || chunkIndex == totalChunks - 1) {
                    long elapsed = System.currentTimeMillis() - startTime;
                    int percent = (int) ((double) bytesWritten / data.length * 100);
                    double speed = bytesWritten / (double) (elapsed > 0 ? elapsed : 1) * 1000;
                    logD(tag, "SYNC进度: " + (chunkIndex + 1) + "/" + totalChunks + "块 (" + 
                         percent + "%) | 已写=" + bytesWritten + "/" + data.length + " bytes | " +
                         (int) speed + "KB/s | 耗时=" + elapsed + "ms");
                }
            }
            
            // 4. 发送DONE命令（含修改时间戳，8字节little-endian）
            logD(tag, "步骤4: 发送DONE命令...");
            byte[] timestamp = new byte[8];
            long mtime = System.currentTimeMillis() / 1000; // Unix timestamp
            for (int i = 0; i < 8; i++) {
                timestamp[i] = (byte) (mtime >>> (i * 8));
            }
            byte[] doneMsg = buildSyncMessage(A_S_DONE, 0, 0, 8, 0, timestamp);
            sendShellMessage(out, A_WRTE, localId, remoteId, doneMsg, tag);
            
            // 5. 等待最终响应（OKAY或FAIL）
            logD(tag, "步骤5: 等待设备处理完成...");
            response = readAdbMessageRaw(in, tag);
            if (response == null) {
                logE(tag, "SYNC推送超时: 无响应");
                sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
                return new ShellResult(-1, "", "SYNC推送超时");
            }
            
            if (response.command == A_OKAY) {
                logI(tag, "SYNC推送完成 | 大小=" + data.length + " bytes | 耗时=" + 
                     (System.currentTimeMillis() - startTime) + "ms");
                sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
                return new ShellResult(0, "", "");
            } else if (response.command == A_CLSE) {
                // 设备主动关闭 - 可能表示文件已写入但没发OKAY
                logW(tag, "设备主动关闭SYNC通道，检查文件大小...");
                sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
                if (verifyFileSize(connection, remotePath, data.length)) {
                    return new ShellResult(0, "", "");
                }
                return new ShellResult(-1, "", "设备关闭SYNC通道");
            } else {
                // 可能是FAIL消息
                String failMsg = "";
                if (response.payload != null && response.payload.length > 0) {
                    failMsg = new String(response.payload, StandardCharsets.UTF_8);
                }
                logE(tag, "SYNC推送失败 | command=0x" + 
                     Integer.toHexString(response.command).toUpperCase() + 
                     " | 消息=" + failMsg);
                sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
                return new ShellResult(-1, "", "SYNC推送失败: " + failMsg);
            }
            
        } catch (SocketTimeoutException e) {
            logE(tag, "SYNC推送超时", e);
            return new ShellResult(-1, "", "SYNC超时: " + e.getMessage());
        } catch (Exception e) {
            logE(tag, "SYNC推送异常", e);
            return new ShellResult(-1, "", "SYNC异常: " + e.getMessage());
        }
    }
    
    /**
     * 构建SYNC协议消息
     * 格式: id(4bytes="SYNC") + command(4) + arg0(4) + arg1(4) + data_length(4) + data_crc32(4) + payload
     */
    private static byte[] buildSyncMessage(int command, int arg0, int arg1, 
                                            int dataLength, int dataCrc32, byte[] payload) {
        int totalSize = SYNC_HEADER_SIZE + (payload != null ? payload.length : 0);
        ByteBuffer buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN);
        buf.put("SYNC".getBytes(StandardCharsets.US_ASCII));
        buf.putInt(command);
        buf.putInt(arg0);
        buf.putInt(arg1);
        buf.putInt(dataLength);
        buf.putInt(dataCrc32);
        if (payload != null && payload.length > 0) {
            buf.put(payload);
        }
        return buf.array();
    }
    
    /**
     * 验证远程文件大小
     */
    /**
     * 验证远程文件大小（使用已建立的ADB连接）
     */
    private static boolean verifyFileSize(AdbConnection connection, String remotePath, int expectedSize) {
        try {
            ShellResult result = executeShell(connection, 
                    "stat -c %s " + escapeShellArg(remotePath));
            if (result.isSuccess()) {
                try {
                    int actualSize = Integer.parseInt(result.stdout.trim());
                    boolean match = (actualSize == expectedSize);
                    if (!match) {
                        logW("Verify", "大小不匹配 | 期望=" + expectedSize + " 实际=" + actualSize);
                    }
                    return match;
                } catch (NumberFormatException ignored) {
                }
            }
            // 降级: 用ls解析
            ShellResult lsResult = executeShell(connection, 
                    "ls -la " + escapeShellArg(remotePath));
            if (lsResult.isSuccess()) {
                String[] parts = lsResult.stdout.trim().split("\\s+");
                if (parts.length >= 5) {
                    try {
                        int actualSize = Integer.parseInt(parts[4]);
                        return (actualSize == expectedSize);
                    } catch (NumberFormatException ignored) {}
                }
            }
            logW("Verify", "无法验证文件大小(统计命令不可用)");
            return true;
        } catch (Exception e) {
            logW("Verify", "验证异常: " + e.getMessage());
            return true;
        }
    }
    
    /**
     * 从connection获取host:port（用于SYNC模式的降级验证）
     */
    
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
    

    // ==================== 新增：从文件路径推送（避免大文件一次性加载到内存） ====================
    
    /**
     * 推送文件到设备（从源文件路径读取，避免大文件一次性加载到内存）
     * 小文件走 host/port 快捷路径，大文件自动选择最优策略
     * 
     * @param host 目标主机IP
     * @param port ADB端口
     * @param sourceFilePath 源文件路径（设备或应用可访问的路径）
     * @param remotePath 远程路径
     * @return 执行结果
     */
    public static ShellResult pushFile(String host, int port, String sourceFilePath, String remotePath) {
        String tag = "Push[" + host + ":" + port + "]";
        logI(tag, "推送文件(从路径) | 源=" + sourceFilePath + " | 目标=" + remotePath);
        
        AdbConnection connection = null;
        try {
            AdbConnectionResult connResult = connect(host, port);
            if (!connResult.success || connResult.connection == null) {
                logE(tag, "连接失败 | " + connResult.message);
                return new ShellResult(-1, "", "连接失败: " + connResult.message);
            }
            connection = connResult.connection;
            return pushFile(connection, sourceFilePath, remotePath);
        } catch (Exception e) {
            logE(tag, "推送异常", e);
            return new ShellResult(-1, "", "推送异常: " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.close();
            }
        }
    }
    
    /**
     * 推送文件到设备（从源文件路径读取，复用已有连接）
     * 策略优先级: 流式Shell(最快) > 分块Shell(最可靠) > 直接Shell(小文件更快) > SYNC(备选)
     * 文件通过 FileInputStream 分块读取，不会将整个文件加载到内存中
     * 
     * @param connection 已建立的ADB连接
     * @param sourceFilePath 源文件路径（设备或应用可访问的路径）
     * @param remotePath 远程路径
     * @return 执行结果
     */
    public static ShellResult pushFile(AdbConnection connection, String sourceFilePath, String remotePath) {
        String tag = "Push[" + connection.serial + "]";
        
        // 先获取文件大小
        File sourceFile = new File(sourceFilePath);
        if (!sourceFile.exists()) {
            logE(tag, "源文件不存在: " + sourceFilePath);
            return new ShellResult(-1, "", "源文件不存在: " + sourceFilePath);
        }
        long fileSize = sourceFile.length();
        logI(tag, "推送文件(复用连接/从路径) | 大小=" + fileSize + " bytes | 源=" + sourceFilePath + " | 目标=" + remotePath);
        
        try {
            // 注意：SYNC协议在无线ADB上不稳定，部分设备不支持SYNC over wireless
            // 因此优先使用Shell方式推送，仅在文件较小且Shell失败时尝试SYNC作为备选
            
            // 策略1: 单连接流式Shell推送（性能最优 - 只打开1次Shell通道，从文件流读取）
            logD(tag, "策略1: 使用单连接流式Shell模式推送(从文件)...");
            ShellResult streamResult = pushFileStreamShellFromFile(connection, sourceFilePath, remotePath);
            if (streamResult.isSuccess()) {
                if (verifyFileSize(connection, remotePath, (int) Math.min(fileSize, Integer.MAX_VALUE))) {
                    logI(tag, "流式Shell推送完成(从文件) | 大小=" + fileSize + " bytes 验证通过");
                    return streamResult;
                }
                logW(tag, "流式Shell推送成功但大小验证失败");
                return new ShellResult(-1, "", "文件大小验证失败");
            }
            
            // 策略2: 分块Shell推送（从文件流读取，最可靠）
            logD(tag, "策略2: 使用分块Shell模式推送(从文件)...");
            ShellResult chunkResult = pushFileChunkedFromFile(connection, sourceFilePath, remotePath);
            if (chunkResult.isSuccess()) {
                if (verifyFileSize(connection, remotePath, (int) Math.min(fileSize, Integer.MAX_VALUE))) {
                    logI(tag, "分块推送完成 | 大小=" + fileSize + " bytes 验证通过");
                    return chunkResult;
                }
                logW(tag, "分块推送成功但大小验证失败");
                return new ShellResult(-1, "", "文件大小验证失败");
            }
            
            // 策略3: 直接Shell推送（小文件专用，更快）
            if (fileSize <= 200 * 1024) {
                logD(tag, "策略3: 尝试直接Shell推送(从文件/小文件)...");
                ShellResult directResult = pushFileDirectFromFile(connection, sourceFilePath, remotePath);
                if (directResult.isSuccess()) {
                    if (verifyFileSize(connection, remotePath, (int) Math.min(fileSize, Integer.MAX_VALUE))) {
                        logI(tag, "直接推送完成 | 大小=" + fileSize + " bytes 验证通过");
                        return directResult;
                    }
                    logW(tag, "直接推送成功但大小验证失败");
                }
            }
            
            // 策略4: 作为最后备选，尝试SYNC协议（部分设备可能支持）
            logD(tag, "策略4: 备选尝试SYNC原生协议推送(从文件)...");
            ShellResult syncResult = pushFileSyncFromFile(connection, sourceFilePath, remotePath);
            if (syncResult.isSuccess()) {
                logI(tag, "SYNC推送成功(备选) | 大小=" + fileSize + " bytes");
                return syncResult;
            }
            
            logE(tag, "所有推送策略均失败");
            return new ShellResult(-1, "", "所有推送策略均失败");
            
        } catch (Exception e) {
            logE(tag, "推送异常", e);
            return new ShellResult(-1, "", "推送异常: " + e.getMessage());
        }
    }
    
    /**
     * 通过ADB SYNC协议推送文件（从文件路径读取，流式传输）
     * 使用 FileInputStream 分块读取文件，避免大文件一次性加载到内存
     */
    private static ShellResult pushFileSyncFromFile(AdbConnection connection, String sourceFilePath, String remotePath) {
        String tag = "PushSyncFile[" + connection.serial + "]";
        FileInputStream fis = null;
        
        try {
            fis = new FileInputStream(new File(sourceFilePath));
            long fileSize = new File(sourceFilePath).length();
            
            DataOutputStream out = connection.output;
            DataInputStream in = connection.input;
            
            // 1. 打开SYNC通道
            int localId = connection.nextLocalId();
            String syncTarget = "sync\0";
            logD(tag, "步骤1: 打开SYNC通道...");
            
            sendShellMessage(out, A_OPEN, localId, 0x00000000,
                    syncTarget.getBytes(StandardCharsets.UTF_8), tag);
            
            AdbMessage response = readAdbMessageRaw(in, tag);
            if (response == null || response.command != A_OKAY) {
                logE(tag, "SYNC通道打开失败 | command=0x" + 
                     Integer.toHexString(response != null ? response.command : 0).toUpperCase());
                return new ShellResult(-1, "", "SYNC通道打开失败");
            }
            
            int remoteId = response.arg0;
            logD(tag, "SYNC通道已打开 | localId=" + localId + " | remoteId=" + remoteId);
            
            // 2. 发送SEND命令
            String fileName = remotePath.substring(remotePath.lastIndexOf('/') + 1);
            String sendCommand = "SEND\0" + remotePath + "\0" + "100644\0";
            logD(tag, "步骤2: 发送SEND命令 | 文件=" + fileName);
            
            byte[] sendPayload = sendCommand.getBytes(StandardCharsets.UTF_8);
            int sendCrc = calculateCrc32(sendPayload);
            byte[] sendMsg = buildSyncMessage(A_S_SEND, 0, 0, sendPayload.length, sendCrc, sendPayload);
            
            sendShellMessage(out, A_WRTE, localId, remoteId, sendMsg, tag);
            
            response = readAdbMessageRaw(in, tag);
            if (response == null || response.command != A_OKAY) {
                logE(tag, "SEND命令失败 | command=0x" + 
                     Integer.toHexString(response != null ? response.command : 0).toUpperCase());
                sendShellMessage(out, A_WRTE, localId, remoteId, 
                        buildSyncMessage(A_S_QUIT, 0, 0, 0, 0, null), tag);
                sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
                return new ShellResult(-1, "", "SEND命令失败");
            }
            logD(tag, "SEND命令已确认");
            
            // 3. 分块读取文件并发送数据
            int chunkSize = Math.min(FILE_CHUNK_SIZE, MAX_PAYLOAD - 64);
            long totalSent = 0;
            long startTime = System.currentTimeMillis();
            byte[] readBuffer = new byte[chunkSize];
            int bytesRead;
            
            logD(tag, "步骤3: 发送文件数据 | 块大小=" + chunkSize + " | 总大小=" + fileSize + " bytes");
            
            while ((bytesRead = fis.read(readBuffer)) != -1) {
                byte[] chunk = java.util.Arrays.copyOf(readBuffer, bytesRead);
                
                // 构建DATA消息
                int chunkCrc = calculateCrc32(chunk);
                byte[] dataMsg = buildSyncMessage(A_S_DATA, 0, 0, bytesRead, chunkCrc, chunk);
                
                sendShellMessage(out, A_WRTE, localId, remoteId, dataMsg, tag);
                
                // 等待OKAY确认
                response = readAdbMessageRaw(in, tag);
                if (response == null || response.command != A_OKAY) {
                    logE(tag, "DATA块确认失败 | command=0x" + 
                         Integer.toHexString(response != null ? response.command : 0).toUpperCase());
                    sendShellMessage(out, A_WRTE, localId, remoteId, 
                            buildSyncMessage(A_S_QUIT, 0, 0, 0, 0, null), tag);
                    sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
                    return new ShellResult(-1, "", "DATA传输失败");
                }
                
                totalSent += bytesRead;
                
                if (totalSent % (32 * 1024) == 0 || totalSent == fileSize) {
                    long elapsed = System.currentTimeMillis() - startTime;
                    int percent = (int) (totalSent * 100 / fileSize);
                    double speed = totalSent / (double) (elapsed > 0 ? elapsed : 1) * 1000;
                    logD(tag, "SYNC进度: " + percent + "% | 已送=" + totalSent + "/" + fileSize + " bytes | " +
                         (int) speed + "KB/s | 耗时=" + elapsed + "ms");
                }
            }
            
            // 4. 发送DONE命令
            logD(tag, "步骤4: 发送DONE命令...");
            byte[] timestamp = new byte[8];
            long mtime = System.currentTimeMillis() / 1000;
            for (int i = 0; i < 8; i++) {
                timestamp[i] = (byte) (mtime >>> (i * 8));
            }
            byte[] doneMsg = buildSyncMessage(A_S_DONE, 0, 0, 8, 0, timestamp);
            sendShellMessage(out, A_WRTE, localId, remoteId, doneMsg, tag);
            
            // 5. 等待最终响应
            logD(tag, "步骤5: 等待设备处理完成...");
            response = readAdbMessageRaw(in, tag);
            if (response == null) {
                logE(tag, "SYNC推送超时: 无响应");
                sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
                return new ShellResult(-1, "", "SYNC推送超时");
            }
            
            if (response.command == A_OKAY) {
                logI(tag, "SYNC推送完成 | 大小=" + fileSize + " bytes | 耗时=" + 
                     (System.currentTimeMillis() - startTime) + "ms");
                sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
                return new ShellResult(0, "", "");
            } else if (response.command == A_CLSE) {
                logW(tag, "设备主动关闭SYNC通道，检查文件大小...");
                sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
                if (verifyFileSize(connection, remotePath, (int) Math.min(fileSize, Integer.MAX_VALUE))) {
                    return new ShellResult(0, "", "");
                }
                return new ShellResult(-1, "", "设备关闭SYNC通道");
            } else {
                String failMsg = "";
                if (response.payload != null && response.payload.length > 0) {
                    failMsg = new String(response.payload, StandardCharsets.UTF_8);
                }
                logE(tag, "SYNC推送失败 | command=0x" + 
                     Integer.toHexString(response.command).toUpperCase() + 
                     " | 消息=" + failMsg);
                sendShellMessage(out, A_CLSE, localId, remoteId, null, tag);
                return new ShellResult(-1, "", "SYNC推送失败: " + failMsg);
            }
            
        } catch (SocketTimeoutException e) {
            logE(tag, "SYNC推送超时", e);
            return new ShellResult(-1, "", "SYNC超时: " + e.getMessage());
        } catch (Exception e) {
            logE(tag, "SYNC推送异常", e);
            return new ShellResult(-1, "", "SYNC异常: " + e.getMessage());
        } finally {
            if (fis != null) {
                try { fis.close(); } catch (Exception ignored) {}
            }
        }
    }
    
    /**
     * 分块推送（从文件路径读取，逐块base64编码后写入）
     * 使用 FileInputStream 分块读取文件，避免大文件一次性加载到内存
     * 所有分块复用同一个AdbConnection
     */
    private static ShellResult pushFileChunkedFromFile(AdbConnection connection, String sourceFilePath, String remotePath) {
        String tag = "PushChunkedFile[" + connection.serial + "]";
        final int CHUNK_SIZE = FILE_CHUNK_SIZE;
        
        // 先删除可能存在的旧文件
        ShellResult rmResult = executeShell(connection, 
                "rm -f " + escapeShellArg(remotePath));
        
        long fileSize = new File(sourceFilePath).length();
        int totalChunks = (int) ((fileSize + CHUNK_SIZE - 1) / CHUNK_SIZE);
        int bytesWritten = 0;
        int failedChunks = 0;
        final int MAX_FAILED_CHUNKS = 5;
        
        logD(tag, "分块推送开始 | 总块数=" + totalChunks + " | 块大小=" + CHUNK_SIZE + " | 总大小=" + fileSize);
        
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(new File(sourceFilePath));
            byte[] readBuffer = new byte[CHUNK_SIZE];
            int bytesRead;
            
            for (int chunkIndex = 0; (bytesRead = fis.read(readBuffer)) != -1; chunkIndex++) {
                byte[] chunk = java.util.Arrays.copyOf(readBuffer, bytesRead);
                
                // Base64编码当前块
                String base64Chunk = Base64.getEncoder().encodeToString(chunk);
                
                // 构建shell命令（使用>>追加模式写入）
                String cmd = "printf \'%s\' \'" + base64Chunk + 
                             "\' | base64 -d >> " + escapeShellArg(remotePath);
                
                // 检查连接状态，如果连接已关闭则重试
                if (connection.isClosed()) {
                    logW(tag, "连接已关闭，等待5000ms后重试...");
                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        executeShell(connection, "rm -f " + escapeShellArg(remotePath));
                        return new ShellResult(-1, "", "写入被中断");
                    }
                    // 不推进，重试当前块
                    chunkIndex--;
                    continue;
                }
                
                // 使用executeShell(connection)复用已有连接
                ShellResult result = executeShell(connection, cmd);
                
                if (!result.isSuccess()) {
                    failedChunks++;
                    logE(tag, "块#" + chunkIndex + "写入失败 | offset=" + bytesWritten + 
                         " | 连续失败=" + failedChunks + " | " + result.stderr);
                    
                    if (failedChunks >= MAX_FAILED_CHUNKS) {
                        logE(tag, "连续失败过多(" + MAX_FAILED_CHUNKS + "次)，清理文件并退出");
                        executeShell(connection, "rm -f " + escapeShellArg(remotePath));
                        return new ShellResult(-1, "", "分块写入连续失败");
                    }
                    
                    try {
                        // 指数退避：2s -> 4s -> 6s -> ...
                        int waitTime = Math.min(2000 + failedChunks * 1000, 10000);
                        logD(tag, "等待" + waitTime + "ms后重试块#" + chunkIndex + "...");
                        Thread.sleep(waitTime);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        executeShell(connection, "rm -f " + escapeShellArg(remotePath));
                        return new ShellResult(-1, "", "写入被中断");
                    }
                    
                    // 不推进，重试当前块
                    chunkIndex--;
                    continue;
                }
                
                failedChunks = 0;
                bytesWritten += bytesRead;
                
                // 打印进度
                if ((chunkIndex + 1) % 10 == 0 || bytesWritten == fileSize) {
                    int percent = (int) ((double) bytesWritten / fileSize * 100);
                    logD(tag, "进度: " + (chunkIndex + 1) + "块 (" + percent + "%) | 已写=" + bytesWritten + "/" + fileSize + " bytes");
                }
            }
            
            // 验证文件大小
            if (verifyFileSize(connection, remotePath, (int) Math.min(fileSize, Integer.MAX_VALUE))) {
                logI(tag, "分块推送完成 | 大小=" + fileSize + " bytes 验证通过");
                return new ShellResult(0, "", "");
            } else {
                logE(tag, "文件大小验证失败 | 期望=" + fileSize + " bytes");
                executeShell(connection, "rm -f " + escapeShellArg(remotePath));
                return new ShellResult(-1, "", "文件大小验证失败");
            }
            
        } catch (Exception e) {
            logE(tag, "分块推送异常", e);
            return new ShellResult(-1, "", "分块推送异常: " + e.getMessage());
        } finally {
            if (fis != null) {
                try { fis.close(); } catch (Exception ignored) {}
            }
        }
    }
    
    /**
     * 直接推送（小文件专用 - 从文件路径读取，单次shell命令完成）
     * 复用已有连接
     */
    private static ShellResult pushFileDirectFromFile(AdbConnection connection, String sourceFilePath, String remotePath) {
        String tag = "PushDirectFile[" + connection.serial + "]";
        
        // 读取小文件到内存（小文件安全）
        File sourceFile = new File(sourceFilePath);
        if (sourceFile.length() > 200 * 1024) {
            logW(tag, "文件过大(" + sourceFile.length() + " bytes)，跳过直接推送");
            return new ShellResult(-1, "", "文件过大");
        }
        
        byte[] fileData;
        try (FileInputStream fis = new FileInputStream(sourceFile)) {
            fileData = fis.readAllBytes();
        } catch (IOException e) {
            logE(tag, "读取源文件失败: " + e.getMessage());
            return new ShellResult(-1, "", "读取源文件失败: " + e.getMessage());
        }
        
        String base64Data = Base64.getEncoder().encodeToString(fileData);
        logD(tag, "Base64编码后大小=" + base64Data.length() + " chars");
        
        String cmd = "printf '%s' '" + base64Data + 
                     "' | base64 -d > " + escapeShellArg(remotePath);
        
        ShellResult result = executeShell(connection, cmd);
        logD(tag, "直接推送执行完成 | exitCode=" + result.exitCode);
        return result;
    }

public static java.util.List<String> scanLanDevices(String subnet, int timeoutMs) {
        String tag = "LanScan[" + subnet + ".0/24]";
        logI(tag, "开始扫描局域网ADB设备...");
        
        java.util.List<String> devices = new java.util.ArrayList<>();
        int[] commonPorts = {5555, 5556, 5557, 5558, 5559, 6666, 8888};
        
        int totalHosts = 254;
        int scannedHosts = 0;
        int progressStep = totalHosts / 10; // 每10%汇报一次
        
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
}
