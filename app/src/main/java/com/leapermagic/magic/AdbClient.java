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
    public static class AdbConnection implements Closeable {
        private final Socket socket;
        private final DataInputStream input;
        private final DataOutputStream output;
        private final String serial;
        private final String tag;
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private final long connectTime;
        
        AdbConnection(Socket socket, String serial) throws IOException {
            this.socket = socket;
            this.serial = serial;
            this.tag = "AdbConn[" + serial + "]";
            this.connectTime = System.currentTimeMillis();
            this.input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            this.output = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
            socket.setSoTimeout(READ_TIMEOUT);
            logI(tag, "连接已建立 | 本地端口=" + socket.getLocalPort());
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
    public static AdbConnectionResult connect(String host, int port, KeyPair keyPair) {
        String tag = "Connect[" + host + ":" + port + "]";
        Socket socket = null;
        
        logI(tag, "========== 开始ADB连接 ==========");
        
        try {
            // 1. 建立TCP连接
            logD(tag, "步骤1/5: 建立TCP连接...");
            long t1 = System.currentTimeMillis();
            
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT);
            socket.setTcpNoDelay(true);
            
            long tcpTime = System.currentTimeMillis() - t1;
            logI(tag, "TCP连接成功 | 耗时=" + tcpTime + "ms | " + 
                     socket.getLocalAddress().getHostAddress() + ":" + socket.getLocalPort() + 
                     " -> " + host + ":" + port);
            
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
            
            // 2. 发送连接命令
            String connectCmd = String.format(CMD_CONNECT, host, port);
            logD(tag, "步骤2/5: 发送连接命令... | 命令=" + connectCmd);
            
            sendAdbMessage(out, connectCmd, tag);
            
            // 3. 读取响应
            logD(tag, "步骤3/5: 等待响应...");
            AdbMessage response = readAdbMessage(in, tag);
            
            if (response == null) {
                logE(tag, "连接失败：无响应");
                return new AdbConnectionResult(false, "无响应", null);
            }
            
            logD(tag, "收到响应 | command=0x" + Integer.toHexString(response.command).toUpperCase() + 
                       " | dataLen=" + response.dataLength);
            
            // 4. 处理认证
            if (response.command == AUTH_TOKEN) {
                logI(tag, "步骤4/5: 需要RSA认证...");
                
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
                sendAdbMessage(out, AUTH_RSAPUBLICKEY, publicKey, tag);
                logD(tag, "公钥已发送 | 大小=" + publicKey.length + " bytes");
                
                // 等待响应
                response = readAdbMessage(in, tag);
                
                if (response != null && response.command == AUTH_TOKEN) {
                    logD(tag, "收到认证令牌 | 长度=" + response.payload.length + " bytes");
                    
                    // 发送签名
                    byte[] token = response.payload;
                    long signStart = System.currentTimeMillis();
                    byte[] signature = signToken(token, keyPair);
                    long signTime = System.currentTimeMillis() - signStart;
                    
                    logD(tag, "发送签名 | 大小=" + signature.length + " bytes | 签名耗时=" + signTime + "ms");
                    sendAdbMessage(out, AUTH_SIGNATURE, signature, tag);
                    
                    // 读取最终结果
                    response = readAdbMessage(in, tag);
                } else if (response != null) {
                    logD(tag, "认证跳过 | command=0x" + Integer.toHexString(response.command).toUpperCase());
                }
            } else {
                logD(tag, "步骤4/5: 无需认证（设备已信任）");
            }
            
            // 5. 解析连接状态
            logD(tag, "步骤5/5: 解析连接状态...");
            
            if (response != null && response.command == CMD_OKAY) {
                String serial = host + ":" + port;
                AdbConnection conn = new AdbConnection(socket, serial);
                logI(tag, "========== 连接成功 ✓ ==========");
                return new AdbConnectionResult(true, "连接成功: " + serial, conn);
            } else {
                String msg = "未知错误";
                if (response != null && response.payload != null) {
                    msg = new String(response.payload, StandardCharsets.UTF_8).trim();
                }
                logE(tag, "连接被拒绝 | 原因=" + msg + 
                         (response != null ? " | command=0x" + Integer.toHexString(response.command).toUpperCase() : ""));
                
                try { socket.close(); } catch (Exception ignored) {}
                return new AdbConnectionResult(false, "连接失败: " + msg, null);
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
    
    /**
     * 自动生成密钥对连接
     */
    public static AdbConnectionResult connect(String host, int port) {
        return connect(host, port, null);
    }

    // ==================== ADB Shell执行 ====================
    
    /**
     * 执行ADB Shell命令（使用已建立的连接）
     * @param connection ADB连接对象
     * @param command 要执行的shell命令
     * @return Shell执行结果
     */
    public static ShellResult executeShell(AdbConnection connection, String command) {
        String tag = "Shell[" + connection.serial + "]";
        
        logI(tag, "========== 执行命令: '" + command + "' ==========");
        
        try {
            if (connection.isClosed()) {
                logE(tag, "连接已关闭，无法执行");
                return new ShellResult(-1, "", "连接已关闭");
            }
            
            DataOutputStream out = connection.output;
            DataInputStream in = connection.input;
            
            // 1. 打开Shell通道
            logD(tag, "打开Shell通道...");
            String shellCmd = String.format(CMD_SHELL, command);
            
            long t1 = System.currentTimeMillis();
            sendAdbMessage(out, CMD_OPEN, 0x00000000, shellCmd.getBytes(StandardCharsets.UTF_8), tag);
            
            // 2. 等待OKAY
            AdbMessage response = readAdbMessage(in, tag);
            if (response == null || response.command != CMD_OKAY) {
                logE(tag, "无法打开Shell通道 | response=" + 
                         (response != null ? "0x" + Integer.toHexString(response.command) : "null"));
                return new ShellResult(-1, "", "无法打开Shell通道");
            }
            
            int localId = response.arg0;
            logD(tag, "Shell通道已打开 | localId=" + localId + " | 耗时=" + (System.currentTimeMillis() - t1) + "ms");
            
            // 3. 读取输出数据
            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();
            boolean shellClosed = false;
            int writeCount = 0;
            long totalBytes = 0;
            
            logD(tag, "开始读取输出...");
            
            while (!shellClosed) {
                response = readAdbMessage(in, tag);
                if (response == null) {
                    logW(tag, "读取到null消息，终止读取");
                    break;
                }
                
                switch (response.command) {
                    case CMD_WRTE:
                        writeCount++;
                        String data = new String(response.payload, StandardCharsets.UTF_8);
                        stdout.append(data);
                        totalBytes += response.payload.length;
                        
                        if (writeCount <= 3 || writeCount % 50 == 0) {
                            logD(tag, "收到数据块#" + writeCount + " | 大小=" + response.payload.length + 
                                       " bytes | 累计=" + totalBytes + " bytes");
                        }
                        
                        // 发送OKAY确认
                        sendAdbMessage(out, CMD_OKAY, response.arg0, null, tag);
                        break;
                        
                    case CMD_CLSE:
                        shellClosed = true;
                        logD(tag, "Shell通道关闭 | 总数据块=" + writeCount + 
                                   " | 总字节=" + totalBytes + " bytes");
                        // 发送CLSE确认
                        sendAdbMessage(out, CMD_CLSE, response.arg0, null, tag);
                        break;
                        
                    case CMD_OKAY:
                        logD(tag, "收到OKAY确认 | arg0=" + response.arg0);
                        break;
                        
                    default:
                        if (response.payload != null) {
                            String errData = new String(response.payload, StandardCharsets.UTF_8);
                            stderr.append(errData);
                            logW(tag, "收到未知响应 | command=0x" + 
                                      Integer.toHexString(response.command).toUpperCase() + 
                                      " | data=" + errData.substring(0, Math.min(100, errData.length())));
                        }
                        break;
                }
            }
            
            // 4. 关闭本地通道
            sendAdbMessage(out, CMD_CLSE, localId, null, tag);
            
            long elapsed = System.currentTimeMillis() - t1;
            
            // 输出结果摘要
            String stdoutStr = stdout.toString();
            String stderrStr = stderr.toString();
            
            logI(tag, "命令执行完成 | 耗时=" + elapsed + "ms | stdout=" + stdoutStr.length() + 
                     " bytes | stderr=" + stderrStr.length() + " bytes");
            
            if (!stdoutStr.isEmpty() && stdoutStr.length() <= 200) {
                logD(tag, "stdout: " + stdoutStr.trim());
            } else if (!stdoutStr.isEmpty()) {
                logD(tag, "stdout(前200字符): " + stdoutStr.substring(0, Math.min(200, stdoutStr.length())).trim() + "...");
            }
            
            if (!stderrStr.isEmpty()) {
                logW(tag, "stderr: " + stderrStr.trim());
            }
            
            return new ShellResult(0, stdoutStr, stderrStr);
            
        } catch (SocketTimeoutException e) {
            logE(tag, "读取超时", e);
            return new ShellResult(-1, "", "读取超时: " + e.getMessage());
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
        
        logI(tag, "一次性执行开始 | 命令='" + command + "'");
        
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
    
    /**
     * 推送文件（通过base64编码传输）
     */
    public static ShellResult pushFile(String host, int port, byte[] data, String remotePath) {
        String tag = "Push[" + host + ":" + port + "]";
        logI(tag, "推送文件 | 大小=" + data.length + " bytes | 目标=" + remotePath);
        
        String base64Data = Base64.getEncoder().encodeToString(data);
        logD(tag, "Base64编码后大小=" + base64Data.length() + " chars");
        
        String cmd = "echo " + escapeShellArg(base64Data) + 
                     " | base64 -d > " + escapeShellArg(remotePath);
        
        ShellResult result = executeShellOneShot(host, port, cmd);
        logI(tag, "推送完成 | exitCode=" + result.exitCode);
        return result;
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
