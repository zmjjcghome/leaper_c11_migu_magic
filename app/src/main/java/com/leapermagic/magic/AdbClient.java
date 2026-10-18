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

/**
 * 纯Java实现的ADB客户端
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
            this.stdout = stdout;
            this.stderr = stderr;
        }
        
        public boolean isSuccess() {
            return exitCode == 0;
        }
        
        @Override
        public String toString() {
            return "ExitCode=" + exitCode + "\nSTDOUT:\n" + stdout + "\nSTDERR:\n" + stderr;
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
        private final AtomicBoolean closed = new AtomicBoolean(false);
        
        AdbConnection(Socket socket, String serial) throws IOException {
            this.socket = socket;
            this.serial = serial;
            this.input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            this.output = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
            socket.setSoTimeout(READ_TIMEOUT);
        }
        
        public String getSerial() {
            return serial;
        }
        
        public boolean isClosed() {
            return closed.get() || socket.isClosed();
        }
        
        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
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
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (Exception e) {
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
        java.util.List<Integer> openPorts = new java.util.ArrayList<>();
        for (int port : ports) {
            if (checkAdbPort(host, port, timeoutMs)) {
                openPorts.add(port);
            }
        }
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
        Socket socket = null;
        
        try {
            // 1. 建立TCP连接
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT);
            socket.setTcpNoDelay(true);
            
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
            
            // 2. 发送连接命令 "host:connect:..."
            String connectCmd = String.format(CMD_CONNECT, host, port);
            sendAdbMessage(out, connectCmd);
            
            // 3. 读取响应
            AdbMessage response = readAdbMessage(in);
            
            if (response == null) {
                return new AdbConnectionResult(false, "无响应", null);
            }
            
            // 4. 处理认证
            if (response.command == AUTH_TOKEN) {
                // 需要认证
                if (keyPair == null) {
                    keyPair = generateAdbKey();
                }
                
                // 发送公钥
                byte[] publicKey = encodePublicKey(keyPair.getPublic());
                sendAdbMessage(out, AUTH_RSAPUBLICKEY, publicKey);
                
                // 等待响应
                response = readAdbMessage(in);
                
                if (response != null && response.command == AUTH_TOKEN) {
                    // 发送签名
                    byte[] token = response.payload;
                    byte[] signature = signToken(token, keyPair);
                    sendAdbMessage(out, AUTH_SIGNATURE, signature);
                    
                    // 读取最终结果
                    response = readAdbMessage(in);
                }
            }
            
            // 5. 解析连接状态
            if (response != null && response.command == CMD_OKAY) {
                // 提取设备序列号
                String serial = host + ":" + port;
                AdbConnection conn = new AdbConnection(socket, serial);
                return new AdbConnectionResult(true, "连接成功: " + serial, conn);
            } else {
                String msg = response != null ? new String(response.payload, StandardCharsets.UTF_8) : "未知错误";
                return new AdbConnectionResult(false, "连接失败: " + msg, null);
            }
            
        } catch (Exception e) {
            if (socket != null) {
                try { socket.close(); } catch (Exception ignored) {}
            }
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
        try {
            if (connection.isClosed()) {
                return new ShellResult(-1, "", "连接已关闭");
            }
            
            DataOutputStream out = connection.output;
            DataInputStream in = connection.input;
            
            // 1. 打开Shell通道
            String shellCmd = String.format(CMD_SHELL, command);
            sendAdbMessage(out, CMD_OPEN, 0x00000000, shellCmd.getBytes(StandardCharsets.UTF_8));
            
            // 2. 等待OKAY
            AdbMessage response = readAdbMessage(in);
            if (response == null || response.command != CMD_OKAY) {
                return new ShellResult(-1, "", "无法打开Shell通道");
            }
            
            int localId = response.arg0; // 服务端分配的local-id
            
            // 3. 读取输出数据
            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();
            boolean shellClosed = false;
            
            while (!shellClosed) {
                response = readAdbMessage(in);
                if (response == null) break;
                
                switch (response.command) {
                    case CMD_WRTE:
                        // 数据输出
                        String data = new String(response.payload, StandardCharsets.UTF_8);
                        stdout.append(data);
                        // 发送OKAY确认
                        sendAdbMessage(out, CMD_OKAY, response.arg0, null);
                        break;
                        
                    case CMD_CLSE:
                        // Shell关闭
                        shellClosed = true;
                        // 发送CLSE确认
                        sendAdbMessage(out, CMD_CLSE, response.arg0, null);
                        break;
                        
                    case CMD_OKAY:
                        // 确认消息，继续
                        break;
                        
                    default:
                        // 其他情况
                        if (response.payload != null) {
                            stderr.append(new String(response.payload, StandardCharsets.UTF_8));
                        }
                        break;
                }
            }
            
            // 4. 关闭本地通道
            sendAdbMessage(out, CMD_CLSE, localId, null);
            
            return new ShellResult(0, stdout.toString(), stderr.toString());
            
        } catch (Exception e) {
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
        AdbConnectionResult result = connect(host, port);
        if (!result.success || result.connection == null) {
            return new ShellResult(-1, "", "连接失败: " + result.message);
        }
        
        try (AdbConnection conn = result.connection) {
            return executeShell(conn, command);
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
    private static void sendAdbMessage(DataOutputStream out, String payload) throws IOException {
        sendAdbMessage(out, CMD_OPEN, 0x00000000, 
                       payload.getBytes(StandardCharsets.UTF_8));
    }
    
    /**
     * 发送ADB消息（byte[] payload）
     */
    private static void sendAdbMessage(DataOutputStream out, int command, byte[] payload) throws IOException {
        sendAdbMessage(out, command, 0x00000000, payload);
    }
    
    /**
     * 发送完整的ADB消息
     */
    private static void sendAdbMessage(DataOutputStream out, int command, int arg0, byte[] payload) throws IOException {
        int dataLength = (payload != null) ? payload.length : 0;
        int dataCrc32 = (payload != null) ? calculateCrc32(payload) : 0;
        int magic = command ^ 0xFFFFFFFF;
        
        // 写入24字节头
        // 注意：ADB协议使用小端字节序
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
    private static AdbMessage readAdbMessage(DataInputStream in) throws IOException {
        try {
            AdbMessage msg = new AdbMessage();
            
            byte[] header = new byte[24];
            int bytesRead = in.read(header);
            if (bytesRead != 24) {
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
            if ((msg.command ^ 0xFFFFFFFF) != msg.magic) {
                throw new IOException("ADB消息magic验证失败");
            }
            
            // 读取payload
            if (msg.dataLength > 0 && msg.dataLength <= MAX_PAYLOAD) {
                msg.payload = new byte[msg.dataLength];
                bytesRead = in.read(msg.payload);
                if (bytesRead != msg.dataLength) {
                    // 允许部分读取
                    msg.payload = Arrays.copyOf(msg.payload, Math.max(0, bytesRead));
                }
            }
            
            return msg;
            
        } catch (EOFException e) {
            return null;
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
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("生成密钥失败", e);
        }
    }
    
    /**
     * 编码公钥为ADB格式
     * 格式：32字节Android头 + "\0android-rsa\0" + Base64编码的公钥
     */
    private static byte[] encodePublicKey(PublicKey publicKey) {
        try {
            // 获取公钥字节
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey.getEncoded());
            
            // Base64编码（无换行）
            String base64Key = Base64.getEncoder().withoutPadding()
                                     .encodeToString(spec.getEncoded());
            
            // 构造ADB格式
            // 结构: [4字节长度][base64key\0login@hostname\0]
            String loginName = "adbclient@android";
            String keyString = base64Key + "\0" + loginName + "\0";
            byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
            
            ByteBuffer buf = ByteBuffer.allocate(keyBytes.length)
                                       .order(ByteOrder.LITTLE_ENDIAN);
            buf.put(keyBytes);
            
            return buf.array();
        } catch (Exception e) {
            throw new RuntimeException("编码公钥失败", e);
        }
    }
    
    /**
     * 对认证令牌签名
     */
    private static byte[] signToken(byte[] token, KeyPair keyPair) {
        try {
            java.security.Signature signature = java.security.Signature.getInstance("SHA1withRSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(token);
            return signature.sign();
        } catch (Exception e) {
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
        StringBuilder info = new StringBuilder();
        
        ShellResult prop = executeShellOneShot(host, port, "getprop ro.build.version.sdk");
        info.append("SDK: ").append(prop.stdout.trim()).append("\n");
        
        ShellResult model = executeShellOneShot(host, port, "getprop ro.product.model");
        info.append("Model: ").append(model.stdout.trim()).append("\n");
        
        ShellResult brand = executeShellOneShot(host, port, "getprop ro.product.brand");
        info.append("Brand: ").append(brand.stdout.trim()).append("\n");
        
        return info.toString();
    }
    
    /**
     * 安装APK
     */
    public static ShellResult installApk(String host, int port, String remoteApkPath) {
        return executeShellOneShot(host, port, 
            "pm install -r -d " + escapeShellArg(remoteApkPath));
    }
    
    /**
     * 推送文件（通过exec:cmd实现cat写入）
     */
    public static ShellResult pushFile(String host, int port, byte[] data, String remotePath) {
        // 使用base64传输避免二进制问题
        String base64Data = Base64.getEncoder().encodeToString(data);
        String cmd = "echo " + escapeShellArg(base64Data) + 
                     " | base64 -d > " + escapeShellArg(remotePath);
        return executeShellOneShot(host, port, cmd);
    }
    
    // ==================== 工具方法 ====================
    
    /**
     * Shell参数转义
     */
    public static String escapeShellArg(String arg) {
        if (arg == null) return "''";
        // 使用单引号包裹并转义内部单引号
        return "'" + arg.replace("'", "'\\''") + "'";
    }
    
    /**
     * 扫描局域网ADB设备（常用端口）
     */
    public static java.util.List<String> scanLanDevices(String subnet, int timeoutMs) {
        java.util.List<String> devices = new java.util.ArrayList<>();
        int[] commonPorts = {5555, 5556, 5557, 5558, 5559, 6666, 8888};
        
        for (int i = 1; i <= 254; i++) {
            final String host = subnet + "." + i;
            for (int port : commonPorts) {
                if (checkAdbPort(host, port, timeoutMs)) {
                    devices.add(host + ":" + port);
                }
            }
        }
        return devices;
    }
}
