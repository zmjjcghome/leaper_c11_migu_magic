package com.leapermagic.magic;

import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * 完整的 ADB 协议直连 adbd 实现
 * 通过 TCP Socket 连接到 127.0.0.1:PORT 上的 adbd，
 * 直接以 shell UID (2000) 执行命令。
 *
 * 协议参考: system/core/adb/protocol.txt (AOSP)
 *
 * 消息格式:
 *   [4字节命令(CNXN/OPEN/OKAY/CLSE/WRTE/AUTH)]
 *   [4字节参数1]
 *   [4字节参数2]
 *   [4字节payload长度]
 *   [4字节magic(仅CNXN消息, 即 payload 的 CRC32)]
 *   [4字节padding(仅CNXN, 恒为0)]
 *   [payload]
 *
 * 简化版 (ADB 支持): 直接发送 "host:transport-anything\n"
 *   然后 "shell:command\n" — adbd 接受这种简化格式
 */
public class AdbConnection implements Closeable {

    private Socket socket;
    private OutputStream out;
    private InputStream in;
    private int localId = 1; // 本地连接 ID 计数器

    // ADB 协议常量
    private static final int A_SYNC  = 0x434e5953;
    private static final int A_CNXN  = 0x4e584e43;
    private static final int A_OPEN  = 0x4e45504f;
    private static final int A_OKAY  = 0x59414b4f;
    private static final int A_CLSE  = 0x45534c43;
    private static final int A_WRTE  = 0x45545257;
    private static final int A_AUTH  = 0x48545541;

    private static final int VERSION = 0x01000000;
    private static final int MAX_PAYLOAD = 256 * 1024;

    /**
     * 连接到 adbd
     * @param host 通常为 "127.0.0.1" 或 "localhost"
     * @param port adbd 的 TCP 监听端口
     * @param timeout 连接超时 (毫秒)
     */
    public void connect(String host, int port, int timeout) throws IOException {
        socket = new Socket();
        socket.setTcpNoDelay(true);
        socket.connect(new java.net.InetSocketAddress(host, port), timeout);
        socket.setSoTimeout(timeout);
        out = socket.getOutputStream();
        in  = socket.getInputStream();

        // ADB 握手: 发送 CNXN 消息
        sendConnect();
    }

    /**
     * 发送 ADB CNXN (连接) 消息
     */
    private void sendConnect() throws IOException {
        // payload: "host::\0" — 表示主机连接
        String systemType = "host::";
        byte[] payload = systemType.getBytes(StandardCharsets.UTF_8);

        // 写入 ADB 消息头 + CNXN 特有的 8 字节
        ByteBuffer bb = ByteBuffer.allocate(24 + payload.length).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(A_CNXN);          // command
        bb.putInt(VERSION);         // arg0 = version
        bb.putInt(MAX_PAYLOAD);     // arg1 = max payload
        bb.putInt(payload.length);  // payload length
        bb.putInt(0);               // magic (crc32 of payload, 可填0)
        bb.putInt(0);               // padding
        bb.put(payload);

        out.write(bb.array());
        out.flush();

        // 读取响应
        AdbMessage resp = readMessage();
        if (resp == null || resp.command != A_CNXN) {
            throw new IOException("ADB 握手失败: 未收到 CNXN 响应");
        }
    }

    /**
     * 执行 shell 命令 (核心方法)
     *
     * ADB shell 流程:
     *   1. OPEN (id, 0, "shell:command\0")
     *   2. 等待 OKAY
     *   3. 读取 WRTE 消息获取输出
     *   4. 收到 CLSE 表示结束
     *
     * @param command 要执行的命令
     * @return 命令的输出结果
     */
    public ShellResult shell(String command) throws IOException {
        int remoteId = openService("shell:" + command);
        StringBuilder stdout = new StringBuilder();
        StringBuilder stderr = new StringBuilder();
        int exitCode = -1;

        // 读取响应直到 CLSE
        while (true) {
            AdbMessage msg = readMessage();
            if (msg == null) break;

            switch (msg.command) {
                case A_OKAY:
                    // 确认连接建立
                    break;

                case A_WRTE:
                    // 命令输出数据
                    if (msg.payload != null && msg.payload.length > 0) {
                        // adbd 输出格式: [fd_id:1字节][data:剩余]
                        // fd_id: 1=stdout, 2=stderr
                        if (msg.payload.length > 1) {
                            int fd = msg.payload[0] & 0xFF;
                            String text = new String(msg.payload, 1,
                                    msg.payload.length - 1, StandardCharsets.UTF_8);
                            if (fd == 1) {
                                stdout.append(text);
                            } else if (fd == 2) {
                                stderr.append(text);
                            } else {
                                stdout.append(text); // 默认当 stdout
                            }
                        }
                    }
                    // 确认收到: 发送 OKAY(remoteId, localId)
                    sendOkay(remoteId, msg.arg0);
                    break;

                case A_CLSE:
                    // 连接关闭, arg1 可能是退出码
                    exitCode = msg.arg1;
                    sendClose(remoteId, msg.arg0);
                    return new ShellResult(exitCode, stdout.toString(), stderr.toString());

                default:
                    break;
            }
        }

        return new ShellResult(exitCode, stdout.toString(), stderr.toString());
    }

    /**
     * 打开一个服务 (如 shell, exec, sync 等)
     * 发送 OPEN(localId, 0, "service\0")
     * 等待 OKAY 响应
     *
     * @return remoteId
     */
    private int openService(String service) throws IOException {
        int id = localId++;
        byte[] payload = (service + "\0").getBytes(StandardCharsets.UTF_8);

        ByteBuffer bb = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(A_OPEN);
        bb.putInt(id);              // arg0 = local id
        bb.putInt(0);               // arg1 = 0
        bb.putInt(payload.length);  // payload length
        bb.putInt(0);               // magic (unused for OPEN)
        bb.putInt(0);               // padding

        out.write(bb.array());
        out.write(payload);
        out.flush();

        // 等待 OKAY 响应，获取 remoteId
        AdbMessage resp = readMessage();
        if (resp == null) {
            throw new IOException("打开服务失败: 无响应");
        }
        if (resp.command == A_OKAY) {
            return resp.arg1; // remote id
        }
        if (resp.command == A_CLSE) {
            throw new IOException("服务不可用: " + service);
        }
        throw new IOException("打开服务失败: 未知响应 0x" +
                Integer.toHexString(resp.command));
    }

    /**
     * 发送 OKAY 消息
     */
    private void sendOkay(int localId, int remoteId) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(A_OKAY);
        bb.putInt(localId);
        bb.putInt(remoteId);
        bb.putInt(0); // payload length = 0
        bb.putInt(0);
        bb.putInt(0);
        out.write(bb.array());
        out.flush();
    }

    /**
     * 发送 CLSE 消息
     */
    private void sendClose(int localId, int remoteId) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(A_CLSE);
        bb.putInt(localId);
        bb.putInt(remoteId);
        bb.putInt(0);
        bb.putInt(0);
        bb.putInt(0);
        out.write(bb.array());
        out.flush();
    }

    /**
     * 读取一个 ADB 消息 (24字节头 + payload)
     */
    private AdbMessage readMessage() throws IOException {
        byte[] header = new byte[24];
        int read = fillBuffer(header);
        if (read != 24) {
            return null; // 连接已关闭
        }

        ByteBuffer bb = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
        int command   = bb.getInt();
        int arg0      = bb.getInt();
        int arg1      = bb.getInt();
        int payloadLen = bb.getInt();
        int magic     = bb.getInt();
        int padding   = bb.getInt();

        byte[] payload = null;
        if (payloadLen > 0 && payloadLen <= MAX_PAYLOAD) {
            payload = new byte[payloadLen];
            fillBuffer(payload);
        }

        return new AdbMessage(command, arg0, arg1, payloadLen, payload);
    }

    /**
     * 填满缓冲区（处理 TCP 分包）
     */
    private int fillBuffer(byte[] buffer) throws IOException {
        int total = 0;
        int len = buffer.length;
        while (total < len) {
            int read = in.read(buffer, total, len - total);
            if (read == -1) return total;
            total += read;
        }
        return total;
    }

    /**
     * 检测 adbd 是否在指定端口监听
     */
    public static boolean isAdbdListening(String host, int port) {
        try (Socket s = new Socket()) {
            s.connect(new java.net.InetSocketAddress(host, port), 500);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    @Override
    public void close() throws IOException {
        if (socket != null && !socket.isClosed()) {
            socket.close();
        }
    }

    // ============================================
    // 内部类
    // ============================================

    /** ADB 消息 */
    private static class AdbMessage {
        final int command;
        final int arg0;
        final int arg1;
        final int payloadLength;
        final byte[] payload;

        AdbMessage(int command, int arg0, int arg1, int payloadLength, byte[] payload) {
            this.command = command;
            this.arg0 = arg0;
            this.arg1 = arg1;
            this.payloadLength = payloadLength;
            this.payload = payload;
        }
    }

    /** Shell 命令执行结果 */
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
            StringBuilder sb = new StringBuilder();
            sb.append("ExitCode=").append(exitCode).append("\n");
            if (stdout != null && !stdout.isEmpty()) {
                sb.append("[STDOUT]\n").append(stdout);
            }
            if (stderr != null && !stderr.isEmpty()) {
                sb.append("[STDERR]\n").append(stderr);
            }
            return sb.toString();
        }
    }
}
