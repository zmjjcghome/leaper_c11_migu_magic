package com.leapermagic.magic;

import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import android.util.Log;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
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

    private static final String TAG = "AdbConnection";

    private Socket socket;
    private OutputStream out;
    private InputStream in;
    private int localId = 1;

    // ========== ADB 协议常量 ==========
    private static final int A_CNXN = 0x4e584e43;
    private static final int A_OPEN = 0x4e45504f;
    private static final int A_OKAY = 0x59414b4f;
    private static final int A_CLSE = 0x45534c43;
    private static final int A_WRTE = 0x45545257;
    private static final int A_AUTH = 0x48545541;

    private static final int VERSION = 0x01000000;
    private static final int MAX_PAYLOAD = 256 * 1024;

    // ========== 超时配置 ==========
    private int connectTimeout = 3000;   // 连接超时 3 秒
    private int readTimeout = 5000;      // 读取超时 5 秒
    private int maxRetries = 2;          // 握手失败重试次数

    private DebugCallback debugCallback;

    public interface DebugCallback {
        void onLog(String msg);
    }

    public void setDebugCallback(DebugCallback callback) {
        this.debugCallback = callback;
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        if (debugCallback != null) {
            debugCallback.onLog("[ADB] " + msg);
        }
    }

    // ============================================
    // 连接（带重试 + 多种协议变体）
    // ============================================

    public void connect(String host, int port, int timeout) throws IOException {
        this.connectTimeout = timeout;
        IOException lastError = null;

        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                if (attempt > 0) {
                    log("重试第 " + attempt + " 次...");
                    Thread.sleep(500);
                }
                doConnect(host, port, attempt);
                return;  // 成功
            } catch (IOException e) {
                lastError = e;
                log("第 " + attempt + " 次尝试失败: " + e.getMessage());
                close();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("连接被中断", e);
            }
        }
        throw new IOException("连接失败（已重试 " + maxRetries + " 次）", lastError);
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
    private void doConnect(String host, int port, int attempt) throws IOException {
        log("连接 " + host + ":" + port + " (尝试 " + attempt + ")");

        socket = new Socket();
        socket.setTcpNoDelay(true);
        socket.connect(new InetSocketAddress(host, port), connectTimeout);
        socket.setSoTimeout(readTimeout);

        out = socket.getOutputStream();
        in = socket.getInputStream();

        log("TCP 已连接，开始 ADB 握手...");

        // ====== 发送 CNXN ======
        byte[] cnxnPayload = "host::".getBytes(StandardCharsets.UTF_8);
        sendMessage(A_CNXN, VERSION, MAX_PAYLOAD, cnxnPayload);
        log("已发送 CNXN");

        // ====== 读取响应 ======
        AdbMessage resp = readMessage();
        if (resp == null) {
            throw new IOException("握手超时：adbd 无响应。\n" +
                "可能原因：\n" +
                "1. 端口不是 adbd 服务\n" +
                "2. adbd 需要密钥认证（USB 连接后执行 adb tcpip 5555）\n" +
                "3. Android 11+ 无线调试需要配对");
        }

        log("收到响应: cmd=0x" + Integer.toHexString(resp.command) +
            ", arg0=0x" + Integer.toHexString(resp.arg0) +
            ", arg1=0x" + Integer.toHexString(resp.arg1));

        // ====== 处理 AUTH ======
        if (resp.command == A_AUTH) {
            int authType = resp.arg0;
            log("收到 AUTH 请求，类型=" + authType + " (1=Token, 2=Signature, 3=RSAPublicKey)");

            // 发送空公钥，触发 adbd 回退（某些版本有效）
            if (authType == 1 && attempt == 0) {
                log("发送空公钥尝试绕过...");
                sendMessage(A_AUTH, 3, 0, new byte[0]);
                resp = readMessage();
                if (resp != null && resp.command == A_CNXN) {
                    log("绕过成功！");
                } else {
                    throw new IOException(
                        "ADB 需要密钥认证，无法绕过。\n" +
                        "请通过 USB 执行: adb tcpip 5555");
                }
            } else {
                throw new IOException(
                    "ADB 需要密钥认证 (AUTH type=" + authType + ")\n" +
                    "解决方案：\n" +
                    "1. USB 连接手机\n" +
                    "2. 执行 adb tcpip 5555\n" +
                    "3. 拔掉 USB 后重试");
            }
        }

        if (resp.command != A_CNXN) {
            throw new IOException(
                "握手失败：期望 CNXN，收到 0x" +
                Integer.toHexString(resp.command));
        }

        log("握手成功！maxPayload=" + resp.arg1);
    }

    // ============================================
    // Shell 命令执行
    // ============================================

    public ShellResult shell(String command) throws IOException {
        if (!isConnected()) {
            throw new IOException("未连接到 adbd");
        }

        log("shell: " + command);

        int remoteId = openService("shell:" + command);

        StringBuilder stdout = new StringBuilder();
        StringBuilder stderr = new StringBuilder();
        int exitCode = -1;

        while (true) {
            AdbMessage msg = readMessage();
            if (msg == null) {
                log("连接关闭");
                break;
            }

            switch (msg.command) {
                case A_WRTE:
                    if (msg.payload != null && msg.payload.length > 0) {
                        // shell_v2: first byte = fd (1=stdout, 2=stderr)
                        int offset = 0;
                        if (msg.payload.length > 1) {
                            int fd = msg.payload[0] & 0xFF;
                            String text = new String(msg.payload, 1,
                                    msg.payload.length - 1, StandardCharsets.UTF_8);
                            if (fd == 1) stdout.append(text);
                            else if (fd == 2) stderr.append(text);
                            else stdout.append(text);  // unknown fd -> stdout
                        } else {
                            stdout.append(new String(msg.payload, StandardCharsets.UTF_8));
                        }
                    }
                    sendOkay(remoteId, msg.arg0);
                    break;

                case A_CLSE:
                    exitCode = msg.arg1;
                    log("exitCode=" + exitCode);
                    sendClose(remoteId, msg.arg0);
                    return new ShellResult(exitCode, stdout.toString(), stderr.toString());

                case A_OKAY:
                    break;

                default:
                    log("未知消息: 0x" + Integer.toHexString(msg.command));
                    break;
            }
        }

        return new ShellResult(exitCode, stdout.toString(), stderr.toString());
    }

    // ============================================
    // 底层 ADB 协议方法
    // ============================================

    private int openService(String service) throws IOException {
        int local = localId++;
        byte[] payload = (service + "\0").getBytes(StandardCharsets.UTF_8);

        sendMessage(A_OPEN, local, 0, payload);

        AdbMessage resp = readMessage();
        if (resp == null) throw new IOException("openService 无响应");

        if (resp.command == A_OKAY) return resp.arg1;

        if (resp.command == A_CLSE) {
            String err = "服务不可用: " + service;
            if (resp.payload != null) {
                err += " - " + new String(resp.payload, StandardCharsets.UTF_8);
            }
            throw new IOException(err);
        }

        throw new IOException("openService 异常响应: 0x" + Integer.toHexString(resp.command));
    }

    private void sendMessage(int cmd, int arg0, int arg1, byte[] payload) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(cmd);
        bb.putInt(arg0);
        bb.putInt(arg1);
        bb.putInt(payload != null ? payload.length : 0);
        bb.putInt(0);  // magic
        bb.putInt(0);  // padding

        synchronized (out) {
            out.write(bb.array());
            if (payload != null && payload.length > 0) {
                out.write(payload);
            }
            out.flush();
        }
    }

    private void sendOkay(int localId, int remoteId) throws IOException {
        sendMessage(A_OKAY, localId, remoteId, null);
    }

    private void sendClose(int localId, int remoteId) throws IOException {
        sendMessage(A_CLSE, localId, remoteId, null);
    }

    private AdbMessage readMessage() throws IOException {
        if (!isConnected()) return null;

        byte[] header = new byte[24];
        int read = fillBuffer(header);
        if (read == 0) return null;
        if (read != 24) {
            log("头部不完整: " + read + "/24");
            return null;
        }

        ByteBuffer bb = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
        int command = bb.getInt();
        int arg0 = bb.getInt();
        int arg1 = bb.getInt();
        int payloadLen = bb.getInt();

        byte[] payload = null;
        if (payloadLen > 0 && payloadLen <= MAX_PAYLOAD) {
            payload = new byte[payloadLen];
            fillBuffer(payload);
        } else if (payloadLen > MAX_PAYLOAD) {
            // 跳过超大 payload
            log("超大 payload: " + payloadLen + "，跳过...");
            byte[] skip = new byte[8192];
            int remaining = payloadLen;
            while (remaining > 0) {
                int r = in.read(skip, 0, Math.min(skip.length, remaining));
                if (r == -1) break;
                remaining -= r;
            }
        }

        return new AdbMessage(command, arg0, arg1, payload);
    }

    private int fillBuffer(byte[] buffer) throws IOException {
        int total = 0;
        while (total < buffer.length) {
            int r = in.read(buffer, total, buffer.length - total);
            if (r == -1) {
                log("EOF at " + total + "/" + buffer.length);
                return total;
            }
            total += r;
        }
        return total;
    }

    // ============================================
    // 状态查询
    // ============================================

    public boolean isConnected() {
        return socket != null && !socket.isClosed() && socket.isConnected();
    }

    @Override
    public void close() {
        log("关闭连接");
        try {
            if (socket != null) socket.close();
        } catch (IOException ignored) {
        } finally {
            socket = null;
            out = null;
            in = null;
        }
    }

    // ============================================
    // 内部类
    // ============================================

    private static class AdbMessage {
        final int command, arg0, arg1;
        final byte[] payload;

        AdbMessage(int cmd, int a0, int a1, byte[] p) {
            command = cmd;
            arg0 = a0;
            arg1 = a1;
            payload = p;
        }
    }

    public static class ShellResult {
        public final int exitCode;
        public final String stdout;
        public final String stderr;

        public ShellResult(int code, String out, String err) {
            exitCode = code;
            stdout = out != null ? out : "";
            stderr = err != null ? err : "";
        }

        public boolean isSuccess() {
            return exitCode == 0;
        }
    }
}
