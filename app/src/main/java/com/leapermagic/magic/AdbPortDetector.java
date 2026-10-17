package com.leapermagic.magic;

import java.io.*;
import java.util.*;

/**
 * 自动检测 adbd 的 TCP 监听端口
 * 支持多种检测策略
 */
public class AdbPortDetector {

    /**
     * 综合检测：按优先级依次尝试所有策略
     * @return adbd 端口号，-1 表示未找到
     */
    public static int detect(int preferredPort, Callback callback) {
        int port;

        // 策略1：如果用户指定了端口，先直接尝试
        if (preferredPort > 0) {
            if (callback != null) callback.onLog("检查指定端口: " + preferredPort);
            if (AdbConnection.isAdbdListening("127.0.0.1", preferredPort)) {
                return preferredPort;
            }
        }

        // 策略2：检查常见端口 5555
        if (callback != null) callback.onLog("检查端口 5555...");
        if (AdbConnection.isAdbdListening("127.0.0.1", 5555)) {
            return 5555;
        }

        // 策略3：读 /proc/net/tcp
        if (callback != null) callback.onLog("扫描 /proc/net/tcp...");
        port = detectViaProcNetTcp();
        if (port > 0) {
            if (callback != null) callback.onLog("/proc/net/tcp 发现端口: " + port);
            return port;
        }

        // 策略4：读系统属性
        if (callback != null) callback.onLog("读取系统属性...");
        port = detectViaGetprop();
        if (port > 0) {
            if (callback != null) callback.onLog("getprop 发现端口: " + port);
            return port;
        }

        // 策略5：扫描 35000-50000 范围 (Android 11+ 无线调试常用范围)
        if (callback != null) callback.onLog("扫描端口范围 5000-5999 35000-50000...");
        port = scanRange(5000, 5999, callback);
        if (port > 0) {
            if (callback != null) callback.onLog("扫描发现端口: " + port);
            return port;
        }
        port = scanRange(35000, 50000, callback);
        if (port > 0) {
            if (callback != null) callback.onLog("扫描发现端口: " + port);
            return port;
        }

        return -1;
    }

    /**
     * 策略: 通过 /proc/net/tcp 精确定位 adbd 监听端口
     */
    public static int detectViaProcNetTcp() {
        int adbdPid = findAdbdPid();
        if (adbdPid <= 0) return -1;

        Set<String> inodes = getSocketInodes(adbdPid);
        if (inodes.isEmpty()) return -1;

        return findListeningPort(inodes);
    }

    /**
     * 找到 adbd 进程 PID
     */
    private static int findAdbdPid() {
        // 方式1: pidof
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"pidof", "adbd"});
            String line = readFirstLine(p);
            if (line != null && !line.trim().isEmpty()) {
                return Integer.parseInt(line.trim().split("\\s+")[0]);
            }
        } catch (Exception ignored) {}

        // 方式2: ps
        try {
            Process p = Runtime.getRuntime().exec(
                new String[]{"sh", "-c", "ps -A 2>/dev/null | grep adbd"});
            String line = readFirstLine(p);
            if (line != null) {
                String[] parts = line.trim().split("\\s+");
                // PID 通常是第二列
                for (String part : parts) {
                    try { return Integer.parseInt(part); }
                    catch (NumberFormatException ignored) {}
                }
            }
        } catch (Exception ignored) {}
        return -1;
    }

    /**
     * 读取命令输出的第一行
     */
    private static String readFirstLine(Process p) {
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(p.getInputStream()))) {
            p.waitFor();
            return r.readLine();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 获取进程打开的 socket inode 集合
     */
    private static Set<String> getSocketInodes(int pid) {
        Set<String> inodes = new HashSet<>();
        File fdDir = new File("/proc/" + pid + "/fd");
        File[] files = fdDir.listFiles();
        if (files == null) return inodes;

        for (File fd : files) {
            try {
                String link = fd.getCanonicalPath();
                if (link.startsWith("socket:[") && link.endsWith("]")) {
                    inodes.add(link.substring(8, link.length() - 1));
                }
            } catch (Exception ignored) {}
        }
        return inodes;
    }

    /**
     * 在 /proc/net/tcp 中查找 LISTEN 状态且 inode 匹配的端口
     *
     * 格式:
     * sl  local_address rem_address   st ...                  inode
     * 0:  00000000:15B3 00000000:0000 0A ...                  12345
     *     ↑               ↑           ↑                       ↑
     *     IP:PORT         all zeros   LISTEN                  匹配 inode
     */
    private static int findListeningPort(Set<String> targetInodes) {
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(new FileInputStream("/proc/net/tcp")))) {
            String line;
            boolean first = true;
            while ((line = r.readLine()) != null) {
                if (first) { first = false; continue; }
                String[] cols = line.trim().split("\\s+");
                if (cols.length < 10) continue;

                String st    = cols[3];  // 状态 (0A=LISTEN)
                String local = cols[1];  // local_address
                String inode = cols[9];  // inode

                if (!"0A".equals(st)) continue;          // 只要 LISTEN
                if (!targetInodes.contains(inode)) continue; // 只要 adbd 的 socket

                String[] addrParts = local.split(":");
                if (addrParts.length == 2) {
                    int port = Integer.parseInt(addrParts[1], 16);
                    if (port >= 1024) return port;
                }
            }
        } catch (Exception ignored) {}
        return -1;
    }

    /**
     * 策略: 通过 getprop 获取端口
     */
    public static int detectViaGetprop() {
        String[] keys = {
            "service.adb.tcp.port",
            "persist.adb.tcp.port",
            "persist.vendor.adb.tcp.port",
            "sys.adb.wireless.port",
        };
        for (String key : keys) {
            try {
                Process p = Runtime.getRuntime().exec(
                    new String[]{"getprop", key});
                String val = readFirstLine(p);
                if (val != null && !val.isEmpty() && !"-1".equals(val)) {
                    int port = Integer.parseInt(val.trim());
                    if (port > 0 && port <= 65535) return port;
                }
            } catch (Exception ignored) {}
        }
        return -1;
    }

    /**
     * 策略: 在指定范围内并发扫描
     */
    public static int scanRange(int start, int end, Callback callback) {
        java.util.concurrent.atomic.AtomicInteger result =
            new java.util.concurrent.atomic.AtomicInteger(-1);
        int threads = Math.min(30, (end - start) / 50 + 1);
        java.util.concurrent.ExecutorService executor =
            java.util.concurrent.Executors.newFixedThreadPool(threads);

        int batchSize = 50;
        for (int batchStart = start; batchStart <= end && result.get() == -1;
             batchStart += batchSize) {
            int batchEnd = Math.min(batchStart + batchSize - 1, end);
            for (int port = batchStart; port <= batchEnd; port++) {
                final int p = port;
                executor.submit(() -> {
                    if (result.get() != -1) return;
                    if (AdbConnection.isAdbdListening("127.0.0.1", p)) {
                        result.compareAndSet(-1, p);
                        if (callback != null) {
                            callback.onLog("扫描命中端口: " + p);
                        }
                    }
                });
            }
            // 每批等一小段时间
            try { Thread.sleep(100); } catch (InterruptedException e) { break; }
        }

        executor.shutdown();
        try { executor.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS); }
        catch (InterruptedException ignored) {}

        return result.get();
    }

    /** 回调接口，用于输出日志 */
    public interface Callback {
        void onLog(String msg);
    }
}
