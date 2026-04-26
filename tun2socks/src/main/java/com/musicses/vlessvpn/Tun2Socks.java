package com.musicses.vlessvpn;

import android.content.Context;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import android.util.Log;

import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class Tun2Socks {

    private static final String TAG = "tun2socks";

    // System.loadLibrary 本身是幂等的（同一 ClassLoader 下只加载一次）
    // 用 static initializer 加载，避免任何时序问题
    static {
        System.loadLibrary("tun2socks");
    }

    /**
     * 初始化（现在只是一个可选的显式调用点，实际加载由 static block 完成）。
     * 保留此方法以兼容现有调用代码，不再有任何副作用。
     */
    public static void initialize(Context context) {
        // 无需操作：static block 已完成库加载
        // 之前的 isInitialized 标志会导致第二次调用 initialize() 时打印
        // "initialization before done" 警告，这会误导调试
        Log.d(TAG, "initialize() called (library already loaded via static block)");
    }

    /**
     * 启动 tun2socks（阻塞，须在独立线程中调用）。
     *
     * @return true 表示正常退出（exitCode == 0），false 表示异常退出
     */
    public static boolean startTun2Socks(
            LogLevel logLevel,
            ParcelFileDescriptor vpnInterfaceFileDescriptor,
            int vpnInterfaceMtu,
            String socksServerAddress,
            int socksServerPort,
            String netIPv4Address,
            @Nullable String netIPv6Address,
            String netmask,
            boolean forwardUdp,
            List<String> extraArgs) {

        ArrayList<String> arguments = new ArrayList<>();
        arguments.add("badvpn-tun2socks");
        arguments.addAll(Arrays.asList("--logger", "stdout"));
        arguments.addAll(Arrays.asList("--loglevel", String.valueOf(logLevel.ordinal())));
        arguments.addAll(Arrays.asList("--tunfd",
                String.valueOf(vpnInterfaceFileDescriptor.getFd())));
        arguments.addAll(Arrays.asList("--tunmtu", String.valueOf(vpnInterfaceMtu)));
        arguments.addAll(Arrays.asList("--netif-ipaddr", netIPv4Address));

        if (!TextUtils.isEmpty(netIPv6Address)) {
            arguments.addAll(Arrays.asList("--netif-ip6addr", netIPv6Address));
        }

        arguments.addAll(Arrays.asList("--netif-netmask", netmask));
        arguments.addAll(Arrays.asList("--socks-server-addr",
                String.format(Locale.US, "%s:%d", socksServerAddress, socksServerPort)));

        if (forwardUdp) {
            arguments.add("--socks5-udp");
        }
        arguments.addAll(extraArgs);

        int exitCode = start_tun2socks(arguments.toArray(new String[]{}));
        Log.i(TAG, "startTun2Socks exitCode=" + exitCode);
        return exitCode == 0;
    }

    // ── Native 方法 ───────────────────────────────────────────────────────

    private static native int start_tun2socks(String[] args);

    public static native void stopTun2Socks();

    public static native void printTun2SocksHelp();

    public static native void printTun2SocksVersion();

    // ── LogLevel ─────────────────────────────────────────────────────────

    public enum LogLevel {
        NONE,    // 0
        ERROR,   // 1
        WARNING, // 2
        NOTICE,  // 3
        INFO,    // 4
        DEBUG    // 5
    }
}