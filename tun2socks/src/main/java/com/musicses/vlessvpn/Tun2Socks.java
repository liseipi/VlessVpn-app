package com.musicses.vlessvpn;

import android.content.Context;
import android.net.VpnService;
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
    private static volatile boolean isInitialized = false;

    /**
     * 加载 native 库（只加载一次，进程级别）。
     * System.loadLibrary 本身是幂等的，这里的 isInitialized 仅作为快速返回。
     */
    public static void initialize(Context context) {
        if (isInitialized) {
            Log.w(TAG, "initialization before done");
            return;
        }
        System.loadLibrary("tun2socks");
        isInitialized = true;
    }

    /**
     * 启动 tun2socks（阻塞，需在独立线程中调用）。
     *
     * 修复重连问题：
     *   badvpn 内部有一个全局终止标志，tun2socks_terminate() 设置它，
     *   tun2socks_start() 检查它——若已设置则立即返回，导致第二次连接失败。
     *   native 层的 reset_tun2socks_terminate_flag() 会在每次 start 前用
     *   dlsym 找到该标志并归零。若找不到（变量是 static），会打印 WARNING。
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

    /**
     * 启动 tun2socks（阻塞）。
     * native 层在调用 tun2socks_start() 前会先调用 reset_tun2socks_terminate_flag()
     * 以确保重连可以正常工作。
     */
    private static native int start_tun2socks(String[] args);

    /** 停止 tun2socks。 */
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