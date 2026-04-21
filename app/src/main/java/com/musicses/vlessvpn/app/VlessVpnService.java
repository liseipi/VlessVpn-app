package com.musicses.vlessvpn.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.musicses.vlessvpn.Tun2Socks;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Collections;

/**
 * Android VpnService.
 *
 * 对齐参考项目的核心设计：
 * 1. waitForSocks5() 探测 socket 必须先 protect()，否则 VpnService 会把探测包
 *    路由进 TUN（TUN 此时还没建立），导致探测永远失败。
 * 2. addRoute("0.0.0.0", 0) 全量路由 + addDisallowedApplication 排除本 App，
 *    配合 VlessProxyService 内部的 ProtectedDns + socketFactory protect() 解循环。
 * 3. 暴露 instance 引用，让 VlessProxyService 拿到真实 VpnService 对象调用 protect()。
 */
public class VlessVpnService extends VpnService {
    private static final String TAG       = "VlessVpnService";
    static final String ACTION_START      = "START_VPN";
    static final String ACTION_STOP       = "STOP_VPN";
    static final String EXTRA_CONFIG_JSON = "config_json";

    private static final String CHANNEL_ID = "vless_vpn";
    private static final int    NOTIF_ID   = 1;

    private static final int    MTU           = 1500;
    private static final String TUN_IP4       = "10.0.0.2";
    private static final String TUN_IP6       = "fd00::2";
    private static final String TUN_NETMASK   = "255.255.255.0";
    private static final String DNS_PRIMARY   = "8.8.8.8";
    private static final String DNS_SECONDARY = "1.1.1.1";

    private static final int SOCKS5_READY_TIMEOUT_SEC = 10;

    /** 暴露给 VlessProxyService，用于调用 protect() */
    static volatile VlessVpnService instance = null;

    private ParcelFileDescriptor vpnFd;
    private Thread               tun2socksThread;
    private String               configJson;

    // ── Lifecycle ─────────────────────────────────────────────────────────

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) return START_NOT_STICKY;

        if (ACTION_STOP.equals(intent.getAction())) {
            stopVpn();
            stopSelf();
            return START_NOT_STICKY;
        }

        configJson = intent.getStringExtra(EXTRA_CONFIG_JSON);
        if (configJson == null) { stopSelf(); return START_NOT_STICKY; }

        startForeground(NOTIF_ID, buildNotification("VPN connecting…"));

        new Thread(() -> {
            try {
                startVpn();
            } catch (Exception e) {
                Log.e(TAG, "Failed to start VPN: " + e.getMessage());
                VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
                stopSelf();
            }
        }, "vpn-startup").start();

        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        instance = null;
        super.onDestroy();
        stopVpn();
    }

    // ── Start ─────────────────────────────────────────────────────────────

    private void startVpn() throws IOException {
        Tun2Socks.initialize(getApplicationContext());

        // 启动 VLESS SOCKS5 代理服务
        Intent proxyIntent = new Intent(this, VlessProxyService.class);
        proxyIntent.setAction(VlessProxyService.ACTION_START);
        proxyIntent.putExtra(VlessProxyService.EXTRA_CONFIG, configJson);
        startForegroundService(proxyIntent);

        // 等待 SOCKS5 就绪：TCP 探测，关键是 protect(s) 必须在 connect 前调用
        Log.i(TAG, "Waiting for SOCKS5 proxy on :" + VlessConfig.SOCKS5_PORT);
        if (!waitForSocks5(SOCKS5_READY_TIMEOUT_SEC)) {
            throw new IOException("SOCKS5 proxy did not become ready in time");
        }
        Log.i(TAG, "SOCKS5 proxy is ready");

        // 建立 TUN 接口，全量路由 + 排除本 App
        Builder builder = new Builder();
        builder.setMtu(MTU);
        builder.addAddress(TUN_IP4, 24);
        builder.addAddress(TUN_IP6, 64);
        builder.addRoute("0.0.0.0", 0);   // 全量 IPv4
        builder.addRoute("::", 0);         // 全量 IPv6
        builder.addDnsServer(DNS_PRIMARY);
        builder.addDnsServer(DNS_SECONDARY);
        builder.setSession("VLESS VPN");

        // 排除本 App 流量，防止 Java 层 socket（OkHttp）进 TUN
        // native tun2socks socket 由 ProtectedDns + socketFactory.protect() 保护
        try {
            builder.addDisallowedApplication(getPackageName());
        } catch (android.content.pm.PackageManager.NameNotFoundException e) {
            Log.w(TAG, "addDisallowedApplication failed: " + e.getMessage());
        }

        vpnFd = builder.establish();
        if (vpnFd == null) throw new IOException("Failed to establish VPN interface");

        final ParcelFileDescriptor fd = vpnFd;
        tun2socksThread = new Thread(() -> {
            updateNotification("VPN connected → " + getServerName());
            VpnStateHolder.setState(VpnStateHolder.State.CONNECTED);

            Log.i(TAG, "Starting tun2socks → SOCKS5 127.0.0.1:" + VlessConfig.SOCKS5_PORT);
            boolean ok = Tun2Socks.startTun2Socks(
                    Tun2Socks.LogLevel.WARNING,
                    fd,
                    MTU,
                    "127.0.0.1",
                    VlessConfig.SOCKS5_PORT,
                    "10.0.0.1",
                    null,
                    TUN_NETMASK,
                    false,
                    Collections.emptyList()
            );
            Log.i(TAG, "tun2socks exited, ok=" + ok);
            VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
        }, "tun2socks-thread");
        tun2socksThread.setDaemon(true);
        tun2socksThread.start();
    }

    // ── 等待 SOCKS5 就绪（对齐参考项目）─────────────────────────────────────

    /**
     * 对参考项目 waitForSocks5() 的精确移植。
     *
     * 关键：protect(s) 必须在 s.connect() 之前调用。
     * 原因：VpnService 建立后，所有未 protect 的 socket 都会被路由进 TUN。
     * 即使 TUN 还未完全建立，探测包也可能被丢弃导致 connect 超时。
     * protect() 让探测 socket 直接走物理网卡，确保能连到 127.0.0.1:10800。
     */
    private boolean waitForSocks5(int timeoutSec) {
        long deadline = System.currentTimeMillis() + timeoutSec * 1000L;
        while (System.currentTimeMillis() < deadline) {
            Socket s = new Socket();
            try {
                protect(s);  // ← 必须在 connect 之前
                s.connect(new InetSocketAddress("127.0.0.1", VlessConfig.SOCKS5_PORT), 300);
                s.close();
                return true;
            } catch (IOException e) {
                try { s.close(); } catch (IOException ignored) {}
                try { Thread.sleep(150); } catch (InterruptedException ie) { return false; }
            }
        }
        return false;
    }

    // ── Stop ──────────────────────────────────────────────────────────────

    private void stopVpn() {
        try { Tun2Socks.stopTun2Socks(); } catch (Exception ignored) {}
        if (tun2socksThread != null) {
            tun2socksThread.interrupt();
            tun2socksThread = null;
        }
        if (vpnFd != null) {
            try { vpnFd.close(); } catch (IOException ignored) {}
            vpnFd = null;
        }
        Intent proxyStop = new Intent(this, VlessProxyService.class);
        proxyStop.setAction(VlessProxyService.ACTION_STOP);
        startService(proxyStop);

        VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
        stopForeground(true);
    }

    // ── Notification ──────────────────────────────────────────────────────

    private Notification buildNotification(String text) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "VPN Status", NotificationManager.IMPORTANCE_LOW);
            nm.createNotificationChannel(ch);
        }
        Intent stopIntent = new Intent(this, VlessVpnService.class);
        stopIntent.setAction(ACTION_STOP);
        PendingIntent stopPi = PendingIntent.getService(this, 0, stopIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("VLESS VPN")
                .setContentText(text)
                .setOngoing(true)
                .addAction(android.R.drawable.ic_delete, "Stop", stopPi)
                .build();
    }

    private void updateNotification(String text) {
        getSystemService(NotificationManager.class).notify(NOTIF_ID, buildNotification(text));
    }

    private String getServerName() {
        VlessConfig cfg = ConfigStore.fromJson(configJson);
        return cfg != null ? cfg.server : "unknown";
    }
}