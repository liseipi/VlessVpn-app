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
import java.util.Collections;

/**
 * Android VpnService.
 *
 * FIX: 删除了 waitForSocks5() TCP 探测机制。
 *
 * 原来用一个 TCP connect 探测 SOCKS5 是否就绪，但：
 *  1. protect(s) 对 loopback 地址在 VPN 未建立时行为异常
 *  2. 日志显示 AppsFilter 将 tun2socks 库模块(uid=10214) 与主 app(uid=10213)
 *     判定为不同应用，跨进程 loopback 访问被 BLOCKED，导致探测永远失败
 *
 * 修复方案：
 *  - VlessProxyService 就绪后通过静态 volatile 标志通知，主服务轮询该标志
 *  - 完全绕开 TCP 探测，不再需要 protect()
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
    private static final String TUN_ROUTE4    = "0.0.0.0";
    private static final String TUN_ROUTE6    = "::";
    private static final String DNS_PRIMARY   = "8.8.8.8";
    private static final String DNS_SECONDARY = "1.1.1.1";

    /** VlessProxyService 就绪后设为 true，停止后重置为 false */
    static volatile boolean proxyReady = false;

    private ParcelFileDescriptor vpnFd;
    private Thread               tun2socksThread;
    private String               configJson;

    // ── Lifecycle ─────────────────────────────────────────────────────────

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
        super.onDestroy();
        stopVpn();
    }

    // ── Start ─────────────────────────────────────────────────────────────

    private void startVpn() throws IOException {
        // 1. 初始化 native 库
        Tun2Socks.initialize(getApplicationContext());

        // 2. 重置就绪标志
        proxyReady = false;

        // 3. 启动 VLESS SOCKS5 代理服务
        Intent proxyIntent = new Intent(this, VlessProxyService.class);
        proxyIntent.setAction(VlessProxyService.ACTION_START);
        proxyIntent.putExtra(VlessProxyService.EXTRA_CONFIG, configJson);
        startForegroundService(proxyIntent);

        // 4. 等待代理就绪（轮询 proxyReady 标志，由 VlessProxyService 设置）
        //    FIX: 不再使用 TCP 探测（会被 AppsFilter BLOCKED），改为内存标志
        Log.i(TAG, "Waiting for SOCKS5 proxy to become ready...");
        if (!waitForProxyReady(10_000)) {
            throw new IOException("SOCKS5 proxy did not become ready in time");
        }
        Log.i(TAG, "SOCKS5 proxy is ready");

        // 5. 建立 TUN 接口
        Builder builder = new Builder();
        builder.setMtu(MTU);
        builder.addAddress(TUN_IP4, 24);
        builder.addAddress(TUN_IP6, 64);
        builder.addRoute(TUN_ROUTE4, 0);
        builder.addRoute(TUN_ROUTE6, 0);
        builder.addDnsServer(DNS_PRIMARY);
        builder.addDnsServer(DNS_SECONDARY);
        builder.setSession("VLESS VPN");

        try {
            builder.addDisallowedApplication(getPackageName());
        } catch (android.content.pm.PackageManager.NameNotFoundException e) {
            Log.w(TAG, "addDisallowedApplication failed: " + e.getMessage());
        }

        vpnFd = builder.establish();
        if (vpnFd == null) throw new IOException("Failed to establish VPN interface");

        // 6. 启动 tun2socks
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

    // ── 等待代理就绪（轮询内存标志）────────────────────────────────────────

    /**
     * FIX: 替换原来的 TCP 探测。
     *
     * VlessProxyService 的 acceptLoop 在 ServerSocket.bind() 成功后
     * 会将 VlessVpnService.proxyReady 设为 true。
     * 这里每 100ms 轮询一次，最多等待 timeoutMs 毫秒。
     */
    private boolean waitForProxyReady(long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (proxyReady) return true;
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return proxyReady; // 最后再检查一次
    }

    // ── Stop ──────────────────────────────────────────────────────────────

    private void stopVpn() {
        proxyReady = false;
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