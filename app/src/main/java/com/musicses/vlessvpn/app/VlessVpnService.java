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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Android VpnService that:
 *   1. Starts VlessProxyService (SOCKS5 server)
 *   2. Waits until SOCKS5 port is actually accepting connections
 *   3. Establishes TUN interface
 *   4. Starts tun2socks routing TUN → SOCKS5
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

    // Max seconds to wait for SOCKS5 to become ready
    private static final int SOCKS5_READY_TIMEOUT_SEC = 10;

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

        // Run startup in background — don't block onStartCommand
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
        // 1. Initialize native library (idempotent guard is inside Tun2Socks)
        Tun2Socks.initialize(getApplicationContext());

        // 2. Start VLESS SOCKS5 proxy service
        Intent proxyIntent = new Intent(this, VlessProxyService.class);
        proxyIntent.setAction(VlessProxyService.ACTION_START);
        proxyIntent.putExtra(VlessProxyService.EXTRA_CONFIG, configJson);
        startForegroundService(proxyIntent);

        // 3. Wait until SOCKS5 is actually listening (poll with TCP probe)
        Log.i(TAG, "Waiting for SOCKS5 proxy on :" + VlessConfig.SOCKS5_PORT);
        if (!waitForSocks5(SOCKS5_READY_TIMEOUT_SEC)) {
            throw new IOException("SOCKS5 proxy did not become ready in time");
        }
        Log.i(TAG, "SOCKS5 proxy is ready");

        // 4. Build TUN interface
        Builder builder = new Builder();
        builder.setMtu(MTU);
        builder.addAddress(TUN_IP4, 24);
        builder.addAddress(TUN_IP6, 64);
        builder.addRoute(TUN_ROUTE4, 0);       // route all IPv4
        builder.addRoute(TUN_ROUTE6, 0);       // route all IPv6
        builder.addDnsServer(DNS_PRIMARY);
        builder.addDnsServer(DNS_SECONDARY);
        builder.setSession("VLESS VPN");

        // Exclude our own app from the VPN tunnel to avoid loop
        try {
            builder.addDisallowedApplication(getPackageName());
        } catch (android.content.pm.PackageManager.NameNotFoundException e) {
            Log.w(TAG, "addDisallowedApplication failed: " + e.getMessage());
        }

        vpnFd = builder.establish();
        if (vpnFd == null) throw new IOException("Failed to establish VPN interface");

        // 5. Start tun2socks — blocks until stopped
        final ParcelFileDescriptor fd = vpnFd;
        tun2socksThread = new Thread(() -> {
            // Mark connected now that everything is truly ready
            updateNotification("VPN connected → " + getServerName());
            VpnStateHolder.setState(VpnStateHolder.State.CONNECTED);

            Log.i(TAG, "Starting tun2socks → SOCKS5 127.0.0.1:" + VlessConfig.SOCKS5_PORT);
            boolean ok = Tun2Socks.startTun2Socks(
                    Tun2Socks.LogLevel.WARNING,
                    fd,
                    MTU,
                    "127.0.0.1",               // SOCKS5 server address
                    VlessConfig.SOCKS5_PORT,   // SOCKS5 port
                    "10.0.0.1",                // TUN gateway IPv4
                    null,                      // IPv6 (optional)
                    TUN_NETMASK,
                    false,                     // forwardUdp — VLESS is TCP only
                    Collections.emptyList()
            );
            Log.i(TAG, "tun2socks exited, ok=" + ok);
            VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
        }, "tun2socks-thread");
        tun2socksThread.setDaemon(true);
        tun2socksThread.start();
    }

    // ── Wait for SOCKS5 ready ─────────────────────────────────────────────

    /**
     * Polls TCP port until a connection succeeds or timeout expires.
     * IMPORTANT: must call protect() on the probe socket because VpnService
     * routes all unprotected sockets through the TUN — which doesn't exist yet,
     * causing the probe to fail even when SOCKS5 is listening.
     */
    private boolean waitForSocks5(int timeoutSec) {
        long deadline = System.currentTimeMillis() + timeoutSec * 1000L;
        while (System.currentTimeMillis() < deadline) {
            Socket s = new Socket();
            try {
                // protect() exempts this socket from VPN routing
                protect(s);
                s.connect(new InetSocketAddress("127.0.0.1", VlessConfig.SOCKS5_PORT), 300);
                s.close();
                return true;   // port is accepting connections
            } catch (IOException e) {
                try { s.close(); } catch (IOException ignored) {}
                // Not ready yet — wait a bit and retry
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
        // Stop proxy service
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
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.notify(NOTIF_ID, buildNotification(text));
    }

    private String getServerName() {
        VlessConfig cfg = ConfigStore.fromJson(configJson);
        return cfg != null ? cfg.server : "unknown";
    }
}