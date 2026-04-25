package com.musicses.vlessvpn.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.musicses.vlessvpn.Tun2Socks;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class VlessVpnService extends VpnService {
    private static final String TAG       = "VlessVpnService";
    static final String ACTION_START      = "START_VPN";
    static final String ACTION_STOP       = "STOP_VPN";
    static final String ACTION_RESTART    = "RESTART_VPN";
    static final String EXTRA_CONFIG_JSON = "config_json";

    private static final String CHANNEL_ID = "vless_vpn";
    private static final int    NOTIF_ID   = 1;

    private static final int    MTU           = 1500;
    private static final String TUN_IP4       = "10.0.0.2";
    private static final String TUN_IP6       = "fd00::2";
    private static final String TUN_NETMASK   = "255.255.255.0";
    private static final String DNS_PRIMARY   = "8.8.8.8";
    private static final String DNS_SECONDARY = "1.1.1.1";

    private static final int  SOCKS5_READY_TIMEOUT_SEC  = 15;
    private static final long NATIVE_CLEANUP_TIMEOUT_MS = 5_000L;
    private static final long NATIVE_CLEANUP_POLL_MS    = 200L;

    static volatile VlessVpnService instance = null;

    private volatile ParcelFileDescriptor vpnFd;
    private volatile Thread               tun2socksThread;
    private volatile boolean              nativeCleanDone = true;

    private String          configJson;
    private ServerSocket    serverSocket;
    private ExecutorService proxyPool;
    private final AtomicBoolean stopping = new AtomicBoolean(false);

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

        if (ACTION_RESTART.equals(intent.getAction())) {
            configJson = intent.getStringExtra(EXTRA_CONFIG_JSON);
            if (configJson == null) { stopSelf(); return START_NOT_STICKY; }
            VpnStateHolder.setState(VpnStateHolder.State.CONNECTING);
            new Thread(() -> {
                stopVpn();
                try {
                    startForeground(NOTIF_ID, buildNotification("VPN reconnecting..."));
                    startVpn();
                } catch (Exception e) {
                    Log.e(TAG, "Failed to restart VPN: " + e.getMessage());
                    VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
                    stopSelf();
                }
            }, "vpn-restart").start();
            return START_STICKY;
        }

        configJson = intent.getStringExtra(EXTRA_CONFIG_JSON);
        if (configJson == null) { stopSelf(); return START_NOT_STICKY; }

        stopping.set(false);
        startForeground(NOTIF_ID, buildNotification("VPN connecting..."));

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
        stopVpn();
        instance = null;
        super.onDestroy();
    }

    // ── Start ─────────────────────────────────────────────────────────────

    private void startVpn() throws Exception {
        waitForNativeClean();
        startProxyServer();

        Log.i(TAG, "Waiting for SOCKS5 proxy on :" + VlessConfig.SOCKS5_PORT);
        if (!waitForSocks5(SOCKS5_READY_TIMEOUT_SEC)) {
            throw new IOException("SOCKS5 proxy did not become ready in time");
        }
        Log.i(TAG, "SOCKS5 proxy is ready");

        Builder builder = new Builder();
        builder.setMtu(MTU);
        builder.addAddress(TUN_IP4, 24);
        builder.addAddress(TUN_IP6, 64);
        builder.addRoute("0.0.0.0", 0);
        builder.addRoute("::", 0);
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

        // 告知系统底层物理网络，改善路由和流量统计
        reportUnderlyingNetworks();

        nativeCleanDone = false;

        final ParcelFileDescriptor fd = vpnFd;
        tun2socksThread = new Thread(() -> {
            try {
                updateNotification("VPN connected -> " + getServerName());
                VpnStateHolder.setState(VpnStateHolder.State.CONNECTED);
                Log.i(TAG, "Starting tun2socks -> SOCKS5 127.0.0.1:" + VlessConfig.SOCKS5_PORT);

                Tun2Socks.startTun2Socks(
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
                Log.i(TAG, "tun2socks exited");

            } finally {
                Log.i(TAG, "tun2socks finally: calling stopTun2Socks for native cleanup");
                try {
                    Tun2Socks.stopTun2Socks();
                } catch (Exception | UnsatisfiedLinkError e) {
                    Log.w(TAG, "stopTun2Socks in finally: " + e.getMessage());
                }
                try { Thread.sleep(1500); } catch (InterruptedException ignored) {}

                nativeCleanDone = true;
                Log.i(TAG, "native cleanup done");

                closeFd();
                VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);

                if (!stopping.get()) {
                    Log.i(TAG, "tun2socks natural exit, stopping service");
                    stopSelf();
                }
            }
        }, "tun2socks-thread");
        tun2socksThread.setDaemon(true);
        tun2socksThread.start();
    }

    /** 把底层物理网络报告给系统，让系统了解 VPN 实际走哪个物理网卡 */
    private void reportUnderlyingNetworks() {
        try {
            ConnectivityManager cm = (ConnectivityManager)
                    getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return;

            List<Network> physicalNets = new ArrayList<>();
            for (Network net : cm.getAllNetworks()) {
                NetworkCapabilities caps = cm.getNetworkCapabilities(net);
                if (caps == null) continue;
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
                physicalNets.add(net);
            }

            if (!physicalNets.isEmpty()) {
                setUnderlyingNetworks(physicalNets.toArray(new Network[0]));
                Log.d(TAG, "setUnderlyingNetworks: " + physicalNets.size() + " network(s)");
            }
        } catch (Exception e) {
            Log.w(TAG, "reportUnderlyingNetworks: " + e.getMessage());
        }
    }

    private void waitForNativeClean() throws InterruptedException {
        if (nativeCleanDone) {
            Log.i(TAG, "First start or native already clean, initializing tun2socks...");
            try { Tun2Socks.initialize(getApplicationContext()); }
            catch (Exception e) { Log.w(TAG, "initialize: " + e.getMessage()); }
            return;
        }

        Log.i(TAG, "Waiting for previous tun2socks native to finish cleanup...");
        long deadline = System.currentTimeMillis() + NATIVE_CLEANUP_TIMEOUT_MS;
        while (!nativeCleanDone && System.currentTimeMillis() < deadline) {
            Thread.sleep(NATIVE_CLEANUP_POLL_MS);
        }
        if (!nativeCleanDone) {
            Log.w(TAG, "Timeout waiting for native cleanup, proceeding anyway");
        }
        Thread.sleep(200);

        try {
            Tun2Socks.initialize(getApplicationContext());
            Log.i(TAG, "tun2socks re-initialize OK");
        } catch (Exception e) {
            Log.w(TAG, "re-initialize: " + e.getMessage());
            Thread.sleep(500);
            try { Tun2Socks.initialize(getApplicationContext()); }
            catch (Exception e2) { Log.e(TAG, "re-initialize retry failed: " + e2.getMessage()); }
        }
    }

    // ── 内置 SOCKS5 服务器 ────────────────────────────────────────────────

    private void startProxyServer() throws IOException {
        stopping.set(false);
        closeServerSocket();
        if (proxyPool != null) proxyPool.shutdownNow();
        proxyPool = Executors.newCachedThreadPool();

        VlessConfig cfg = ConfigStore.fromJson(configJson);

        ServerSocket ss = new ServerSocket();
        ss.setReuseAddress(true);
        ss.bind(new InetSocketAddress(
                InetAddress.getByName("127.0.0.1"), VlessConfig.SOCKS5_PORT), 512);
        serverSocket = ss;

        Log.i(TAG, "SOCKS5 listening on 127.0.0.1:" + VlessConfig.SOCKS5_PORT);

        Thread acceptThread = new Thread(() -> {
            while (!ss.isClosed() && !stopping.get()) {
                try {
                    Socket client = ss.accept();
                    client.setTcpNoDelay(true);
                    proxyPool.execute(() ->
                            new VlessProxyManager(VlessVpnService.this, cfg).handleClient(client));
                } catch (IOException e) {
                    if (!ss.isClosed() && !stopping.get()) {
                        Log.e(TAG, "accept error: " + e.getMessage());
                    }
                }
            }
            Log.i(TAG, "acceptLoop ended");
        }, "vless-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    private void closeServerSocket() {
        ServerSocket ss = serverSocket;
        serverSocket = null;
        if (ss != null && !ss.isClosed()) {
            try { ss.close(); } catch (IOException ignored) {}
        }
    }

    // ── 等待 SOCKS5 就绪 ─────────────────────────────────────────────────

    private boolean waitForSocks5(int timeoutSec) {
        long deadline = System.currentTimeMillis() + timeoutSec * 1000L;
        while (System.currentTimeMillis() < deadline) {
            Socket s = new Socket();
            try {
                // 127.0.0.1 是 loopback，不走 TUN，不需要 protect
                s.connect(new InetSocketAddress("127.0.0.1", VlessConfig.SOCKS5_PORT), 300);
                s.close();
                return true;
            } catch (IOException e) {
                try { s.close(); } catch (IOException ignored) {}
                try { Thread.sleep(200); } catch (InterruptedException ie) { return false; }
            }
        }
        return false;
    }

    // ── Stop ──────────────────────────────────────────────────────────────

    private void stopVpn() {
        stopping.set(true);

        closeServerSocket();
        if (proxyPool != null) {
            proxyPool.shutdownNow();
            proxyPool = null;
        }

        if (tun2socksThread != null) {
            try { Tun2Socks.stopTun2Socks(); }
            catch (UnsatisfiedLinkError | Exception e) {
                Log.w(TAG, "stopTun2Socks: " + e.getMessage());
            }
        }

        Thread t = tun2socksThread;
        if (t != null) {
            t.interrupt();
            try {
                t.join(6_000);
                if (t.isAlive()) Log.w(TAG, "tun2socksThread still alive after 6s");
            } catch (InterruptedException ignored) {}
            tun2socksThread = null;
        }

        closeFd();
        VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
        stopForeground(true);
    }

    private synchronized void closeFd() {
        ParcelFileDescriptor fd = vpnFd;
        if (fd != null) {
            vpnFd = null;
            try { fd.close(); } catch (IOException ignored) {}
        }
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