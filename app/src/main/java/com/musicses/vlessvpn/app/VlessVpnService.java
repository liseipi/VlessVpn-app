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
import java.util.concurrent.atomic.AtomicBoolean;

import okhttp3.OkHttpClient;

/**
 * VPN Service 实现。
 *
 * 依赖条件：badvpn 源码必须修改，将以下变量去掉 static 关键字：
 *   - base/BLog.c:      static int blog_initialized = 0;  → int blog_initialized = 0;
 *   - system/BSignal.c: static int bsignal_initialized = 0; → int bsignal_initialized = 0;
 *                       static int bsignal_sigfd = -1;    → int bsignal_sigfd = -1;
 * 修改后重新编译 libtun2socks.a，然后 tun2socks.cpp 中的 dlsym 才能找到这些符号并重置。
 *
 * 架构：每次 Connect/Disconnect 都完整地 stop/start 整个 VPN 栈。
 * dlsym 重置 badvpn 全局状态后，tun2socks 可以安全地重复启动。
 */
public class VlessVpnService extends VpnService {
    private static final String TAG       = "VlessVpnService";
    static final String ACTION_START      = "START_VPN";
    static final String ACTION_STOP       = "STOP_VPN";
    static final String ACTION_RESTART    = "RESTART_VPN";
    static final String EXTRA_CONFIG_JSON = "config_json";

    private static final String CHANNEL_ID    = "vless_vpn";
    private static final int    NOTIF_ID      = 1;
    private static final int    MTU           = 1500;
    private static final String TUN_IP4       = "10.0.0.2";
    private static final String TUN_IP6       = "fd00::2";
    private static final String TUN_NETMASK   = "255.255.255.0";
    private static final String DNS_PRIMARY   = "8.8.8.8";
    private static final String DNS_SECONDARY = "1.1.1.1";

    static volatile VlessVpnService instance = null;

    private ParcelFileDescriptor vpnFd;
    private Thread               tun2socksThread;
    private volatile ProxySession currentProxy;
    private String                configJson;

    // ── Lifecycle ─────────────────────────────────────────────────────────

    @Override public void onCreate() { super.onCreate(); instance = this; }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) return START_NOT_STICKY;
        String action = intent.getAction();

        if (ACTION_STOP.equals(action)) {
            new Thread(this::doStop, "vpn-stop").start();
            return START_NOT_STICKY;
        }

        if (ACTION_START.equals(action) || ACTION_RESTART.equals(action)) {
            String json = intent.getStringExtra(EXTRA_CONFIG_JSON);
            if (json == null) { stopSelf(); return START_NOT_STICKY; }
            configJson = json;
            VpnStateHolder.setState(VpnStateHolder.State.CONNECTING);
            startForeground(NOTIF_ID, buildNotification("VPN connecting..."));
            new Thread(() -> doRestart(json), "vpn-restart").start();
            return START_STICKY;
        }

        return START_NOT_STICKY;
    }

    @Override public void onDestroy() {
        doStopInternal();
        instance = null;
        super.onDestroy();
    }

    // ── 核心流程 ──────────────────────────────────────────────────────────

    /** ACTION_RESTART：停旧的，启新的。串行执行。 */
    private void doRestart(String json) {
        doStopInternal();   // 完整停止（等 tun2socks 线程真正退出）
        doStartInternal(json);
    }

    /** ACTION_STOP */
    private void doStop() {
        doStopInternal();
        stopForeground(true);
        stopSelf();
    }

    private void doStartInternal(String json) {
        VlessConfig cfg = ConfigStore.fromJson(json);
        if (cfg == null) {
            VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
            stopSelf(); return;
        }
        try {
            // 1. 启动代理层
            ProxySession proxy = new ProxySession(cfg);
            proxy.start();
            currentProxy = proxy;
            if (!proxy.waitReady(15)) throw new IOException("SOCKS5 not ready");
            Log.i(TAG, "SOCKS5 ready");

            // 2. 建立 TUN
            vpnFd = buildTun();
            if (vpnFd == null) throw new IOException("establish() null");
            reportUnderlyingNetworks();

            // 3. 启动 tun2socks
            Tun2Socks.initialize(getApplicationContext());
            launchTun2Socks(vpnFd);

        } catch (Exception e) {
            Log.e(TAG, "start failed: " + e.getMessage());
            doStopInternal();
            stopSelf();
        }
    }

    private void doStopInternal() {
        // 停代理层
        ProxySession p = currentProxy;
        currentProxy = null;
        if (p != null) p.stop();

        // 停 tun2socks（发信号后等线程真正退出，确保全局状态已完成清理）
        Thread t = tun2socksThread;
        if (t != null && t.isAlive()) {
            try { Tun2Socks.stopTun2Socks(); }
            catch (Exception | UnsatisfiedLinkError e) { Log.w(TAG, "stopTun2Socks: " + e.getMessage()); }
            try { t.join(7_000); }
            catch (InterruptedException ignored) {}
            if (t.isAlive()) Log.w(TAG, "tun2socks thread still alive after 7s");
        }
        tun2socksThread = null;

        // 关 TUN fd
        closeFd();
        VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
    }

    private void launchTun2Socks(final ParcelFileDescriptor fd) {
        tun2socksThread = new Thread(() -> {
            try {
                Log.i(TAG, "Starting tun2socks");
                updateNotification("VPN connected");
                VpnStateHolder.setState(VpnStateHolder.State.CONNECTED);
                Tun2Socks.startTun2Socks(
                        Tun2Socks.LogLevel.WARNING, fd, MTU,
                        "127.0.0.1", VlessConfig.SOCKS5_PORT,
                        "10.0.0.1", null, TUN_NETMASK, false,
                        Collections.emptyList());
                Log.i(TAG, "tun2socks exited");
            } catch (Exception e) {
                Log.e(TAG, "tun2socks: " + e.getMessage());
            } finally {
                closeFd();
                ProxySession p = currentProxy; currentProxy = null;
                if (p != null) p.stop();
                VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
                if (instance != null) stopSelf();
            }
        }, "t2s-main");
        tun2socksThread.setDaemon(true);
        tun2socksThread.start();
    }

    private synchronized void closeFd() {
        ParcelFileDescriptor f = vpnFd; vpnFd = null;
        if (f != null) try { f.close(); } catch (IOException ignored) {}
    }

    // ── TUN builder ───────────────────────────────────────────────────────

    private ParcelFileDescriptor buildTun() {
        try {
            Builder b = new Builder()
                    .setMtu(MTU)
                    .addAddress(TUN_IP4, 24).addAddress(TUN_IP6, 64)
                    .addRoute("0.0.0.0", 0).addRoute("::", 0)
                    .addDnsServer(DNS_PRIMARY).addDnsServer(DNS_SECONDARY)
                    .setSession("VLESS VPN");
            try { b.addDisallowedApplication(getPackageName()); } catch (Exception ignored) {}
            return b.establish();
        } catch (Exception e) { Log.e(TAG, "buildTun: " + e.getMessage()); return null; }
    }

    // ── ProxySession ──────────────────────────────────────────────────────

    private class ProxySession {
        private final VlessConfig   cfg;
        private final AtomicBoolean stopped = new AtomicBoolean(false);
        private ServerSocket        serverSocket;
        private ExecutorService     proxyPool;
        private OkHttpClient        okHttpClient;

        ProxySession(VlessConfig cfg) { this.cfg = cfg; }

        void start() throws IOException {
            okHttpClient = VlessProxyManager.buildSharedClient(VlessVpnService.this, cfg);
            proxyPool    = Executors.newCachedThreadPool();
            ServerSocket ss = new ServerSocket();
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress(
                    InetAddress.getByName("127.0.0.1"), VlessConfig.SOCKS5_PORT), 512);
            serverSocket = ss;
            Log.i(TAG, "SOCKS5 listening on :10800");
            final OkHttpClient client = okHttpClient;
            Thread t = new Thread(() -> {
                while (!ss.isClosed() && !stopped.get()) {
                    try {
                        Socket sock = ss.accept();
                        sock.setTcpNoDelay(true);
                        proxyPool.execute(() ->
                                new VlessProxyManager(VlessVpnService.this, cfg, client)
                                        .handleClient(sock));
                    } catch (IOException e) {
                        if (!ss.isClosed() && !stopped.get())
                            Log.e(TAG, "accept: " + e.getMessage());
                    }
                }
                Log.i(TAG, "acceptLoop ended");
            }, "vless-accept");
            t.setDaemon(true); t.start();
        }

        boolean waitReady(int sec) {
            long end = System.currentTimeMillis() + sec * 1000L;
            while (System.currentTimeMillis() < end && !stopped.get()) {
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress("127.0.0.1", VlessConfig.SOCKS5_PORT), 300);
                    return true;
                } catch (IOException e) { sleep(150); }
            }
            return false;
        }

        void stop() {
            if (!stopped.compareAndSet(false, true)) return;
            ServerSocket ss = serverSocket; serverSocket = null;
            if (ss != null && !ss.isClosed()) try { ss.close(); } catch (IOException ignored) {}
            ExecutorService pool = proxyPool; proxyPool = null;
            if (pool != null) pool.shutdownNow();
            OkHttpClient c = okHttpClient; okHttpClient = null;
            if (c != null) {
                try { c.dispatcher().executorService().shutdownNow(); c.connectionPool().evictAll(); }
                catch (Exception ignored) {}
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private void reportUnderlyingNetworks() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (cm == null) return;
            List<Network> nets = new ArrayList<>();
            for (Network n : cm.getAllNetworks()) {
                NetworkCapabilities c = cm.getNetworkCapabilities(n);
                if (c == null || !c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
                if (c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
                nets.add(n);
            }
            if (!nets.isEmpty()) setUnderlyingNetworks(nets.toArray(new Network[0]));
        } catch (Exception e) { Log.w(TAG, "underlyingNetworks: " + e.getMessage()); }
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) {}
    }

    private Notification buildNotification(String text) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm.getNotificationChannel(CHANNEL_ID) == null)
            nm.createNotificationChannel(new NotificationChannel(
                    CHANNEL_ID, "VPN Status", NotificationManager.IMPORTANCE_LOW));
        Intent si = new Intent(this, VlessVpnService.class).setAction(ACTION_STOP);
        PendingIntent pi = PendingIntent.getService(this, 0, si,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("VLESS VPN").setContentText(text).setOngoing(true)
                .addAction(android.R.drawable.ic_delete, "Stop", pi).build();
    }

    private void updateNotification(String text) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null) nm.notify(NOTIF_ID, buildNotification(text));
    }
}