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
 * 架构说明：
 *
 * tun2socks（badvpn）内部有大量 C 全局状态（BLog、BSignal、BReactor 等），
 * 无法在同一进程内安全地多次 start/stop。
 *
 * 解决方案：让 tun2socks 线程持续运行整个 VPN 生命周期，永不中途重启。
 * 重连操作（切换服务器、网络变化）只重建 SOCKS5 代理层（ProxySession），
 * tun2socks 和 TUN 接口保持不变，流量自然切换。
 *
 * 生命周期：
 *   VPN 开启 → TUN 建立 → tun2socks 启动 → ProxySession 启动
 *   用户切换配置 → 旧 ProxySession 关闭 → 新 ProxySession 启动（tun2socks 不动）
 *   VPN 关闭 → ProxySession 关闭 → tun2socks 终止 → TUN 关闭
 */
public class VlessVpnService extends VpnService {
    private static final String TAG       = "VlessVpnService";
    static final String ACTION_START      = "START_VPN";
    static final String ACTION_STOP       = "STOP_VPN";
    static final String ACTION_RESTART    = "RESTART_VPN";
    static final String EXTRA_CONFIG_JSON = "config_json";

    private static final String CHANNEL_ID   = "vless_vpn";
    private static final int    NOTIF_ID     = 1;
    private static final int    MTU          = 1500;
    private static final String TUN_IP4      = "10.0.0.2";
    private static final String TUN_IP6      = "fd00::2";
    private static final String TUN_NETMASK  = "255.255.255.0";
    private static final String DNS_PRIMARY  = "8.8.8.8";
    private static final String DNS_SECONDARY= "1.1.1.1";

    static volatile VlessVpnService instance = null;

    // TUN 层（整个 VPN 生命周期只建立一次）
    private ParcelFileDescriptor vpnFd;
    private Thread               tun2socksThread;

    // 代理层（每次重连可以独立重启）
    private volatile ProxySession currentProxy;

    private String configJson;

    @Override public void onCreate() { super.onCreate(); instance = this; }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) return START_NOT_STICKY;
        String action = intent.getAction();

        if (ACTION_STOP.equals(action)) {
            doFullStop();
            stopSelf();
            return START_NOT_STICKY;
        }

        if (ACTION_START.equals(action) || ACTION_RESTART.equals(action)) {
            String json = intent.getStringExtra(EXTRA_CONFIG_JSON);
            if (json == null) { stopSelf(); return START_NOT_STICKY; }

            boolean isTunRunning = (tun2socksThread != null && tun2socksThread.isAlive());

            if (ACTION_RESTART.equals(action) && isTunRunning) {
                // TUN 层已在运行，只重启代理层
                configJson = json;
                VpnStateHolder.setState(VpnStateHolder.State.CONNECTING);
                new Thread(() -> restartProxyOnly(json), "proxy-restart").start();
            } else {
                // 全新启动（包括 TUN 层）
                configJson = json;
                VpnStateHolder.setState(VpnStateHolder.State.CONNECTING);
                startForeground(NOTIF_ID, buildNotification("VPN connecting..."));
                new Thread(() -> doFullStart(json), "vpn-start").start();
            }
            return START_STICKY;
        }

        return START_NOT_STICKY;
    }

    @Override public void onDestroy() { doFullStop(); instance = null; super.onDestroy(); }

    // ── 全量启动（TUN + tun2socks + 代理）────────────────────────────────

    private void doFullStart(String json) {
        VlessConfig cfg = ConfigStore.fromJson(json);
        if (cfg == null) {
            VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
            stopSelf(); return;
        }

        try {
            // Step 1：启动代理服务器
            ProxySession proxy = new ProxySession(cfg);
            proxy.start();
            currentProxy = proxy;
            if (!proxy.waitReady(15)) throw new IOException("SOCKS5 not ready");
            Log.i(TAG, "SOCKS5 ready");

            // Step 2：建立 TUN 接口
            vpnFd = buildTun();
            if (vpnFd == null) throw new IOException("establish() null");
            reportUnderlyingNetworks();

            // Step 3：启动 tun2socks（整个 VPN 期间只启动一次）
            Tun2Socks.initialize(getApplicationContext());
            startTun2Socks(vpnFd);

        } catch (Exception e) {
            Log.e(TAG, "doFullStart failed: " + e.getMessage());
            doFullStop();
            stopSelf();
        }
    }

    // ── 仅重启代理层（tun2socks 不动）────────────────────────────────────

    private void restartProxyOnly(String json) {
        VlessConfig cfg = ConfigStore.fromJson(json);
        if (cfg == null) {
            VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
            return;
        }

        // 关闭旧代理
        ProxySession oldProxy = currentProxy;
        currentProxy = null;
        if (oldProxy != null) oldProxy.stop();

        // 启动新代理
        try {
            ProxySession newProxy = new ProxySession(cfg);
            newProxy.start();
            currentProxy = newProxy;
            if (!newProxy.waitReady(10)) {
                Log.e(TAG, "New proxy not ready");
                VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
                return;
            }
            Log.i(TAG, "Proxy restarted successfully");
            updateNotification("VPN connected → " + cfg.server);
            VpnStateHolder.setState(VpnStateHolder.State.CONNECTED);
        } catch (Exception e) {
            Log.e(TAG, "restartProxyOnly failed: " + e.getMessage());
            VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
        }
    }

    // ── 全量停止 ──────────────────────────────────────────────────────────

    private void doFullStop() {
        // 1. 停代理
        ProxySession p = currentProxy;
        currentProxy = null;
        if (p != null) p.stop();

        // 2. 停 tun2socks
        if (tun2socksThread != null) {
            try { Tun2Socks.stopTun2Socks(); }
            catch (Exception | UnsatisfiedLinkError e) {
                Log.w(TAG, "stopTun2Socks: " + e.getMessage());
            }
            try { tun2socksThread.join(6_000); }
            catch (InterruptedException ignored) {}
            tun2socksThread = null;
        }

        // 3. 关 TUN fd
        closeFd();
        VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
        stopForeground(true);
    }

    // ── TUN 接口 ──────────────────────────────────────────────────────────

    private ParcelFileDescriptor buildTun() {
        try {
            Builder b = new Builder()
                    .setMtu(MTU)
                    .addAddress(TUN_IP4, 24).addAddress(TUN_IP6, 64)
                    .addRoute("0.0.0.0", 0).addRoute("::", 0)
                    .addDnsServer(DNS_PRIMARY).addDnsServer(DNS_SECONDARY)
                    .setSession("VLESS VPN");
            try { b.addDisallowedApplication(getPackageName()); }
            catch (Exception ignored) {}
            return b.establish();
        } catch (Exception e) {
            Log.e(TAG, "buildTun: " + e.getMessage());
            return null;
        }
    }

    private void startTun2Socks(final ParcelFileDescriptor fd) {
        tun2socksThread = new Thread(() -> {
            try {
                updateNotification("VPN connected");
                VpnStateHolder.setState(VpnStateHolder.State.CONNECTED);
                Log.i(TAG, "Starting tun2socks");

                Tun2Socks.startTun2Socks(
                        Tun2Socks.LogLevel.WARNING, fd, MTU,
                        "127.0.0.1", VlessConfig.SOCKS5_PORT,
                        "10.0.0.1", null, TUN_NETMASK, false,
                        Collections.emptyList());
                Log.i(TAG, "tun2socks exited");
            } catch (Exception e) {
                Log.e(TAG, "tun2socks error: " + e.getMessage());
            } finally {
                closeFd();
                ProxySession p = currentProxy;
                currentProxy = null;
                if (p != null) p.stop();
                VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
                stopSelf();
            }
        }, "t2s-main");
        tun2socksThread.setDaemon(true);
        tun2socksThread.start();
    }

    private synchronized void closeFd() {
        ParcelFileDescriptor f = vpnFd; vpnFd = null;
        if (f != null) try { f.close(); } catch (IOException ignored) {}
    }

    // ── ProxySession：可独立重启的代理层 ─────────────────────────────────

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
            t.setDaemon(true);
            t.start();
        }

        boolean waitReady(int timeoutSec) {
            long end = System.currentTimeMillis() + timeoutSec * 1000L;
            while (System.currentTimeMillis() < end && !stopped.get()) {
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress("127.0.0.1",
                            VlessConfig.SOCKS5_PORT), 300);
                    return true;
                } catch (IOException e) {
                    sleep(200);
                }
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
                try { c.dispatcher().executorService().shutdownNow();
                    c.connectionPool().evictAll(); }
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
        getSystemService(NotificationManager.class).notify(NOTIF_ID, buildNotification(text));
    }
}