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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * VlessVpnService — 合并版本（将 SOCKS5 代理内嵌到 VpnService 中运行）
 *
 * ════════════════════════════════════════════════════════
 * 修复的 Bug 列表
 * ════════════════════════════════════════════════════════
 *
 * [Bug 1 — 本次新增修复] protect(socket) FAILED
 *   现象：日志持续输出 "protect(socket) FAILED — possible routing loop!"
 *   原因：VlessProxyService 是独立 Service，跨 Service 调用
 *         VlessVpnService.instance.protect() 时，Android 的 VpnService
 *         内部会校验调用方的 Binder 身份，只允许 VpnService 自身调用
 *         protect()。跨 Service 调用会静默失败（返回 false）。
 *         protect 失败 → OkHttp socket 被路由进 TUN → DNS/连接死循环。
 *   修复：将 SOCKS5 acceptLoop 和所有 OkHttp 连接逻辑迁移到
 *         VlessVpnService 内部（通过 VlessProxyManager 辅助类），
 *         直接 this.protect() 调用，彻底消除跨 Service protect 失败。
 *
 * [Bug 2 — 本次新增修复] tun2socks "initialization before done"
 *   现象：第二次连接时日志打印 "initialization before done"，
 *         tun2socks 实际没有运行，TUN fd 无人消费，流量全部丢弃。
 *   原因：Tun2Socks.stopTun2Socks() 是异步的，上一次 native 线程还未
 *         退出，下一次 startVpn() 就调用了 initialize()，native 层
 *         检测到重复初始化并拒绝，startTun2Socks() 立即返回。
 *   修复：引入 tun2socksLatch（CountDownLatch），在 tun2socksThread 的
 *         finally 块 countDown，startVpn() 开始时 await 上一个 latch，
 *         确保 native 层完全退出后再执行下一次 initialize()。
 *
 * [Bug 3 — 上次修复] onDestroy() 中 instance = null 顺序错误
 *   修复：先 stopVpn()，最后才 instance = null。
 *
 * [Bug 4 — 上次修复] ServerSocket 端口未释放导致 BindException
 *   修复：SO_REUSEADDR + 重启前先 closeServerSocket()。
 *
 * [Bug 5 — 上次修复] stopVpn() 未 join tun2socksThread 就 close vpnFd
 *   修复：join(3000) 后再 close fd。
 */
public class VlessVpnService extends VpnService {
    private static final String TAG       = "VlessVpnService";
    static final String ACTION_START      = "START_VPN";
    static final String ACTION_STOP       = "STOP_VPN";
    static final String ACTION_RESTART    = "RESTART_VPN";   // 原子重连，避免时序竞态
    static final String EXTRA_CONFIG_JSON = "config_json";

    private static final String CHANNEL_ID = "vless_vpn";
    private static final int    NOTIF_ID   = 1;

    private static final int    MTU           = 1500;
    private static final String TUN_IP4       = "10.0.0.2";
    private static final String TUN_IP6       = "fd00::2";
    private static final String TUN_NETMASK   = "255.255.255.0";
    private static final String DNS_PRIMARY   = "8.8.8.8";
    private static final String DNS_SECONDARY = "1.1.1.1";

    private static final int SOCKS5_READY_TIMEOUT_SEC = 15;

    /**
     * 供 VlessProxyManager 使用。
     * 现在 protect() 在同一个 VpnService 内调用，不再有 Binder 身份校验问题。
     */
    static volatile VlessVpnService instance = null;

    private ParcelFileDescriptor vpnFd;
    private Thread               tun2socksThread;

    /**
     * [Bug 2 修复] 追踪 tun2socks native 线程的真实退出时机。
     * tun2socksThread finally 块 countDown；
     * startVpn() 开始时 await 上一个 latch。
     */
    private volatile CountDownLatch tun2socksLatch = null;

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

        // ACTION_RESTART：原子化 stop → start，彻底解决两个 Intent 时序竞态问题
        if (ACTION_RESTART.equals(intent.getAction())) {
            configJson = intent.getStringExtra(EXTRA_CONFIG_JSON);
            if (configJson == null) { stopSelf(); return START_NOT_STICKY; }
            VpnStateHolder.setState(VpnStateHolder.State.CONNECTING);
            new Thread(() -> {
                // 先完整 stop（内部已 join tun2socks 线程）
                stopVpn();
                stopping.set(false); // 重置停止标志
                try {
                    startForeground(NOTIF_ID, buildNotification("VPN reconnecting…"));
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
        // [Bug 3 修复] 先释放资源，最后才清 instance
        stopVpn();
        instance = null;
        super.onDestroy();
    }

    // ── Start ─────────────────────────────────────────────────────────────

    private void startVpn() throws Exception {
        // ── 等待上一次 tun2socks 完全退出（仅重连时需要）─────────────────────
        CountDownLatch prevLatch = tun2socksLatch;
        if (prevLatch != null) {
            // 等 Java 线程退出
            Log.i(TAG, "Waiting for previous tun2socks thread to exit...");
            if (!prevLatch.await(6, TimeUnit.SECONDS)) {
                Log.w(TAG, "tun2socks thread did not exit in 6s");
            }
            // 等线程对象终止
            Thread prevThread = tun2socksThread;
            if (prevThread != null && prevThread.isAlive()) {
                Log.i(TAG, "Joining tun2socksThread...");
                prevThread.join(5000);
            }
            // 轮询等 native 清理完毕
            Log.i(TAG, "Waiting for native tun2socks to fully clean up...");
            for (int attempt = 0; attempt < 20; attempt++) {
                try {
                    Tun2Socks.initialize(getApplicationContext());
                    Log.i(TAG, "tun2socks native ready (attempt " + (attempt + 1) + ")");
                    break;
                } catch (Exception e) {
                    Log.w(TAG, "initialize attempt " + (attempt + 1) + " failed: " + e.getMessage());
                    Thread.sleep(500);
                }
            }
        } else {
            // 首次连接，native 库尚未加载，直接 initialize
            Log.i(TAG, "First start, initializing tun2socks native...");
            Tun2Socks.initialize(getApplicationContext());
        }

        // 启动内置 SOCKS5（在本 Service 内运行，protect() 直接有效）
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

        // [Bug 2 修复] 为本次 tun2socks 创建新 latch
        CountDownLatch latch = new CountDownLatch(1);
        tun2socksLatch = latch;

        final ParcelFileDescriptor fd = vpnFd;
        tun2socksThread = new Thread(() -> {
            try {
                updateNotification("VPN connected → " + getServerName());
                VpnStateHolder.setState(VpnStateHolder.State.CONNECTED);
                Log.i(TAG, "Starting tun2socks → SOCKS5 127.0.0.1:" + VlessConfig.SOCKS5_PORT);

                boolean ok = false;
                int retryCount = 0;
                while (!stopping.get() && retryCount < 5) {
                    long startMs = System.currentTimeMillis();
                    ok = Tun2Socks.startTun2Socks(
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
                    long elapsed = System.currentTimeMillis() - startMs;
                    Log.i(TAG, "tun2socks exited, ok=" + ok + ", elapsed=" + elapsed + "ms");

                    // 如果极短时间内就退出（< 500ms），说明 native 初始化失败（"initialization before done"）
                    // 等待 native 清理后重试 initialize + startTun2Socks
                    if (!ok && elapsed < 500 && !stopping.get()) {
                        retryCount++;
                        Log.w(TAG, "tun2socks exited too fast (native not ready?), retry " + retryCount + "/5 after 1s...");
                        try { Thread.sleep(1000); } catch (InterruptedException ie) { break; }
                        try {
                            Tun2Socks.initialize(getApplicationContext());
                        } catch (Exception e) {
                            Log.w(TAG, "re-initialize failed: " + e.getMessage());
                        }
                    } else {
                        // 正常退出（被 stop 触发）或运行了足够长时间，不重试
                        break;
                    }
                }
            } finally {
                latch.countDown();
                VpnStateHolder.setState(VpnStateHolder.State.DISCONNECTED);
            }
        }, "tun2socks-thread");
        tun2socksThread.setDaemon(true);
        tun2socksThread.start();
    }

    // ── 内置 SOCKS5 服务器 ────────────────────────────────────────────────

    /**
     * 内置 SOCKS5 服务器运行在 VlessVpnService 内部。
     * 所有 protect() 调用直接走 VlessVpnService.this，完全合法。
     *
     * [Bug 1 修复 - 加强版] startProxyServer 开始时强制 reset stopping 标志，
     * 防止上一次 stopVpn() 设置的 stopping=true 泄漏到新的 acceptLoop，
     * 导致新 acceptLoop 建立后立即退出。
     */
    private void startProxyServer() throws IOException {
        // 重置停止标志，确保新的 acceptLoop 能正常运行
        stopping.set(false);
        closeServerSocket();
        if (proxyPool != null) proxyPool.shutdownNow();
        proxyPool = Executors.newCachedThreadPool();

        VlessConfig cfg = ConfigStore.fromJson(configJson);

        // [Bug 4 修复] SO_REUSEADDR 保证端口立即可复用
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
                    // VlessProxyManager 持有 VlessVpnService 引用，
                    // 在其内部调用 vpnService.protect() — 同一个 Service，合法
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
                protect(s); // 在 VpnService 内调用，100% 有效
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

        // 1. 停止接受新连接
        closeServerSocket();
        if (proxyPool != null) {
            proxyPool.shutdownNow();
            proxyPool = null;
        }

        // 2. 停止 tun2socks（仅在 native 库已加载时调用，否则会 UnsatisfiedLinkError）
        if (tun2socksThread != null) {
            try { Tun2Socks.stopTun2Socks(); } catch (UnsatisfiedLinkError | Exception ignored) {}
        }

        // 3. [Bug 5 修复 - 加强版] join tun2socksThread，等它退出后再 close fd
        //    join 超时设为 5s（native 退出通常 < 1s，给足余量）
        if (tun2socksThread != null) {
            tun2socksThread.interrupt();
            try {
                tun2socksThread.join(5000);
                if (tun2socksThread.isAlive()) {
                    Log.w(TAG, "tun2socksThread still alive after 5s join, forcing continue");
                }
            } catch (InterruptedException ignored) {}
            tun2socksThread = null;
        }

        // 4. 关闭 TUN fd（在 tun2socks 线程退出后，fd 才能安全关闭）
        if (vpnFd != null) {
            try { vpnFd.close(); } catch (IOException ignored) {}
            vpnFd = null;
        }

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