package com.musicses.vlessvpn.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.net.SocketFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;
import okio.ByteString;

/**
 * A foreground service that listens on localhost SOCKS5,
 * and tunnels each connection through VLESS-over-WebSocket.
 *
 * FIXES applied:
 *   1. 删除"早期数据收集"线程 —— 原实现中两个线程同时读同一个 InputStream，
 *      造成数据被抢占/乱序。改为在 onOpen 里先发 VLESS 头，再单独启动上游 relay。
 *   2. onMessage 里 out.write() 后加 out.flush()，避免数据滞留缓冲区。
 *   3. 使用 VlessHeader（已修复，不再做 DNS 解析）构建头部。
 *   4. [核心修复] buildOkHttpClient() 注入自定义 SocketFactory，在每个 socket
 *      connect() 之前调用 VlessVpnService.protectSocket()，将出站连接绑定到物理
 *      网卡，彻底解决"代理自循环"（proxy loop）问题。
 *      addDisallowedApplication 在 Android 12+ 某些设备/模拟器上对 loopback 行为
 *      不稳定，逐 socket protect() 是官方推荐的正确做法。
 */
public class VlessProxyService extends Service {
    private static final String TAG = "VlessProxy";
    static final String ACTION_START = "START";
    static final String ACTION_STOP  = "STOP";
    static final String EXTRA_CONFIG = "config_json";

    private static final String CHANNEL_ID = "vless_proxy";
    private static final int    NOTIF_ID   = 2;

    private ServerSocket    serverSocket;
    private ExecutorService pool;
    private VlessConfig     cfg;
    private OkHttpClient    httpClient;

    static volatile String lastStatus = "Stopped";

    // ── Lifecycle ─────────────────────────────────────────────────────────

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) return START_NOT_STICKY;

        if (ACTION_STOP.equals(intent.getAction())) {
            stopSelf();
            return START_NOT_STICKY;
        }

        String json = intent.getStringExtra(EXTRA_CONFIG);
        cfg = ConfigStore.fromJson(json);
        if (cfg == null || !cfg.isValid()) {
            Log.e(TAG, "Invalid config");
            stopSelf();
            return START_NOT_STICKY;
        }

        startForeground(NOTIF_ID, buildNotification("VLESS proxy running"));
        pool = Executors.newCachedThreadPool();
        httpClient = buildOkHttpClient();

        pool.execute(this::acceptLoop);
        lastStatus = "Proxy running on :" + VlessConfig.SOCKS5_PORT;
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        lastStatus = "Stopped";
        if (pool != null) pool.shutdownNow();
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
        if (httpClient != null) httpClient.dispatcher().executorService().shutdown();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) { return null; }

    // ── Accept loop ───────────────────────────────────────────────────────

    private void acceptLoop() {
        try {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new java.net.InetSocketAddress(
                    InetAddress.getLoopbackAddress(), VlessConfig.SOCKS5_PORT));
            Log.i(TAG, "SOCKS5 listening on :" + VlessConfig.SOCKS5_PORT);

            // 通知 VlessVpnService 代理已就绪，替代 TCP 探测方案
            VlessVpnService.proxyReady = true;

            while (!serverSocket.isClosed()) {
                Socket client = serverSocket.accept();
                pool.execute(() -> handleSocks5(client));
            }
        } catch (IOException e) {
            if (serverSocket != null && !serverSocket.isClosed()) {
                Log.e(TAG, "accept error: " + e.getMessage());
            }
        }
    }

    // ── SOCKS5 handshake ──────────────────────────────────────────────────

    private void handleSocks5(Socket sock) {
        try {
            InputStream  in  = sock.getInputStream();
            OutputStream out = sock.getOutputStream();

            // Auth negotiation: VER(1) + NMETHODS(1)
            byte[] greet = readN(in, 2);
            if (greet == null || greet[0] != 0x05) { sock.close(); return; }
            int nmethods = greet[1] & 0xFF;
            readN(in, nmethods);
            out.write(new byte[]{0x05, 0x00}); // no auth

            // Request: VER(1) + CMD(1) + RSV(1) + ATYP(1)
            byte[] req = readN(in, 4);
            if (req == null || req[0] != 0x05 || req[1] != 0x01) { sock.close(); return; }

            String host;
            int    port;
            byte   atyp = req[3];

            if (atyp == 0x01) {           // IPv4
                byte[] ip = readN(in, 4);
                if (ip == null) { sock.close(); return; }
                host = (ip[0]&0xFF) + "." + (ip[1]&0xFF) + "." + (ip[2]&0xFF) + "." + (ip[3]&0xFF);
                port = readUint16(in);
            } else if (atyp == 0x03) {    // Domain
                int len = in.read() & 0xFF;
                byte[] dom = readN(in, len);
                if (dom == null) { sock.close(); return; }
                host = new String(dom);
                port = readUint16(in);
            } else if (atyp == 0x04) {    // IPv6
                byte[] ip6 = readN(in, 16);
                if (ip6 == null) { sock.close(); return; }
                host = InetAddress.getByAddress(ip6).getHostAddress();
                port = readUint16(in);
            } else { sock.close(); return; }

            // Reply: success
            out.write(new byte[]{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0});

            openTunnelAndRelay(sock, in, out, host, port);

        } catch (Exception e) {
            Log.w(TAG, "socks5 error: " + e.getMessage());
            try { sock.close(); } catch (IOException ignored) {}
        }
    }

    // ── Open VLESS WS tunnel and relay ────────────────────────────────────

    /**
     * 删除了原来的"早期数据收集"辅助线程。
     *
     * 原实现用一个额外线程在 WS 握手期间收集 early data，但这会导致
     * 两个线程（early data 线程 + onOpen 里的 relay 线程）同时读同一个
     * InputStream，造成数据被抢占、乱序、丢包。
     *
     * 正确做法：在 onOpen 里先发纯 VLESS 头（不含 payload），然后启动
     * 单一的上游 relay 线程独占读取 InputStream。
     * VLESS 协议允许头和数据分开发送，服务端会等待后续数据帧。
     */
    private void openTunnelAndRelay(Socket sock, InputStream in, OutputStream out,
                                    String host, int port) {
        Request request = new Request.Builder()
                .url(cfg.buildWsUrl())
                .header("Host",          cfg.wsHost)
                .header("User-Agent",    "Mozilla/5.0 (Linux; Android 13)")
                .header("Cache-Control", "no-cache")
                .header("Pragma",        "no-cache")
                .build();

        httpClient.newWebSocket(request, new WebSocketListener() {

            // VLESS 响应头跳过状态
            private byte[]  respBuf     = new byte[0];
            private boolean respSkipped = false;
            private int     respHdrSize = -1;

            @Override
            public void onOpen(WebSocket ws, Response response) {
                // 第一帧：仅发 VLESS 二进制头（不混入 payload，避免竞争）
                byte[] vlessHdr = VlessHeader.build(cfg.uuid, host, port);
                ws.send(ByteString.of(vlessHdr));

                // 上游 relay：sock → ws，单线程独占读取 InputStream
                pool.execute(() -> {
                    byte[] buf = new byte[4096];
                    try {
                        int n;
                        while ((n = in.read(buf)) > 0) {
                            ws.send(ByteString.of(buf, 0, n));
                        }
                    } catch (IOException ignored) {}
                    ws.close(1000, null);
                });
            }

            @Override
            public void onMessage(WebSocket ws, ByteString bytes) {
                // 下游 relay：ws → sock
                // 先跳过 VLESS 响应头（version(1) + addon_len(1) + addon(addon_len)）
                byte[] buf = bytes.toByteArray();
                try {
                    if (respSkipped) {
                        out.write(buf);
                        out.flush(); // 确保数据立即写出，不滞留缓冲区
                        return;
                    }

                    respBuf = concat(respBuf, buf);
                    if (respBuf.length < 2) return;

                    if (respHdrSize == -1) {
                        // byte[0]=version, byte[1]=addon_len => total skip = 2 + addon_len
                        respHdrSize = 2 + (respBuf[1] & 0xFF);
                    }
                    if (respBuf.length < respHdrSize) return;

                    respSkipped = true;
                    byte[] payload = Arrays.copyOfRange(respBuf, respHdrSize, respBuf.length);
                    respBuf = new byte[0];
                    if (payload.length > 0) {
                        out.write(payload);
                        out.flush();
                    }

                } catch (IOException e) {
                    ws.close(1000, null);
                }
            }

            @Override
            public void onClosing(WebSocket ws, int code, String reason) {
                ws.close(1000, null);
                try { sock.close(); } catch (IOException ignored) {}
            }

            @Override
            public void onFailure(WebSocket ws, Throwable t, @Nullable Response response) {
                Log.w(TAG, "ws failure: " + t.getMessage());
                try { sock.close(); } catch (IOException ignored) {}
            }
        });
    }

    // ── OkHttpClient: protect() + trust-all TLS + SNI injection ──────────

    /**
     * 构建 OkHttpClient。
     *
     * 核心修复：通过自定义 SocketFactory 在每个 socket 被 connect() 之前调用
     * VlessVpnService.protectSocket()，将 socket 绑定到物理网卡，防止出站的
     * WebSocket 连接被 TUN 接口拦截形成代理自循环（proxy loop）。
     *
     * OkHttp 调用自定义 SocketFactory.createSocket() 创建未连接的 socket，
     * 然后再调用 socket.connect()。我们在 createSocket() 时立即 protect()，
     * 时机正确，对 TLS 连接同样有效（SSLSocketFactory 会包装该 socket）。
     */
    private OkHttpClient buildOkHttpClient() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(0,  TimeUnit.SECONDS)
                .writeTimeout(0, TimeUnit.SECONDS);

        // ★ 核心修复：注入 protect()，防止出站 socket 被 TUN 拦截
        builder.socketFactory(new SocketFactory() {
            private final SocketFactory def = SocketFactory.getDefault();

            /** protect 后返回 socket，若失败只记录警告不中断连接 */
            private Socket p(Socket s) {
                VlessVpnService.protectSocket(s);
                return s;
            }

            @Override
            public Socket createSocket() throws IOException {
                return p(def.createSocket());
            }

            @Override
            public Socket createSocket(String host, int port) throws IOException {
                return p(def.createSocket(host, port));
            }

            @Override
            public Socket createSocket(String host, int port,
                                       InetAddress localAddr, int localPort) throws IOException {
                return p(def.createSocket(host, port, localAddr, localPort));
            }

            @Override
            public Socket createSocket(InetAddress addr, int port) throws IOException {
                return p(def.createSocket(addr, port));
            }

            @Override
            public Socket createSocket(InetAddress addr, int port,
                                       InetAddress localAddr, int localPort) throws IOException {
                return p(def.createSocket(addr, port, localAddr, localPort));
            }
        });

        try {
            final X509TrustManager trustManager;
            final SSLContext       sslContext;

            if (!cfg.rejectUnauthorized) {
                trustManager = new X509TrustManager() {
                    @Override public void checkClientTrusted(X509Certificate[] c, String a) {}
                    @Override public void checkServerTrusted(X509Certificate[] c, String a) {}
                    @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                };
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[]{trustManager}, new SecureRandom());
                builder.hostnameVerifier((hostname, session) -> true);
            } else {
                TrustManagerFactory tmf = TrustManagerFactory
                        .getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init((KeyStore) null);
                trustManager = (X509TrustManager) tmf.getTrustManagers()[0];
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, null, null);
            }

            final String sniHost = (cfg.sni != null && !cfg.sni.isEmpty()) ? cfg.sni : cfg.server;
            final SSLSocketFactory baseFactory = sslContext.getSocketFactory();

            SSLSocketFactory sniFactory = new SSLSocketFactory() {
                @Override
                public String[] getDefaultCipherSuites() {
                    return baseFactory.getDefaultCipherSuites();
                }

                @Override
                public String[] getSupportedCipherSuites() {
                    return baseFactory.getSupportedCipherSuites();
                }

                private Socket withSni(Socket s) {
                    if (s instanceof SSLSocket) {
                        SSLSocket ssl = (SSLSocket) s;
                        try {
                            SSLParameters params = ssl.getSSLParameters();
                            params.setServerNames(Collections.singletonList(new SNIHostName(sniHost)));
                            ssl.setSSLParameters(params);
                        } catch (Exception e) {
                            Log.w(TAG, "SNI injection failed: " + e.getMessage());
                        }
                    }
                    return s;
                }

                @Override
                public Socket createSocket() throws IOException {
                    return withSni(baseFactory.createSocket());
                }

                @Override
                public Socket createSocket(Socket s, String h, int p, boolean autoClose)
                        throws IOException {
                    return withSni(baseFactory.createSocket(s, sniHost, p, autoClose));
                }

                @Override
                public Socket createSocket(String h, int p) throws IOException {
                    return withSni(baseFactory.createSocket(h, p));
                }

                @Override
                public Socket createSocket(String h, int p, InetAddress la, int lp)
                        throws IOException {
                    return withSni(baseFactory.createSocket(h, p, la, lp));
                }

                @Override
                public Socket createSocket(InetAddress a, int p) throws IOException {
                    return withSni(baseFactory.createSocket(a, p));
                }

                @Override
                public Socket createSocket(InetAddress a, int p, InetAddress la, int lp)
                        throws IOException {
                    return withSni(baseFactory.createSocket(a, p, la, lp));
                }
            };

            builder.sslSocketFactory(sniFactory, trustManager);

        } catch (Exception e) {
            Log.e(TAG, "TLS/SNI setup error: " + e.getMessage());
        }

        return builder.build();
    }

    // ── I/O helpers ───────────────────────────────────────────────────────

    private byte[] readN(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(buf, off, n - off);
            if (r < 0) return null;
            off += r;
        }
        return buf;
    }

    private int readUint16(InputStream in) throws IOException {
        int hi = in.read(), lo = in.read();
        if (hi < 0 || lo < 0) throw new IOException("EOF reading port");
        return (hi << 8) | lo;
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    // ── Notification ──────────────────────────────────────────────────────

    private Notification buildNotification(String text) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(new NotificationChannel(
                    CHANNEL_ID, "VLESS Proxy", NotificationManager.IMPORTANCE_LOW));
        }
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle("VLESS VPN")
                .setContentText(text)
                .setOngoing(true)
                .build();
    }
}