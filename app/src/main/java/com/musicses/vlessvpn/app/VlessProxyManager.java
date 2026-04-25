package com.musicses.vlessvpn.app;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.Dns;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;
import okio.ByteString;

/**
 * 处理单个 SOCKS5 客户端连接并通过 VLESS WebSocket 转发流量。
 *
 * 修复了以下问题：
 * 1. earlyData 竞态：去除不可靠的 available() 探测，直接在 WS 建立后读取上游数据
 * 2. relay 逻辑优化：先建立 WS，再开始双向 relay，避免数据丢失
 * 3. OkHttpClient 按 VPN 连接生命周期复用，减少不必要的 socket 创建
 */
public class VlessProxyManager {
    private static final String TAG = "VlessProxy";

    // 读取缓冲区大小
    private static final int BUF_SIZE = 32768;

    private final VpnService  vpnService;
    private final VlessConfig cfg;

    // 每个 VlessProxyManager 实例共享一个 OkHttpClient
    // 由 VlessVpnService 传入，生命周期与 VPN 连接一致
    private final OkHttpClient sharedClient;

    public VlessProxyManager(VpnService vpnService, VlessConfig cfg, OkHttpClient sharedClient) {
        this.vpnService   = vpnService;
        this.cfg          = cfg;
        this.sharedClient = sharedClient;
    }

    // ── 获取底层物理 Network ──────────────────────────────────────────────

    public static Network getUnderlyingNetwork(VpnService vpnService) {
        ConnectivityManager cm = (ConnectivityManager)
                vpnService.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return null;

        Network wifiNet     = null;
        Network cellNet     = null;
        Network fallbackNet = null;

        try {
            for (Network net : cm.getAllNetworks()) {
                NetworkCapabilities caps = cm.getNetworkCapabilities(net);
                if (caps == null) continue;
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;

                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                    wifiNet = net;
                } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                    cellNet = net;
                } else if (fallbackNet == null) {
                    fallbackNet = net;
                }
            }
        } catch (SecurityException e) {
            Log.e(TAG, "Missing ACCESS_NETWORK_STATE: " + e.getMessage());
            return null;
        }

        Network result = wifiNet != null ? wifiNet
                : cellNet != null ? cellNet
                : fallbackNet;

        if (result != null) Log.d(TAG, "Using underlying network: " + result);
        return result;
    }

    // ── 构建共享 OkHttpClient ────────────────────────────────────────────

    public static OkHttpClient buildSharedClient(VpnService vpnService, VlessConfig cfg) {
        Network underlyingNetwork = getUnderlyingNetwork(vpnService);

        X509TrustManager trustAll = new X509TrustManager() {
            @Override public void checkClientTrusted(X509Certificate[] c, String a) {}
            @Override public void checkServerTrusted(X509Certificate[] c, String a) {}
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };

        SSLContext sslCtx;
        try {
            sslCtx = SSLContext.getInstance("TLS");
            sslCtx.init(null, new TrustManager[]{trustAll}, new SecureRandom());
        } catch (Exception e) {
            throw new RuntimeException("TLS init failed", e);
        }

        final String sniHost = (cfg.sni != null && !cfg.sni.isEmpty()) ? cfg.sni : cfg.server;
        final SSLSocketFactory baseFactory = sslCtx.getSocketFactory();

        final javax.net.SocketFactory physicalFactory;
        if (underlyingNetwork != null) {
            physicalFactory = underlyingNetwork.getSocketFactory();
            Log.d(TAG, "Using Network.getSocketFactory() - no protect() needed");
        } else {
            Log.w(TAG, "No physical network, falling back to protect()");
            final VpnService svc = vpnService;
            physicalFactory = new javax.net.SocketFactory() {
                private final javax.net.SocketFactory def = javax.net.SocketFactory.getDefault();
                private java.net.Socket p(java.net.Socket s) {
                    if (!svc.protect(s)) Log.e(TAG, "protect(socket) FAILED");
                    return s;
                }
                @Override public java.net.Socket createSocket() throws java.io.IOException { return p(def.createSocket()); }
                @Override public java.net.Socket createSocket(String h, int port) throws java.io.IOException { return p(def.createSocket(h, port)); }
                @Override public java.net.Socket createSocket(String h, int port, java.net.InetAddress la, int lp) throws java.io.IOException { return p(def.createSocket(h, port, la, lp)); }
                @Override public java.net.Socket createSocket(java.net.InetAddress a, int port) throws java.io.IOException { return p(def.createSocket(a, port)); }
                @Override public java.net.Socket createSocket(java.net.InetAddress a, int port, java.net.InetAddress la, int lp) throws java.io.IOException { return p(def.createSocket(a, port, la, lp)); }
            };
        }

        SSLSocketFactory sniPhysicalFactory = new SSLSocketFactory() {
            private SSLSocket upgradeToSsl(java.net.Socket plain) throws IOException {
                SSLSocket ssl = (SSLSocket) baseFactory.createSocket(
                        plain, sniHost, plain.getPort(), true);
                SSLParameters p = ssl.getSSLParameters();
                p.setServerNames(Collections.singletonList(new SNIHostName(sniHost)));
                ssl.setSSLParameters(p);
                return ssl;
            }
            @Override public String[] getDefaultCipherSuites() { return baseFactory.getDefaultCipherSuites(); }
            @Override public String[] getSupportedCipherSuites() { return baseFactory.getSupportedCipherSuites(); }
            @Override public java.net.Socket createSocket(java.net.Socket s, String host, int port, boolean autoClose) throws IOException { return upgradeToSsl(s); }
            @Override public java.net.Socket createSocket() throws IOException { return physicalFactory.createSocket(); }
            @Override public java.net.Socket createSocket(String host, int port) throws IOException { return upgradeToSsl(physicalFactory.createSocket(host, port)); }
            @Override public java.net.Socket createSocket(String host, int port, java.net.InetAddress la, int lp) throws IOException { return upgradeToSsl(physicalFactory.createSocket(host, port, la, lp)); }
            @Override public java.net.Socket createSocket(java.net.InetAddress addr, int port) throws IOException { return upgradeToSsl(physicalFactory.createSocket(addr, port)); }
            @Override public java.net.Socket createSocket(java.net.InetAddress addr, int port, java.net.InetAddress la, int lp) throws IOException { return upgradeToSsl(physicalFactory.createSocket(addr, port, la, lp)); }
        };

        Dns physicalDns = underlyingNetwork != null
                ? new NetworkBoundDns(underlyingNetwork, cfg.server)
                : Dns.SYSTEM;

        return new OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(0,     TimeUnit.SECONDS)   // 关键：WebSocket 不能有读超时
                .writeTimeout(30,   TimeUnit.SECONDS)
                .pingInterval(25,   TimeUnit.SECONDS)
                .hostnameVerifier((h, s) -> true)
                .sslSocketFactory(sniPhysicalFactory, trustAll)
                .socketFactory(physicalFactory)
                .dns(physicalDns)
                .build();
    }

    // ── SOCKS5 入口 ───────────────────────────────────────────────────────

    public void handleClient(Socket sock) {
        try {
            sock.setSoTimeout(30_000);
            InputStream  in  = sock.getInputStream();
            OutputStream out = sock.getOutputStream();

            // 握手
            byte[] greet = readN(in, 2);
            if (greet == null || greet[0] != 0x05) { sock.close(); return; }
            readN(in, greet[1] & 0xFF);
            out.write(new byte[]{0x05, 0x00}); out.flush();

            // 命令
            byte[] req = readN(in, 4);
            if (req == null || req[0] != 0x05 || req[1] != 0x01) { sock.close(); return; }

            String host; int port;
            switch (req[3]) {
                case 0x01: {
                    byte[] ip = readN(in, 4); if (ip == null) { sock.close(); return; }
                    host = (ip[0]&0xFF)+"."+(ip[1]&0xFF)+"."+(ip[2]&0xFF)+"."+(ip[3]&0xFF);
                    port = readUint16(in); break;
                }
                case 0x03: {
                    int len = in.read() & 0xFF;
                    byte[] dom = readN(in, len); if (dom == null) { sock.close(); return; }
                    host = new String(dom); port = readUint16(in); break;
                }
                case 0x04: {
                    byte[] ip6 = readN(in, 16); if (ip6 == null) { sock.close(); return; }
                    host = InetAddress.getByAddress(ip6).getHostAddress();
                    port = readUint16(in); break;
                }
                default: sock.close(); return;
            }

            Log.d(TAG, "SOCKS5 CONNECT → " + host + ":" + port);

            // 立即回复 SOCKS5 成功，告知 tun2socks 可以发数据了
            out.write(new byte[]{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0});
            out.flush();

            // 取消读超时，进入 relay 阶段
            sock.setSoTimeout(0);

            openTunnelAndRelay(sock, in, out, host, port);

        } catch (Exception e) {
            Log.w(TAG, "socks5 error: " + e.getMessage());
            try { sock.close(); } catch (IOException ignored) {}
        }
    }

    // ── VLESS WebSocket 隧道 ──────────────────────────────────────────────

    private void openTunnelAndRelay(Socket sock, InputStream in, OutputStream out,
                                    String destHost, int destPort) {
        String wsUrl = cfg.buildWsUrl();

        Request request = new Request.Builder()
                .url(wsUrl)
                .header("Host",          cfg.wsHost.isEmpty() ? cfg.server : cfg.wsHost)
                .header("User-Agent",    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .header("Cache-Control", "no-cache")
                .header("Pragma",        "no-cache")
                .build();

        Log.i(TAG, "Opening WS → " + wsUrl + "  target=" + destHost + ":" + destPort);

        // BUG FIX 1: 使用无界队列避免生产者阻塞
        LinkedBlockingQueue<byte[]> downQueue = new LinkedBlockingQueue<>();
        final byte[] END_MARKER = new byte[0];
        AtomicBoolean relayDone = new AtomicBoolean(false);
        AtomicReference<WebSocket> wsRef = new AtomicReference<>(null);
        CountDownLatch openLatch = new CountDownLatch(1);
        AtomicBoolean openOk = new AtomicBoolean(false);

        sharedClient.newWebSocket(request, new WebSocketListener() {
            @Override
            public void onOpen(WebSocket ws, Response response) {
                wsRef.set(ws);
                // BUG FIX 2: onOpen 时只发送 VLESS header，不发 earlyData
                // earlyData 由上游 relay 线程负责读取和发送，避免竞态
                byte[] header = VlessHeader.build(cfg.uuid, destHost, destPort);
                ws.send(ByteString.of(header));
                openOk.set(true);
                openLatch.countDown();
                Log.i(TAG, "WS onOpen → " + destHost + ":" + destPort);
            }

            @Override
            public void onMessage(WebSocket ws, ByteString bytes) {
                if (!relayDone.get() && bytes.size() > 0) {
                    downQueue.offer(bytes.toByteArray());
                }
            }

            @Override
            public void onClosing(WebSocket ws, int code, String reason) {
                Log.d(TAG, "WS closing: " + code);
                downQueue.offer(END_MARKER);
                ws.cancel();
            }

            @Override
            public void onClosed(WebSocket ws, int code, String reason) {
                downQueue.offer(END_MARKER);
            }

            @Override
            public void onFailure(WebSocket ws, Throwable t, Response response) {
                Log.e(TAG, "WS onFailure: " + t.getClass().getSimpleName() + ": " + t.getMessage());
                downQueue.offer(END_MARKER);
                openLatch.countDown();
            }
        });

        // 等待 WS 建立
        try {
            if (!openLatch.await(15, TimeUnit.SECONDS) || !openOk.get()) {
                Log.e(TAG, "WS open timeout/failed for " + destHost + ":" + destPort);
                try { sock.close(); } catch (IOException ignored) {}
                return;
            }
        } catch (InterruptedException e) {
            try { sock.close(); } catch (IOException ignored) {}
            return;
        }

        WebSocket ws = wsRef.get();
        if (ws == null) {
            try { sock.close(); } catch (IOException ignored) {}
            return;
        }

        // ── 下游线程：WS → sock（剥离 VLESS 响应头）──
        Thread downThread = new Thread(() -> {
            byte[] respBuf = new byte[0];
            boolean respSkipped = false;
            int respHdrSize = -1;
            try {
                while (!relayDone.get()) {
                    // BUG FIX 3: 使用有超时的 poll，避免永久阻塞
                    byte[] chunk = downQueue.poll(120, TimeUnit.SECONDS);
                    if (chunk == null || chunk == END_MARKER) break;

                    byte[] payload;
                    if (respSkipped) {
                        payload = chunk;
                    } else {
                        respBuf = concat(respBuf, chunk);
                        if (respBuf.length < 2) continue;
                        if (respHdrSize == -1) {
                            respHdrSize = 2 + (respBuf[1] & 0xFF);
                        }
                        if (respBuf.length < respHdrSize) continue;
                        respSkipped = true;
                        payload = respBuf.length > respHdrSize
                                ? Arrays.copyOfRange(respBuf, respHdrSize, respBuf.length)
                                : null;
                        respBuf = null; // GC
                    }

                    if (payload != null && payload.length > 0) {
                        out.write(payload);
                        out.flush();
                    }
                }
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                if (!relayDone.get()) {
                    Log.d(TAG, "downstream error [" + destHost + ":" + destPort + "]: " + e.getMessage());
                }
            } finally {
                relayDone.set(true);
                try { out.close(); } catch (IOException ignored) {}
            }
        }, "VT-down-" + destPort);
        downThread.setDaemon(true);

        // ── 上游线程：sock → WS ──
        // BUG FIX 4: 上游线程负责读取实际数据并发送，不再依赖 earlyData
        Thread upThread = new Thread(() -> {
            byte[] buf = new byte[BUF_SIZE];
            try {
                while (!relayDone.get()) {
                    int n = in.read(buf);
                    if (n < 0) break;
                    if (n > 0) {
                        // BUG FIX 5: 检查 send() 返回值，若 false 说明发送队列满或 WS 已关闭
                        if (!ws.send(ByteString.of(buf, 0, n))) {
                            Log.d(TAG, "WS send() returned false, upstream closing");
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                if (!relayDone.get()) {
                    Log.d(TAG, "upstream error [" + destHost + ":" + destPort + "]: " + e.getMessage());
                }
            } finally {
                // 上游结束 → 通知下游
                downQueue.offer(END_MARKER);
                ws.cancel();
            }
        }, "VT-up-" + destPort);
        upThread.setDaemon(true);

        downThread.start();
        upThread.start();

        try {
            downThread.join();
            upThread.join(3_000); // 给上游最多 3s 清理时间
        } catch (InterruptedException ignored) {}

        relayDone.set(true);
        try { sock.close(); } catch (IOException ignored) {}
        Log.d(TAG, "relay ended [" + destHost + ":" + destPort + "]");
    }

    // ── NetworkBoundDns ───────────────────────────────────────────────────

    private static class NetworkBoundDns implements Dns {
        private final Network network;
        private final String  serverHost;
        private volatile List<InetAddress> cache = null;

        NetworkBoundDns(Network network, String serverHost) {
            this.network    = network;
            this.serverHost = serverHost;
        }

        @Override
        public List<InetAddress> lookup(String hostname) throws java.net.UnknownHostException {
            if (serverHost.equals(hostname) && cache != null) return cache;
            try {
                InetAddress[] addrs = network.getAllByName(hostname);
                List<InetAddress> result = Arrays.asList(addrs);
                if (serverHost.equals(hostname)) {
                    cache = result;
                    Log.i("ProtectedDns", hostname + " → " + addrs[0].getHostAddress()
                            + " (via physical network)");
                }
                return result;
            } catch (Exception e) {
                Log.w("ProtectedDns", "Network DNS failed for " + hostname + ": " + e.getMessage());
                return Dns.SYSTEM.lookup(hostname);
            }
        }
    }

    // ── I/O helpers ───────────────────────────────────────────────────────

    private byte[] readN(InputStream in, int n) throws IOException {
        if (n == 0) return new byte[0];
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
}