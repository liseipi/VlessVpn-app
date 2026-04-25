package com.musicses.vlessvpn.app;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.util.Log;

import java.io.ByteArrayOutputStream;
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
 * ═══════════════════════════════════════════════════════════
 * 核心修复：彻底废弃 protect(socket)，改用 Network API
 * ═══════════════════════════════════════════════════════════
 *
 * 问题根源：
 *   真机（尤其 MIUI）上 VpnService.protect(socket) 对 OkHttp 创建的
 *   socket 持续返回 false，导致 WS 连接的 socket 没有被排除在 VPN 之外，
 *   流量绕回 TUN 接口形成死循环，WS 永远无法建立。
 *   同时 ProtectedDns 的 UDP DatagramSocket protect 也失败，
 *   导致 DNS 查询走进 TUN → 超时 → 服务器域名无法解析。
 *
 * 解决方案：
 *   通过 ConnectivityManager 找到底层物理网络（非 VPN 的 Network 对象），
 *   直接用 network.getSocketFactory() 创建 socket。
 *   这类 socket 在内核层面直接绑定到物理网卡，天然不走 TUN，
 *   完全不需要调用 protect()。
 *   DNS 解析同样通过该 Network 完成，绝不走 TUN。
 */
public class VlessProxyManager {
    private static final String TAG = "VlessProxy";

    private final VpnService  vpnService;
    private final VlessConfig cfg;

    public VlessProxyManager(VpnService vpnService, VlessConfig cfg) {
        this.vpnService = vpnService;
        this.cfg        = cfg;
    }

    // ── 获取底层物理 Network ──────────────────────────────────────────────

    /**
     * 遍历所有 Network，找到有 INTERNET 能力、但不是 VPN 的物理网络。
     * 优先返回 WIFI，其次 CELLULAR，都没有则返回第一个非 VPN 网络。
     *
     * 这是替代 protect() 的核心：用这个 Network 的 SocketFactory 创建的
     * socket 会直接走物理网卡，不经过 TUN。
     */
    private Network getUnderlyingNetwork() {
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
            // ACCESS_NETWORK_STATE 权限缺失，AndroidManifest.xml 里必须声明该权限
            Log.e(TAG, "Missing ACCESS_NETWORK_STATE permission! " +
                    "Add <uses-permission android:name=\"android.permission.ACCESS_NETWORK_STATE\"/> " +
                    "to AndroidManifest.xml. Error: " + e.getMessage());
            return null;
        }

        Network result = wifiNet != null ? wifiNet
                : cellNet != null ? cellNet
                : fallbackNet;

        if (result == null) {
            Log.w(TAG, "No underlying physical network found");
        } else {
            Log.d(TAG, "Using underlying network: " + result);
        }
        return result;
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
            out.write(new byte[]{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); out.flush();

            sock.setSoTimeout(0);
            byte[] earlyData = collectEarlyData(in);
            if (earlyData != null) Log.d(TAG, "earlyData: " + earlyData.length + "B");

            openTunnelAndRelay(sock, in, out, host, port, earlyData);

        } catch (Exception e) {
            Log.w(TAG, "socks5 error: " + e.getMessage());
            try { sock.close(); } catch (IOException ignored) {}
        }
    }

    // ── VLESS WebSocket 隧道 ──────────────────────────────────────────────

    private void openTunnelAndRelay(Socket sock, InputStream in, OutputStream out,
                                    String destHost, int destPort, byte[] earlyData) {
        // 每次连接都重新获取，确保在网络切换后能自动适应
        Network underlyingNetwork = getUnderlyingNetwork();
        OkHttpClient client = buildClient(underlyingNetwork);
        String wsUrl = cfg.buildWsUrl();

        Request request = new Request.Builder()
                .url(wsUrl)
                .header("Host",          cfg.wsHost.isEmpty() ? cfg.server : cfg.wsHost)
                .header("User-Agent",    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .header("Cache-Control", "no-cache")
                .header("Pragma",        "no-cache")
                .build();

        Log.i(TAG, "Opening WS → " + wsUrl + "  target=" + destHost + ":" + destPort);

        LinkedBlockingQueue<byte[]> inQueue = new LinkedBlockingQueue<>(4000);
        byte[] END_MARKER = new byte[0];
        AtomicBoolean closed = new AtomicBoolean(false);
        AtomicReference<WebSocket> wsRef = new AtomicReference<>(null);
        CountDownLatch openLatch = new CountDownLatch(1);
        AtomicBoolean openOk = new AtomicBoolean(false);

        client.newWebSocket(request, new WebSocketListener() {
            @Override
            public void onOpen(WebSocket ws, Response response) {
                if (!wsRef.compareAndSet(null, ws)) { ws.cancel(); return; }
                Log.i(TAG, "WS onOpen → " + destHost + ":" + destPort);
                byte[] header = VlessHeader.build(cfg.uuid, destHost, destPort);
                byte[] firstPkt = (earlyData != null && earlyData.length > 0)
                        ? concat(header, earlyData) : header;
                ws.send(ByteString.of(firstPkt));
                openOk.set(true);
                openLatch.countDown();
            }

            @Override
            public void onMessage(WebSocket ws, ByteString bytes) {
                if (!closed.get() && bytes.size() > 0) inQueue.offer(bytes.toByteArray());
            }

            @Override
            public void onClosing(WebSocket ws, int code, String reason) {
                Log.d(TAG, "WS closing: " + code);
                inQueue.offer(END_MARKER); ws.cancel();
            }

            @Override
            public void onClosed(WebSocket ws, int code, String reason) {
                inQueue.offer(END_MARKER);
            }

            @Override
            public void onFailure(WebSocket ws, Throwable t, Response response) {
                Log.e(TAG, "WS onFailure: " + t.getClass().getSimpleName() + ": " + t.getMessage());
                inQueue.offer(END_MARKER);
                openLatch.countDown();
            }
        });

        try {
            if (!openLatch.await(30, TimeUnit.SECONDS) || !openOk.get()) {
                Log.e(TAG, "WS open timeout or failed for " + destHost + ":" + destPort);
                try { sock.close(); } catch (IOException ignored) {}
                return;
            }
        } catch (InterruptedException e) {
            try { sock.close(); } catch (IOException ignored) {}
            return;
        }

        WebSocket ws = wsRef.get();

        // 下游：WS → sock（剥离 VLESS 响应头）
        Thread t1 = new Thread(() -> {
            byte[] respBuf = new byte[0];
            boolean respSkipped = false;
            int respHdrSize = -1;
            try {
                while (!closed.get()) {
                    byte[] chunk = inQueue.poll(120, TimeUnit.SECONDS);
                    if (chunk == null || chunk == END_MARKER) break;
                    byte[] payload;
                    if (respSkipped) {
                        payload = chunk;
                    } else {
                        respBuf = concat(respBuf, chunk);
                        if (respBuf.length < 2) continue;
                        if (respHdrSize == -1) respHdrSize = 2 + (respBuf[1] & 0xFF);
                        if (respBuf.length < respHdrSize) continue;
                        respSkipped = true;
                        payload = respBuf.length > respHdrSize
                                ? Arrays.copyOfRange(respBuf, respHdrSize, respBuf.length)
                                : null;
                        respBuf = new byte[0];
                    }
                    if (payload != null && payload.length > 0) {
                        try { out.write(payload); out.flush(); }
                        catch (Exception e) { break; }
                    }
                }
            } catch (Exception ignored) {
            } finally {
                try { out.close(); } catch (IOException ignored) {}
            }
        }, "VT-ws2l-" + destPort);
        t1.setDaemon(true);

        // 上游：sock → WS
        Thread t2 = new Thread(() -> {
            byte[] buf = new byte[32768];
            try {
                while (!closed.get()) {
                    int n;
                    try { n = in.read(buf); } catch (Exception e) { break; }
                    if (n < 0) break;
                    if (!ws.send(ByteString.of(buf, 0, n))) break;
                }
            } finally {
                inQueue.offer(END_MARKER);
                ws.cancel();
            }
        }, "VT-l2ws-" + destPort);
        t2.setDaemon(true);

        t1.start(); t2.start();
        try { t1.join(); t2.join(); } catch (InterruptedException ignored) {}
        closed.set(true);
        try { sock.close(); } catch (IOException ignored) {}
        Log.d(TAG, "relay ended [" + destHost + ":" + destPort + "]");
    }

    // ── OkHttpClient：基于 Network API，彻底不用 protect() ───────────────

    private OkHttpClient buildClient(Network underlyingNetwork) {

        // Trust-all TLS
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

        // SNI-aware SSLSocketFactory，基于 underlyingNetwork 的原始 SocketFactory
        final String sniHost = (cfg.sni != null && !cfg.sni.isEmpty()) ? cfg.sni : cfg.server;
        final SSLSocketFactory baseFactory = sslCtx.getSocketFactory();

        // 关键：用底层物理 Network 的 SocketFactory 作为基础
        // 通过该 factory 创建的 socket 在内核层面直接绑定到物理网卡，天然不走 TUN
        // 若 network 为 null（权限缺失），降级到 protect() 方案
        final javax.net.SocketFactory physicalFactory;
        if (underlyingNetwork != null) {
            physicalFactory = underlyingNetwork.getSocketFactory();
            Log.d(TAG, "Using Network.getSocketFactory() - no protect() needed");
        } else {
            // 降级方案：用 protect() 逐个保护 socket
            // 需要 AndroidManifest.xml 声明 ACCESS_NETWORK_STATE 权限才能走上面的主路径
            Log.w(TAG, "No physical network available, falling back to protect()");
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

        // 包装：在物理 SocketFactory 之上套 SSL + SNI
        SSLSocketFactory sniPhysicalFactory = new SSLSocketFactory() {

            private SSLSocket upgradeToSsl(Socket plain) throws IOException {
                SSLSocket ssl = (SSLSocket) baseFactory.createSocket(
                        plain, sniHost, plain.getPort(), true);
                SSLParameters p = ssl.getSSLParameters();
                p.setServerNames(Collections.singletonList(new SNIHostName(sniHost)));
                ssl.setSSLParameters(p);
                return ssl;
            }

            @Override
            public String[] getDefaultCipherSuites() {
                return baseFactory.getDefaultCipherSuites();
            }

            @Override
            public String[] getSupportedCipherSuites() {
                return baseFactory.getSupportedCipherSuites();
            }

            // OkHttp 主要走这个方法：先用物理 factory 建 TCP，再升级 SSL
            @Override
            public Socket createSocket(Socket s, String host, int port, boolean autoClose)
                    throws IOException {
                // s 是 OkHttp 传入的已连接 socket（由 physicalFactory 创建）
                // 直接升级到 SSL，SNI 设为我们的 sniHost
                return upgradeToSsl(s);
            }

            @Override
            public Socket createSocket() throws IOException {
                return physicalFactory.createSocket();
            }

            @Override
            public Socket createSocket(String host, int port) throws IOException {
                return upgradeToSsl(physicalFactory.createSocket(host, port));
            }

            @Override
            public Socket createSocket(String host, int port,
                                       java.net.InetAddress localAddr, int localPort)
                    throws IOException {
                return upgradeToSsl(physicalFactory.createSocket(host, port, localAddr, localPort));
            }

            @Override
            public Socket createSocket(java.net.InetAddress addr, int port) throws IOException {
                return upgradeToSsl(physicalFactory.createSocket(addr, port));
            }

            @Override
            public Socket createSocket(java.net.InetAddress addr, int port,
                                       java.net.InetAddress localAddr, int localPort)
                    throws IOException {
                return upgradeToSsl(physicalFactory.createSocket(addr, port, localAddr, localPort));
            }
        };

        // DNS：通过底层物理 Network 解析，完全不走 TUN
        Dns physicalDns = underlyingNetwork != null
                ? new NetworkBoundDns(underlyingNetwork, cfg.server)
                : Dns.SYSTEM;

        return new OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(60,    TimeUnit.SECONDS)
                .writeTimeout(60,   TimeUnit.SECONDS)
                .pingInterval(25,   TimeUnit.SECONDS)
                .hostnameVerifier((h, s) -> true)
                .sslSocketFactory(sniPhysicalFactory, trustAll)
                // socketFactory 用物理网络的，OkHttp 建 TCP 连接时走物理网卡
                .socketFactory(physicalFactory)
                .dns(physicalDns)
                .build();
    }

    // ── NetworkBoundDns：直接通过物理 Network 解析域名 ───────────────────

    /**
     * 通过指定的底层物理 Network 做 DNS 解析。
     * network.getAllByName() 在内核层面走该 Network 绑定的 DNS 服务器，
     * 不经过 TUN，不需要任何 protect()。
     */
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
            // 对代理服务器域名做缓存，避免每个 WS 连接都解析一次
            if (serverHost.equals(hostname) && cache != null) {
                return cache;
            }
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
                Log.w("ProtectedDns", "Network DNS failed for " + hostname
                        + ": " + e.getMessage() + ", falling back to SYSTEM");
                // 降级到系统 DNS
                return Dns.SYSTEM.lookup(hostname);
            }
        }
    }

    // ── I/O helpers ───────────────────────────────────────────────────────

    private byte[] collectEarlyData(InputStream in) {
        try {
            int avail = in.available();
            if (avail <= 0) return null;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[65536];
            while (avail > 0) {
                int n = in.read(buf, 0, Math.min(avail, buf.length));
                if (n <= 0) break;
                baos.write(buf, 0, n);
                avail = in.available();
            }
            return baos.size() > 0 ? baos.toByteArray() : null;
        } catch (Exception e) { return null; }
    }

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