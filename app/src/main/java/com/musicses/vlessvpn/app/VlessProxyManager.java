package com.musicses.vlessvpn.app;

import android.net.VpnService;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
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

import javax.net.SocketFactory;
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
 * 关键设计：持有 VlessVpnService（VpnService 子类）引用，
 * 所有 protect() 调用在同一个 VpnService 上下文内执行，完全合法。
 *
 * 原先放在独立 VlessProxyService 里跨 Service 调用 protect() 会静默失败。
 */
public class VlessProxyManager {
    private static final String TAG = "VlessProxy";

    private final VpnService  vpnService;
    private final VlessConfig cfg;

    public VlessProxyManager(VpnService vpnService, VlessConfig cfg) {
        this.vpnService = vpnService;
        this.cfg        = cfg;
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
        OkHttpClient client = buildClient();
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

    // ── OkHttpClient：ProtectedDns + socketFactory + TLS ─────────────────

    private OkHttpClient buildClient() {
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
        SSLSocketFactory baseFactory = sslCtx.getSocketFactory();
        SSLSocketFactory sniFactory = new SSLSocketFactory() {
            @Override public String[] getDefaultCipherSuites() { return baseFactory.getDefaultCipherSuites(); }
            @Override public String[] getSupportedCipherSuites() { return baseFactory.getSupportedCipherSuites(); }
            private Socket withSni(Socket s) {
                if (s instanceof SSLSocket) {
                    try {
                        SSLParameters p = ((SSLSocket) s).getSSLParameters();
                        p.setServerNames(Collections.singletonList(new SNIHostName(sniHost)));
                        ((SSLSocket) s).setSSLParameters(p);
                    } catch (Exception e) { Log.w(TAG, "SNI failed: " + e.getMessage()); }
                }
                return s;
            }
            @Override public Socket createSocket() throws IOException { return withSni(baseFactory.createSocket()); }
            @Override public Socket createSocket(Socket s, String h, int p, boolean ac) throws IOException { return withSni(baseFactory.createSocket(s, sniHost, p, ac)); }
            @Override public Socket createSocket(String h, int p) throws IOException { return withSni(baseFactory.createSocket(h, p)); }
            @Override public Socket createSocket(String h, int p, InetAddress la, int lp) throws IOException { return withSni(baseFactory.createSocket(h, p, la, lp)); }
            @Override public Socket createSocket(InetAddress a, int p) throws IOException { return withSni(baseFactory.createSocket(a, p)); }
            @Override public Socket createSocket(InetAddress a, int p, InetAddress la, int lp) throws IOException { return withSni(baseFactory.createSocket(a, p, la, lp)); }
        };

        // socketFactory：每个 TCP socket 在创建时立即 protect()
        // vpnService 就是 VlessVpnService 自身，protect() 合法有效
        final VpnService svc = vpnService;
        SocketFactory protectedFactory = new SocketFactory() {
            private final SocketFactory def = SocketFactory.getDefault();
            private Socket p(Socket s) {
                if (svc != null && !svc.protect(s))
                    Log.e(TAG, "protect(socket) FAILED");
                return s;
            }
            @Override public Socket createSocket() throws IOException { return p(def.createSocket()); }
            @Override public Socket createSocket(String h, int port) throws IOException { return p(def.createSocket(h, port)); }
            @Override public Socket createSocket(String h, int port, InetAddress la, int lp) throws IOException { return p(def.createSocket(h, port, la, lp)); }
            @Override public Socket createSocket(InetAddress a, int port) throws IOException { return p(def.createSocket(a, port)); }
            @Override public Socket createSocket(InetAddress a, int port, InetAddress la, int lp) throws IOException { return p(def.createSocket(a, port, la, lp)); }
        };

        return new OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(60,  TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS)
                .pingInterval(25, TimeUnit.SECONDS)
                .hostnameVerifier((h, s) -> true)
                .sslSocketFactory(sniFactory, trustAll)
                .socketFactory(protectedFactory)
                .dns(new ProtectedDns(cfg.server, vpnService))
                .build();
    }

    // ── ProtectedDns ──────────────────────────────────────────────────────

    private static class ProtectedDns implements Dns {
        private static final String[] DNS_SERVERS = {"8.8.8.8", "8.8.4.4"};
        private static final long     TIMEOUT_MS  = 3_000L;

        private final String     serverHost;
        private final VpnService vpnService;
        private volatile List<InetAddress> sessionCache = null;

        ProtectedDns(String serverHost, VpnService vpnService) {
            this.serverHost = serverHost;
            this.vpnService = vpnService;
        }

        @Override
        public List<InetAddress> lookup(String hostname) throws UnknownHostException {
            if (!serverHost.equals(hostname)) {
                Log.w("ProtectedDns", "Unexpected host: " + hostname);
                return Dns.SYSTEM.lookup(hostname);
            }
            if (sessionCache != null) return sessionCache;
            List<InetAddress> resolved = tryResolveProtected();
            if (resolved != null && !resolved.isEmpty()) {
                sessionCache = resolved;
                Log.i("ProtectedDns", serverHost + " → " + resolved.get(0).getHostAddress());
                return resolved;
            }
            Log.w("ProtectedDns", "Protected DNS failed, falling back to system DNS");
            List<InetAddress> fallback = Dns.SYSTEM.lookup(hostname);
            if (!fallback.isEmpty()) { sessionCache = fallback; return fallback; }
            throw new UnknownHostException("ProtectedDns: cannot resolve " + hostname);
        }

        private List<InetAddress> tryResolveProtected() {
            if (vpnService == null) {
                try { return Dns.SYSTEM.lookup(serverHost); } catch (Exception e) { return null; }
            }
            byte[] query = buildDnsQuery(serverHost);
            AtomicReference<List<InetAddress>> result = new AtomicReference<>(null);
            CountDownLatch latch = new CountDownLatch(DNS_SERVERS.length);
            for (String dnsIp : DNS_SERVERS) {
                Thread t = new Thread(() -> {
                    try {
                        DatagramSocket sock = new DatagramSocket();
                        vpnService.protect(sock); // protect UDP socket，走物理网卡
                        sock.setSoTimeout((int) TIMEOUT_MS);
                        try {
                            InetAddress dest = InetAddress.getByName(dnsIp);
                            sock.send(new DatagramPacket(query, query.length, dest, 53));
                            byte[] buf = new byte[512];
                            DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                            sock.receive(pkt);
                            List<InetAddress> addrs = parseDnsARecords(buf, pkt.getLength());
                            if (!addrs.isEmpty()) result.compareAndSet(null, addrs);
                        } finally {
                            try { sock.close(); } catch (Exception ignored) {}
                        }
                    } catch (Exception e) {
                        Log.d("ProtectedDns", "DNS via " + dnsIp + " failed: " + e.getMessage());
                    } finally {
                        latch.countDown();
                    }
                });
                t.setDaemon(true);
                t.start();
            }
            try { latch.await(TIMEOUT_MS + 500, TimeUnit.MILLISECONDS); }
            catch (InterruptedException ignored) {}
            return result.get();
        }

        private static byte[] buildDnsQuery(String hostname) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(0x12); out.write(0x34);
            out.write(0x01); out.write(0x00);
            out.write(0x00); out.write(0x01);
            out.write(0x00); out.write(0x00);
            out.write(0x00); out.write(0x00);
            out.write(0x00); out.write(0x00);
            for (String label : hostname.split("\\.")) {
                out.write(label.length());
                for (byte b : label.getBytes()) out.write(b);
            }
            out.write(0x00);
            out.write(0x00); out.write(0x01);
            out.write(0x00); out.write(0x01);
            return out.toByteArray();
        }

        private static List<InetAddress> parseDnsARecords(byte[] buf, int len) {
            List<InetAddress> result = new java.util.ArrayList<>();
            if (len < 12) return result;
            int anCount = ((buf[6] & 0xFF) << 8) | (buf[7] & 0xFF);
            if (anCount == 0) return result;
            int pos = 12;
            while (pos < len) {
                int b = buf[pos] & 0xFF;
                if ((b & 0xC0) == 0xC0) { pos += 2; break; }
                if (b == 0) { pos++; break; }
                pos += b + 1;
            }
            pos += 4;
            for (int i = 0; i < anCount && pos < len; i++) {
                if ((buf[pos] & 0xC0) == 0xC0) { pos += 2; }
                else {
                    while (pos < len) {
                        int b = buf[pos] & 0xFF;
                        if ((b & 0xC0) == 0xC0) { pos += 2; break; }
                        if (b == 0) { pos++; break; }
                        pos += b + 1;
                    }
                }
                if (pos + 10 > len) break;
                int type  = ((buf[pos] & 0xFF) << 8) | (buf[pos+1] & 0xFF);
                int rdLen = ((buf[pos+8] & 0xFF) << 8) | (buf[pos+9] & 0xFF);
                pos += 10;
                if (type == 1 && rdLen == 4 && pos + 4 <= len) {
                    try { result.add(InetAddress.getByAddress(Arrays.copyOfRange(buf, pos, pos + 4))); }
                    catch (Exception ignored) {}
                }
                pos += rdLen;
            }
            return result;
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