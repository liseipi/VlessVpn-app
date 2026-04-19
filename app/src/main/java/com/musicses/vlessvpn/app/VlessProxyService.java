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
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;
import okio.ByteString;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

/**
 * A foreground service that listens on localhost SOCKS5,
 * and tunnels each connection through VLESS-over-WebSocket.
 *
 * Logic mirrors client.js:
 *   handleSocks5() → openTunnel() → buildVlessHeader() → relay()
 */
public class VlessProxyService extends Service {
    private static final String TAG = "VlessProxy";
    static final String ACTION_START = "START";
    static final String ACTION_STOP  = "STOP";
    static final String EXTRA_CONFIG = "config_json";

    private static final String CHANNEL_ID = "vless_proxy";
    private static final int    NOTIF_ID   = 2;

    private ServerSocket     serverSocket;
    private ExecutorService  pool;
    private VlessConfig      cfg;
    private OkHttpClient     httpClient;

    // Shared state for UI updates
    static volatile String lastStatus = "Stopped";

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

    // ── Accept loop ────────────────────────────────────────────────────────

    private void acceptLoop() {
        try {
            serverSocket = new ServerSocket(VlessConfig.SOCKS5_PORT, 50,
                    java.net.InetAddress.getLoopbackAddress());
            Log.i(TAG, "SOCKS5 listening on :" + VlessConfig.SOCKS5_PORT);

            while (!serverSocket.isClosed()) {
                Socket client = serverSocket.accept();
                pool.execute(() -> handleSocks5(client));
            }
        } catch (IOException e) {
            if (!serverSocket.isClosed()) {
                Log.e(TAG, "accept error: " + e.getMessage());
            }
        }
    }

    // ── SOCKS5 handshake (mirrors handleSocks5 in client.js) ──────────────

    private void handleSocks5(Socket sock) {
        try {
            InputStream  in  = sock.getInputStream();
            OutputStream out = sock.getOutputStream();

            // Auth negotiation
            byte[] greet = readN(in, 2);
            if (greet == null || greet[0] != 0x05) { sock.close(); return; }
            int nmethods = greet[1] & 0xFF;
            readN(in, nmethods); // discard method list
            out.write(new byte[]{0x05, 0x00}); // no auth

            // Request
            byte[] req = readN(in, 4);
            if (req == null || req[0] != 0x05 || req[1] != 0x01) { sock.close(); return; }

            String host;
            int    port;
            byte atyp = req[3];

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
                host = java.net.InetAddress.getByAddress(ip6).getHostAddress();
                port = readUint16(in);
            } else { sock.close(); return; }

            // Reply success
            out.write(new byte[]{0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0});

            openTunnelAndRelay(sock, in, out, host, port);

        } catch (Exception e) {
            Log.w(TAG, "socks5 error: " + e.getMessage());
            try { sock.close(); } catch (IOException ignored) {}
        }
    }

    // ── Open VLESS WS tunnel and relay (mirrors openTunnel + relay) ───────

    private void openTunnelAndRelay(Socket sock, InputStream in, OutputStream out,
                                    String host, int port) {
        String wsUrl = cfg.buildWsUrl();

        Request request = new Request.Builder()
                .url(wsUrl)
                .header("Host",          cfg.wsHost)
                .header("User-Agent",    "Mozilla/5.0 (Linux; Android 13)")
                .header("Cache-Control", "no-cache")
                .header("Pragma",        "no-cache")
                .build();

        // Collect early data while WS is connecting
        java.util.concurrent.LinkedBlockingQueue<byte[]> earlyData =
                new java.util.concurrent.LinkedBlockingQueue<>();
        java.util.concurrent.atomic.AtomicBoolean tunnelReady =
                new java.util.concurrent.AtomicBoolean(false);

        // Start reading early data in background
        pool.execute(() -> {
            byte[] buf = new byte[4096];
            try {
                int n;
                while (!tunnelReady.get() && (n = in.read(buf)) > 0) {
                    earlyData.add(Arrays.copyOf(buf, n));
                }
            } catch (IOException ignored) {}
        });

        httpClient.newWebSocket(request, new WebSocketListener() {

            // VLESS response skip state (mirrors relay() in client.js)
            private byte[]  respBuf     = new byte[0];
            private boolean respSkipped = false;
            private int     respHdrSize = -1;

            @Override
            public void onOpen(WebSocket ws, Response response) {
                tunnelReady.set(true);

                // Build first packet: VLESS header + early data
                byte[] vlessHdr = VlessHeader.build(cfg.uuid, host, port);
                java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                try {
                    baos.write(vlessHdr);
                    byte[] ed;
                    while ((ed = earlyData.poll()) != null) baos.write(ed);
                    ws.send(ByteString.of(baos.toByteArray()));
                } catch (IOException e) {
                    Log.e(TAG, "send vless hdr: " + e.getMessage());
                }

                // Forward sock→ws
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
                // Mirror relay() VLESS response header skip logic
                byte[] buf = bytes.toByteArray();
                try {
                    if (respSkipped) {
                        out.write(buf);
                        return;
                    }

                    // Accumulate until we have at least 2 bytes
                    respBuf = concat(respBuf, buf);
                    if (respBuf.length < 2) return;

                    if (respHdrSize == -1) {
                        // byte[0]=version, byte[1]=addon_len => total = 2 + addon_len
                        respHdrSize = 2 + (respBuf[1] & 0xFF);
                    }
                    if (respBuf.length < respHdrSize) return;

                    respSkipped = true;
                    byte[] payload = Arrays.copyOfRange(respBuf, respHdrSize, respBuf.length);
                    respBuf = new byte[0];
                    if (payload.length > 0) out.write(payload);

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

    // ── OkHttpClient with optional TLS skip + real SNI override ──────────

    private OkHttpClient buildOkHttpClient() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.SECONDS)
                .writeTimeout(0, TimeUnit.SECONDS);

        try {
            // Build a trust manager — either trust-all or default
            X509TrustManager trustManager;
            SSLContext        sslContext;

            if (!cfg.rejectUnauthorized) {
                // Trust all certs (same as rejectUnauthorized:false in client.js)
                trustManager = new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] c, String a) {}
                    public void checkServerTrusted(X509Certificate[] c, String a) {}
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                };
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[]{trustManager}, new java.security.SecureRandom());
                builder.hostnameVerifier((hostname, session) -> true);
            } else {
                // Use system default trust manager
                javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory
                        .getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
                tmf.init((java.security.KeyStore) null);
                trustManager = (X509TrustManager) tmf.getTrustManagers()[0];
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, null, null);
            }

            // Wrap SSLSocketFactory to inject SNI hostname (client.js uses `servername: CFG.sni`)
            final String sniHost = (cfg.sni != null && !cfg.sni.isEmpty()) ? cfg.sni : cfg.server;
            javax.net.ssl.SSLSocketFactory baseFactory = sslContext.getSocketFactory();

            javax.net.ssl.SSLSocketFactory sniFactory = new javax.net.ssl.SSLSocketFactory() {
                @Override public String[] getDefaultCipherSuites() { return baseFactory.getDefaultCipherSuites(); }
                @Override public String[] getSupportedCipherSuites() { return baseFactory.getSupportedCipherSuites(); }

                private javax.net.ssl.SSLSocket setSnI(java.net.Socket s) {
                    if (s instanceof javax.net.ssl.SSLSocket) {
                        javax.net.ssl.SSLSocket ssl = (javax.net.ssl.SSLSocket) s;
                        try {
                            // Set SNI via SSLParameters
                            javax.net.ssl.SSLParameters params = ssl.getSSLParameters();
                            params.setServerNames(java.util.Collections.singletonList(
                                    new javax.net.ssl.SNIHostName(sniHost)));
                            ssl.setSSLParameters(params);
                        } catch (Exception e) {
                            Log.w(TAG, "SNI set failed: " + e.getMessage());
                        }
                    }
                    return (javax.net.ssl.SSLSocket) s;
                }

                @Override
                public java.net.Socket createSocket() throws IOException {
                    return setSnI(baseFactory.createSocket());
                }
                @Override
                public java.net.Socket createSocket(java.net.Socket s, String h, int p, boolean ac) throws IOException {
                    return setSnI(baseFactory.createSocket(s, sniHost, p, ac));
                }
                @Override
                public java.net.Socket createSocket(String h, int p) throws IOException {
                    return setSnI(baseFactory.createSocket(h, p));
                }
                @Override
                public java.net.Socket createSocket(String h, int p, java.net.InetAddress la, int lp) throws IOException {
                    return setSnI(baseFactory.createSocket(h, p, la, lp));
                }
                @Override
                public java.net.Socket createSocket(java.net.InetAddress a, int p) throws IOException {
                    return setSnI(baseFactory.createSocket(a, p));
                }
                @Override
                public java.net.Socket createSocket(java.net.InetAddress a, int p, java.net.InetAddress la, int lp) throws IOException {
                    return setSnI(baseFactory.createSocket(a, p, la, lp));
                }
            };

            builder.sslSocketFactory(sniFactory, trustManager);

        } catch (Exception e) {
            Log.e(TAG, "TLS/SNI setup error: " + e.getMessage());
        }

        return builder.build();
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────

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

    // ── Helpers ───────────────────────────────────────────────────────────

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
