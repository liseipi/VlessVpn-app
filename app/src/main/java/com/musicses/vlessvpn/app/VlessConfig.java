package com.musicses.vlessvpn.app;

import android.net.Uri;
import android.text.TextUtils;
import android.util.Log;

/**
 * VLESS configuration parsed from a vless:// URI.
 *
 * Format:
 *   vless://<uuid>@<server>:<port>?encryption=none&security=tls&sni=...&type=ws&host=...&path=...#<name>
 */
public class VlessConfig {
    private static final String TAG = "VlessConfig";

    public String name;
    public String uuid;
    public String server;
    public int    port;
    public String path;       // WebSocket path, e.g. /?ed=2560
    public String sni;        // TLS SNI
    public String wsHost;     // WS Host header
    public String security;   // "tls" or "none"
    public boolean rejectUnauthorized = false;

    /** Proxy listen port on localhost (SOCKS5) */
    public static final int SOCKS5_PORT = 10800;

    // ── Parse ──────────────────────────────────────────────────────────────

    public static VlessConfig parse(String url) {
        if (url == null || !url.startsWith("vless://")) return null;
        try {
            Uri uri = Uri.parse(url);
            VlessConfig cfg = new VlessConfig();

            // uuid is the userInfo part (before @)
            cfg.uuid     = uri.getUserInfo();
            cfg.server   = uri.getHost();
            cfg.port     = uri.getPort() > 0 ? uri.getPort() : 443;
            cfg.name     = uri.getFragment(); // after #

            // Query params
            cfg.path     = uri.getQueryParameter("path");
            if (TextUtils.isEmpty(cfg.path)) cfg.path = "/";

            cfg.security = uri.getQueryParameter("security");
            if (TextUtils.isEmpty(cfg.security)) cfg.security = "none";

            cfg.sni      = uri.getQueryParameter("sni");
            if (TextUtils.isEmpty(cfg.sni)) cfg.sni = cfg.server;

            cfg.wsHost   = uri.getQueryParameter("host");
            if (TextUtils.isEmpty(cfg.wsHost)) cfg.wsHost = cfg.server;

            // ed= parameter is part of path query string in the original URL
            // The path param may come URL-encoded like /?ed=2560
            String rawPath = uri.getQueryParameter("path");
            if (!TextUtils.isEmpty(rawPath)) {
                cfg.path = rawPath;
            }

            if (TextUtils.isEmpty(cfg.uuid) || TextUtils.isEmpty(cfg.server)) {
                return null;
            }

            return cfg;
        } catch (Exception e) {
            Log.e(TAG, "parse error: " + e.getMessage());
            return null;
        }
    }

    // ── Build WS URL ───────────────────────────────────────────────────────

    /**
     * Builds the WebSocket URL, mirroring buildWsUrl() in client.js.
     *
     * client.js splits path at '?' and reconstructs manually to avoid
     * the ws library double-encoding the query string.
     * We return the raw string here; OkHttp's HttpUrl.parse() handles it,
     * but we mark the URL as already-encoded via okhttp3.HttpUrl.get().
     */
    public String buildWsUrl() {
        String scheme = ("tls".equals(security) || port == 443) ? "wss" : "ws";
        String p = (path != null && !path.isEmpty()) ? path : "/";
        // If path contains '?', split so we can reconstruct cleanly (same as client.js qIdx logic)
        int qIdx = p.indexOf('?');
        if (qIdx != -1) {
            String pathPart  = p.substring(0, qIdx);
            String queryPart = p.substring(qIdx + 1);
            return scheme + "://" + server + ":" + port + pathPart + "?" + queryPart;
        }
        return scheme + "://" + server + ":" + port + p;
    }

    // ── Validate ───────────────────────────────────────────────────────────

    public boolean isValid() {
        return !TextUtils.isEmpty(uuid) && !TextUtils.isEmpty(server) && port > 0;
    }

    @Override
    public String toString() {
        return (name != null ? name : server) + " [" + server + ":" + port + "]";
    }
}
