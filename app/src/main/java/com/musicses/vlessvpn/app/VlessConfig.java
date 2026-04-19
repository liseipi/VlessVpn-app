package com.musicses.vlessvpn.app;

import android.net.Uri;
import android.text.TextUtils;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

/**
 * VLESS configuration parsed from a vless:// URI.
 *
 * FIX: path 参数含 '?' 时（如 /?ed=2560），Uri.getQueryParameter("path") 会把
 *      '?' 后面的内容误当顶层 query，导致 path 被截断为 '/'。
 *      改为手动从原始 URL 字符串中提取 path 参数，确保完整保留。
 *
 * Format:
 *   vless://<uuid>@<server>:<port>?encryption=none&security=tls&sni=...&type=ws&host=...&path=...#<name>
 */
public class VlessConfig {
    private static final String TAG = "VlessConfig";

    public String  name;
    public String  uuid;
    public String  server;
    public int     port;
    public String  path;       // WebSocket path, e.g. /?ed=2560
    public String  sni;        // TLS SNI
    public String  wsHost;     // WS Host header
    public String  security;   // "tls" or "none"
    public boolean rejectUnauthorized = false;

    /** Proxy listen port on localhost (SOCKS5) */
    public static final int SOCKS5_PORT = 10800;

    // ── Parse ──────────────────────────────────────────────────────────────

    public static VlessConfig parse(String url) {
        if (url == null || !url.startsWith("vless://")) return null;
        try {
            Uri uri = Uri.parse(url);
            VlessConfig cfg = new VlessConfig();

            cfg.uuid   = uri.getUserInfo();
            cfg.server = uri.getHost();
            cfg.port   = uri.getPort() > 0 ? uri.getPort() : 443;
            cfg.name   = uri.getFragment();

            cfg.security = uri.getQueryParameter("security");
            if (TextUtils.isEmpty(cfg.security)) cfg.security = "none";

            cfg.sni = uri.getQueryParameter("sni");
            if (TextUtils.isEmpty(cfg.sni)) cfg.sni = cfg.server;

            cfg.wsHost = uri.getQueryParameter("host");
            if (TextUtils.isEmpty(cfg.wsHost)) cfg.wsHost = cfg.server;

            // FIX: 手动从原始 URL 提取 path 参数，避免 Uri 把 /?ed=2560 中的
            //      ed=2560 误解析为顶层 query 参数导致 path 被截断
            cfg.path = extractRawParam(url, "path");
            if (TextUtils.isEmpty(cfg.path)) cfg.path = "/";

            if (TextUtils.isEmpty(cfg.uuid) || TextUtils.isEmpty(cfg.server)) {
                return null;
            }

            return cfg;
        } catch (Exception e) {
            Log.e(TAG, "parse error: " + e.getMessage());
            return null;
        }
    }

    /**
     * 从原始 URL 字符串手动提取指定 query 参数值（URL 解码后返回）。
     * 例如 url 含 "path=%2F%3Fed%3D2560" 时返回 "/?ed=2560"。
     */
    private static String extractRawParam(String url, String paramName) {
        // 找到 query 部分（# 之前）
        int hashIdx = url.indexOf('#');
        String query = hashIdx != -1 ? url.substring(0, hashIdx) : url;

        String needle = paramName + "=";
        int start = query.indexOf("?" + needle);
        if (start == -1) start = query.indexOf("&" + needle);
        if (start == -1) return null;

        start += needle.length() + 1; // 跳过 "path="
        int end = query.indexOf('&', start);
        if (end == -1) end = query.length();

        String raw = query.substring(start, end);
        try {
            return URLDecoder.decode(raw, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return raw;
        }
    }

    // ── Build WS URL ───────────────────────────────────────────────────────

    /**
     * Builds the WebSocket URL.
     * If path contains '?', splits to avoid double-encoding (same as client.js qIdx logic).
     */
    public String buildWsUrl() {
        String scheme = ("tls".equals(security) || port == 443) ? "wss" : "ws";
        String p = (path != null && !path.isEmpty()) ? path : "/";
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