package com.musicses.vlessvpn.app;

import android.content.Context;
import android.content.SharedPreferences;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

/**
 * Persists the list of VLESS configs and the active config index
 * using SharedPreferences + Gson.
 */
public class ConfigStore {
    private static final String PREFS_NAME   = "vless_configs";
    private static final String KEY_CONFIGS  = "configs";
    private static final String KEY_ACTIVE   = "active_index";
    private static final Gson   GSON         = new Gson();

    // ── List operations ───────────────────────────────────────────────────

    public static List<VlessConfig> loadAll(Context ctx) {
        SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String json = prefs.getString(KEY_CONFIGS, null);
        if (json == null) return new ArrayList<>();
        Type t = new TypeToken<List<VlessConfig>>(){}.getType();
        List<VlessConfig> list = GSON.fromJson(json, t);
        return list != null ? list : new ArrayList<>();
    }

    public static void saveAll(Context ctx, List<VlessConfig> configs) {
        ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
           .edit().putString(KEY_CONFIGS, GSON.toJson(configs)).apply();
    }

    public static void add(Context ctx, VlessConfig cfg) {
        List<VlessConfig> list = loadAll(ctx);
        list.add(cfg);
        saveAll(ctx, list);
    }

    public static void remove(Context ctx, int index) {
        List<VlessConfig> list = loadAll(ctx);
        if (index >= 0 && index < list.size()) {
            list.remove(index);
            saveAll(ctx, list);
        }
    }

    // ── Active index ──────────────────────────────────────────────────────

    public static int getActiveIndex(Context ctx) {
        return ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                  .getInt(KEY_ACTIVE, 0);
    }

    public static void setActiveIndex(Context ctx, int idx) {
        ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
           .edit().putInt(KEY_ACTIVE, idx).apply();
    }

    public static VlessConfig getActive(Context ctx) {
        List<VlessConfig> list = loadAll(ctx);
        int idx = getActiveIndex(ctx);
        if (list.isEmpty()) return null;
        if (idx < 0 || idx >= list.size()) idx = 0;
        return list.get(idx);
    }

    // ── JSON helpers (for passing via Intent extras) ──────────────────────

    public static String toJson(VlessConfig cfg) {
        return GSON.toJson(cfg);
    }

    public static VlessConfig fromJson(String json) {
        if (json == null) return null;
        return GSON.fromJson(json, VlessConfig.class);
    }
}
