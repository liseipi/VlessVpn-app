package com.musicses.vlessvpn.app;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.Nullable;

/**
 * 已废弃。SOCKS5 代理逻辑已迁移至 VlessProxyManager，
 * 由 VlessVpnService 直接在内部运行。
 *
 * 保留此空壳仅为兼容 AndroidManifest.xml 中的 <service> 声明，
 * 避免系统报错。可安全地从 Manifest 中移除此 Service 声明。
 */
public class VlessProxyService extends Service {
    private static final String TAG = "VlessProxy";

    static final String ACTION_START = "START";
    static final String ACTION_STOP  = "STOP";
    static final String EXTRA_CONFIG = "config_json";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.w(TAG, "VlessProxyService is deprecated — logic moved to VlessVpnService");
        stopSelf();
        return START_NOT_STICKY;
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) { return null; }
}