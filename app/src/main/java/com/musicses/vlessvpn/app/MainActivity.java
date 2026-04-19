package com.musicses.vlessvpn.app;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.View;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;

import com.musicses.vlessvpn.app.databinding.ActivityMainBinding;

import java.util.List;

public class MainActivity extends AppCompatActivity implements VpnStateHolder.Listener {

    private ActivityMainBinding binding;
    private ConfigAdapter        adapter;
    private List<VlessConfig>   configs;
    private final Handler        uiHandler = new Handler(Looper.getMainLooper());

    private final ActivityResultLauncher<Intent> vpnPermLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), result -> {
                if (result.getResultCode() == Activity.RESULT_OK) {
                    doStartVpn();
                } else {
                    toast("VPN permission denied");
                }
            });

    // ── Lifecycle ─────────────────────────────────────────────────────────

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        configs = ConfigStore.loadAll(this);

        // RecyclerView
        adapter = new ConfigAdapter(configs, ConfigStore.getActiveIndex(this), (idx, action) -> {
            if (action == ConfigAdapter.Action.SELECT) {
                ConfigStore.setActiveIndex(this, idx);
                adapter.setActiveIndex(idx);
            } else if (action == ConfigAdapter.Action.DELETE) {
                ConfigStore.remove(this, idx);
                configs.remove(idx);
                adapter.notifyItemRemoved(idx);
                adapter.notifyItemRangeChanged(idx, configs.size());
            }
        });
        binding.recyclerConfigs.setLayoutManager(new LinearLayoutManager(this));
        binding.recyclerConfigs.setAdapter(adapter);

        // Buttons
        binding.btnToggleVpn.setOnClickListener(v -> onToggleVpn());
        binding.btnImport.setOnClickListener(v -> showImportDialog());

        // Handle vless:// intent from browser/clipboard
        handleIntent(getIntent());

        // Observe VPN state
        VpnStateHolder.addListener(this);
        syncUi(VpnStateHolder.getState());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIntent(intent);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        VpnStateHolder.removeListener(this);
    }

    // ── VPN state ─────────────────────────────────────────────────────────

    @Override
    public void onStateChanged(VpnStateHolder.State state) {
        uiHandler.post(() -> syncUi(state));
    }

    private void syncUi(VpnStateHolder.State state) {
        switch (state) {
            case CONNECTED:
                binding.btnToggleVpn.setText("Disconnect");
                binding.tvStatus.setText("● Connected");
                binding.tvStatus.setTextColor(0xFF4CAF50);
                break;
            case CONNECTING:
                binding.btnToggleVpn.setText("Connecting…");
                binding.tvStatus.setText("● Connecting");
                binding.tvStatus.setTextColor(0xFFFF9800);
                break;
            case DISCONNECTED:
            default:
                binding.btnToggleVpn.setText("Connect");
                binding.tvStatus.setText("○ Disconnected");
                binding.tvStatus.setTextColor(0xFF9E9E9E);
                break;
        }
    }

    // ── Toggle VPN ────────────────────────────────────────────────────────

    private void onToggleVpn() {
        if (VpnStateHolder.getState() == VpnStateHolder.State.CONNECTED) {
            stopVpn();
        } else {
            requestVpnPermission();
        }
    }

    private void requestVpnPermission() {
        Intent permIntent = VpnService.prepare(this);
        if (permIntent != null) {
            vpnPermLauncher.launch(permIntent);
        } else {
            doStartVpn();
        }
    }

    private void doStartVpn() {
        VlessConfig cfg = ConfigStore.getActive(this);
        if (cfg == null) {
            toast("No config selected. Import a vless:// URL first.");
            return;
        }
        VpnStateHolder.setState(VpnStateHolder.State.CONNECTING);

        Intent intent = new Intent(this, VlessVpnService.class);
        intent.setAction(VlessVpnService.ACTION_START);
        intent.putExtra(VlessVpnService.EXTRA_CONFIG_JSON, ConfigStore.toJson(cfg));
        startForegroundService(intent);
    }

    private void stopVpn() {
        Intent intent = new Intent(this, VlessVpnService.class);
        intent.setAction(VlessVpnService.ACTION_STOP);
        startService(intent);
    }

    // ── Import ────────────────────────────────────────────────────────────

    private void handleIntent(Intent intent) {
        if (intent == null) return;
        Uri data = intent.getData();
        if (data != null && "vless".equals(data.getScheme())) {
            importUrl(data.toString());
        }
    }

    private void showImportDialog() {
        android.widget.EditText et = new android.widget.EditText(this);
        et.setHint("vless://uuid@server:port?...");
        et.setSingleLine(false);
        et.setMinLines(3);

        new AlertDialog.Builder(this)
                .setTitle("Import VLESS URL")
                .setView(et)
                .setPositiveButton("Import", (d, w) -> {
                    String url = et.getText().toString().trim();
                    importUrl(url);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void importUrl(String url) {
        if (TextUtils.isEmpty(url)) return;
        VlessConfig cfg = VlessConfig.parse(url);
        if (cfg == null || !cfg.isValid()) {
            toast("Invalid VLESS URL");
            return;
        }
        ConfigStore.add(this, cfg);
        configs.add(cfg);
        adapter.notifyItemInserted(configs.size() - 1);
        // Auto-select newly added config
        int newIdx = configs.size() - 1;
        ConfigStore.setActiveIndex(this, newIdx);
        adapter.setActiveIndex(newIdx);
        toast("Imported: " + cfg);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }
}
