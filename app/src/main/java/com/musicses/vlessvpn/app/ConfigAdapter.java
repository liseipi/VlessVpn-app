package com.musicses.vlessvpn.app;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.RadioButton;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.List;

public class ConfigAdapter extends RecyclerView.Adapter<ConfigAdapter.VH> {

    public enum Action { SELECT, DELETE }

    public interface Callback {
        void onAction(int index, Action action);
    }

    private final List<VlessConfig> items;
    private int activeIndex;
    private final Callback callback;

    public ConfigAdapter(List<VlessConfig> items, int activeIndex, Callback callback) {
        this.items       = items;
        this.activeIndex = activeIndex;
        this.callback    = callback;
    }

    public void setActiveIndex(int idx) {
        int old = activeIndex;
        activeIndex = idx;
        notifyItemChanged(old);
        notifyItemChanged(idx);
    }

    @NonNull @Override
    public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_config, parent, false);
        return new VH(v);
    }

    @Override
    public void onBindViewHolder(@NonNull VH h, int position) {
        VlessConfig cfg = items.get(position);
        h.tvName.setText(cfg.name != null && !cfg.name.isEmpty() ? cfg.name : cfg.server);
        h.tvDetail.setText(cfg.server + ":" + cfg.port + " [" + cfg.security + "]");
        h.radio.setChecked(position == activeIndex);

        h.radio.setOnClickListener(v -> callback.onAction(position, Action.SELECT));
        h.itemView.setOnClickListener(v -> callback.onAction(position, Action.SELECT));
        h.btnDelete.setOnClickListener(v -> callback.onAction(position, Action.DELETE));
    }

    @Override public int getItemCount() { return items.size(); }

    static class VH extends RecyclerView.ViewHolder {
        RadioButton radio;
        TextView    tvName, tvDetail;
        ImageButton btnDelete;

        VH(View v) {
            super(v);
            radio     = v.findViewById(R.id.radio);
            tvName    = v.findViewById(R.id.tvName);
            tvDetail  = v.findViewById(R.id.tvDetail);
            btnDelete = v.findViewById(R.id.btnDelete);
        }
    }
}
