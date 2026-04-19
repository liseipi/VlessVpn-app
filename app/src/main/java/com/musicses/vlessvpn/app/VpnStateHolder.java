package com.musicses.vlessvpn.app;

import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Simple in-process observable for VPN connection state.
 * Services update it; MainActivity observes it.
 */
public class VpnStateHolder {

    public enum State { DISCONNECTED, CONNECTING, CONNECTED }

    public interface Listener {
        void onStateChanged(State state);
    }

    private static volatile State state = State.DISCONNECTED;
    private static final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();

    public static State getState() { return state; }

    public static void setState(State newState) {
        state = newState;
        for (Listener l : listeners) l.onStateChanged(newState);
    }

    public static void addListener(Listener l)    { listeners.add(l); }
    public static void removeListener(Listener l) { listeners.remove(l); }
}
