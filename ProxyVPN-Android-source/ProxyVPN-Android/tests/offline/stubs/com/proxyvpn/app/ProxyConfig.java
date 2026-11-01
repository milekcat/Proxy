package com.proxyvpn.app;

/** Test-only stub used to exercise transport without the Android SDK. */
public class ProxyConfig {
    public enum Mode { SOCKS5, HTTP, HTTPS }
    public final Mode mode;
    public final String host, username, password;
    public final int port;
    public final boolean selectedOnly = false;
    public final java.util.List<String> packages = java.util.Collections.emptyList();
    ProxyConfig(Mode mode, String host, int port, String username, String password) {
        this.mode = mode;
        this.host = host;
        this.port = port;
        this.username = username;
        this.password = password;
    }
}
