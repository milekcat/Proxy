package com.proxyvpn.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import java.io.IOException;
import java.net.Socket;

public final class ProxyVpnService extends VpnService {
    public static final String START = "com.proxyvpn.app.START";
    public static final String STOP = "com.proxyvpn.app.STOP";
    private static final String CHANNEL = "vpn_status";
    private volatile PacketEngine engine;
    private static volatile boolean running;
    private static volatile String currentStatus = "● VPN отключён";
    public static boolean isRunning() { return running; }
    public static String getStatus() { return currentStatus; }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && STOP.equals(intent.getAction())) {
            shutdown(); stopSelf(); return START_NOT_STICKY;
        }
        notifyForeground();
        shutdown();
        currentStatus = "● Подключаем VPN-туннель…";
        try {
            ProxyConfig config = ProxyConfig.load(this); config.validate();
            Builder builder = new Builder().setSession("ProxyVPN").setMtu(1500)
                .addAddress("10.91.0.2", 32).addRoute("0.0.0.0", 0)
                .addAddress("fd42:ac::2", 128).addRoute("::", 0)
                .addDnsServer("1.1.1.1");
            if (config.selectedOnly) {
                int added = 0;
                for (String p : config.packages) {
                    try { builder.addAllowedApplication(p); added++; }
                    catch (android.content.pm.PackageManager.NameNotFoundException ignored) { }
                }
                if (added == 0) throw new IllegalStateException("Выбранные приложения не установлены");
            }
            ParcelFileDescriptor tun = builder.establish();
            if (tun == null) throw new IllegalStateException("Android не разрешил VPN");
            engine = new PacketEngine(this, tun, config);
            running = true;
            currentStatus = "● VPN включён, проверяем прокси…";
            PacketEngine started = engine;
            engine.start();
            verifyProxyAsync(config, started);
        } catch (Exception ex) {
            Log.e("ProxyVPN", "VPN startup failed: " + ex.getClass().getSimpleName());
            running = false;
            currentStatus = "● Ошибка VPN: " + ex.getMessage();
            stopSelf();
        }
        return START_NOT_STICKY;
    }
    private void verifyProxyAsync(ProxyConfig config, PacketEngine expected) {
        Thread thread = new Thread(() -> {
            String error = "Нет ответа от прокси";
            for (String endpoint : new String[]{"cloudflare-dns.com", "dns.google"}) {
                try (Socket s = new ProxyTransport(this, config).connect(endpoint, 443)) {
                    if (running && engine == expected)
                        currentStatus = "● Прокси отвечает, VPN работает";
                    return;
                } catch (IOException e) {
                    error = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
                }
            }
            if (running && engine == expected)
                currentStatus = "● VPN включён, но прокси не отвечает: " + error;
        }, "ProxyVPN-connectivity-check");
        thread.setDaemon(true);
        thread.start();
    }
    private void notifyForeground() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (Build.VERSION.SDK_INT >= 26)
            nm.createNotificationChannel(new NotificationChannel(CHANNEL, "ProxyVPN", NotificationManager.IMPORTANCE_LOW));
        Intent open = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification n = new Notification.Builder(this, CHANNEL)
            .setContentTitle("ProxyVPN").setContentText("VPN-туннель работает")
            .setSmallIcon(android.R.drawable.ic_lock_lock).setContentIntent(pi).setOngoing(true).build();
        startForeground(1, n);
    }
    private synchronized void shutdown() {
        running = false;
        if (engine != null) { engine.close(); engine = null; }
        if (!currentStatus.startsWith("● Ошибка")) currentStatus = "● VPN отключён";
    }
    @Override public void onRevoke() { shutdown(); stopSelf(); super.onRevoke(); }
    @Override public void onDestroy() { shutdown(); super.onDestroy(); }
}
