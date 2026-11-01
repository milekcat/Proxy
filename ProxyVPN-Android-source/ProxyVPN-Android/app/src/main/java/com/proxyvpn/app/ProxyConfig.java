package com.proxyvpn.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import org.json.JSONArray;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class ProxyConfig {
    public enum Mode { SOCKS5, HTTP, HTTPS }
    public final Mode mode;
    public final String host, username, password;
    public final int port;
    public final boolean selectedOnly;
    public final List<String> packages;

    public ProxyConfig(Mode mode, String host, int port, String username, String password,
                       boolean selectedOnly, List<String> packages) {
        this.mode = mode; this.host = host; this.port = port;
        this.username = username; this.password = password;
        this.selectedOnly = selectedOnly; this.packages = new ArrayList<>(packages);
    }

    public void validate() {
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) throw new IllegalArgumentException("Укажи IPv4 прокси, например 203.0.113.10");
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) throw new IllegalArgumentException("Некорректный IPv4");
            for (int i = 0; i < part.length(); i++) if (!Character.isDigit(part.charAt(i))) throw new IllegalArgumentException("Некорректный IPv4");
            if (Integer.parseInt(part) > 255) throw new IllegalArgumentException("Некорректный IPv4");
        }
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Порт должен быть от 1 до 65535");
        if (selectedOnly && packages.isEmpty()) throw new IllegalArgumentException("Выбери хотя бы одно приложение");
        if (mode == Mode.SOCKS5 && (username.getBytes(StandardCharsets.UTF_8).length > 255 ||
                password.getBytes(StandardCharsets.UTF_8).length > 255))
            throw new IllegalArgumentException("SOCKS5 логин и пароль не длиннее 255 байт");
    }

    private static SharedPreferences prefs(Context c) { return c.getSharedPreferences("proxy_settings", Context.MODE_PRIVATE); }
    public void save(Context ctx) throws Exception {
        validate();
        JSONArray arr = new JSONArray(); for (String p : packages) arr.put(p);
        prefs(ctx).edit().putString("mode", mode.name()).putString("host", host)
            .putInt("port", port).putString("user", encrypt(username))
            .putString("pass", encrypt(password)).putBoolean("selected", selectedOnly)
            .putString("packages", arr.toString()).apply();
    }
    public static ProxyConfig load(Context ctx) throws Exception {
        SharedPreferences p = prefs(ctx);
        JSONArray arr = new JSONArray(p.getString("packages", "[]"));
        List<String> packages = new ArrayList<>();
        for (int i = 0; i < arr.length(); i++) packages.add(arr.getString(i));
        return new ProxyConfig(Mode.valueOf(p.getString("mode", "SOCKS5")), p.getString("host", ""),
                p.getInt("port", 1080), decrypt(p.getString("user", "")),
                decrypt(p.getString("pass", "")), p.getBoolean("selected", false), packages);
    }

    private static SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore"); ks.load(null);
        if (ks.containsAlias("proxyvpn-v1")) return ((KeyStore.SecretKeyEntry) ks.getEntry("proxyvpn-v1", null)).getSecretKey();
        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        kg.init(new KeyGenParameterSpec.Builder("proxyvpn-v1", KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).build());
        return kg.generateKey();
    }
    private static String encrypt(String s) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, key());
        byte[] iv = c.getIV(); byte[] enc = c.doFinal(s.getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[iv.length + enc.length]; System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(enc, 0, out, iv.length, enc.length);
        return Base64.encodeToString(out, Base64.NO_WRAP);
    }
    private static String decrypt(String s) throws Exception {
        if (s.isEmpty()) return "";
        byte[] in = Base64.decode(s, Base64.NO_WRAP);
        if (in.length < 29) throw new IllegalArgumentException("Повреждены сохранённые учётные данные");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, in, 0, 12));
        return new String(c.doFinal(in, 12, in.length - 12), StandardCharsets.UTF_8);
    }
}
