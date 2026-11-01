package com.proxyvpn.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Color;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class MainActivity extends Activity {
    private EditText host, port, username, password;
    private Spinner type;
    private CheckBox selectedMode;
    private TextView status, selection;
    private final Set<String> chosen = new HashSet<>();
    private static final int REQUEST_VPN = 100;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable refreshStatus = new Runnable() {
        @Override public void run() {
            if (status != null) status.setText(ProxyVpnService.getStatus());
            handler.postDelayed(this, 750);
        }
    };

    @Override public void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setStatusBarColor(Color.rgb(18, 35, 58));
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL); root.setPadding(30, 26, 30, 30);
        root.setBackgroundColor(Color.rgb(245, 248, 252));
        ScrollView scroll = new ScrollView(this); scroll.addView(root); setContentView(scroll);
        TextView title = new TextView(this); title.setText("ProxyVPN"); title.setTextSize(28);
        title.setTextColor(Color.rgb(26, 46, 69)); title.setPadding(0, 0, 0, 8); root.addView(title);
        status = addText(root, "● Не подключено", 16);
        addText(root, "Протокол", 15);
        type = new Spinner(this);
        type.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item,
                new String[]{"SOCKS5", "HTTP CONNECT", "HTTPS CONNECT"})); root.addView(type);
        host = edit(root, "IPv4 прокси, например 203.0.113.10", false);
        port = edit(root, "Порт, например 1080", false);
        port.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        username = edit(root, "Логин", false);
        password = edit(root, "Пароль", true);
        selectedMode = new CheckBox(this);
        selectedMode.setText("VPN только для выбранных приложений"); root.addView(selectedMode);
        Button pick = new Button(this); pick.setText("Выбрать приложения"); root.addView(pick);
        selection = addText(root, "Приложений выбрано: 0", 14);
        selectedMode.setOnCheckedChangeListener((b1, isChecked) -> {
            pick.setEnabled(isChecked);
            selection.setVisibility(isChecked ? View.VISIBLE : View.GONE);
        });
        pick.setOnClickListener(v -> selectApps());
        Button start = new Button(this); start.setText("ПОДКЛЮЧИТЬ"); root.addView(start);
        start.setOnClickListener(v -> connect());
        Button stop = new Button(this); stop.setText("ОТКЛЮЧИТЬ"); root.addView(stop);
        stop.setOnClickListener(v -> {
            Intent i = new Intent(this, ProxyVpnService.class); i.setAction(ProxyVpnService.STOP);
            startService(i); status.setText("● Отключение…");
        });
        addText(root, "HTTP CONNECT передаёт логин/пароль без шифрования между телефоном и прокси. HTTPS CONNECT требует корректный TLS-сертификат прокси для его IPv4. DNS идёт через HTTPS поверх прокси; IPv6 и ICMP блокируются. UDP доступен только при поддержке SOCKS5 UDP ASSOCIATE провайдером.", 12);
        try {
            ProxyConfig c = ProxyConfig.load(this);
            host.setText(c.host); port.setText(String.valueOf(c.port));
            username.setText(c.username); password.setText(c.password);
            type.setSelection(c.mode.ordinal()); chosen.addAll(c.packages);
            selectedMode.setChecked(c.selectedOnly); updateSelection();
        } catch (Exception e) { port.setText("1080"); }
        pick.setEnabled(selectedMode.isChecked());
        selection.setVisibility(selectedMode.isChecked() ? View.VISIBLE : View.GONE);
    }

    private TextView addText(LinearLayout root, String s, int sp) {
        TextView t = new TextView(this); t.setText(s); t.setTextSize(sp); t.setTextColor(Color.rgb(56, 69, 85));
        t.setPadding(0, 12, 0, 12); root.addView(t); return t;
    }
    private EditText edit(LinearLayout root, String hint, boolean secret) {
        EditText t = new EditText(this); t.setSingleLine(true); t.setHint(hint);
        if (secret) t.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        root.addView(t); return t;
    }
    private void updateSelection() { if (selection != null) selection.setText("Приложений выбрано: " + chosen.size()); }
    private void selectApps() {
        PackageManager pm = getPackageManager();
        Intent launch = new Intent(Intent.ACTION_MAIN); launch.addCategory(Intent.CATEGORY_LAUNCHER);
        List<ResolveInfo> resolved = pm.queryIntentActivities(launch, 0);
        List<AppItem> items = new ArrayList<>(); Set<String> seen = new HashSet<>();
        for (ResolveInfo r : resolved) {
            if (r.activityInfo == null) continue;
            String pkg = r.activityInfo.packageName;
            if (seen.add(pkg)) items.add(new AppItem(pkg, String.valueOf(r.loadLabel(pm))));
        }
        Collections.sort(items, Comparator.comparing(a -> a.label.toLowerCase()));
        if (items.isEmpty()) { toast("Не удалось получить список приложений"); return; }
        String[] labels = new String[items.size()]; boolean[] checked = new boolean[items.size()];
        for (int i = 0; i < items.size(); i++) { labels[i] = items.get(i).label + " (" + items.get(i).pkg + ")"; checked[i] = chosen.contains(items.get(i).pkg); }
        Set<String> draft = new HashSet<>(chosen);
        new AlertDialog.Builder(this).setTitle("Приложения для VPN")
            .setMultiChoiceItems(labels, checked, (d, which, on) -> {
                if (on) draft.add(items.get(which).pkg); else draft.remove(items.get(which).pkg);
            }).setNegativeButton("Отмена", null).setPositiveButton("Сохранить", (d, which) -> {
                chosen.clear(); chosen.addAll(draft); updateSelection();
            }).show();
    }
    private void connect() {
        try {
            ProxyConfig c = new ProxyConfig(ProxyConfig.Mode.values()[type.getSelectedItemPosition()],
                host.getText().toString().trim(), Integer.parseInt(port.getText().toString().trim()),
                username.getText().toString(), password.getText().toString(), selectedMode.isChecked(),
                new ArrayList<>(chosen));
            c.save(this);
            Intent permission = VpnService.prepare(this);
            if (permission != null) startActivityForResult(permission, REQUEST_VPN);
            else startVpn();
        } catch (Exception e) { toast("Ошибка: " + e.getMessage()); }
    }
    @Override protected void onActivityResult(int req, int result, Intent data) {
        super.onActivityResult(req, result, data);
        if (req == REQUEST_VPN && result == RESULT_OK) startVpn();
        else if (req == REQUEST_VPN) toast("Необходимо разрешение Android на VPN");
    }
    private void startVpn() {
        Intent i = new Intent(this, ProxyVpnService.class); i.setAction(ProxyVpnService.START);
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i); else startService(i);
        status.setText("● Запуск VPN…");
    }
    @Override protected void onResume() {
        super.onResume();
        handler.removeCallbacks(refreshStatus);
        handler.post(refreshStatus);
    }
    @Override protected void onPause() {
        handler.removeCallbacks(refreshStatus);
        super.onPause();
    }
    private void toast(String msg) { Toast.makeText(this, msg, Toast.LENGTH_LONG).show(); }
    private static final class AppItem {
        final String pkg, label;
        AppItem(String p, String l) { pkg = p; label = l; }
    }
}
