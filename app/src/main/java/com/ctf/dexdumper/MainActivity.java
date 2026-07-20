package com.ctf.dexdumper;

import android.Manifest;
import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;

public class MainActivity extends Activity {
    private EditText targetPackage;
    private RadioGroup modeGroup;
    private CheckBox dumpApplication;
    private CheckBox dumpAcf;
    private CheckBox recordName;
    private CheckBox loadClassHook;
    private EditText loadClassRule;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (Build.VERSION.SDK_INT >= 23) {
            requestPermissions(new String[]{Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE}, 7);
        }
        buildUi();
        loadConfig();
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(16);
        root.setPadding(pad, pad, pad, pad);
        scroll.addView(root);

        TextView title = new TextView(this);
        title.setText("DexDumper");
        title.setTextSize(24);
        title.setGravity(Gravity.CENTER_HORIZONTAL);
        root.addView(title);

        TextView desc = new TextView(this);
        desc.setText("授权 CTF/逆向脱壳用。在 LSPosed 中启用模块并把目标 App 加入作用域，强停/重启目标 App 即自动 dump。包名留空则对作用域内全部 App 生效。");
        desc.setPadding(0, dp(8), 0, dp(12));
        root.addView(desc);

        targetPackage = edit("可留空");
        root.addView(label("Target package（可选二次过滤）"));
        root.addView(targetPackage);

        TextView out = new TextView(this);
        out.setText("输出目录：/sdcard/DexDumper/<目标包名>/\n每次 dump 生成 .dex 与 manifest.txt");
        out.setPadding(0, dp(10), 0, dp(8));
        root.addView(out);

        root.addView(label("Dump 模式"));
        modeGroup = new RadioGroup(this);
        RadioButton r0 = new RadioButton(this); r0.setText("default — 落盘直读（APK 内 classes*.dex / .dex/.odex）");
        RadioButton r1 = new RadioButton(this); r1.setText("data — 内存缓冲（hook DexPathList 抓 ByteBuffer，对抗加载后清零）");
        RadioButton r2 = new RadioButton(this); r2.setText("pointer — 原生指针直拷（mprotect+memcpy DexFile.begin_/size_，最强）");
        modeGroup.addView(r0); modeGroup.addView(r1); modeGroup.addView(r2);
        root.addView(modeGroup);

        dumpApplication = check("dump 主 Application dex（sourceDir + splits）");
        dumpAcf = check("dump AppComponentFactory 加载来源");
        recordName = check("记录原文件名");
        loadClassHook = check("hook loadClass 在动态加载后重新 dump（热加载场景）");
        root.addView(dumpApplication);
        root.addView(dumpAcf);
        root.addView(recordName);
        root.addView(loadClassHook);

        loadClassRule = edit("类名包含关键字，留空则每次 loadClass 都触发（节流 2s）");
        loadClassRule.setInputType(InputType.TYPE_CLASS_TEXT);
        root.addView(label("loadClass 规则（关键字）"));
        root.addView(loadClassRule);

        {
            android.widget.Button save = new android.widget.Button(this);
            save.setText("保存配置");
            save.setOnClickListener(v -> saveConfig());
            root.addView(save, new LinearLayout.LayoutParams(-1, -2));
        }

        TextView tips = new TextView(this);
        tips.setPadding(0, dp(12), 0, 0);
        tips.setText("运行中即时 dump：adb shell am broadcast -a com.ctf.dexdumper.action.DUMP\n"
                + "查状态：adb shell am broadcast -a com.ctf.dexdumper.action.STATUS\n"
                + "清空输出：adb shell am broadcast -a com.ctf.dexdumper.action.CLEAR --es package <pkg>\n"
                + "取回：adb pull /sdcard/DexDumper/<pkg>/");
        root.addView(tips);

        setContentView(scroll);
    }

    private void loadConfig() {
        SharedPreferences sp = getSharedPreferences(Config.PREFS_NAME, MODE_PRIVATE);
        Config c = Config.fromSharedPreferences(sp);
        targetPackage.setText(c.targetPackage);
        // 选中对应 RadioButton
        RadioButton rb = (RadioButton) modeGroup.getChildAt(c.mode);
        if (rb != null) rb.setChecked(true);
        dumpApplication.setChecked(c.dumpApplication);
        dumpAcf.setChecked(c.dumpAppComponentFactory);
        recordName.setChecked(c.recordFileName);
        loadClassHook.setChecked(c.loadClassHook);
        loadClassRule.setText(c.loadClassRule);
        makePrefsReadable();
    }

    private void saveConfig() {
        int mode = Config.MODE_POINTER;
        for (int i = 0; i < modeGroup.getChildCount(); i++) {
            if (((RadioButton) modeGroup.getChildAt(i)).isChecked()) { mode = i; break; }
        }
        getSharedPreferences(Config.PREFS_NAME, MODE_PRIVATE).edit()
                .putString(Config.KEY_TARGET, targetPackage.getText().toString().trim())
                .putInt(Config.KEY_MODE, mode)
                .putBoolean(Config.KEY_DUMP_APPLICATION, dumpApplication.isChecked())
                .putBoolean(Config.KEY_DUMP_ACF, dumpAcf.isChecked())
                .putBoolean(Config.KEY_RECORD_NAME, recordName.isChecked())
                .putBoolean(Config.KEY_LOADCLASS, loadClassHook.isChecked())
                .putString(Config.KEY_LOADCLASS_RULE, loadClassRule.getText().toString().trim())
                .apply();
        makePrefsReadable();
        Toast.makeText(this, "已保存。请在 LSPosed 中启用模块并重启目标 App。", Toast.LENGTH_LONG).show();
    }

    private void makePrefsReadable() {
        try {
            File data = new File(getApplicationInfo().dataDir);
            File spDir = new File(data, "shared_prefs");
            File spFile = new File(spDir, Config.PREFS_NAME + ".xml");
            data.setExecutable(true, false);
            data.setReadable(true, false);
            spDir.setExecutable(true, false);
            spDir.setReadable(true, false);
            spFile.setReadable(true, false);
        } catch (Throwable ignored) {}
    }

    private TextView label(String s) {
        TextView v = new TextView(this);
        v.setText(s);
        v.setPadding(0, dp(10), 0, dp(2));
        return v;
    }

    private EditText edit(String hint) {
        EditText e = new EditText(this);
        e.setSingleLine(true);
        e.setHint(hint);
        return e;
    }

    private CheckBox check(String text) {
        CheckBox c = new CheckBox(this);
        c.setText(text);
        return c;
    }

    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density + 0.5f); }
}
