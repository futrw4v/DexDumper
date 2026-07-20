package com.ctf.dexdumper;

import android.content.SharedPreferences;

import java.lang.reflect.Method;

/**
 * 配置模型。语义镜像 Layout.Inspect 的 "Dump Dex.json"（C0212a）：
 *   application            : 是否 dump 主 dex
 *   appComponentFactory    : 是否 dump AppComponentFactory 加载来源
 *   dexFileName            : 是否记录/显示原文件名
 *   dexFileSize.type       : 0=default(落盘直读) 1=data(内存缓冲) 2=pointer(原生指针直拷)
 *   loadClass              : 是否 hook loadClass/forName 在动态加载后重新 dump
 *
 * 出于与 LposedNetDump 一致的可编译/可配置体验，改用 XSharedPreferences（XML，world-readable）
 * 承载，而非磁盘 JSON。语义不变。
 */
public class Config {
    public static final String MODULE_PACKAGE = "com.ctf.dexdumper";
    public static final String PREFS_NAME = "dexdumper_config";

    public static final String KEY_TARGET = "target_package";
    public static final String KEY_MODE = "dex_size_type";          // 0/1/2
    public static final String KEY_DUMP_APPLICATION = "application";
    public static final String KEY_DUMP_ACF = "app_component_factory";
    public static final String KEY_RECORD_NAME = "dex_file_name";
    public static final String KEY_LOADCLASS = "load_class";
    public static final String KEY_LOADCLASS_RULE = "load_class_rule";

    public static final int MODE_DEFAULT = 0;
    public static final int MODE_DATA = 1;
    public static final int MODE_POINTER = 2;

    public static final String FIXED_BASE_OUTPUT_DIR = "/sdcard/DexDumper";

    public String targetPackage = "";
    /** 0=default 1=data 2=pointer */
    public int mode = MODE_POINTER;
    public boolean dumpApplication = true;
    public boolean dumpAppComponentFactory = true;
    public boolean recordFileName = true;
    public boolean loadClassHook = false;
    public String loadClassRule = "";

    public static Config fromSharedPreferences(SharedPreferences sp) {
        Config c = new Config();
        c.targetPackage = sp.getString(KEY_TARGET, "");
        c.mode = clampMode(sp.getInt(KEY_MODE, MODE_POINTER));
        c.dumpApplication = sp.getBoolean(KEY_DUMP_APPLICATION, true);
        c.dumpAppComponentFactory = sp.getBoolean(KEY_DUMP_ACF, true);
        c.recordFileName = sp.getBoolean(KEY_RECORD_NAME, true);
        c.loadClassHook = sp.getBoolean(KEY_LOADCLASS, false);
        c.loadClassRule = sp.getString(KEY_LOADCLASS_RULE, "");
        return c;
    }

    public static Config fromXSharedPreferences(Object xprefs) {
        Config c = new Config();
        c.targetPackage = getString(xprefs, KEY_TARGET, "");
        c.mode = clampMode(getInt(xprefs, KEY_MODE, MODE_POINTER));
        c.dumpApplication = getBoolean(xprefs, KEY_DUMP_APPLICATION, true);
        c.dumpAppComponentFactory = getBoolean(xprefs, KEY_DUMP_ACF, true);
        c.recordFileName = getBoolean(xprefs, KEY_RECORD_NAME, true);
        c.loadClassHook = getBoolean(xprefs, KEY_LOADCLASS, false);
        c.loadClassRule = getString(xprefs, KEY_LOADCLASS_RULE, "");
        return c;
    }

    public static int clampMode(int v) {
        if (v < 0 || v > 2) return MODE_POINTER;
        return v;
    }

    public static String modeName(int m) {
        switch (m) {
            case MODE_DEFAULT: return "default";
            case MODE_DATA: return "data";
            case MODE_POINTER: return "pointer";
            default: return "unknown";
        }
    }

    private static String getString(Object o, String k, String d) {
        try { Method m = o.getClass().getMethod("getString", String.class, String.class); return (String) m.invoke(o, k, d); } catch (Throwable e) { return d; }
    }
    private static boolean getBoolean(Object o, String k, boolean d) {
        try { Method m = o.getClass().getMethod("getBoolean", String.class, boolean.class); return (Boolean) m.invoke(o, k, d); } catch (Throwable e) { return d; }
    }
    private static int getInt(Object o, String k, int d) {
        try { Method m = o.getClass().getMethod("getInt", String.class, int.class); return (Integer) m.invoke(o, k, d); } catch (Throwable e) { return d; }
    }
}
