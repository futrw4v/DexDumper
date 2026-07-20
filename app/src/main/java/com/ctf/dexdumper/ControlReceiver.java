package com.ctf.dexdumper;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.widget.Toast;

import java.io.File;

/**
 * 模块进程内运行的 receiver（在 LSPosed 管理器里点模块图标对应的进程）。
 * 仅做与文件系统相关的离线操作：清空输出目录、查询输出目录大小。
 *
 * 即时 re-dump（运行中触发）由 DexDumper 在目标进程内运行时注册的 receiver 处理，
 * 广播 action 相同（com.ctf.dexdumper.action.DUMP），am broadcast 会同时命中两者；
 * 本类忽略 DUMP（模块进程无目标 ClassLoader 可 dump）。
 */
public class ControlReceiver extends BroadcastReceiver {
    public static final String ACTION_DUMP = "com.ctf.dexdumper.action.DUMP";
    public static final String ACTION_STATUS = "com.ctf.dexdumper.action.STATUS";
    public static final String ACTION_CLEAR = "com.ctf.dexdumper.action.CLEAR";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (context == null || intent == null || intent.getAction() == null) return;
        String action = intent.getAction();
        String pkg = intent.getStringExtra("package");
        if (ACTION_STATUS.equals(action)) {
            File base = new File(android.os.Environment.getExternalStorageDirectory(), "DexDumper");
            long count = countDex(base, pkg);
            toast(context, "DexDumper output: " + count + " dex file(s) under " + base.getAbsolutePath());
        } else if (ACTION_CLEAR.equals(action)) {
            File base = new File(android.os.Environment.getExternalStorageDirectory(), "DexDumper");
            long removed = clearDir(base, pkg);
            toast(context, "DexDumper cleared " + removed + " file(s)");
        }
        // ACTION_DUMP: 模块进程内忽略，由目标进程内运行时 receiver 处理。
    }

    private long countDex(File base, String pkg) {
        long n = 0;
        if (base == null || !base.isDirectory()) return 0;
        File[] targets = (pkg != null && pkg.trim().length() > 0)
                ? new File[]{new File(base, sanitize(pkg))}
                : base.listFiles();
        if (targets == null) return 0;
        for (File d : targets) {
            if (d == null) continue;
            if (d.isDirectory()) {
                File[] fs = d.listFiles();
                if (fs != null) for (File f : fs) if (f.isFile() && f.getName().endsWith(".dex")) n++;
            } else if (d.isFile() && d.getName().endsWith(".dex")) {
                n++;
            }
        }
        return n;
    }

    private long clearDir(File base, String pkg) {
        long removed = 0;
        if (base == null || !base.isDirectory()) return 0;
        File[] targets = (pkg != null && pkg.trim().length() > 0)
                ? new File[]{new File(base, sanitize(pkg))}
                : base.listFiles();
        if (targets == null) return 0;
        for (File d : targets) {
            if (d == null) continue;
            removed += deleteRecursive(d);
        }
        return removed;
    }

    private long deleteRecursive(File f) {
        long n = 0;
        if (f == null || !f.exists()) return 0;
        if (f.isDirectory()) {
            File[] fs = f.listFiles();
            if (fs != null) for (File c : fs) n += deleteRecursive(c);
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
        return n + 1;
    }

    private String sanitize(String s) {
        return s == null ? "unknown" : s.replaceAll("[^a-zA-Z0-9_.-]", "_");
    }

    private void toast(Context context, String msg) {
        try { Toast.makeText(context, msg, Toast.LENGTH_SHORT).show(); } catch (Throwable ignored) {}
    }
}
