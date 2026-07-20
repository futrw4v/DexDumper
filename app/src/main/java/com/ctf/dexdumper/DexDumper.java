package com.ctf.dexdumper;

import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.os.Environment;
import android.os.Handler;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * 三模式 dump 引擎（镜像 Layout.Inspect 的 default/data/pointer）。
 *
 * default : 落盘直读（APK 内 classes*.dex / .dex/.odex/.vdex 文件）
 * data    : hook DexPathList.<init>(ByteBuffer[]) 抓取内存加载字节，对抗加载后清零
 * pointer : native 直拷 ART DexFile.begin_/size_（mprotect 翻页 + memcpy）
 */
public final class DexDumper {

    private static final String TAG = "[DexDumper] ";

    private static Context sCtx;
    private static String sPkg;
    private static Config sCfg;
    private static File sOutDir;

    /** data 模式：按 ClassLoader 缓存其内存加载的 ByteBuffer[]。 */
    private static final Map<ClassLoader, List<ByteBuffer>> sMemDex = new java.util.WeakHashMap<>();
    /** 去重：已落盘 dex 的 sha1。 */
    private static final List<String> sWrittenSha = new ArrayList<>();

    public static void init(Context ctx, String pkg, Config cfg) {
        sCtx = ctx;
        sPkg = pkg;
        sCfg = cfg;
        sOutDir = ensureOutDir(pkg);
        installDataHook(cfg);
        if (cfg.loadClassHook) {
            installLoadClassHook(cfg);
        }
        installRuntimeReceiver();
        XposedBridge.log(TAG + "init ok, mode=" + Config.modeName(cfg.mode)
                + " out=" + sOutDir.getAbsolutePath());
    }

    // ---------------------------------------------------------------- public trigger

    public static int dumpNow() {
        if (sCtx == null || sCfg == null) {
            XposedBridge.log(TAG + "not initialized");
            return 0;
        }
        ClassLoader cl = sCtx.getClassLoader();
        return dumpWith(cl, sCfg.mode);
    }

    public static int dumpWith(ClassLoader root, int mode) {
        List<DexFileWalker.DexEntry> entries = DexFileWalker.walk(root);
        XposedBridge.log(TAG + "walk got " + entries.size() + " dex entry(ies) for mode=" + Config.modeName(mode));

        Map<String, File> results = new LinkedHashMap<>();
        int idx = 0;
        for (DexFileWalker.DexEntry e : entries) {
            idx++;
            try {
                List<File> files;
                switch (mode) {
                    case Config.MODE_DEFAULT:  files = dumpDefault(e); break;
                    case Config.MODE_DATA:     files = dumpData(e);    break;
                    case Config.MODE_POINTER:  files = dumpPointer(e); break;
                    default:                   files = dumpPointer(e);
                }
                for (File f : files) {
                    if (f == null || !f.exists() || f.length() <= 0) continue;
                    String sha = sha1(f);
                    if (sha == null) continue;
                    if (sWrittenSha.contains(sha)) {
                        //noinspection ResultOfMethodCallIgnored
                        f.delete();
                        continue;
                    }
                    sWrittenSha.add(sha);
                    String origin = sCfg.recordFileName ? safeName(e.sourcePath) : ("entry" + idx);
                    File dest = new File(sOutDir, Config.modeName(mode) + "_" + sha.substring(0, 8)
                            + "_" + origin + ".dex");
                    boolean moved = false;
                    if (f.renameTo(dest)) {
                        moved = true;
                    } else if (f.exists()) {
                        copy(f, dest);
                        if (dest.exists() && dest.length() == f.length()) {
                            //noinspection ResultOfMethodCallIgnored
                            f.delete();
                            moved = true;
                        }
                    }
                    if (!moved) {
                        // dest 不可写：把 temp 改名留在 codeCache 作为兜底产物（可 root pull）
                        File keep = new File(sCtx.getCodeCacheDir(),
                                Config.modeName(mode) + "_" + sha.substring(0, 8) + "_" + origin + ".dex");
                        if (!f.renameTo(keep) && f.exists()) copy(f, keep);
                        File out = keep.exists() ? keep : f;
                        results.put(sha, out);
                        XposedBridge.log(TAG + "dest unwritable, kept temp: " + out.getAbsolutePath());
                    } else {
                        results.put(sha, dest);
                    }
                }
            } catch (Throwable t) {
                XposedBridge.log(TAG + "dump entry #" + idx + " failed: " + t);
                XposedBridge.log(t);
            }
        }
        writeManifest(results, mode);
        XposedBridge.log(TAG + "mode=" + Config.modeName(mode) + " done, wrote " + results.size() + " dex");
        return results.size();
    }

    // ---------------------------------------------------------------- mode 0 default

    private static List<File> dumpDefault(DexFileWalker.DexEntry e) {
        List<File> out = new ArrayList<>();
        // 1) 优先从 ApplicationInfo.sourceDir / splits 取 APK 内 classes*.dex
        if (sCfg.dumpApplication) {
            for (String apk : collectApkPaths()) {
                out.addAll(extractDexFromApk(apk));
            }
        }
        // 2) 从 entry 自带路径取
        String p = e.sourcePath;
        if (p != null && p.length() > 0) {
            if (p.toLowerCase().endsWith(".apk")) {
                out.addAll(extractDexFromApk(p));
            } else if (p.toLowerCase().endsWith(".dex")) {
                File src = new File(p);
                if (src.exists()) out.add(copyToTemp(src));
            } else if (p.toLowerCase().endsWith(".odex") || p.toLowerCase().endsWith(".vdex")
                    || p.toLowerCase().endsWith(".cdex") || p.toLowerCase().endsWith(".art")) {
                File src = new File(p);
                if (src.exists()) out.add(copyToTemp(src));   // v1 整文件拷贝并记录
            }
        }
        return out;
    }

    private static List<String> collectApkPaths() {
        List<String> apks = new ArrayList<>();
        try {
            ApplicationInfo ai = sCtx.getApplicationInfo();
            if (ai.sourceDir != null) apks.add(ai.sourceDir);
            if (ai.splitPublicSourceDirs != null) apks.addAll(Arrays.asList(ai.splitPublicSourceDirs));
        } catch (Throwable ignored) {}
        return apks;
    }

    private static List<File> extractDexFromApk(String apkPath) {
        List<File> out = new ArrayList<>();
        File apk = new File(apkPath);
        if (!apk.exists()) return out;
        ZipInputStream zis = null;
        try {
            zis = new ZipInputStream(new FileInputStream(apk));
            ZipEntry ze;
            while ((ze = zis.getNextEntry()) != null) {
                String n = ze.getName();
                if (n.startsWith("classes") && n.endsWith(".dex")) {
                    File tmp = tempFile(".dex");
                    pipe(zis, tmp);
                    out.add(tmp);
                }
                zis.closeEntry();
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + "extract apk " + apkPath + " failed: " + t);
        } finally {
            if (zis != null) try { zis.close(); } catch (Throwable ignored) {}
        }
        return out;
    }

    // ---------------------------------------------------------------- mode 1 data

    private static List<File> dumpData(DexFileWalker.DexEntry e) {
        List<File> out = new ArrayList<>();
        if (e.dexFile == null) return out;
        // 1) 优先查 ClassLoader 缓存的内存 ByteBuffer（DexPathList.<init> 捕获）
        synchronized (sMemDex) {
            for (Map.Entry<ClassLoader, List<ByteBuffer>> en : sMemDex.entrySet()) {
                // 无法精确关联 entry 与 loader，data 模式把所有缓存一次性 dump（去重由 sha 保证）
                for (ByteBuffer bb : en.getValue()) {
                    out.add(writeByteBuffer(bb));
                }
            }
        }
        // 2) 兜底：尝试反射 Element/DexFile 上的 ByteBuffer/byte[] 字段
        Object maybeBuf = readAny(e.dexFile, new String[]{"mData", "mDexBuffer"});
        if (maybeBuf instanceof ByteBuffer) out.add(writeByteBuffer((ByteBuffer) maybeBuf));
        if (maybeBuf instanceof byte[]) out.add(writeBytes((byte[]) maybeBuf));
        return out;
    }

    // ---------------------------------------------------------------- mode 2 pointer

    private static List<File> dumpPointer(DexFileWalker.DexEntry e) {
        List<File> out = new ArrayList<>();
        if (e.dexFile == null) {
            XposedBridge.log(TAG + "pointer: dexFile null for " + e.sourcePath + ", skip");
            return out;
        }
        try {
            File tmp = tempFile(".dex");
            int n = NativeBridge.dumpDexFromDexFile(e.dexFile, tmp.getAbsolutePath());
            if (n > 0 && tmp.exists() && tmp.length() > 0) {
                out.add(tmp);
            } else {
                //noinspection ResultOfMethodCallIgnored
                tmp.delete();
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + "pointer native call failed: " + t);
        }
        return out;
    }

    // ---------------------------------------------------------------- hooks

    private static void installDataHook(Config cfg) {
        // hook DexPathList.<init>(ClassLoader, ByteBuffer[]) —— InMemoryDexClassLoader 路径
        try {
            Class<?> dexPathList = Class.forName("dalvik.system.DexPathList");
            XposedHelpers.findAndHookConstructor(dexPathList,
                    ClassLoader.class, ByteBuffer[].class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                Object thisObj = param.thisObject;
                                ClassLoader owner = readOwner(thisObj);
                                ByteBuffer[] bufs = (ByteBuffer[]) param.args[1];
                                if (bufs == null || bufs.length == 0) return;
                                synchronized (sMemDex) {
                                    sMemDex.put(owner, new ArrayList<>(Arrays.asList(bufs)));
                                }
                                XposedBridge.log(TAG + "data: captured " + bufs.length
                                        + " in-memory ByteBuffer(s) for " + owner);
                            } catch (Throwable t) {
                                XposedBridge.log(TAG + "data hook after failed: " + t);
                            }
                        }
                    });
            XposedBridge.log(TAG + "data hook installed (DexPathList.<init> ByteBuffer[])");
        } catch (Throwable t) {
            XposedBridge.log(TAG + "data hook install failed: " + t);
        }
    }

    /** 反射取 DexPathList.definingContext（持有它的 ClassLoader）。 */
    private static ClassLoader readOwner(Object dexPathList) {
        try {
            Class<?> c = dexPathList.getClass();
            while (c != null && c != Object.class) {
                try {
                    java.lang.reflect.Field f = c.getDeclaredField("definingContext");
                    f.setAccessible(true);
                    Object o = f.get(dexPathList);
                    if (o instanceof ClassLoader) return (ClassLoader) o;
                    break;
                } catch (NoSuchFieldException ignored) {
                    c = c.getSuperclass();
                }
            }
        } catch (Throwable ignored) {}
        return Thread.currentThread().getContextClassLoader();
    }

    private static void installLoadClassHook(Config cfg) {
        final String rule = cfg.loadClassRule == null ? "" : cfg.loadClassRule.trim();
        try {
            XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class, boolean.class,
                    new XC_MethodHook() {
                        private long last = 0;
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                String name = (String) param.args[0];
                                if (name == null) return;
                                if (rule.length() > 0 && !name.contains(rule)) return;
                                long now = System.currentTimeMillis();
                                if (now - last < 2000) return; // 节流
                                last = now;
                                XposedBridge.log(TAG + "loadClass trigger: " + name);
                                dumpWith(sCtx.getClassLoader(), sCfg.mode);
                            } catch (Throwable ignored) {}
                        }
                    });
            XposedBridge.log(TAG + "loadClass hook installed (rule=" + rule + ")");
        } catch (Throwable t) {
            XposedBridge.log(TAG + "loadClass hook install failed: " + t);
        }
    }

    // ---------------------------------------------------------------- runtime receiver (target process)

    /** 在目标进程内运行时注册 receiver：am broadcast 可直接命中并触发即时 dump。 */
    private static void installRuntimeReceiver() {
        try {
            BroadcastReceiver rr = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    if (intent == null || intent.getAction() == null) return;
                    String action = intent.getAction();
                    if ("com.ctf.dexdumper.action.DUMP".equals(action)) {
                        try {
                            int n = dumpNow();
                            toast("DexDumper dump: " + n + " dex");
                        } catch (Throwable t) {
                            XposedBridge.log(TAG + "runtime DUMP failed: " + t);
                        }
                    } else if ("com.ctf.dexdumper.action.STATUS".equals(action)) {
                        int cnt = countDexInDir();
                        toast("DexDumper: " + cnt + " dex in " + sOutDir.getAbsolutePath());
                    }
                }
            };
            IntentFilter f = new IntentFilter();
            f.addAction("com.ctf.dexdumper.action.DUMP");
            f.addAction("com.ctf.dexdumper.action.STATUS");
            sCtx.registerReceiver(rr, f);
            XposedBridge.log(TAG + "runtime receiver registered (DUMP/STATUS)");
        } catch (Throwable t) {
            XposedBridge.log(TAG + "runtime receiver install failed: " + t);
        }
    }

    private static int countDexInDir() {
        try {
            File[] fs = sOutDir.listFiles();
            if (fs == null) return 0;
            int n = 0;
            for (File f : fs) if (f.isFile() && f.getName().endsWith(".dex")) n++;
            return n;
        } catch (Throwable t) {
            return -1;
        }
    }

    private static void toast(final String msg) {
        new Handler(android.os.Looper.getMainLooper()).post(() -> {
            try { Toast.makeText(sCtx, msg, Toast.LENGTH_LONG).show(); } catch (Throwable ignored) {}
        });
    }

    // ---------------------------------------------------------------- io helpers

    private static File ensureOutDir(String pkg) {
        // 1) 优先 /sdcard/DexDumper/<pkg>（legacy，需目标有存储权限）
        File legacy = new File(new File(Environment.getExternalStorageDirectory(), "DexDumper"), pkg);
        try {
            if ((legacy.mkdirs() || legacy.isDirectory()) && canWriteTo(legacy)) return legacy;
        } catch (Throwable ignored) {}
        // 2) 回退到目标 App 自己的 external files dir（免权限可写）
        try {
            File ef = sCtx.getExternalFilesDir(null);
            if (ef != null) {
                File d = new File(ef, "DexDumper");
                if (d.mkdirs() || d.isDirectory()) return d;
            }
        } catch (Throwable ignored) {}
        // 3) 再回退到内部 files dir（总是可写，pull 需 root）
        try {
            File d = new File(sCtx.getFilesDir(), "DexDumper");
            if (d.mkdirs() || d.isDirectory()) return d;
        } catch (Throwable ignored) {}
        return legacy;
    }

    private static boolean canWriteTo(File dir) {
        File t = new File(dir, ".writetest");
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(t)) {
            fos.write(1); fos.flush();
            return true;
        } catch (Throwable t2) {
            return false;
        } finally {
            try { t.delete(); } catch (Throwable ignored) {}
        }
    }

    private static File tempFile(String suffix) {
        try {
            File f = File.createTempFile("dex_", suffix, sCtx.getCodeCacheDir());
            //noinspection ResultOfMethodCallIgnored
            f.deleteOnExit();
            return f;
        } catch (Throwable t) {
            return new File(sCtx.getCodeCacheDir(), "dex_" + System.nanoTime() + suffix);
        }
    }

    private static File writeByteBuffer(ByteBuffer bb) {
        File f = tempFile(".dex");
        try {
            ByteBuffer dup = bb.duplicate();
            dup.rewind();
            byte[] buf = new byte[dup.remaining()];
            dup.get(buf);
            write(f, buf);
        } catch (Throwable t) {
            XposedBridge.log(TAG + "write bb failed: " + t);
        }
        return f;
    }

    private static File writeBytes(byte[] bytes) {
        File f = tempFile(".dex");
        write(f, bytes);
        return f;
    }

    private static File copyToTemp(File src) {
        File f = tempFile(".dex");
        try {
            pipe(new FileInputStream(src), f);
        } catch (Throwable t) {
            XposedBridge.log(TAG + "copy " + src + " failed: " + t);
        }
        return f;
    }

    private static void copy(File src, File dst) {
        try { pipe(new FileInputStream(src), dst); } catch (Throwable t) { XposedBridge.log(TAG + "copy failed: " + t); }
    }

    private static void pipe(InputStream in, File out) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(out);
            byte[] b = new byte[8192];
            int n;
            while ((n = in.read(b)) > 0) fos.write(b, 0, n);
            fos.flush();
        } catch (Throwable t) {
            XposedBridge.log(TAG + "pipe failed: " + t);
        } finally {
            try { in.close(); } catch (Throwable ignored) {}
            if (fos != null) try { fos.close(); } catch (Throwable ignored) {}
        }
    }

    private static void write(File f, byte[] data) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(f);
            fos.write(data);
            fos.flush();
        } catch (Throwable t) {
            XposedBridge.log(TAG + "write failed: " + t);
        } finally {
            if (fos != null) try { fos.close(); } catch (Throwable ignored) {}
        }
    }

    private static void writeManifest(Map<String, File> results, int mode) {
        File m = new File(sOutDir, "manifest.txt");
        StringBuilder sb = new StringBuilder();
        sb.append("package=").append(sPkg).append('\n');
        sb.append("mode=").append(Config.modeName(mode)).append('\n');
        sb.append("dumped=").append(results.size()).append('\n');
        int i = 0;
        for (Map.Entry<String, File> e : results.entrySet()) {
            sb.append('#').append(++i).append(' ')
              .append(e.getValue().getName()).append(' ')
              .append(e.getValue().length()).append(" sha1=").append(e.getKey()).append('\n');
        }
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(m);
            fos.write(sb.toString().getBytes("UTF-8"));
        } catch (Throwable t) {
            XposedBridge.log(TAG + "write manifest failed: " + t);
        } finally {
            if (fos != null) try { fos.close(); } catch (Throwable ignored) {}
        }
    }

    private static String sha1(File f) {
        FileInputStream in = null;
        try {
            in = new FileInputStream(f);
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] b = new byte[8192];
            int n;
            while ((n = in.read(b)) > 0) md.update(b, 0, n);
            return toHex(md.digest());
        } catch (Throwable t) {
            return null;
        } finally {
            if (in != null) try { in.close(); } catch (Throwable ignored) {}
        }
    }

    private static String toHex(byte[] d) {
        StringBuilder sb = new StringBuilder();
        for (byte x : d) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    private static String safeName(String p) {
        if (p == null) return "unk";
        int slash = p.lastIndexOf('/');
        String n = slash >= 0 ? p.substring(slash + 1) : p;
        return n.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    private static Object readAny(Object obj, String[] fields) {
        for (String name : fields) {
            try {
                Class<?> c = obj.getClass();
                while (c != null && c != Object.class) {
                    try {
                        java.lang.reflect.Field f = c.getDeclaredField(name);
                        f.setAccessible(true);
                        return f.get(obj);
                    } catch (NoSuchFieldException ignored) {
                        c = c.getSuperclass();
                    }
                }
            } catch (Throwable ignored) {}
        }
        return null;
    }
}
