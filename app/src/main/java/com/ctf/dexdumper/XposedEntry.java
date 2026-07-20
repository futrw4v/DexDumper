package com.ctf.dexdumper;

import android.app.Application;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import java.util.concurrent.atomic.AtomicBoolean;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class XposedEntry implements IXposedHookLoadPackage {
    private final AtomicBoolean installed = new AtomicBoolean(false);
    private final AtomicBoolean dumped = new AtomicBoolean(false);

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (lpparam == null || lpparam.packageName == null) return;
        if (Config.MODULE_PACKAGE.equals(lpparam.packageName)) return;

        final Config cfg = readConfig();
        // LSPosed 作用域决定模块对哪些 App 生效；targetPackage 仅作可选二次过滤。
        if (cfg.targetPackage != null && cfg.targetPackage.trim().length() > 0
                && !lpparam.packageName.equals(cfg.targetPackage.trim())) {
            return;
        }

        XposedBridge.log("[DexDumper] target matched: " + lpparam.packageName
                + " mode=" + Config.modeName(cfg.mode));

        XposedHelpers.findAndHookMethod(Application.class, "attach", Context.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (!installed.compareAndSet(false, true)) return;
                Context ctx = (Context) param.args[0];
                try {
                    DexDumper.init(ctx, lpparam.packageName, cfg);
                    XposedBridge.log("[DexDumper] engine ready for " + lpparam.packageName);
                    // 等 Application 真正起来后再 dump，classloader 已就绪。
                    XposedHelpers.findAndHookMethod(Application.class, "onCreate", new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            if (!dumped.compareAndSet(false, true)) return;
                            new Handler(Looper.getMainLooper()).postDelayed(() -> {
                                try {
                                    int n = DexDumper.dumpNow();
                                    XposedBridge.log("[DexDumper] initial dump wrote " + n + " dex");
                                } catch (Throwable t) {
                                    XposedBridge.log("[DexDumper] initial dump failed: " + t);
                                    XposedBridge.log(t);
                                }
                            }, 1500);
                        }
                    });
                } catch (Throwable t) {
                    XposedBridge.log("[DexDumper] init failed: " + t);
                    XposedBridge.log(t);
                }
            }
        });
    }

    private Config readConfig() {
        try {
            XSharedPreferences xp = new XSharedPreferences(Config.MODULE_PACKAGE, Config.PREFS_NAME);
            xp.makeWorldReadable();
            xp.reload();
            return Config.fromXSharedPreferences(xp);
        } catch (Throwable t) {
            XposedBridge.log("[DexDumper] read config failed: " + t);
            return new Config();
        }
    }
}
