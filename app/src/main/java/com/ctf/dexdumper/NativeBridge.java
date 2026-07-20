package com.ctf.dexdumper;

/**
 * native 桥接。pointer 模式的核心脱壳逻辑在 libdexdumper.so 中。
 *
 * 设计：不硬编码 ART DexFile 结构体偏移，运行时用 dex 魔数定位 begin_，
 * 紧邻 8 字节取 size_，mprotect 翻页后 memcpy 落盘。全版本兼容。
 */
public class NativeBridge {
    static {
        try {
            System.loadLibrary("dexdumper");
        } catch (Throwable t) {
            // 模块在目标进程内加载；若 .so 缺失仅影响 pointer 模式，不致命。
        }
    }

    /**
     * 对一个 dalvik.system.DexFile 对象执行 pointer 模式 dump。
     * @param dexFile DexFile 实例（来自 DexPathList.dexElements[].dexFile）
     * @param outPath 输出 .dex 文件绝对路径
     * @return 成功写入的字节数；<=0 表示失败（具体见 XposedBridge.log）
     */
    public static native int dumpDexFromDexFile(Object dexFile, String outPath);

    /** native 侧统一日志回调（写往 XposedBridge.log）。 */
    public static void nativeLog(String msg) {
        try {
            de.robv.android.xposed.XposedBridge.log("[DexDumper/native] " + msg);
        } catch (Throwable ignored) {
        }
    }
}
