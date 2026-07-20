package com.ctf.dexdumper;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.robv.android.xposed.XposedBridge;

/**
 * 反射遍历 ClassLoader 链，收集所有 dalvik.system.DexFile 对象及其来源路径。
 *
 * 链路：BaseDexClassLoader.pathList(DexPathList) -> dexElements(Element[])
 *      -> Element.dexFile(DexFile) / Element.path(File)
 *
 * LSPosed 已 unseal hidden API，反射可达 DexFile.mCookie 等隐藏字段。
 */
public final class DexFileWalker {

    public static final class DexEntry {
        /** dalvik.system.DexFile 实例；可能为 null（仅落盘路径可达时） */
        public final Object dexFile;
        /** 原始 dex/apk/odex 路径，可能为 null */
        public final String sourcePath;
        /** 该 dex 所属 ClassLoader 的简单描述 */
        public final String loaderDesc;

        public DexEntry(Object dexFile, String sourcePath, String loaderDesc) {
            this.dexFile = dexFile;
            this.sourcePath = sourcePath;
            this.loaderDesc = loaderDesc;
        }
    }

    public static List<DexEntry> walk(ClassLoader root) {
        List<DexEntry> out = new ArrayList<>();
        Set<Object> visited = new HashSet<>();   // 去重 DexFile 对象引用
        ClassLoader cl = root;
        int guard = 0;
        while (cl != null && guard++ < 64) {
            String desc = cl.getClass().getName();
            if (cl.getClass().getName().startsWith("dalvik.system.BaseDexClassLoader")
                    || cl.getClass().getName().contains("DexClassLoader")
                    || cl.getClass().getName().contains("PathClassLoader")
                    || cl.getClass().getName().contains("DelegateLastClassLoader")
                    || cl.getClass().getName().contains("InMemoryDexClassLoader")) {
                collectFromBaseDexClassLoader(cl, desc, out, visited);
            }
            try {
                cl = cl.getParent();
            } catch (Throwable t) {
                break;
            }
        }
        return out;
    }

    private static void collectFromBaseDexClassLoader(ClassLoader cl, String desc,
                                                      List<DexEntry> out, Set<Object> visited) {
        try {
            Field pathList = findField(cl.getClass(), "pathList");
            if (pathList == null) return;
            pathList.setAccessible(true);
            Object dexPathList = pathList.get(cl);
            if (dexPathList == null) return;

            Field dexElements = findField(dexPathList.getClass(), "dexElements");
            if (dexElements == null) return;
            dexElements.setAccessible(true);
            Object[] elements = (Object[]) dexElements.get(dexPathList);
            if (elements == null) return;

            for (Object element : elements) {
                if (element == null) continue;
                Object dexFile = readField(element, "dexFile");
                String path = null;
                Object pathObj = readField(element, "path");
                if (pathObj instanceof java.io.File) {
                    path = ((java.io.File) pathObj).getAbsolutePath();
                } else if (pathObj != null) {
                    path = String.valueOf(pathObj);
                }
                if (dexFile != null) {
                    if (!visited.add(dexFile)) continue;     // 同一 DexFile 已收集
                    String name = readFileName(dexFile);
                    out.add(new DexEntry(dexFile, path != null ? path : name, desc));
                } else if (path != null) {
                    out.add(new DexEntry(null, path, desc));
                }
            }
        } catch (Throwable t) {
            XposedBridge.log("[DexDumper] walk " + desc + " failed: " + t);
        }
    }

    private static String readFileName(Object dexFile) {
        try {
            Object name = readField(dexFile, "mFileName");
            return name != null ? String.valueOf(name) : null;
        } catch (Throwable t) {
            return null;
        }
    }

    private static Object readField(Object obj, String name) {
        try {
            Field f = findField(obj.getClass(), name);
            if (f == null) return null;
            f.setAccessible(true);
            return f.get(obj);
        } catch (Throwable t) {
            return null;
        }
    }

    /** 沿继承链查找字段（子类隐藏父类字段时也能取到）。 */
    private static Field findField(Class<?> clazz, String name) {
        Class<?> c = clazz;
        while (c != null && c != Object.class) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
                c = c.getSuperclass();
            } catch (Throwable t) {
                break;
            }
        }
        return null;
    }
}
