// native_dump.cpp — DexDumper pointer mode
//
// 全版本兼容策略：不硬编码 ART DexFile 结构体偏移，不依赖被 strip 的 ART 符号。
//  1) JNI 反射取 dalvik.system.DexFile 的 mCookie / mInternalCookie。
//  2) 解码 cookie（long[] / Long / Integer / String 自适应），取出候选 DexFile* 指针。
//  3) 对每个候选指针 p，在 [0,512) 步长 8 扫描：读 q=*(void**)(p+off)，
//     若 q 指向的内存命中 dex 魔数 "dex\n035/037/038/039"，则 q 即 begin_。
//  4) size_ 紧邻 begin_（ART 各版本均为 `const uint8_t* begin_; size_t size_;`）→ size=*(size_t*)(p+off+8)。
//  5) mprotect 翻页为可读（失败忽略）→ write(2) 落盘。

#include <jni.h>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cinttypes>
#include <string>
#include <vector>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <fstream>
#include <sstream>

namespace {
struct Map { uintptr_t start, end; bool r; };

pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
std::vector<Map> g_maps;
bool g_maps_ok = false;

static void refreshMaps() {
    std::vector<Map> ms;
    std::ifstream f("/proc/self/maps");
    std::string line;
    while (std::getline(f, line)) {
        // start-end rwxp ...
        uintptr_t s = 0, e = 0;
        char perms[5] = {0};
        if (sscanf(line.c_str(), "%" SCNxPTR "-%" SCNxPTR " %4s", &s, &e, perms) >= 3) {
            ms.push_back({s, e, perms[0] == 'r'});
        }
    }
    pthread_mutex_lock(&g_lock);
    g_maps = std::move(ms);
    g_maps_ok = !g_maps.empty();
    pthread_mutex_unlock(&g_lock);
}

static bool readable(uintptr_t a, size_t n) {
    if (!g_maps_ok) refreshMaps();
    pthread_mutex_lock(&g_lock);
    bool ok = false;
    for (const auto& m : g_maps) {
        if (a >= m.start && a < m.end) {
            if (a + n <= m.end) ok = m.r;
            else ok = false;
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return ok;
}

static bool isDexMagic(const uint8_t* p) {
    if (!readable((uintptr_t)p, 8)) return false;
    return p[0] == 'd' && p[1] == 'e' && p[2] == 'x' && p[3] == '\n'
        && p[4] == '0' && p[5] == '3'
        && (p[6] == '5' || p[6] == '7' || p[6] == '8' || p[6] == '9');
}

// 在结构体 p 的前 512 字节内找 begin_（指向 dex 魔数的指针），返回 size，0 表示未命中。
// 命中时直接落盘到 outPath。
static long tryDumpBeginInStruct(uintptr_t p, const char* outPath) {
    if (p == 0 || !readable(p, 16)) return 0;
    for (size_t off = 0; off + 16 <= 512; off += 8) {
        uintptr_t q = 0;
        if (!readable(p + off, sizeof(uintptr_t))) continue;
        std::memcpy(&q, reinterpret_cast<const void*>(p + off), sizeof(uintptr_t));
        if (q == 0) continue;
        const uint8_t* qp = reinterpret_cast<const uint8_t*>(q);
        if (!isDexMagic(qp)) continue;
        size_t size = 0;
        if (!readable(p + off + sizeof(uintptr_t), sizeof(size_t))) continue;
        std::memcpy(&size, reinterpret_cast<const void*>(p + off + sizeof(uintptr_t)), sizeof(size_t));
        if (size < 0x70 || size > 0x10000000) continue;
        if (!readable(q, size)) {
            mprotect(reinterpret_cast<void*>(q), size, PROT_READ);
            if (!readable(q, size)) continue;
        }
        int fd = open(outPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) continue;
        ssize_t w = write(fd, qp, size);
        close(fd);
        if (w == (ssize_t)size) return (long)size;
        // 部分写入：逐页 mprotect 后拷贝到缓冲再落盘
        std::vector<uint8_t> tmp(size, 0);
        bool ok = true;
        for (size_t i = 0; i < size; ) {
            long psz = sysconf(_SC_PAGESIZE);
            size_t chunk = (size_t)psz - ((uintptr_t)qp + i) % (size_t)psz;
            if (chunk > size - i) chunk = size - i;
            if (!readable((uintptr_t)qp + i, chunk)) {
                mprotect((void*)((uintptr_t)(((uintptr_t)qp + i) & ~((uintptr_t)psz - 1))), (size_t)psz, PROT_READ);
                if (!readable((uintptr_t)qp + i, chunk)) { ok = false; break; }
            }
            std::memcpy(tmp.data() + i, qp + i, chunk);
            i += chunk;
        }
        if (ok) {
            fd = open(outPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) { ssize_t w2 = write(fd, tmp.data(), size); close(fd); if (w2 == (ssize_t)size) return (long)size; }
        }
    }
    return 0;
}

static long dumpFromPtr(uintptr_t dexFilePtr, const char* outPath) {
    if (dexFilePtr == 0) return 0;
    // Level 1：p 本身即 art::DexFile*，begin_ 直接在其结构体内
    long sz = tryDumpBeginInStruct(dexFilePtr, outPath);
    if (sz > 0) return sz;
    // Level 2：p 可能是 OatDexFile* 等中间结构，其中某指针字段指向真正的 DexFile*
    if (!readable(dexFilePtr, 16)) return 0;
    for (size_t off = 0; off + sizeof(uintptr_t) <= 256; off += 8) {
        uintptr_t q = 0;
        if (!readable(dexFilePtr + off, sizeof(uintptr_t))) continue;
        std::memcpy(&q, reinterpret_cast<const void*>(dexFilePtr + off), sizeof(uintptr_t));
        if (q == 0) continue;
        sz = tryDumpBeginInStruct(q, outPath);
        if (sz > 0) return sz;
    }
    return 0;
}

// ---- JNI 反射工具：按名取字段值（沿继承链），LSPosed 已 unseal hidden API ----

static jobject readFieldByName(JNIEnv* env, jobject target, const char* name) {
    if (!target) return nullptr;
    jclass classCls = env->FindClass("java/lang/Class");
    jmethodID getDeclaredField = env->GetMethodID(classCls, "getDeclaredField",
        "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    jmethodID getSuperclass = env->GetMethodID(classCls, "getSuperclass", "()Ljava/lang/Class;");
    jclass fieldCls = env->FindClass("java/lang/reflect/Field");
    jmethodID setAccessible = env->GetMethodID(fieldCls, "setAccessible", "(Z)V");
    jmethodID fieldGet = env->GetMethodID(fieldCls, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");

    jclass cls = env->GetObjectClass(target);
    jobject result = nullptr;
    while (cls != nullptr) {
        env->ExceptionClear();
        jstring jname = env->NewStringUTF(name);
        jobject field = env->CallObjectMethod(cls, getDeclaredField, jname);
        env->DeleteLocalRef(jname);
        if (env->ExceptionCheck()) { env->ExceptionClear(); }
        if (field != nullptr) {
            env->CallVoidMethod(field, setAccessible, JNI_TRUE);
            if (env->ExceptionCheck()) env->ExceptionClear();
            result = env->CallObjectMethod(field, fieldGet, target);
            if (env->ExceptionCheck()) { env->ExceptionClear(); result = nullptr; }
            env->DeleteLocalRef(field);
            env->DeleteLocalRef(cls);
            return result;
        }
        jclass sup = (jclass) env->CallObjectMethod(cls, getSuperclass);
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(cls);
        cls = sup;
        if (cls == env->FindClass("java/lang/Object")) { env->DeleteLocalRef(cls); break; }
    }
    return nullptr;
}

// native 侧统一写日志到 XposedBridge.log（通过调用 Java 静态方法 NativeBridge.nativeLog）
static void NativeBridge_nativeLog(JNIEnv* env, const char* msg) {
    if (!env || !msg) return;
    jclass cls = env->FindClass("com/ctf/dexdumper/NativeBridge");
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!cls) return;
    jmethodID mid = env->GetStaticMethodID(cls, "nativeLog", "(Ljava/lang/String;)V");
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (mid) {
        jstring jmsg = env->NewStringUTF(msg);
        env->CallStaticVoidMethod(cls, mid, jmsg);
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(jmsg);
    }
    env->DeleteLocalRef(cls);
}

} // namespace anon

extern "C" JNIEXPORT jint JNICALL
Java_com_ctf_dexdumper_NativeBridge_dumpDexFromDexFile(
        JNIEnv* env, jclass, jobject dexFile, jstring outPathJ) {
    if (!dexFile || !outPathJ) return -1;
    const char* outPath = env->GetStringUTFChars(outPathJ, nullptr);
    if (!outPath) return -1;
    std::string path(outPath);
    env->ReleaseStringUTFChars(outPathJ, outPath);

    refreshMaps();

    // 1) 取 cookie：优先 mCookie，回退 mInternalCookie
    jobject cookie = readFieldByName(env, dexFile, "mCookie");
    if (!cookie) cookie = readFieldByName(env, dexFile, "mInternalCookie");
    if (!cookie) {
        NativeBridge_nativeLog(env, "no mCookie/mInternalCookie on DexFile");
        return -2;
    }

    // 2) 解码 cookie 类型
    std::vector<uintptr_t> candidates;
    jclass longArrayCls = env->FindClass("[J");       // long[]
    jclass longCls = env->FindClass("java/lang/Long");
    jclass intCls = env->FindClass("java/lang/Integer");
    jclass strCls = env->FindClass("java/lang/String");

    if (env->IsInstanceOf(cookie, longArrayCls)) {
        jlongArray arr = reinterpret_cast<jlongArray>(cookie);
        jsize n = env->GetArrayLength(arr);
        std::vector<jlong> buf(n);
        env->GetLongArrayRegion(arr, 0, n, buf.data());
        for (jlong v : buf) {
            candidates.push_back((uintptr_t)v);
        }
    } else if (env->IsInstanceOf(cookie, longCls)) {
        jmethodID lv = env->GetMethodID(longCls, "longValue", "()J");
        candidates.push_back((uintptr_t) env->CallLongMethod(cookie, lv));
    } else if (env->IsInstanceOf(cookie, intCls)) {
        jmethodID iv = env->GetMethodID(intCls, "intValue", "()I");
        candidates.push_back((uintptr_t)(uint32_t) env->CallIntMethod(cookie, iv));
    } else if (env->IsInstanceOf(cookie, strCls)) {
        NativeBridge_nativeLog(env, "cookie is String (oat path), pointer mode needs long[]/Long/Integer cookie");
        env->DeleteLocalRef(cookie);
        return -3;
    } else {
        // 未知类型，尝试把它当 long[] 不行就放弃
        NativeBridge_nativeLog(env, "cookie has unknown type, skip");
        env->DeleteLocalRef(cookie);
        return -4;
    }
    env->DeleteLocalRef(cookie);

    // 3) 对每个候选指针尝试 dump
    long best = 0;
    for (uintptr_t p : candidates) {
        if (p == 0) continue;
        long sz = dumpFromPtr(p, path.c_str());
        if (sz > 0) { best = sz; break; }
    }
    return (jint) best;
}
