// Native pointer-mode DEX dumper. ART's DexFile layout is private and changes
// between releases, so the begin_/size_ pair is discovered from DEX magic.
#include <jni.h>
#include <android/log.h>
#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <pthread.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <deque>
#include <unordered_set>
#include <vector>

namespace {
constexpr char kLogTag[] = "DexDumper/native";
constexpr size_t kMaxDexSize = 256u * 1024u * 1024u;
// NativeDexFile/DexFile layouts are private ART implementation details.  A
// cookie may therefore point at either object, with one or more pointer
// indirections before the actual DexFile.  Keep the graph walk bounded: the
// cookie is trusted input from ART, but arbitrary pointer chasing must never
// turn a failed dump into an unbounded scan of the process address space.
constexpr size_t kObjectScanBytes = 2048u;
constexpr size_t kMaxGraphNodes = 16u;
constexpr int kMaxGraphDepth = 2;

struct Map { uintptr_t start; uintptr_t end; int protection; };
pthread_mutex_t g_mapsLock = PTHREAD_MUTEX_INITIALIZER;
std::vector<Map> g_maps;
thread_local JNIEnv* g_logEnv = nullptr;

static void javaNativeLog(JNIEnv* env, const char* message);

static void nativeLog(const char* format, ...) {
    char message[512];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "%s", message);
    // Also mirror native diagnostics into XposedBridge.log while the JNI call
    // is active, so an operator does not need a separate logcat collection.
    if (g_logEnv != nullptr) javaNativeLog(g_logEnv, message);
}

static void refreshMaps() {
    std::vector<Map> maps;
    std::ifstream file("/proc/self/maps");
    std::string line;
    while (std::getline(file, line)) {
        uintptr_t start = 0, end = 0;
        char permissions[5] = {0};
        if (sscanf(line.c_str(), "%" SCNxPTR "-%" SCNxPTR " %4s",
                   &start, &end, permissions) >= 3 && start < end) {
            int protection = 0;
            if (permissions[0] == 'r') protection |= PROT_READ;
            if (permissions[1] == 'w') protection |= PROT_WRITE;
            if (permissions[2] == 'x') protection |= PROT_EXEC;
            maps.push_back({start, end, protection});
        }
    }
    pthread_mutex_lock(&g_mapsLock);
    g_maps.swap(maps);
    pthread_mutex_unlock(&g_mapsLock);
}

// Check every mapping crossed by [address, address + length), not just one
// /proc/self/maps row. Large DEX images commonly cross several rows.
static bool rangeReadableCached(uintptr_t address, size_t length) {
    if (length == 0) return true;
    if (address > UINTPTR_MAX - length) return false;
    pthread_mutex_lock(&g_mapsLock);
    uintptr_t cursor = address;
    const uintptr_t end = address + length;
    while (cursor < end) {
        const Map* found = nullptr;
        for (const Map& map : g_maps) {
            if (cursor >= map.start && cursor < map.end) { found = &map; break; }
        }
        if (found == nullptr || !(found->protection & PROT_READ)) {
            pthread_mutex_unlock(&g_mapsLock);
            return false;
        }
        cursor = found->end < end ? found->end : end;
    }
    pthread_mutex_unlock(&g_mapsLock);
    return true;
}

static bool rangeReadable(uintptr_t address, size_t length) {
    if (rangeReadableCached(address, length)) return true;
    refreshMaps();
    return rangeReadableCached(address, length);
}

static int protectionAt(uintptr_t address) {
    pthread_mutex_lock(&g_mapsLock);
    for (const Map& map : g_maps) {
        if (address >= map.start && address < map.end) {
            const int protection = map.protection;
            pthread_mutex_unlock(&g_mapsLock);
            return protection;
        }
    }
    pthread_mutex_unlock(&g_mapsLock);
    return -1;
}

static bool rangeMapped(uintptr_t address, size_t length) {
    if (length == 0 || address > UINTPTR_MAX - length) return false;
    pthread_mutex_lock(&g_mapsLock);
    uintptr_t cursor = address;
    const uintptr_t end = address + length;
    while (cursor < end) {
        const Map* found = nullptr;
        for (const Map& map : g_maps) {
            if (cursor >= map.start && cursor < map.end) { found = &map; break; }
        }
        if (found == nullptr) {
            pthread_mutex_unlock(&g_mapsLock);
            return false;
        }
        cursor = found->end < end ? found->end : end;
    }
    pthread_mutex_unlock(&g_mapsLock);
    return true;
}

static uintptr_t pageStart(uintptr_t address, size_t pageSize) {
    return address & ~(static_cast<uintptr_t>(pageSize) - 1u);
}

// mprotect requires page-aligned ranges. The previous implementation passed
// the raw DEX pointer, causing EINVAL and a silent zero-byte dump on Android 14.
static bool makeReadable(uintptr_t address, size_t length) {
    if (rangeReadable(address, length)) return true;
    // Never attempt mprotect across an unmapped hole. This also prevents a
    // corrupt header from causing tens of thousands of noisy failed calls.
    if (!rangeMapped(address, length)) return false;
    const long configuredPageSize = sysconf(_SC_PAGESIZE);
    const size_t pageSize = configuredPageSize > 0
            ? static_cast<size_t>(configuredPageSize) : 4096u;
    if (address > UINTPTR_MAX - length) return false;
    const uintptr_t first = pageStart(address, pageSize);
    const uintptr_t last = pageStart(address + length - 1u, pageSize);
    for (uintptr_t page = first;; page += pageSize) {
        int protection = protectionAt(page);
        if (protection >= 0 && mprotect(reinterpret_cast<void*>(page), pageSize,
                                       protection | PROT_READ) != 0 && errno != EACCES) {
            nativeLog("mprotect page=%" PRIxPTR " failed errno=%d", page, errno);
        }
        if (page == last || page > UINTPTR_MAX - pageSize) break;
    }
    refreshMaps();
    return rangeReadable(address, length);
}

static bool readMemory(uintptr_t address, void* destination, size_t length) {
    if (!makeReadable(address, length)) return false;
    std::memcpy(destination, reinterpret_cast<const void*>(address), length);
    return true;
}

static bool readPointer(uintptr_t address, uintptr_t* value) {
    return value != nullptr && readMemory(address, value, sizeof(*value));
}

static bool readU32(uintptr_t address, uint32_t* value) {
    return value != nullptr && readMemory(address, value, sizeof(*value));
}

static bool copyObjectWords(uintptr_t object, uintptr_t* words, size_t count) {
    if (words == nullptr || count == 0 || count > kObjectScanBytes / sizeof(uintptr_t)) {
        return false;
    }
    const size_t bytes = count * sizeof(uintptr_t);
    if (!makeReadable(object, bytes)) return false;
    std::memcpy(words, reinterpret_cast<const void*>(object), bytes);
    return true;
}

enum class DexFormat { NONE, DEX, CDEX };

static DexFormat dexFormat(uintptr_t address, char version[4]) {
    uint8_t magic[8] = {0};
    if (!readMemory(address, magic, sizeof(magic))) return DexFormat::NONE;
    if (magic[0] == 'd' && magic[1] == 'e' && magic[2] == 'x' && magic[3] == '\n' &&
            magic[4] == '0' && magic[5] == '3' && magic[6] >= '5' && magic[6] <= '9' &&
            magic[7] == '\0') {
        if (version != nullptr) {
            version[0] = static_cast<char>(magic[4]);
            version[1] = static_cast<char>(magic[5]);
            version[2] = static_cast<char>(magic[6]);
            version[3] = '\0';
        }
        return DexFormat::DEX;
    }
    if (magic[0] == 'c' && magic[1] == 'd' && magic[2] == 'e' && magic[3] == 'x' &&
            magic[4] == '0' && magic[5] == '0' && magic[6] == '1' && magic[7] == '\0') {
        if (version != nullptr) std::memcpy(version, "001", 4);
        return DexFormat::CDEX;
    }
    return DexFormat::NONE;
}

static bool writeAll(int fd, const uint8_t* bytes, size_t length) {
    size_t written = 0;
    while (written < length) {
        const ssize_t result = write(fd, bytes + written, length - written);
        if (result > 0) written += static_cast<size_t>(result);
        else if (result < 0 && errno == EINTR) continue;
        else return false;
    }
    return true;
}

static bool containsAscii(const std::vector<uint8_t>& bytes, const char* marker) {
    if (marker == nullptr || *marker == '\0') return false;
    const size_t length = std::strlen(marker);
    if (length == 0 || bytes.size() < length) return false;
    const auto it = std::search(bytes.begin(), bytes.end(), marker, marker + length);
    return it != bytes.end();
}

static bool isInjectedFrameworkDex(const std::vector<uint8_t>& image) {
    // These markers identify LSPosed/Xposed support DEXes that are added to
    // the target process by the hooking framework.  They share the target's
    // mCookie and must not be mistaken for application payloads.
    static constexpr const char* kMarkers[] = {
            "LSPHooker", "xposed/dummy", "libxposed", "XposedInterface", "XC_MethodHook"
    };
    for (const char* marker : kMarkers) {
        if (containsAscii(image, marker)) return true;
    }
    return false;
}

static bool copyMemory(uintptr_t address, size_t length, std::vector<uint8_t>* output) {
    if (output == nullptr || length == 0 || length > kMaxDexSize) return false;
    output->resize(length);
    if (!makeReadable(address, length)) return false;
    // The common case is one readable range; use one memcpy for speed.
    if (rangeReadable(address, length)) {
        std::memcpy(output->data(), reinterpret_cast<const void*>(address), length);
        return true;
    }
    const long configuredPageSize = sysconf(_SC_PAGESIZE);
    const size_t pageSize = configuredPageSize > 0
            ? static_cast<size_t>(configuredPageSize) : 4096u;
    for (size_t offset = 0; offset < length;) {
        const size_t chunk = std::min(pageSize - ((address + offset) % pageSize), length - offset);
        if (!readMemory(address + offset, output->data() + offset, chunk)) return false;
        offset += chunk;
    }
    return true;
}

static bool dumpDexImage(uintptr_t begin, size_t hintedSize, const char* outputPath,
                         long* writtenSize, bool* skipped = nullptr) {
    if (skipped != nullptr) *skipped = false;
    char version[4] = {0};
    const DexFormat format = dexFormat(begin, version);
    if (format == DexFormat::NONE) return false;
    uint32_t declaredSize = 0;
    size_t imageSize = 0;
    if (readU32(begin + 0x20, &declaredSize) && declaredSize >= 0x70 &&
            declaredSize <= kMaxDexSize) imageSize = declaredSize;
    if ((imageSize < 0x70 || imageSize > kMaxDexSize) &&
            hintedSize >= 0x70 && hintedSize <= kMaxDexSize) imageSize = hintedSize;
    if (imageSize < 0x70 || imageSize > kMaxDexSize) return false;

    std::vector<uint8_t> image;
    if (!copyMemory(begin, imageSize, &image)) return false;
    // LSPosed injects tiny per-hook DEX files into the same ART cookie as the
    // target APK.  They contain only the generated LSPHooker_ class and are
    // not application payloads; emitting them made a three-dex target look
    // like seven files.  Ignore this well-known marker while retaining every
    // real application DEX (including small anti-hijack payloads).
    if (isInjectedFrameworkDex(image)) {
        if (skipped != nullptr) *skipped = true;
        nativeLog("skip injected framework DEX begin=%" PRIxPTR " size=%zu", begin, imageSize);
        return false;
    }
    const int fd = open(outputPath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return false;
    const bool ok = writeAll(fd, image.data(), image.size());
    close(fd);
    if (!ok) return false;
    if (writtenSize != nullptr) *writtenSize = static_cast<long>(image.size());
    nativeLog("matched %s version=%s begin=%" PRIxPTR " size=%zu",
              format == DexFormat::CDEX ? "CDEX" : "DEX", version, begin, imageSize);
    return true;
}

// A single java DexFile can own more than one native ART DexFile.  This is
// represented by a long[] mCookie for APKs containing secondary dex files.
// Keep every successfully located image instead of stopping at the first one.
// The first image uses the requested path; subsequent images use path.1,
// path.2, ... and are collected by the Java wrapper.
struct DumpCollector {
    explicit DumpCollector(const char* path) : basePath(path == nullptr ? "" : path) {}

    bool dump(uintptr_t begin, size_t hintedSize) {
        if (begin == 0 || basePath.empty()) return false;
        if (skippedBegins.find(begin) != skippedBegins.end()) return false;
        if (!seenBegins.insert(begin).second) return false;
        const std::string path = count == 0
                ? basePath
                : basePath + "." + std::to_string(count);
        long written = 0;
        bool skipped = false;
        if (!dumpDexImage(begin, hintedSize, path.c_str(), &written, &skipped)) {
            seenBegins.erase(begin);
            if (skipped) skippedBegins.insert(begin);
            return false;
        }
        ++count;
        totalBytes += written;
        return true;
    }

    std::string basePath;
    size_t count = 0;
    long totalBytes = 0;
    std::unordered_set<uintptr_t> seenBegins;
    std::unordered_set<uintptr_t> skippedBegins;
};

static uintptr_t normalizePointer(uintptr_t value);

static uintptr_t normalizePointer(uintptr_t value) {
#if defined(__aarch64__)
    // Android may carry a top-byte allocation tag (or PAC metadata) on a
    // pointer copied through a long[] cookie.  ART's native addresses live in
    // the lower 56 bits on arm64; stripping only the top byte preserves the
    // canonical user-space address while leaving ordinary pointers unchanged.
    return value & UINT64_C(0x00ffffffffffffff);
#else
    return value;
#endif
}

static size_t tryDumpDirectDexAll(uintptr_t candidate, DumpCollector* collector,
                                  int* magicCandidates) {
    if (collector == nullptr) return 0;
    candidate = normalizePointer(candidate);
    if (candidate == 0 || !rangeReadableCached(candidate, sizeof(uintptr_t))) return 0;
    char version[4] = {0};
    if (dexFormat(candidate, version) == DexFormat::NONE) return 0;
    if (magicCandidates != nullptr) ++(*magicCandidates);
    return collector->dump(candidate, 0) ? 1u : 0u;
}

static size_t tryDumpBeginInStructAll(uintptr_t object, DumpCollector* collector,
                                      int* magicCandidates) {
    if (object == 0 || collector == nullptr) return 0;
    constexpr size_t kWordCount = kObjectScanBytes / sizeof(uintptr_t);
    uintptr_t words[kWordCount] = {};
    if (!copyObjectWords(object, words, kWordCount)) return 0;
    size_t dumped = 0;
    for (size_t index = 0; index + 1 < kWordCount; ++index) {
        const uintptr_t begin = normalizePointer(words[index]);
        if (begin == 0 || !rangeReadableCached(begin, sizeof(uintptr_t))) continue;
        char version[4] = {0};
        if (dexFormat(begin, version) == DexFormat::NONE) continue;
        if (magicCandidates != nullptr) ++(*magicCandidates);
        if (collector->dump(begin, static_cast<size_t>(words[index + 1]))) ++dumped;
    }
    return dumped;
}

// Graph variant of the scanner above.  It deliberately keeps walking after a
// match because the same cookie may reference several NativeDexFile objects.
static size_t scanCookieGraphAll(uintptr_t root, DumpCollector* collector,
                                 int* magicCandidates) {
    if (collector == nullptr) return 0;
    root = normalizePointer(root);
    if (root == 0) return 0;
    struct Node { uintptr_t address; int depth; };
    std::deque<Node> pending;
    std::unordered_set<uintptr_t> visited;
    pending.push_back({root, 0});
    size_t dumped = 0;

    while (!pending.empty() && visited.size() < kMaxGraphNodes) {
        const Node node = pending.front();
        pending.pop_front();
        const uintptr_t object = normalizePointer(node.address);
        if (object == 0 || !visited.insert(object).second) continue;
        constexpr size_t kWordCount = kObjectScanBytes / sizeof(uintptr_t);
        uintptr_t words[kWordCount] = {};
        if (!copyObjectWords(object, words, kWordCount)) continue;

        for (size_t index = 0; index < kWordCount; ++index) {
            const uintptr_t pointer = normalizePointer(words[index]);
            if (pointer == 0 || pointer == object ||
                    !rangeReadableCached(pointer, sizeof(uintptr_t))) continue;
            char version[4] = {0};
            const DexFormat format = dexFormat(pointer, version);
            if (format != DexFormat::NONE) {
                if (magicCandidates != nullptr) ++(*magicCandidates);
                if (collector->dump(pointer, 0)) ++dumped;
                // DEX bytes are not ART objects; do not enqueue their contents.
                continue;
            }
            if (node.depth >= kMaxGraphDepth || visited.size() >= kMaxGraphNodes) continue;
            if (rangeReadableCached(pointer, sizeof(uintptr_t))) {
                pending.push_back({pointer, node.depth + 1});
            }
        }
    }
    nativeLog("cookie graph all scan exhausted nodes=%zu dumped=%zu",
              visited.size(), dumped);
    return dumped;
}

static size_t dumpFromPtrAll(uintptr_t dexFilePointer, DumpCollector* collector,
                            int* magicCandidates) {
    if (collector == nullptr) return 0;
    dexFilePointer = normalizePointer(dexFilePointer);
    if (dexFilePointer == 0) return 0;
    size_t dumped = tryDumpDirectDexAll(dexFilePointer, collector, magicCandidates);
    dumped += tryDumpBeginInStructAll(dexFilePointer, collector, magicCandidates);
    // The struct scan handles the common layout.  The bounded graph catches
    // ART holder objects and additional dex pointers at a different depth.
    dumped += scanCookieGraphAll(dexFilePointer, collector, magicCandidates);
    return dumped;
}

// JNI reflection helper: find a field along the DexFile class hierarchy.
static jobject readFieldByName(JNIEnv* env, jobject target, const char* name) {
    if (env == nullptr || target == nullptr) return nullptr;
    jclass classClass = env->FindClass("java/lang/Class");
    jclass fieldClass = env->FindClass("java/lang/reflect/Field");
    if (classClass == nullptr || fieldClass == nullptr) { env->ExceptionClear(); return nullptr; }
    const jmethodID getDeclaredField = env->GetMethodID(classClass, "getDeclaredField",
            "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    const jmethodID getSuperclass = env->GetMethodID(classClass, "getSuperclass", "()Ljava/lang/Class;");
    const jmethodID setAccessible = env->GetMethodID(fieldClass, "setAccessible", "(Z)V");
    const jmethodID fieldGet = env->GetMethodID(fieldClass, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    jclass current = env->GetObjectClass(target);
    while (current != nullptr) {
        jstring fieldName = env->NewStringUTF(name);
        jobject field = env->CallObjectMethod(current, getDeclaredField, fieldName);
        env->DeleteLocalRef(fieldName);
        if (env->ExceptionCheck()) { env->ExceptionClear(); field = nullptr; }
        if (field != nullptr) {
            env->CallVoidMethod(field, setAccessible, JNI_TRUE);
            if (env->ExceptionCheck()) env->ExceptionClear();
            jobject value = env->CallObjectMethod(field, fieldGet, target);
            if (env->ExceptionCheck()) { env->ExceptionClear(); value = nullptr; }
            env->DeleteLocalRef(field);
            env->DeleteLocalRef(current);
            return value;
        }
        jclass parent = reinterpret_cast<jclass>(env->CallObjectMethod(current, getSuperclass));
        if (env->ExceptionCheck()) { env->ExceptionClear(); parent = nullptr; }
        env->DeleteLocalRef(current);
        current = parent;
    }
    return nullptr;
}

static void javaNativeLog(JNIEnv* env, const char* message) {
    if (env == nullptr || message == nullptr) return;
    jclass bridge = env->FindClass("com/ctf/dexdumper/NativeBridge");
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (bridge == nullptr) return;
    const jmethodID method = env->GetStaticMethodID(bridge, "nativeLog", "(Ljava/lang/String;)V");
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (method != nullptr) {
        jstring text = env->NewStringUTF(message);
        env->CallStaticVoidMethod(bridge, method, text);
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(text);
    }
    env->DeleteLocalRef(bridge);
}

} // namespace

extern "C" JNIEXPORT jint JNICALL
Java_com_ctf_dexdumper_NativeBridge_dumpDexFromDexFile(
        JNIEnv* env, jclass, jobject dexFile, jstring outputPathString) {
    if (env == nullptr || dexFile == nullptr || outputPathString == nullptr) return -1;
    g_logEnv = env;
    const char* outputPathChars = env->GetStringUTFChars(outputPathString, nullptr);
    if (outputPathChars == nullptr) { g_logEnv = nullptr; return -1; }
    const std::string outputPath(outputPathChars);
    env->ReleaseStringUTFChars(outputPathString, outputPathChars);

    refreshMaps();
    jobject cookie = readFieldByName(env, dexFile, "mCookie");
    if (cookie == nullptr) cookie = readFieldByName(env, dexFile, "mInternalCookie");
    if (cookie == nullptr) {
        javaNativeLog(env, "no mCookie/mInternalCookie on DexFile");
        g_logEnv = nullptr;
        return -2;
    }

    std::vector<uintptr_t> candidates;
    jclass longArrayClass = env->FindClass("[J");
    jclass longClass = env->FindClass("java/lang/Long");
    jclass integerClass = env->FindClass("java/lang/Integer");
    jclass stringClass = env->FindClass("java/lang/String");
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (longArrayClass != nullptr && env->IsInstanceOf(cookie, longArrayClass)) {
        const jlongArray array = reinterpret_cast<jlongArray>(cookie);
        const jsize count = env->GetArrayLength(array);
        std::vector<jlong> values(static_cast<size_t>(count));
        env->GetLongArrayRegion(array, 0, count, values.data());
        for (jlong value : values) candidates.push_back(static_cast<uintptr_t>(value));
        nativeLog("cookie type=long[] entries=%d", static_cast<int>(count));
    } else if (longClass != nullptr && env->IsInstanceOf(cookie, longClass)) {
        const jmethodID method = env->GetMethodID(longClass, "longValue", "()J");
        candidates.push_back(static_cast<uintptr_t>(env->CallLongMethod(cookie, method)));
        nativeLog("cookie type=Long entries=1");
    } else if (integerClass != nullptr && env->IsInstanceOf(cookie, integerClass)) {
        const jmethodID method = env->GetMethodID(integerClass, "intValue", "()I");
        candidates.push_back(static_cast<uintptr_t>(static_cast<uint32_t>(env->CallIntMethod(cookie, method))));
        nativeLog("cookie type=Integer entries=1");
    } else if (stringClass != nullptr && env->IsInstanceOf(cookie, stringClass)) {
        javaNativeLog(env, "cookie type=String (oat path), pointer mode requires a native cookie");
        env->DeleteLocalRef(cookie);
        g_logEnv = nullptr;
        return -3;
    } else {
        javaNativeLog(env, "cookie type=unknown; expected long[]/Long/Integer");
        env->DeleteLocalRef(cookie);
        g_logEnv = nullptr;
        return -4;
    }
    env->DeleteLocalRef(cookie);

    int magicCandidates = 0;
    DumpCollector collector(outputPath.c_str());
    for (uintptr_t candidate : candidates) {
        if (candidate == 0) continue;
        dumpFromPtrAll(candidate, &collector, &magicCandidates);
    }
    nativeLog("pointer scan candidates=%zu dexMagicCandidates=%d dumped=%zu resultBytes=%ld",
              candidates.size(), magicCandidates, collector.count, collector.totalBytes);
    if (collector.count == 0) javaNativeLog(env, "pointer scan completed with no readable DEX image");
    g_logEnv = nullptr;
    return static_cast<jint>(collector.totalBytes);
}
