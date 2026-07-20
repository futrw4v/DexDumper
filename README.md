# DexDumper

LSPosed 模块，复刻 `Layout.Inspect` 的三模式 dump dex 引擎（全版本兼容）。仅用于授权 CTF / 逆向脱壳。

## 三模式

| 模式 | 原理 | 适用 |
|------|------|------|
| `default` | 落盘直读：APK 内 `classes*.dex` / `.dex/.odex/.vdex` 文件 | 未加壳 / 落盘 dex |
| `data` | hook `DexPathList.<init>(ByteBuffer[])`，在 dex 进 native 前抓内存字节 | InMemoryDexClassLoader / 加载后清零 |
| `pointer` | native 解码 `DexFile.mCookie` → 取 `DexFile*` → 魔数扫描定位 `begin_` → `mprotect` 翻页 + `memcpy` 直拷 `begin_/size_` 内存区间 | 加壳 / 运行时已解密 dex（最强） |

`pointer` 模式不硬编码 ART 结构体偏移、不依赖被 strip 的 ART 符号：运行时在 `DexFile` 结构体前 512B 内扫描“指向 dex 魔数 `dex\n035/037/038/039` 的指针”定位 `begin_`，紧邻 8B 取 `size_`，并做两级扫描以兼容 `OatDexFile → dex_file_ → DexFile` 间接布局。

## 构建

与同目录 `LposedNetDump` 同一套本地工具链（gitignore 的 `tools/`）：

```
DexDumper/
  tools/android-sdk/      # 含 platform-tools、ndk、cmake、platforms/android-35
  tools/gradle-8.10.2/    # 解压 gradle-8.10.2-all.zip
```

把 `LposedNetDump/tools/` 整个拷过来即可（两者构建配置一致）。然后：

```powershell
# Debug
./build-apk.ps1
# Release（自动生成签名）
./build-release-apk.ps1
```

产物：`dist/DexDumper-release.apk`。

## 用法

1. 安装 APK，在 LSPosed 管理器启用模块，把目标 App 加入作用域。
2. 打开 DexDumper 图标选模式（默认 `pointer`），保存配置。
3. 强停 / 重启目标 App，`Application.onCreate` 后自动 dump。
4. 取回：

```bash
adb pull /sdcard/DexDumper/<目标包名>/
```

目录内：`<mode>_<sha8>_<原名>.dex` + `manifest.txt`。

## 运行中即时控制

```bash
# 即时再 dump（目标进程内运行时 receiver 命中）
adb shell am broadcast -a com.ctf.dexdumper.action.DUMP
# 查状态
adb shell am broadcast -a com.ctf.dexdumper.action.STATUS
# 清空输出
adb shell am broadcast -a com.ctf.dexdumper.action.CLEAR --es package <pkg>
```

`loadClass` 规则开启时，目标动态 `loadClass` 命中关键字会自动追加 dump（捕获热加载 dex）。

## 日志

LSPosed 日志看 `[DexDumper]` / `[DexDumper/native]` 前缀。

## 已知限制（v1）

- `pointer` 模式 cookie 若为 `String`（个别版本 oat 路径）取不到指针，会记日志跳过——可换 `data` 模式。
- `.vdex/.cdex` 在 `default` 模式下整文件拷贝（未剥离 dex 段），优先用 `pointer` 拿已解密 dex。
- `pointer` 依赖 `mCookie`/`mInternalCookie` 可反射（LSPosed 已 unseal hidden API）。
