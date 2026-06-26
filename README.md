# anti_dev_pm_zygisk

Author: geekbyte  
Version: v2.5.3

Standalone Zygisk module for DuckDetector visibility checks.

This module does not hide SukiSU or any other app from Android itself. It does
not run `pm hide`, and does not disable ADB/developer options. On MIUI/HyperOS,
the module grants DuckDetector the real installed-app inventory appop
`MIUIOP(10022)` when that appop exists, because `QUERY_ALL_PACKAGES` can be
granted while the ROM-level inventory gate is still `ignore`. Other bypass work
is process-local: only DuckDetector's observations are sanitized.

## Scope

Target process:

```text
com.eltavine.duckdetector
```

It is intentionally separate from `selinux_avc_bypass_zygisk` and does not hook
audit/logcat/SELinux policy paths.

Runtime service:

```text
module/service.sh
```

The service only touches DuckDetector's MIUI/HyperOS installed-app inventory
appop. It skips non-MIUI ROMs and ROMs where op `10022` is unsupported.

## What It Hooks

- `android.os.SystemProperties` native getters.
- `android.os.BinderProxy.transactNative`, used to sanitize Binder replies from
  PackageManager and Settings-related calls. Direct PackageManager lookups for
  risky package names are rewritten before the Binder call, so Android returns a
  normal not-found result instead of a half-sanitized PackageInfo.
- `module/service.sh`, used to grant DuckDetector `MIUIOP(10022)=allow` on
  MIUI/HyperOS so PackageManager inventory is not reported as ROM-scoped.
- `java.lang.UNIXProcess` / `java.lang.ProcessImpl` native process creation for
  Duck's `getprop` subprocess snapshots. Only `getprop` is redirected, and only
  ADB/developer property lines are filtered from that snapshot.
- DuckDetector's own native bridge snapshots via retryable JNI hooks:
  - SystemPropertiesNativeBridge
  - PlayIntegrityFixNativeBridge
  - DangerousAppsNativeBridge
  - MemoryNativeBridge
  - LSPosedNativeBridge
  - ZygiskNativeBridge
  - SuNativeBridge
  - CgroupProcessLeakNativeBridge
  - NativeRootNativeBridge

v2.5.0 does not enable broad native PLT/file hooks in DuckDetector's main
process. Those hooks were fragile on Android 13/14 and could make DuckDetector
hang or open to a black screen. The module now relies on framework JNI hooks,
Binder request/reply sanitizing, and confirmed Duck native bridge hooks.

## Covered Signals

ADB/developer properties are reported to DuckDetector as normal-device values.
USB config properties are derived from the real device value with only the
`adb` token removed, so device-specific modes are preserved where possible:

```text
persist.sys.usb.config=mtp        # example: mtp,adb -> mtp
sys.usb.config=mtp                # example: adb -> mtp
sys.usb.state=mtp                 # example: diag,adb -> diag
init.svc.adbd=stopped
service.adb.root=0
persist.adb.tcp.port=-1
service.adb.tcp.port=-1
ro.debuggable=0
ro.secure=1
ro.adb.secure=1
```

Risky package evidence is sanitized for the built-in package list, including:

```text
com.sukisu.ultra
com.sukisu.ultra.manager
com.topjohnwu.magisk
io.github.huskydg.magisk
me.weishu.kernelsu
io.github.a13e300.mksu
com.resukisu.resukisu
com.rifsxd.ksunext
me.bmax.apatch
com.bmax.apatch
bin.mt.plus
com.termux
com.omarea.vtools
com.omarea.scene
```

Duck native bridge snapshots for native root, SU, Zygisk, LSPosed, memory, and
dangerous-app probes are normalized in-process. Broad filesystem path hooks are
kept disabled by default in v2.5.0 for compatibility.

MIUI/HyperOS inventory visibility is handled by a real appop grant:

```text
cmd appops set com.eltavine.duckdetector 10022 allow
```

The module runs that command from `service.sh` during Magisk late-start service,
not from ADB. The previous appop output is saved to:

```text
/data/adb/anti_dev_pm_zygisk/miuiop10022.prev
```

`customize.sh` applies the grant once during module installation, and
`service.sh` starts a low-frequency worker that re-checks the mode because
HyperOS/MIUI can rewrite this appop after boot or after a permission UI change.
`uninstall.sh` stops the worker and restores the saved mode when possible. This
addresses Duck's `Inventory visibility limited` result on ROMs where
`android.permission.QUERY_ALL_PACKAGES` is granted but `MIUIOP(10022)` remains
`ignore`.

## Android 16 Compatibility

v2.4.1 keeps the real `Build.VERSION.SDK_INT` and `RESOURCES_SDK_INT` on
Android 16/API 36 and newer. Older builds used a process-local SDK downgrade for
some DuckDetector inventory checks, but that can break new framework/UI
compatibility paths and cause a black screen on Android 16. Other package,
property, Binder, and native probe hooks are unchanged.

v2.4.2 further narrows Zygisk activation on Android 16-era DuckDetector builds.
The module runs in the main DuckDetector process and the explicit
`:zygisk_fd_detector` helper only. It skips DuckDetector app-zygote and
virtualization/isolated helper processes, because those processes require a
single-threaded zygote state or intentionally run sacrificial native probes.
Injecting delayed JNI/PLT passes there can make DuckDetector open to a black
screen even when the main process is healthy.

v2.4.3 disables native PLT hooks and delayed hook retries on Android 16/API 36
and newer. On these builds, repeated PLT registration attempts fail and can
disturb HWUI/Vulkan surface timing. The module keeps the process-local JNI
hooks for `SystemProperties` and DuckDetector native bridge snapshots, but does
not keep a delayed worker thread in the app process.

v2.5.0 applies that conservative model to Android 10-16. It keeps the real SDK
level, disables broad PLT hooks on all supported versions, preserves USB
configuration tokens other than `adb`, and retries Duck native bridge hooks
until late-loaded classes are actually hooked. This fixes Android 13/14
black-screen or click-to-open failures caused by failed PLT passes.

v2.5.1 keeps the v2.5.0 compatibility rollback but moves Duck native bridge
retry to the early startup window. It also sanitizes Duck's `getprop`
subprocess snapshot without restoring broad PLT/file hooks. This prevents
memory, property, and nativeStat probes from running before their bridge
methods are replaced while keeping Android 13/14 startup stable.

v2.5.2 adds a ROM-scoped inventory visibility fix for MIUI/HyperOS. During
late-start service, the module checks whether DuckDetector is installed and
whether appop `10022` exists. If so, it sets that op to `allow` so DuckDetector's
own PackageManager inventory is not limited by the ROM-level installed-app-list
gate. Non-MIUI ROMs and ROMs without op `10022` are skipped.

v2.5.3 makes the inventory fix durable. The installer now marks module scripts
executable, applies DuckDetector's `MIUIOP(10022)=allow` during install when
available, the native log version matches the module version, and `service.sh`
starts a low-frequency worker that keeps DuckDetector's `MIUIOP(10022)` at
`allow` if HyperOS/MIUI rewrites it later.

## Why v2.1 Changed

`Settings.Global/Secure.getInt` and `ApplicationPackageManager` methods are
ordinary Java methods, not JNI native methods. Zygisk's
`hookJniNativeMethods()` cannot replace them directly. v2.1 removes that
ineffective route and instead hooks:

- Binder transactions, where Java framework API results return to the app.
- Native filesystem/process probes, where Duck verifies app/path evidence.

## Local Build

```powershell
cd C:\Users\admin\Documents\dirtysepolicy\anti_dev_pm_zygisk
powershell -ExecutionPolicy Bypass -File .\tools\build.ps1
```

Manual build:

```powershell
cd C:\Users\admin\Documents\dirtysepolicy\anti_dev_pm_zygisk
& "$env:LOCALAPPDATA\Android\Sdk\ndk\29.0.14206865\ndk-build.cmd" -C .\jni
powershell -ExecutionPolicy Bypass -File .\tools\package.ps1
```

Output:

```text
C:\Users\admin\Documents\dirtysepolicy\anti_dev_pm_zygisk-v2.5.3.zip
```

## GitHub Cloud Build

Push this folder as the repository root. The workflow at
`.github/workflows/build.yml` installs Android NDK `27.2.12479018`, runs
`ndk-build -C jni`, packages the Magisk module, and uploads the zip artifact.

## Install

```sh
su -c "magisk --install-module /sdcard/anti_dev_pm_zygisk-v2.5.3.zip"
su -c reboot
```

After reboot, force-stop and reopen DuckDetector so its process starts with the
Zygisk module loaded.

## Verify

```sh
su -c "logcat -d -s DuckVisBypass"
su -c "logcat -d -s AntiDevPmZygisk"
cmd appops get com.eltavine.duckdetector 10022
pm list packages | grep sukisu
settings get global adb_enabled
```

Expected:

- `logcat` shows `DuckVisBypass` only for DuckDetector.
- `logcat` eventually shows `Duck native bridge hooks ready=9/9`.
- On MIUI/HyperOS, `cmd appops get com.eltavine.duckdetector 10022` shows
  `MIUIOP(10022): allow`.
- SukiSU still appears in normal system/package-manager output.
- ADB/developer settings keep their real values outside DuckDetector.
- DuckDetector receives sanitized observations inside its own process.

## Notes

This module is intentionally narrow. Its only persistent system-state change is
DuckDetector's MIUI/HyperOS installed-app inventory appop. Other package,
property, and native observations remain process-local to DuckDetector.
