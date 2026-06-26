# anti_dev_pm_zygisk

Author: geekbyte  
Version: v2.4.3

Standalone Zygisk module for DuckDetector visibility checks.

This module does not hide SukiSU or any other app from Android itself. It does
not run `pm hide`, does not change appops, and does not disable ADB/developer
options. The bypass is process-local: only DuckDetector's observations are
sanitized.

## Scope

Target process:

```text
com.eltavine.duckdetector
```

It is intentionally separate from `selinux_avc_bypass_zygisk` and does not hook
audit/logcat/SELinux policy paths.

## What It Hooks

- `android.os.SystemProperties` native getters.
- Native property imports:
  - `__system_property_get`
  - `__system_property_read`
  - `__system_property_read_callback`
  - `property_get`
- `android.os.BinderProxy.transactNative`, used to sanitize Binder replies from
  PackageManager and Settings-related calls.
- DuckDetector's own native bridge snapshots via JNI hook and `dlsym`
  interception:
  - SystemPropertiesNativeBridge
  - PlayIntegrityFixNativeBridge
  - DangerousAppsNativeBridge
  - MemoryNativeBridge
  - LSPosedNativeBridge
  - ZygiskNativeBridge
  - SuNativeBridge
  - NativeRootNativeBridge
  - CgroupProcessLeakNativeBridge
- `getprop` process probes in DuckDetector.
- KernelSU manager fingerprint probes in DuckDetector:
  - direct `IPackageManager` lookups for known KernelSU/SukiSU manager names
  - `KSU_*` / `KERNELSU` environment-style probes
  - `prctl(0xDEADBEEF, ...)` KernelSU magic probe
- Native file/path probes commonly used by DuckDetector:
  - `open`, `open64`, `openat`, `fopen`, `read`, `close`
  - `access`, `faccessat`, `faccessat2`
  - `stat`, `lstat`, `fstatat`, `statx`
  - `readlink`, `readlinkat`, `realpath`
  - `getxattr`, `lgetxattr`
  - `opendir`, `readdir`, `closedir`
  - `execve`, `execv`, `execvp`, `posix_spawn`, `popen`

## Covered Signals

ADB/developer properties are reported to DuckDetector as normal-device values,
for example:

```text
persist.sys.usb.config=mtp
sys.usb.config=mtp
sys.usb.state=mtp
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

The module also suppresses Duck-visible path evidence such as `/data/adb`,
`/sdcard/Android/data/<pkg>`, `/sdcard/Android/obb/<pkg>`, APK paths containing
these package names, and several known risky-app residue paths.

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
C:\Users\admin\Documents\dirtysepolicy\anti_dev_pm_zygisk-v2.4.3.zip
```

## GitHub Cloud Build

Push this folder as the repository root. The workflow at
`.github/workflows/build.yml` installs Android NDK `27.2.12479018`, runs
`ndk-build -C jni`, packages the Magisk module, and uploads the zip artifact.

## Install

```sh
su -c "magisk --install-module /sdcard/anti_dev_pm_zygisk-v2.4.3.zip"
su -c reboot
```

After reboot, force-stop and reopen DuckDetector so its process starts with the
Zygisk module loaded.

## Verify

```sh
su -c "logcat -d -s DuckVisBypass"
pm list packages | grep sukisu
settings get global adb_enabled
```

Expected:

- `logcat` shows `DuckVisBypass` only for DuckDetector.
- SukiSU still appears in normal system/package-manager output.
- ADB/developer settings keep their real values outside DuckDetector.
- DuckDetector receives sanitized observations inside its own process.

## Notes

This module is intentionally narrow. It avoids changing persistent system state
so it can run alongside AVC/audit modules with fewer side effects.
