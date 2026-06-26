// anti_dev_pm_zygisk v2.4.3
// DuckDetector-scoped observation bypass:
//   - Does not hide, disable, stop, or uninstall any real package/service.
//   - Spoofs Duck-visible ADB/developer system properties.
//   - Sanitizes Binder Parcel replies for PackageManager/Settings observations.
//   - Suppresses Duck's native filesystem/process probes for risky app evidence.

#include <android/log.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <jni.h>
#include <pthread.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "zygisk.hpp"

#define MODULE_VERSION "v2.4.3"
#define LOG_TAG "DuckVisBypass"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#ifdef DEBUG
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#else
#define LOGD(...) ((void)0)
#endif

#ifndef PROP_VALUE_MAX
#define PROP_VALUE_MAX 92
#endif

#ifndef PROP_NAME_MAX
#define PROP_NAME_MAX 256
#endif

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

struct prop_info;

void *operator new(size_t s) { return malloc(s); }
void *operator new[](size_t s) { return malloc(s); }
void operator delete(void *p) noexcept { free(p); }
void operator delete[](void *p) noexcept { free(p); }
void operator delete(void *p, size_t) noexcept { free(p); }
void operator delete[](void *p, size_t) noexcept { free(p); }

static zygisk::Api *g_api = nullptr;
static JavaVM *g_vm = nullptr;
static pthread_mutex_t g_hook_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_jni_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_hooks_started = false;
static bool g_jni_installed = false;
static char g_app_name[128] = "?";

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

struct PropSpoof {
    const char *name;
    const char *value;
};

static const PropSpoof kPropSpoofs[] = {
    { "persist.sys.usb.config",      "mtp" },
    { "sys.usb.config",              "mtp" },
    { "sys.usb.state",               "mtp" },
    { "init.svc.adbd",               "stopped" },
    { "init.svc.adbd_root",          "stopped" },
    { "service.adb.root",            "0" },
    { "persist.service.adb.enable",  "0" },
    { "persist.adb.tcp.port",        "-1" },
    { "service.adb.tcp.port",        "-1" },
    { "ro.debuggable",               "0" },
    { "ro.secure",                   "1" },
    { "ro.adb.secure",               "1" },
    { "ro.allow.mock.location",      "0" },
    { "persist.sys.development_settings_enabled", "0" },
    { "ro.boot.selinux",             "enforcing" },
    { "ro.build.selinux",            "1" },
    { "ro.boot.verifiedbootstate",   "green" },
    { "ro.boot.flash.locked",        "1" },
    { "ro.boot.veritymode",          "enforcing" },
    { "ro.boot.vbmeta.device_state", "locked" },
    { "ro.boot.vbmeta.hash_alg",     "sha256" },
    { "ro.boot.vbmeta.invalidate_on_error", "yes" },
    { "partition.system.verified",   "1" },
    { "partition.vendor.verified",   "1" },
    { "partition.product.verified",  "1" },
    { "partition.system_ext.verified", "1" },
    { "partition.odm.verified",      "1" },
    { "ro.build.type",               "user" },
    { "ro.build.tags",               "release-keys" },
    { "ro.crypto.state",             "encrypted" },
    { "sys.oem_unlock_allowed",      "0" },
    { "ro.oem_unlock_supported",     "0" },
    { "init.svc.magisk_daemon",      "stopped" },
    { "init.svc.magisk_service",     "stopped" },
    { "ro.magisk.hide",              "0" },
    { "ro.boot.warranty_bit",        "0" },
    { "ro.warranty_bit",             "0" },
    { "ro.boot.knox.state",          "NORMAL" },
    { "ro.modversion",               "" },
    { "ro.cm.version",               "" },
    { "ro.lineage.version",          "" },
    { "ro.resurrection.version",     "" },
    { "ro.pa.version",               "" },
    { "ro.crdroid.version",          "" },
    { "ro.pixelexperience.version",  "" },
    { "ro.evolution.version",        "" },
    { "ro.havoc.version",            "" },
    { "persist.sys.spoof.gms",       "" },
    { "persist.sys.pihooks.disable.gms", "" },
    { "persist.sys.pihooks_ID",      "" },
    { "persist.sys.pihooks_DEVICE_INIT", "" },
    { "persist.sys.pixelprops.pi",   "" },
    { "persist.sys.pixelprops.gms",  "" },
    { "persist.sys.pixelprops.gapps", "" },
    { "persist.sys.pixelprops.google", "" },
    { "persist.sys.pihooks_BRAND",   "" },
    { "persist.sys.pihooks_MODEL",   "" },
    { "persist.sys.pihooks_DEVICE",  "" },
    { "persist.sys.pihooks_PRODUCT", "" },
    { "persist.sys.pihooks_MANUFACTURE", "" },
    { "persist.sys.pihooks_MANUFACTURER", "" },
    { "persist.sys.pihooks_RELEASE", "" },
    { "persist.sys.pihooks_SDK_INT", "" },
    { "persist.sys.pihooks_FINGERPRINT", "" },
    { "persist.sys.pihooks_SECURITY_PA", "" },
    { "persist.sys.pihooks_SECURITY_PATCH", "" },
    { nullptr, nullptr },
};

static const char *spoof_prop(const char *name) {
    if (!name || !*name) return nullptr;
    for (const PropSpoof *p = kPropSpoofs; p->name; ++p) {
        if (strcmp(name, p->name) == 0) return p->value;
    }
    return nullptr;
}

static const char *spoof_prop(JNIEnv *env, jstring key) {
    if (!env || !key) return nullptr;
    const char *s = env->GetStringUTFChars(key, nullptr);
    if (!s) return nullptr;
    const char *r = spoof_prop(s);
    env->ReleaseStringUTFChars(key, s);
    return r;
}

static int copy_prop(char *dst, const char *val) {
    if (!dst || !val) return 0;
    size_t n = strlen(val);
    if (n >= PROP_VALUE_MAX) n = PROP_VALUE_MAX - 1;
    memcpy(dst, val, n);
    dst[n] = '\0';
    return (int)n;
}

static long prop_to_long(const char *v, long def) {
    if (!v || !*v) return def;
    char *end = nullptr;
    errno = 0;
    long r = strtol(v, &end, 10);
    return (errno || end == v) ? def : r;
}

static bool prop_to_bool(const char *v, bool def) {
    if (!v || !*v) return def;
    return strcmp(v, "1") == 0 || strcmp(v, "true") == 0 ||
           strcmp(v, "TRUE") == 0 || strcmp(v, "y") == 0 ||
           strcmp(v, "yes") == 0 || strcmp(v, "on") == 0;
}

static int get_runtime_sdk(JNIEnv *env) {
    if (!env) return -1;
    jclass version = env->FindClass("android/os/Build$VERSION");
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!version) return -1;
    jfieldID sdk = env->GetStaticFieldID(version, "SDK_INT", "I");
    if (env->ExceptionCheck()) env->ExceptionClear();
    int value = -1;
    if (sdk) value = env->GetStaticIntField(version, sdk);
    env->DeleteLocalRef(version);
    return value;
}

static int (*o_sys_prop_get)(const char *, char *) = nullptr;
static const prop_info *(*o_sys_prop_find)(const char *) = nullptr;
static int (*o_prop_get)(const char *, char *, const char *) = nullptr;
static int (*o_sys_prop_read)(const prop_info *, char *, char *) = nullptr;
static void (*o_sys_prop_read_callback)(
    const prop_info *,
    void (*)(void *, const char *, const char *, uint32_t),
    void *) = nullptr;
static int (*o_sys_prop_foreach)(void (*)(const prop_info *, void *),
                                 void *) = nullptr;

static int h_sys_prop_get(const char *name, char *value) {
    const char *s = spoof_prop(name);
    if (s) return copy_prop(value, s);
    if (!o_sys_prop_get) {
        if (value) value[0] = '\0';
        errno = ENOSYS;
        return 0;
    }
    return o_sys_prop_get(name, value);
}

static const prop_info *h_sys_prop_find(const char *name) {
    if (spoof_prop(name)) {
        errno = ENOENT;
        return nullptr;
    }
    return o_sys_prop_find ? o_sys_prop_find(name) : nullptr;
}

static int h_prop_get(const char *name, char *value, const char *def) {
    const char *s = spoof_prop(name);
    if (s) return copy_prop(value, s);
    if (!o_prop_get) {
        if (def) return copy_prop(value, def);
        if (value) value[0] = '\0';
        return 0;
    }
    return o_prop_get(name, value, def);
}

static int h_sys_prop_read(const prop_info *pi, char *name, char *value) {
    int rc = o_sys_prop_read ? o_sys_prop_read(pi, name, value) : 0;
    const char *s = spoof_prop(name);
    if (s) return copy_prop(value, s);
    return rc;
}

struct PropReadCbCookie {
    void (*cb)(void *, const char *, const char *, uint32_t);
    void *cookie;
};

static void prop_read_cb_bridge(void *data, const char *name, const char *value,
                                uint32_t serial) {
    PropReadCbCookie *ctx = (PropReadCbCookie *)data;
    if (!ctx || !ctx->cb) return;
    const char *s = spoof_prop(name);
    ctx->cb(ctx->cookie, name, s ? s : value, serial);
}

static void h_sys_prop_read_callback(
    const prop_info *pi,
    void (*cb)(void *, const char *, const char *, uint32_t),
    void *cookie) {
    if (!o_sys_prop_read_callback || !cb) return;
    PropReadCbCookie ctx{cb, cookie};
    o_sys_prop_read_callback(pi, prop_read_cb_bridge, &ctx);
}

struct PropForeachCtx {
    void (*cb)(const prop_info *, void *);
    void *cookie;
};

static void prop_foreach_bridge(const prop_info *pi, void *data) {
    PropForeachCtx *ctx = (PropForeachCtx *)data;
    if (!ctx || !ctx->cb || !pi) return;
    char name[PROP_NAME_MAX] = {};
    char value[PROP_VALUE_MAX] = {};
    if (o_sys_prop_read && o_sys_prop_read(pi, name, value) >= 0 &&
        spoof_prop(name)) {
        return;
    }
    ctx->cb(pi, ctx->cookie);
}

static int h_sys_prop_foreach(void (*cb)(const prop_info *, void *),
                              void *cookie) {
    if (!o_sys_prop_foreach || !cb) {
        errno = ENOSYS;
        return -1;
    }
    PropForeachCtx ctx{cb, cookie};
    return o_sys_prop_foreach(prop_foreach_bridge, &ctx);
}

static jstring (*o_sp_get1)(JNIEnv *, jclass, jstring) = nullptr;
static jstring (*o_sp_get2)(JNIEnv *, jclass, jstring, jstring) = nullptr;
static jint (*o_sp_geti)(JNIEnv *, jclass, jstring, jint) = nullptr;
static jlong (*o_sp_getl)(JNIEnv *, jclass, jstring, jlong) = nullptr;
static jboolean (*o_sp_getb)(JNIEnv *, jclass, jstring, jboolean) = nullptr;

static jstring h_sp_get1(JNIEnv *env, jclass cls, jstring key) {
    (void)cls;
    const char *s = spoof_prop(env, key);
    if (s) return env->NewStringUTF(s);
    return o_sp_get1 ? o_sp_get1(env, cls, key) : env->NewStringUTF("");
}

static jstring h_sp_get2(JNIEnv *env, jclass cls, jstring key, jstring def) {
    (void)cls;
    const char *s = spoof_prop(env, key);
    if (s) return env->NewStringUTF(s);
    if (o_sp_get2) return o_sp_get2(env, cls, key, def);
    return def ? (jstring)env->NewLocalRef(def) : env->NewStringUTF("");
}

static jint h_sp_geti(JNIEnv *env, jclass cls, jstring key, jint def) {
    (void)cls;
    const char *s = spoof_prop(env, key);
    if (s) return (jint)prop_to_long(s, def);
    return o_sp_geti ? o_sp_geti(env, cls, key, def) : def;
}

static jlong h_sp_getl(JNIEnv *env, jclass cls, jstring key, jlong def) {
    (void)cls;
    const char *s = spoof_prop(env, key);
    if (s) return (jlong)prop_to_long(s, (long)def);
    return o_sp_getl ? o_sp_getl(env, cls, key, def) : def;
}

static jboolean h_sp_getb(JNIEnv *env, jclass cls, jstring key, jboolean def) {
    (void)cls;
    const char *s = spoof_prop(env, key);
    if (s) return prop_to_bool(s, def == JNI_TRUE) ? JNI_TRUE : JNI_FALSE;
    return o_sp_getb ? o_sp_getb(env, cls, key, def) : def;
}

// ---------------------------------------------------------------------------
// Hidden package/path definitions
// ---------------------------------------------------------------------------

struct Alias {
    const char *from;
    const char *to;
};

static const Alias kPackageAliases[] = {
    { "com.sukisu.ultra",          "com.android.wall" },
    { "com.sukisu.ultra.manager",  "com.android.fake.manager" },
    { "com.topjohnwu.magisk",      "com.android.fakeappx" },
    { "io.github.huskydg.magisk",  "io.github.android.fakepk" },
    { "me.weishu.kernelsu",        "me.android.fakeapp" },
    { "io.github.a13e300.mksu",    "io.github.android.safe" },
    { "com.resukisu.resukisu",     "com.android.clean.app" },
    { "com.rifsxd.ksunext",        "me.android.fakepkg" },
    { "me.bmax.apatch",            "me.fake.normal" },
    { "com.bmax.apatch",           "com.fake.normal" },
    { "bin.mt.plus",               "app.ok.safe" },
    { "com.termux",                "com.notess" },
    { "com.omarea.vtools",         "com.android.tools" },
    { "com.omarea.scene",          "com.android.misc" },
    { nullptr, nullptr },
};

static const char * const kPathTokens[] = {
    "com.sukisu.ultra",
    "com.sukisu.ultra.manager",
    "com.topjohnwu.magisk",
    "io.github.huskydg.magisk",
    "me.weishu.kernelsu",
    "io.github.a13e300.mksu",
    "com.resukisu.resukisu",
    "com.rifsxd.ksunext",
    "me.bmax.apatch",
    "com.bmax.apatch",
    "bin.mt.plus",
    "com.termux",
    "com.omarea.vtools",
    "com.omarea.scene",
    "/data/adb",
    "/sbin/su",
    "/system/bin/su",
    "/system/xbin/su",
    "/vendor/bin/su",
    "/cache/magisk",
    "magisk.db",
    "sukisu",
    "resukisu",
    "kernelsu",
    "ksunext",
    "mksu",
    "ksu_",
    "ksud",
    "ksu_driver",
    "ksu_fdwrapper",
    "ksu_file",
    "kernel su",
    "magisk",
    "apatch",
    "/sdcard/mt2",
    "/sdcard/np",
    "/sdcard/xinhao",
    "/sdcard/download/advanced",
    "/sdcard/.oshin",
    "/sdcard/1.h",
    "/dev/cpuset/scene-daemon",
    "zygisk",
    "lsposed",
    "xposed",
    "riru",
    "edxposed",
    "frida",
    "shamiko",
    "zygisknext",
    "zygisk_next",
    "zygisk-detach",
    "pihooks",
    "pixelprops",
    "playintegrityfix",
    "duck_visibility_bypass",
    "anti_dev_pm_zygisk",
    "selinux_avc_bypass",
    "dirtysepolicy",
    nullptr,
};

static const char * const kLineDropTokens[] = {
    "com.sukisu.ultra",
    "com.sukisu.ultra.manager",
    "com.topjohnwu.magisk",
    "io.github.huskydg.magisk",
    "me.weishu.kernelsu",
    "io.github.a13e300.mksu",
    "com.resukisu.resukisu",
    "com.rifsxd.ksunext",
    "me.bmax.apatch",
    "com.bmax.apatch",
    "bin.mt.plus",
    "com.termux",
    "com.omarea.vtools",
    "com.omarea.scene",
    "/data/adb",
    "/sdcard/mt2",
    "/sdcard/np",
    "/sdcard/xinhao",
    "/sdcard/download/advanced",
    "/sdcard/.oshin",
    "/sdcard/1.h",
    "/dev/cpuset/scene-daemon",
    "sukisu",
    "resukisu",
    "kernelsu",
    "ksunext",
    "mksu",
    "ksu_",
    "ksud",
    "ksu_driver",
    "ksu_fdwrapper",
    "ksu_file",
    "kernel su",
    "u:object_r:ksu_file:s0",
    "ksu_supercall_manager",
    "kernelsu manager",
    "persist.sys.usb.config",
    "sys.usb.config",
    "sys.usb.state",
    "persist.sys.development_settings_enabled",
    "mtp,adb",
    "ptp,adb",
    "zygisk",
    "lsposed",
    "xposed",
    "riru",
    "edxposed",
    "frida",
    "shamiko",
    "zygisknext",
    "zygisk_next",
    "zygisk-detach",
    "pihooks",
    "pixelprops",
    "playintegrityfix",
    "duck_visibility_bypass",
    "anti_dev_pm_zygisk",
    "selinux_avc_bypass",
    "dirtysepolicy",
    nullptr,
};

static const char * const kSettingsKeys[] = {
    "adb_enabled",
    "adb_wifi_enabled",
    "development_settings_enabled",
    "adb_port",
    nullptr,
};

static char lower_ascii(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return (char)(c + ('a' - 'A'));
    return (char)c;
}

static size_t normalize_ascii_n(const char *in, size_t in_len,
                                char *out, size_t out_max) {
    if (!out || out_max == 0) return 0;
    size_t pos = 0;
    if (!in) {
        out[0] = '\0';
        return 0;
    }
    for (size_t i = 0; i < in_len && pos + 1 < out_max; ++i) {
        unsigned char c = (unsigned char)in[i];
        if (c < 0x80 && c != '\r' && c != '\t') {
            out[pos++] = lower_ascii(c);
        }
    }
    out[pos] = '\0';
    return pos;
}

static size_t normalize_ascii_z(const char *in, char *out, size_t out_max) {
    return normalize_ascii_n(in, in ? strlen(in) : 0, out, out_max);
}

static bool normalized_contains_any(const char *norm,
                                    const char * const *tokens) {
    if (!norm || !tokens) return false;
    for (const char * const *t = tokens; *t; ++t) {
        char tn[256];
        normalize_ascii_z(*t, tn, sizeof(tn));
        if (tn[0] && strstr(norm, tn)) return true;
    }
    return false;
}

static bool path_should_hide(const char *path) {
    if (!path || !*path) return false;
    char norm[2048];
    normalize_ascii_z(path, norm, sizeof(norm));
    return normalized_contains_any(norm, kPathTokens);
}

static bool path_is_sensitive_text(const char *path) {
    if (!path || !*path) return false;
    char norm[2048];
    normalize_ascii_z(path, norm, sizeof(norm));
    return strstr(norm, "packages.list") ||
           strstr(norm, "packages.xml") ||
           strstr(norm, "packages-stopped.xml") ||
           strstr(norm, "settings_global.xml") ||
           strstr(norm, "settings_secure.xml") ||
           strstr(norm, "settings_ssaid.xml") ||
           strstr(norm, "/proc/self/maps") ||
           strstr(norm, "/proc/self/smaps") ||
           strstr(norm, "/proc/self/mountinfo") ||
           strstr(norm, "/proc/self/mounts") ||
           strstr(norm, "/proc/self/status") ||
           strstr(norm, "/proc/self/cmdline") ||
           strstr(norm, "/proc/self/comm") ||
           strstr(norm, "/proc/self/cgroup") ||
           strstr(norm, "/proc/self/attr/current") ||
           strstr(norm, "/proc/self/environ") ||
           strstr(norm, "/proc/self/fd") ||
           strstr(norm, "/proc/self/fdinfo") ||
           strstr(norm, "/proc/self/task") ||
           strstr(norm, "/proc/thread-self/attr/current") ||
           strstr(norm, "/proc/mounts") ||
           strstr(norm, "/proc/self/mounts");
}

static bool dir_should_filter_entries(const char *path) {
    if (!path || !*path) return false;
    char norm[2048];
    normalize_ascii_z(path, norm, sizeof(norm));
    return strstr(norm, "/android/data") ||
           strstr(norm, "/android/obb") ||
           strstr(norm, "/storage/emulated") ||
           strstr(norm, "/sdcard") ||
           strstr(norm, "/data/app") ||
           strstr(norm, "/data/user") ||
           strstr(norm, "/data/user_de") ||
           strstr(norm, "/proc/self/fd");
}

static bool text_looks_ascii(const char *data, size_t len) {
    if (!data || len == 0) return false;
    size_t n = len < 512 ? len : 512;
    size_t printable = 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)data[i];
        if (c == 0) return false;
        if ((c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t') {
            ++printable;
        }
    }
    return printable * 100 / n >= 85;
}

static bool line_should_drop(const char *line, size_t len) {
    char norm[4096];
    normalize_ascii_n(line, len, norm, sizeof(norm));
    if (normalized_contains_any(norm, kLineDropTokens)) return true;
    return normalized_contains_any(norm, kSettingsKeys);
}

static size_t filter_text_lines(const char *in, size_t in_len,
                                char *out, size_t out_max) {
    if (!in || !out || out_max == 0) return 0;
    size_t out_pos = 0;
    const char *line = in;
    const char *end = in + in_len;
    while (line < end) {
        const char *nl = (const char *)memchr(line, '\n', (size_t)(end - line));
        if (!nl) nl = end;
        size_t line_len = (size_t)(nl - line);
        bool drop = line_should_drop(line, line_len);
        if (!drop) {
            size_t copy_len = line_len + (nl < end ? 1u : 0u);
            if (out_pos + copy_len > out_max) copy_len = out_max - out_pos;
            if (copy_len) {
                memcpy(out + out_pos, line, copy_len);
                out_pos += copy_len;
            }
        }
        line = nl + (nl < end ? 1 : 0);
    }
    return out_pos;
}

static bool entry_name_should_hide(const char *name) {
    if (!name || !*name) return false;
    char norm[512];
    normalize_ascii_z(name, norm, sizeof(norm));
    return normalized_contains_any(norm, kLineDropTokens);
}

// ---------------------------------------------------------------------------
// Binder Parcel sanitizing
// ---------------------------------------------------------------------------

static jboolean (*o_binder_transact)(JNIEnv *, jobject, jint, jobject, jobject,
                                     jint) = nullptr;

static jclass g_parcel_cls = nullptr;
static jmethodID g_parcel_marshall = nullptr;
static jmethodID g_parcel_unmarshall = nullptr;
static jmethodID g_parcel_set_pos = nullptr;

static bool ensure_parcel_methods(JNIEnv *env) {
    if (!env) return false;
    if (g_parcel_cls && g_parcel_marshall && g_parcel_unmarshall &&
        g_parcel_set_pos) {
        return true;
    }
    jclass local = env->FindClass("android/os/Parcel");
    if (!local) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return false;
    }
    g_parcel_cls = (jclass)env->NewGlobalRef(local);
    env->DeleteLocalRef(local);
    if (!g_parcel_cls) return false;
    g_parcel_marshall = env->GetMethodID(g_parcel_cls, "marshall", "()[B");
    g_parcel_unmarshall = env->GetMethodID(g_parcel_cls, "unmarshall", "([BII)V");
    g_parcel_set_pos = env->GetMethodID(g_parcel_cls, "setDataPosition", "(I)V");
    if (env->ExceptionCheck()) env->ExceptionClear();
    return g_parcel_marshall && g_parcel_unmarshall && g_parcel_set_pos;
}

static jbyte *parcel_to_bytes(JNIEnv *env, jobject parcel, jsize *out_len,
                              jbyteArray *out_arr) {
    if (!env || !parcel || !out_len || !out_arr || !ensure_parcel_methods(env)) {
        return nullptr;
    }
    *out_len = 0;
    *out_arr = (jbyteArray)env->CallObjectMethod(parcel, g_parcel_marshall);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        *out_arr = nullptr;
        return nullptr;
    }
    if (!*out_arr) return nullptr;
    *out_len = env->GetArrayLength(*out_arr);
    if (*out_len <= 0) return nullptr;
    return env->GetByteArrayElements(*out_arr, nullptr);
}

static void parcel_release_bytes(JNIEnv *env, jbyteArray arr, jbyte *bytes) {
    if (env && arr && bytes) env->ReleaseByteArrayElements(arr, bytes, JNI_ABORT);
    if (env && arr) env->DeleteLocalRef(arr);
}

static bool replace_ascii_equal(unsigned char *buf, size_t len,
                                const char *from, const char *to) {
    if (!buf || !from || !to) return false;
    size_t fl = strlen(from);
    size_t tl = strlen(to);
    if (fl == 0 || fl != tl || len < fl) return false;
    bool changed = false;
    for (size_t i = 0; i + fl <= len; ++i) {
        if (memcmp(buf + i, from, fl) == 0) {
            memcpy(buf + i, to, fl);
            changed = true;
            i += fl - 1;
        }
    }
    return changed;
}

static bool replace_utf16le_equal(unsigned char *buf, size_t len,
                                  const char *from, const char *to) {
    if (!buf || !from || !to) return false;
    size_t fl = strlen(from);
    size_t tl = strlen(to);
    if (fl == 0 || fl != tl || len < fl * 2) return false;
    bool changed = false;
    for (size_t i = 0; i + fl * 2 <= len; ++i) {
        bool hit = true;
        for (size_t j = 0; j < fl; ++j) {
            if (buf[i + j * 2] != (unsigned char)from[j] ||
                buf[i + j * 2 + 1] != 0) {
                hit = false;
                break;
            }
        }
        if (hit) {
            for (size_t j = 0; j < fl; ++j) {
                buf[i + j * 2] = (unsigned char)to[j];
                buf[i + j * 2 + 1] = 0;
            }
            changed = true;
            i += fl * 2 - 1;
        }
    }
    return changed;
}

static bool parcel_bytes_contain_ascii_or_utf16(const unsigned char *buf,
                                                size_t len,
                                                const char *needle) {
    if (!buf || !needle) return false;
    size_t nl = strlen(needle);
    if (nl == 0) return false;
    for (size_t i = 0; i + nl <= len; ++i) {
        if (memcmp(buf + i, needle, nl) == 0) return true;
    }
    for (size_t i = 0; i + nl * 2 <= len; ++i) {
        bool hit = true;
        for (size_t j = 0; j < nl; ++j) {
            if (buf[i + j * 2] != (unsigned char)needle[j] ||
                buf[i + j * 2 + 1] != 0) {
                hit = false;
                break;
            }
        }
        if (hit) return true;
    }
    return false;
}

static bool parcel_bytes_contain_any(const unsigned char *buf, size_t len,
                                     const char * const *tokens) {
    if (!tokens) return false;
    for (const char * const *p = tokens; *p; ++p) {
        if (parcel_bytes_contain_ascii_or_utf16(buf, len, *p)) return true;
    }
    return false;
}

static bool parcel_request_is_relevant(const unsigned char *buf, size_t len) {
    if (!buf || len == 0) return false;
    if (parcel_bytes_contain_any(buf, len, kSettingsKeys)) return true;
    if (parcel_bytes_contain_any(buf, len, kLineDropTokens)) return true;
    return parcel_bytes_contain_ascii_or_utf16(buf, len,
                                               "android.content.pm.IPackageManager") ||
           parcel_bytes_contain_ascii_or_utf16(buf, len,
                                               "android.content.IContentProvider") ||
           parcel_bytes_contain_ascii_or_utf16(buf, len,
                                               "android.provider.ISettingsProvider");
}

static bool request_has_setting_key(const unsigned char *buf, size_t len) {
    return parcel_bytes_contain_any(buf, len, kSettingsKeys);
}

static bool parcel_bytes_contain_hidden_package(const unsigned char *buf,
                                                size_t len) {
    for (const Alias *a = kPackageAliases; a->from; ++a) {
        if (parcel_bytes_contain_ascii_or_utf16(buf, len, a->from)) {
            return true;
        }
    }
    return false;
}

static bool request_is_direct_pm_hidden_package(const unsigned char *buf,
                                                size_t len) {
    return parcel_bytes_contain_ascii_or_utf16(
               buf, len, "android.content.pm.IPackageManager") &&
           parcel_bytes_contain_hidden_package(buf, len);
}

static bool null_direct_pm_reply(unsigned char *buf, size_t len) {
    if (!buf || len < 8) return false;
    if (buf[0] != 0 || buf[1] != 0 || buf[2] != 0 || buf[3] != 0) {
        return false;
    }
    if (buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] == 0) {
        return false;
    }
    buf[4] = 0;
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = 0;
    return true;
}

static bool zero_setting_scalar_values(unsigned char *buf, size_t len) {
    if (!buf || len < 6) return false;
    bool changed = false;
    for (size_t i = 0; i + 8 <= len; ++i) {
        if (buf[i] == 1 && buf[i + 1] == 0 && buf[i + 2] == 0 &&
            buf[i + 3] == 0 && buf[i + 4] == '1' && buf[i + 5] == 0 &&
            buf[i + 6] == 0 && buf[i + 7] == 0) {
            buf[i + 4] = '0';
            changed = true;
        }
    }
    for (size_t i = 0; i + 6 <= len; ++i) {
        if (buf[i] == 1 && buf[i + 1] == 0 && buf[i + 2] == 0 &&
            buf[i + 3] == 0 && buf[i + 4] == '1' && buf[i + 5] == 0) {
            buf[i + 4] = '0';
            changed = true;
        }
    }
    return changed;
}

static bool sanitize_parcel_bytes(unsigned char *buf, size_t len,
                                  bool settings_request) {
    if (!buf || len == 0) return false;
    bool changed = false;
    for (const Alias *a = kPackageAliases; a->from; ++a) {
        changed |= replace_ascii_equal(buf, len, a->from, a->to);
        changed |= replace_utf16le_equal(buf, len, a->from, a->to);
    }
    if (settings_request) changed |= zero_setting_scalar_values(buf, len);
    return changed;
}

static bool write_bytes_to_parcel(JNIEnv *env, jobject parcel,
                                  const unsigned char *buf, jsize len) {
    if (!env || !parcel || !buf || len <= 0 || !ensure_parcel_methods(env)) {
        return false;
    }
    jbyteArray arr = env->NewByteArray(len);
    if (!arr) return false;
    env->SetByteArrayRegion(arr, 0, len, (const jbyte *)buf);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(arr);
        return false;
    }
    env->CallVoidMethod(parcel, g_parcel_set_pos, 0);
    env->CallVoidMethod(parcel, g_parcel_unmarshall, arr, 0, len);
    env->CallVoidMethod(parcel, g_parcel_set_pos, 0);
    bool ok = !env->ExceptionCheck();
    if (!ok) env->ExceptionClear();
    env->DeleteLocalRef(arr);
    return ok;
}

static jboolean h_binder_transact(JNIEnv *env, jobject thiz, jint code,
                                  jobject data, jobject reply, jint flags) {
    bool relevant = false;
    bool settings_request = false;
    bool direct_hidden_pkg = false;
    jbyteArray data_arr = nullptr;
    jsize data_len = 0;
    jbyte *data_bytes = parcel_to_bytes(env, data, &data_len, &data_arr);
    if (data_bytes && data_len > 0) {
        relevant = parcel_request_is_relevant((const unsigned char *)data_bytes,
                                              (size_t)data_len);
        settings_request = request_has_setting_key(
            (const unsigned char *)data_bytes, (size_t)data_len);
        direct_hidden_pkg = request_is_direct_pm_hidden_package(
            (const unsigned char *)data_bytes, (size_t)data_len);
    }
    parcel_release_bytes(env, data_arr, data_bytes);

    jboolean rc = o_binder_transact ?
        o_binder_transact(env, thiz, code, data, reply, flags) : JNI_FALSE;
    if (rc != JNI_TRUE || !reply) return rc;

    jbyteArray reply_arr = nullptr;
    jsize reply_len = 0;
    jbyte *reply_bytes = parcel_to_bytes(env, reply, &reply_len, &reply_arr);
    if (!reply_bytes || reply_len <= 0) {
        parcel_release_bytes(env, reply_arr, reply_bytes);
        return rc;
    }

    bool has_hidden = parcel_bytes_contain_any(
        (const unsigned char *)reply_bytes, (size_t)reply_len, kLineDropTokens);
    if (relevant || has_hidden || direct_hidden_pkg) {
        unsigned char *copy = (unsigned char *)malloc((size_t)reply_len);
        if (copy) {
            memcpy(copy, reply_bytes, (size_t)reply_len);
            bool changed = false;
            if (direct_hidden_pkg) {
                changed |= null_direct_pm_reply(copy, (size_t)reply_len);
            }
            changed |= sanitize_parcel_bytes(copy, (size_t)reply_len,
                                             settings_request);
            if (changed) {
                (void)write_bytes_to_parcel(env, reply, copy, reply_len);
                LOGD("[%s] sanitized Binder reply code=%d", g_app_name, (int)code);
            }
            free(copy);
        }
    }
    parcel_release_bytes(env, reply_arr, reply_bytes);
    return rc;
}

// ---------------------------------------------------------------------------
// DuckDetector native bridge overrides
// ---------------------------------------------------------------------------

static jstring h_duck_props_snapshot(JNIEnv *env, jobject thiz,
                                     jobjectArray keys) {
    (void)thiz;
    (void)keys;
    return env->NewStringUTF(
        "AVAILABLE=1\n"
        "PROP_AREA_AVAILABLE=1\n"
        "PROP_AREA_CONTEXTS=0\n"
        "PROP_AREA_HOLES=0\n"
        "RO_HANDLE_AVAILABLE=1\n"
        "RO_HANDLE_CHECKED=0\n");
}

static jstring h_duck_pif_snapshot(JNIEnv *env, jobject thiz,
                                   jobjectArray keys) {
    (void)thiz;
    (void)keys;
    return env->NewStringUTF("AVAILABLE=1\n");
}

static jstring h_duck_dangerous_stat(JNIEnv *env, jobject thiz,
                                     jobjectArray packages) {
    (void)thiz;
    (void)packages;
    return env->NewStringUTF("");
}

static jstring h_duck_memory_snapshot(JNIEnv *env, jobject thiz) {
    (void)thiz;
    return env->NewStringUTF(
        "AVAILABLE=1\n"
        "GOT_PLT_HOOK=0\n"
        "INLINE_HOOK=0\n"
        "PROLOGUE_MODIFIED=0\n"
        "TRAMPOLINE=0\n"
        "SUSPICIOUS_JUMP=0\n"
        "MODIFIED_FUNCTION_COUNT=0\n"
        "WRITABLE_EXEC=0\n"
        "ANONYMOUS_EXEC=0\n"
        "SWAPPED_EXEC=0\n"
        "SHARED_DIRTY_EXEC=0\n"
        "DELETED_SO=0\n"
        "SUSPICIOUS_MEMFD=0\n"
        "EXEC_ASHMEM=0\n"
        "DEV_ZERO_EXEC=0\n"
        "SIGNAL_HANDLER=0\n"
        "FRIDA_SIGNAL=0\n"
        "ANONYMOUS_SIGNAL=0\n"
        "VDSO_REMAPPED=0\n"
        "VDSO_UNUSUAL_BASE=0\n"
        "DELETED_LIBRARY=0\n"
        "HIDDEN_MODULE=0\n"
        "MAPS_ONLY_MODULE=0\n"
        "CRITICAL_COUNT=0\n"
        "HIGH_COUNT=0\n"
        "MEDIUM_COUNT=0\n"
        "LOW_COUNT=0\n");
}

static jstring h_duck_lsposed_snapshot(JNIEnv *env, jobject thiz) {
    (void)thiz;
    return env->NewStringUTF(
        "AVAILABLE=1\n"
        "HEAP_AVAILABLE=1\n"
        "MAPS_HITS=0\n"
        "MAPS_SCANNED=0\n"
        "HEAP_HITS=0\n"
        "HEAP_SCANNED=0\n");
}

static jstring h_duck_zygisk_snapshot(JNIEnv *env, jobject thiz) {
    (void)thiz;
    return env->NewStringUTF(
        "AVAILABLE=1\n"
        "HEAP_AVAILABLE=1\n"
        "SECCOMP_SUPPORTED=1\n"
        "TRACER_PID=0\n"
        "STRONG_HITS=0\n"
        "HEURISTIC_HITS=0\n"
        "SOLIST_HITS=0\n"
        "VMAP_HITS=0\n"
        "ATEXIT_HITS=0\n"
        "SMAPS_HITS=0\n"
        "NAMESPACE_HITS=0\n"
        "LINKER_HOOK_HITS=0\n"
        "STACK_LEAK_HITS=0\n"
        "SECCOMP_HITS=0\n"
        "HEAP_HITS=0\n"
        "THREAD_HITS=0\n"
        "FD_HITS=0\n");
}

static jstring h_duck_su_snapshot(JNIEnv *env, jobject thiz) {
    (void)thiz;
    return env->NewStringUTF(
        "AVAILABLE=1\n"
        "SELF_CONTEXT=u:r:untrusted_app:s0\n"
        "SELF_ABNORMAL=0\n"
        "PROC_CHECKED=0\n"
        "PROC_DENIED=0\n");
}

static jstring h_duck_cgroup_snapshot(JNIEnv *env, jobject thiz) {
    (void)thiz;
    return env->NewStringUTF(
        "AVAILABLE=1\n"
        "PATH_CHECKS=0\n"
        "PATH_ACCESSIBLE=0\n"
        "PROCESS_COUNT=0\n"
        "PROC_DENIED=0\n");
}

static jstring h_duck_native_root_snapshot(JNIEnv *env, jobject thiz,
                                           jboolean xiaomi_like) {
    (void)thiz;
    (void)xiaomi_like;
    return env->NewStringUTF(
        "AVAILABLE=1\n"
        "ROOT_FOUND=0\n"
        "KERNELSU=0\n"
        "APATCH=0\n"
        "MAGISK=0\n"
        "SUSFS=0\n"
        "KSU_VERSION=0\n"
        "PRCTL_HIT=0\n"
        "KERNELPATCH_SIDE_CHANNEL_ATTACK=0\n"
        "DEVPTS_ABNORMAL_PERMISSION_AVAILABLE=1\n"
        "DEVPTS_ABNORMAL_PERMISSION_FOUND=0\n"
        "DEVPTS_ABNORMAL_PERMISSION_CHECKED=1\n"
        "DEVPTS_ABNORMAL_PERMISSION_DENIED=0\n"
        "KSU_SUPERCALL_ATTEMPTED=1\n"
        "KSU_SUPERCALL_HIT=0\n"
        "KSU_SUPERCALL_BLOCKED=0\n"
        "KSU_SUPERCALL_SAFE_MODE=0\n"
        "KSU_SUPERCALL_LKM=0\n"
        "KSU_SUPERCALL_LATE_LOAD=0\n"
        "KSU_SUPERCALL_PR_BUILD=0\n"
        "KSU_SUPERCALL_MANAGER=0\n"
        "SUSFS_HIT=0\n"
        "SELF_SU_DOMAIN=0\n"
        "SELF_CONTEXT=u:r:untrusted_app:s0\n"
        "SELF_KSU_DRIVER_FDS=0\n"
        "SELF_KSU_FDWRAPPER_FDS=0\n"
        "PATH_HITS=0\n"
        "PATH_CHECKS=0\n"
        "PROCESS_HITS=0\n"
        "PROCESS_CHECKED=0\n"
        "PROCESS_DENIED=0\n"
        "KERNEL_HITS=0\n"
        "KERNEL_SOURCES=0\n"
        "PROPERTY_HITS=0\n"
        "PROPERTY_CHECKS=0\n");
}

static void hook_duck_native_methods(JNIEnv *env, const char *class_name,
                                     JNINativeMethod *methods, int count) {
    if (!g_api || !env || !class_name || !methods || count <= 0) return;
    g_api->hookJniNativeMethods(env, class_name, methods, count);
    if (env->ExceptionCheck()) env->ExceptionClear();
}

static int register_plt_hooks();
static void install_jni_hooks(JNIEnv *env);
static void install_jni_hooks_from_vm();

static void *duck_jni_symbol_override(const char *name) {
    if (!name) return nullptr;
    if (strcmp(name,
        "Java_com_eltavine_duckdetector_features_systemproperties_data_native_SystemPropertiesNativeBridge_nativeCollectSnapshot") == 0) {
        return (void *)h_duck_props_snapshot;
    }
    if (strcmp(name,
        "Java_com_eltavine_duckdetector_features_playintegrityfix_data_native_PlayIntegrityFixNativeBridge_nativeCollectSnapshot") == 0) {
        return (void *)h_duck_pif_snapshot;
    }
    if (strcmp(name,
        "Java_com_eltavine_duckdetector_features_dangerousapps_data_native_DangerousAppsNativeBridge_nativeStatPackages") == 0) {
        return (void *)h_duck_dangerous_stat;
    }
    if (strcmp(name,
        "Java_com_eltavine_duckdetector_features_memory_data_native_MemoryNativeBridge_nativeCollectSnapshot") == 0) {
        return (void *)h_duck_memory_snapshot;
    }
    if (strcmp(name,
        "Java_com_eltavine_duckdetector_features_lsposed_data_native_LSPosedNativeBridge_nativeCollectSnapshot") == 0) {
        return (void *)h_duck_lsposed_snapshot;
    }
    if (strcmp(name,
        "Java_com_eltavine_duckdetector_features_zygisk_data_native_ZygiskNativeBridge_nativeCollectSnapshot") == 0) {
        return (void *)h_duck_zygisk_snapshot;
    }
    if (strcmp(name,
        "Java_com_eltavine_duckdetector_features_su_data_native_SuNativeBridge_nativeCollectSnapshot") == 0) {
        return (void *)h_duck_su_snapshot;
    }
    if (strcmp(name,
        "Java_com_eltavine_duckdetector_features_nativeroot_data_native_CgroupProcessLeakNativeBridge_nativeCollectSnapshot") == 0) {
        return (void *)h_duck_cgroup_snapshot;
    }
    if (strcmp(name,
        "Java_com_eltavine_duckdetector_features_nativeroot_data_native_NativeRootNativeBridge_nativeCollectSnapshot") == 0) {
        return (void *)h_duck_native_root_snapshot;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Native filesystem/process probes
// ---------------------------------------------------------------------------

static int (*o_open)(const char *, int, ...) = nullptr;
static int (*o_open64)(const char *, int, ...) = nullptr;
static int (*o_openat)(int, const char *, int, ...) = nullptr;
static FILE *(*o_fopen)(const char *, const char *) = nullptr;
static ssize_t (*o_read)(int, void *, size_t) = nullptr;
static int (*o_close)(int) = nullptr;
static int (*o_access)(const char *, int) = nullptr;
static int (*o_faccessat)(int, const char *, int, int) = nullptr;
static int (*o_faccessat2)(int, const char *, int, int) = nullptr;
static int (*o_stat)(const char *, struct stat *) = nullptr;
static int (*o_lstat)(const char *, struct stat *) = nullptr;
static int (*o_fstatat)(int, const char *, struct stat *, int) = nullptr;
static int (*o_statx)(int, const char *, int, unsigned int, void *) = nullptr;
static ssize_t (*o_readlink)(const char *, char *, size_t) = nullptr;
static ssize_t (*o_readlinkat)(int, const char *, char *, size_t) = nullptr;
static char *(*o_realpath)(const char *, char *) = nullptr;
static ssize_t (*o_getxattr)(const char *, const char *, void *, size_t) = nullptr;
static ssize_t (*o_lgetxattr)(const char *, const char *, void *, size_t) = nullptr;
static DIR *(*o_opendir)(const char *) = nullptr;
static struct dirent *(*o_readdir)(DIR *) = nullptr;
static int (*o_closedir)(DIR *) = nullptr;
static int (*o_execve)(const char *, char *const[], char *const[]) = nullptr;
static int (*o_execv)(const char *, char *const[]) = nullptr;
static int (*o_execvp)(const char *, char *const[]) = nullptr;
static int (*o_posix_spawn)(pid_t *, const char *,
                            const posix_spawn_file_actions_t *,
                            const posix_spawnattr_t *,
                            char *const[], char *const[]) = nullptr;
static FILE *(*o_popen)(const char *, const char *) = nullptr;
static char *(*o_getenv)(const char *) = nullptr;
static char *(*o_secure_getenv)(const char *) = nullptr;
static int (*o_prctl)(int, unsigned long, unsigned long, unsigned long,
                      unsigned long) = nullptr;
static void *(*o_dlsym)(void *, const char *) = nullptr;
static void *(*o_dlopen)(const char *, int) = nullptr;
static void *(*o_android_dlopen_ext)(const char *, int, const void *) = nullptr;

enum FdType {
    FD_NONE = 0,
    FD_TEXT = 1,
};

struct TrackedFd {
    int fd;
    FdType type;
};

#define MAX_TRACKED_FDS 64
static TrackedFd g_fds[MAX_TRACKED_FDS];
static int g_fd_count = 0;
static pthread_mutex_t g_fd_lock = PTHREAD_MUTEX_INITIALIZER;

static void track_fd(int fd, FdType type) {
    if (fd < 0 || type == FD_NONE) return;
    pthread_mutex_lock(&g_fd_lock);
    for (int i = 0; i < g_fd_count; ++i) {
        if (g_fds[i].fd == fd) {
            g_fds[i].type = type;
            pthread_mutex_unlock(&g_fd_lock);
            return;
        }
    }
    if (g_fd_count < MAX_TRACKED_FDS) {
        g_fds[g_fd_count].fd = fd;
        g_fds[g_fd_count].type = type;
        ++g_fd_count;
    }
    pthread_mutex_unlock(&g_fd_lock);
}

static FdType get_fd_type(int fd) {
    FdType type = FD_NONE;
    pthread_mutex_lock(&g_fd_lock);
    for (int i = 0; i < g_fd_count; ++i) {
        if (g_fds[i].fd == fd) {
            type = g_fds[i].type;
            break;
        }
    }
    pthread_mutex_unlock(&g_fd_lock);
    return type;
}

static void untrack_fd(int fd) {
    pthread_mutex_lock(&g_fd_lock);
    for (int i = 0; i < g_fd_count; ++i) {
        if (g_fds[i].fd == fd) {
            g_fds[i] = g_fds[--g_fd_count];
            break;
        }
    }
    pthread_mutex_unlock(&g_fd_lock);
}

struct TrackedDir {
    DIR *dir;
    bool filter;
};

#define MAX_TRACKED_DIRS 64
static TrackedDir g_dirs[MAX_TRACKED_DIRS];
static int g_dir_count = 0;
static pthread_mutex_t g_dir_lock = PTHREAD_MUTEX_INITIALIZER;

static void track_dir(DIR *dir, bool filter) {
    if (!dir || !filter) return;
    pthread_mutex_lock(&g_dir_lock);
    for (int i = 0; i < g_dir_count; ++i) {
        if (g_dirs[i].dir == dir) {
            g_dirs[i].filter = filter;
            pthread_mutex_unlock(&g_dir_lock);
            return;
        }
    }
    if (g_dir_count < MAX_TRACKED_DIRS) {
        g_dirs[g_dir_count].dir = dir;
        g_dirs[g_dir_count].filter = filter;
        ++g_dir_count;
    }
    pthread_mutex_unlock(&g_dir_lock);
}

static bool dir_is_filtered(DIR *dir) {
    bool filtered = false;
    pthread_mutex_lock(&g_dir_lock);
    for (int i = 0; i < g_dir_count; ++i) {
        if (g_dirs[i].dir == dir) {
            filtered = g_dirs[i].filter;
            break;
        }
    }
    pthread_mutex_unlock(&g_dir_lock);
    return filtered;
}

static void untrack_dir(DIR *dir) {
    pthread_mutex_lock(&g_dir_lock);
    for (int i = 0; i < g_dir_count; ++i) {
        if (g_dirs[i].dir == dir) {
            g_dirs[i] = g_dirs[--g_dir_count];
            break;
        }
    }
    pthread_mutex_unlock(&g_dir_lock);
}

static int deny_enoent(const char *what) {
    (void)what;
    LOGD("[%s] suppress path: %s", g_app_name, what ? what : "?");
    errno = ENOENT;
    return -1;
}

static int h_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (path_should_hide(path)) return deny_enoent(path);
    int fd = o_open ? o_open(path, flags, mode) : -1;
    if (fd >= 0 && path_is_sensitive_text(path)) track_fd(fd, FD_TEXT);
    return fd;
}

static int h_open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (path_should_hide(path)) return deny_enoent(path);
    int fd = o_open64 ? o_open64(path, flags, mode) : -1;
    if (fd >= 0 && path_is_sensitive_text(path)) track_fd(fd, FD_TEXT);
    return fd;
}

static int h_openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (path_should_hide(path)) return deny_enoent(path);
    int fd = o_openat ? o_openat(dirfd, path, flags, mode) : -1;
    if (fd >= 0 && path_is_sensitive_text(path)) track_fd(fd, FD_TEXT);
    return fd;
}

static FILE *h_fopen(const char *path, const char *mode) {
    if (path_should_hide(path)) {
        errno = ENOENT;
        return nullptr;
    }
    FILE *f = o_fopen ? o_fopen(path, mode) : nullptr;
    if (f && path_is_sensitive_text(path)) track_fd(fileno(f), FD_TEXT);
    return f;
}

static ssize_t h_read(int fd, void *buf, size_t count) {
    ssize_t n = o_read ? o_read(fd, buf, count) : -1;
    if (n <= 0 || !buf) return n;

    bool should_filter = get_fd_type(fd) == FD_TEXT;
    if (!should_filter && text_looks_ascii((const char *)buf, (size_t)n)) {
        char norm[4096];
        normalize_ascii_n((const char *)buf, (size_t)n, norm, sizeof(norm));
        should_filter = normalized_contains_any(norm, kLineDropTokens) ||
                        normalized_contains_any(norm, kSettingsKeys);
    }
    if (!should_filter) return n;

    char *tmp = (char *)malloc((size_t)n);
    if (!tmp) return n;
    size_t out_len = filter_text_lines((const char *)buf, (size_t)n, tmp, (size_t)n);
    if (out_len < (size_t)n) {
        memcpy(buf, tmp, out_len);
        n = (ssize_t)out_len;
    }
    free(tmp);
    return n;
}

static int h_close(int fd) {
    untrack_fd(fd);
    return o_close ? o_close(fd) : 0;
}

static int h_access(const char *path, int mode) {
    if (path_should_hide(path)) return deny_enoent(path);
    return o_access ? o_access(path, mode) : -1;
}

static int h_faccessat(int dirfd, const char *path, int mode, int flags) {
    if (path_should_hide(path)) return deny_enoent(path);
    return o_faccessat ? o_faccessat(dirfd, path, mode, flags) : -1;
}

static int h_faccessat2(int dirfd, const char *path, int mode, int flags) {
    if (path_should_hide(path)) return deny_enoent(path);
    return o_faccessat2 ? o_faccessat2(dirfd, path, mode, flags) : -1;
}

static int h_stat(const char *path, struct stat *st) {
    if (path_should_hide(path)) return deny_enoent(path);
    return o_stat ? o_stat(path, st) : -1;
}

static int h_lstat(const char *path, struct stat *st) {
    if (path_should_hide(path)) return deny_enoent(path);
    return o_lstat ? o_lstat(path, st) : -1;
}

static int h_fstatat(int dirfd, const char *path, struct stat *st, int flags) {
    if (path_should_hide(path)) return deny_enoent(path);
    return o_fstatat ? o_fstatat(dirfd, path, st, flags) : -1;
}

static int h_statx(int dirfd, const char *path, int flags,
                   unsigned int mask, void *stx) {
    if (path_should_hide(path)) return deny_enoent(path);
    return o_statx ? o_statx(dirfd, path, flags, mask, stx) : -1;
}

static ssize_t h_readlink(const char *path, char *buf, size_t size) {
    if (path_should_hide(path)) return deny_enoent(path);
    ssize_t rc = o_readlink ? o_readlink(path, buf, size) : -1;
    if (rc > 0 && buf) {
        char tmp[2048];
        size_t n = (size_t)rc < sizeof(tmp) - 1 ? (size_t)rc : sizeof(tmp) - 1;
        memcpy(tmp, buf, n);
        tmp[n] = '\0';
        if (path_should_hide(tmp)) {
            errno = ENOENT;
            return -1;
        }
    }
    return rc;
}

static ssize_t h_readlinkat(int dirfd, const char *path, char *buf, size_t size) {
    if (path_should_hide(path)) return deny_enoent(path);
    ssize_t rc = o_readlinkat ? o_readlinkat(dirfd, path, buf, size) : -1;
    if (rc > 0 && buf) {
        char tmp[2048];
        size_t n = (size_t)rc < sizeof(tmp) - 1 ? (size_t)rc : sizeof(tmp) - 1;
        memcpy(tmp, buf, n);
        tmp[n] = '\0';
        if (path_should_hide(tmp)) {
            errno = ENOENT;
            return -1;
        }
    }
    return rc;
}

static char *h_realpath(const char *path, char *resolved) {
    if (path_should_hide(path)) {
        errno = ENOENT;
        return nullptr;
    }
    char *rc = o_realpath ? o_realpath(path, resolved) : nullptr;
    if (rc && path_should_hide(rc)) {
        errno = ENOENT;
        return nullptr;
    }
    return rc;
}

static ssize_t h_getxattr(const char *path, const char *name,
                          void *value, size_t size) {
    if (path_should_hide(path)) {
        errno = ENOENT;
        return -1;
    }
    return o_getxattr ? o_getxattr(path, name, value, size) : -1;
}

static ssize_t h_lgetxattr(const char *path, const char *name,
                           void *value, size_t size) {
    if (path_should_hide(path)) {
        errno = ENOENT;
        return -1;
    }
    return o_lgetxattr ? o_lgetxattr(path, name, value, size) : -1;
}

static DIR *h_opendir(const char *path) {
    if (path_should_hide(path)) {
        errno = ENOENT;
        return nullptr;
    }
    DIR *dir = o_opendir ? o_opendir(path) : nullptr;
    if (dir) track_dir(dir, dir_should_filter_entries(path));
    return dir;
}

static struct dirent *h_readdir(DIR *dir) {
    if (!o_readdir) return nullptr;
    bool filter = dir_is_filtered(dir);
    struct dirent *ent = nullptr;
    do {
        ent = o_readdir(dir);
    } while (filter && ent && entry_name_should_hide(ent->d_name));
    return ent;
}

static int h_closedir(DIR *dir) {
    untrack_dir(dir);
    return o_closedir ? o_closedir(dir) : -1;
}

static const char *base_name(const char *path) {
    if (!path) return "";
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static bool arg_contains_android_listing(const char *arg) {
    if (!arg) return false;
    char norm[2048];
    normalize_ascii_z(arg, norm, sizeof(norm));
    return strstr(norm, "/android/data") || strstr(norm, "/android/obb");
}

static bool streq_ascii(const char *a, const char *b) {
    return a && b && strcmp(a, b) == 0;
}

static bool argv_probe_should_fail(const char *file, char *const argv[]) {
    const char *cmd0 = (argv && argv[0]) ? argv[0] : file;
    const char *op = base_name(cmd0);
    int first_path_arg = 1;
    if ((streq_ascii(op, "toybox") || streq_ascii(op, "toolbox")) &&
        argv && argv[1]) {
        op = argv[1];
        first_path_arg = 2;
    }

    bool hidden_arg = false;
    bool android_listing = false;
    bool mentions_ls = streq_ascii(op, "ls");
    bool mentions_getprop = streq_ascii(op, "getprop");
    if (argv) {
        for (int i = first_path_arg; argv[i]; ++i) {
            if (path_should_hide(argv[i])) hidden_arg = true;
            if (arg_contains_android_listing(argv[i])) android_listing = true;
            char norm[2048];
            normalize_ascii_z(argv[i], norm, sizeof(norm));
            if (strstr(norm, "ls")) mentions_ls = true;
            if (strstr(norm, "getprop")) mentions_getprop = true;
        }
    }
    if (mentions_getprop) return true;
    if (hidden_arg) return true;
    return android_listing &&
           (streq_ascii(op, "ls") ||
            (mentions_ls && (streq_ascii(op, "sh") ||
                             streq_ascii(op, "mksh") ||
                             streq_ascii(op, "toybox") ||
                             streq_ascii(op, "toolbox"))));
}

static int h_execve(const char *file, char *const argv[], char *const envp[]) {
    if (argv_probe_should_fail(file, argv)) {
        errno = ENOENT;
        return -1;
    }
    return o_execve ? o_execve(file, argv, envp) : -1;
}

static int h_execv(const char *file, char *const argv[]) {
    if (argv_probe_should_fail(file, argv)) {
        errno = ENOENT;
        return -1;
    }
    return o_execv ? o_execv(file, argv) : -1;
}

static int h_execvp(const char *file, char *const argv[]) {
    if (argv_probe_should_fail(file, argv)) {
        errno = ENOENT;
        return -1;
    }
    return o_execvp ? o_execvp(file, argv) : -1;
}

static int h_posix_spawn(pid_t *pid, const char *path,
                         const posix_spawn_file_actions_t *actions,
                         const posix_spawnattr_t *attrs,
                         char *const argv[], char *const envp[]) {
    if (argv_probe_should_fail(path, argv)) return ENOENT;
    return o_posix_spawn ? o_posix_spawn(pid, path, actions, attrs, argv, envp)
                         : ENOSYS;
}

static FILE *h_popen(const char *command, const char *mode) {
    bool block = path_should_hide(command);
    if (!block && command) {
        char norm[2048];
        normalize_ascii_z(command, norm, sizeof(norm));
        block = strstr(norm, "getprop") ||
                (strstr(norm, "ls") && (strstr(norm, "/android/data") ||
                                        strstr(norm, "/android/obb")));
    }
    if (block) {
        errno = ENOENT;
        return nullptr;
    }
    return o_popen ? o_popen(command, mode) : nullptr;
}

static bool env_name_should_hide(const char *name) {
    if (!name || !*name) return false;
    char norm[256];
    normalize_ascii_z(name, norm, sizeof(norm));
    return strstr(norm, "kernelsu") ||
           strstr(norm, "ksu_") ||
           strcmp(norm, "kernelsu") == 0 ||
           strcmp(norm, "ksu") == 0;
}

static char *h_getenv(const char *name) {
    if (env_name_should_hide(name)) return nullptr;
    return o_getenv ? o_getenv(name) : nullptr;
}

static char *h_secure_getenv(const char *name) {
    if (env_name_should_hide(name)) return nullptr;
    return o_secure_getenv ? o_secure_getenv(name) : h_getenv(name);
}

static int h_prctl(int option, unsigned long arg2, unsigned long arg3,
                   unsigned long arg4, unsigned long arg5) {
    if ((unsigned int)option == 0xDEADBEEFu) {
        (void)arg2;
        (void)arg3;
        (void)arg4;
        (void)arg5;
        errno = EINVAL;
        return -1;
    }
    return o_prctl ? o_prctl(option, arg2, arg3, arg4, arg5) : -1;
}

static void refresh_after_load(const char *path) {
    (void)path;
    (void)register_plt_hooks();
    install_jni_hooks_from_vm();
}

static void *h_dlsym(void *handle, const char *symbol) {
    void *override = duck_jni_symbol_override(symbol);
    if (override) {
        LOGI("[%s] dlsym override: %s", g_app_name, symbol);
        return override;
    }
    return o_dlsym ? o_dlsym(handle, symbol) : nullptr;
}

static void *h_dlopen(const char *filename, int flags) {
    void *ret = o_dlopen ? o_dlopen(filename, flags) : nullptr;
    if (ret) refresh_after_load(filename);
    return ret;
}

static void *h_android_dlopen_ext(const char *filename, int flags,
                                  const void *extinfo) {
    void *ret = o_android_dlopen_ext ?
        o_android_dlopen_ext(filename, flags, extinfo) : nullptr;
    if (ret) refresh_after_load(filename);
    return ret;
}

// ---------------------------------------------------------------------------
// PLT hook registration
// ---------------------------------------------------------------------------

struct SeenLib {
    dev_t dev;
    ino_t ino;
};

static bool seen_add(SeenLib *seen, int *count, int cap, dev_t dev, ino_t ino) {
    for (int i = 0; i < *count; ++i) {
        if (seen[i].dev == dev && seen[i].ino == ino) return false;
    }
    if (*count >= cap) return false;
    seen[*count].dev = dev;
    seen[*count].ino = ino;
    ++*count;
    return true;
}

static bool should_hook_lib(const char *path) {
    if (!path || !strstr(path, ".so")) return false;
    const char *base = base_name(path);
    if (strstr(base, "duck_visibility_bypass")) return false;
    if (strstr(base, "anti_dev_pm_zygisk")) return false;
    if (strcmp(base, "arm64-v8a.so") == 0 ||
        strcmp(base, "armeabi-v7a.so") == 0 ||
        strcmp(base, "x86.so") == 0 ||
        strcmp(base, "x86_64.so") == 0) {
        return false;
    }
    return true;
}

#define REG_HOOK(sym, hook, orig) \
    g_api->pltHookRegister(st.st_dev, st.st_ino, sym, (void *)(hook), (void **)&(orig))

static int register_plt_hooks() {
    if (!g_api) return 0;
    pthread_mutex_lock(&g_hook_lock);

    FILE *fp = fopen("/proc/self/maps", "re");
    if (!fp) {
        pthread_mutex_unlock(&g_hook_lock);
        return 0;
    }

    SeenLib seen[384];
    int seen_count = 0;
    int reg_count = 0;
    char line[1024];

    while (fgets(line, sizeof(line), fp)) {
        char *path = strchr(line, '/');
        if (!path) continue;
        size_t len = strlen(path);
        if (len && path[len - 1] == '\n') path[--len] = '\0';
        char *deleted = strstr(path, " (deleted)");
        if (deleted) *deleted = '\0';
        if (!should_hook_lib(path)) continue;

        struct stat st {};
        if (stat(path, &st) != 0) continue;
        if (!seen_add(seen, &seen_count, 384, st.st_dev, st.st_ino)) continue;

        REG_HOOK("__system_property_get", h_sys_prop_get, o_sys_prop_get);
        REG_HOOK("__system_property_find", h_sys_prop_find, o_sys_prop_find);
        REG_HOOK("__system_property_read", h_sys_prop_read, o_sys_prop_read);
        REG_HOOK("__system_property_read_callback", h_sys_prop_read_callback,
                 o_sys_prop_read_callback);
        REG_HOOK("__system_property_foreach", h_sys_prop_foreach,
                 o_sys_prop_foreach);
        REG_HOOK("property_get", h_prop_get, o_prop_get);

        REG_HOOK("open", h_open, o_open);
        REG_HOOK("open64", h_open64, o_open64);
        REG_HOOK("openat", h_openat, o_openat);
        REG_HOOK("fopen", h_fopen, o_fopen);
        REG_HOOK("read", h_read, o_read);
        REG_HOOK("close", h_close, o_close);
        REG_HOOK("access", h_access, o_access);
        REG_HOOK("faccessat", h_faccessat, o_faccessat);
        REG_HOOK("faccessat2", h_faccessat2, o_faccessat2);
        REG_HOOK("stat", h_stat, o_stat);
        REG_HOOK("lstat", h_lstat, o_lstat);
        REG_HOOK("fstatat", h_fstatat, o_fstatat);
        REG_HOOK("statx", h_statx, o_statx);
        REG_HOOK("readlink", h_readlink, o_readlink);
        REG_HOOK("readlinkat", h_readlinkat, o_readlinkat);
        REG_HOOK("realpath", h_realpath, o_realpath);
        REG_HOOK("getxattr", h_getxattr, o_getxattr);
        REG_HOOK("lgetxattr", h_lgetxattr, o_lgetxattr);
        REG_HOOK("opendir", h_opendir, o_opendir);
        REG_HOOK("readdir", h_readdir, o_readdir);
        REG_HOOK("closedir", h_closedir, o_closedir);
        REG_HOOK("execve", h_execve, o_execve);
        REG_HOOK("execv", h_execv, o_execv);
        REG_HOOK("execvp", h_execvp, o_execvp);
        REG_HOOK("posix_spawn", h_posix_spawn, o_posix_spawn);
        REG_HOOK("popen", h_popen, o_popen);
        REG_HOOK("getenv", h_getenv, o_getenv);
        REG_HOOK("secure_getenv", h_secure_getenv, o_secure_getenv);
        REG_HOOK("prctl", h_prctl, o_prctl);
        REG_HOOK("dlsym", h_dlsym, o_dlsym);
        REG_HOOK("dlopen", h_dlopen, o_dlopen);
        REG_HOOK("android_dlopen_ext", h_android_dlopen_ext,
                 o_android_dlopen_ext);
        ++reg_count;
    }
    fclose(fp);

    bool ok = reg_count > 0 && g_api->pltHookCommit();
    if (!ok && reg_count > 0) LOGW("pltHookCommit failed (%d libs)", reg_count);
    pthread_mutex_unlock(&g_hook_lock);
    return ok ? reg_count : 0;
}

#undef REG_HOOK

// ---------------------------------------------------------------------------
// JNI hooks
// ---------------------------------------------------------------------------

static void install_jni_hooks(JNIEnv *env) {
    if (!g_api || !env) return;
    pthread_mutex_lock(&g_jni_lock);
    if (g_jni_installed) {
        pthread_mutex_unlock(&g_jni_lock);
        return;
    }

    {
        jclass version = env->FindClass("android/os/Build$VERSION");
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (version) {
            jint real_sdk = -1;
            jfieldID sdk = env->GetStaticFieldID(version, "SDK_INT", "I");
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (sdk) real_sdk = env->GetStaticIntField(version, sdk);

            // Android 16/API 36+ framework and UI code can depend on the real SDK.
            // Keep the older compatibility spoof only for API 30-35.
            const bool allow_sdk_spoof = real_sdk >= 30 && real_sdk < 36;
            if (allow_sdk_spoof) {
                if (sdk) env->SetStaticIntField(version, sdk, 29);

                jfieldID res_sdk = env->GetStaticFieldID(version, "RESOURCES_SDK_INT", "I");
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (res_sdk) {
                    jint cur = env->GetStaticIntField(version, res_sdk);
                    if (cur >= 30) env->SetStaticIntField(version, res_sdk, 29);
                }
                LOGI("[%s] Build.VERSION SDK spoof installed (sdk=%d)", g_app_name, real_sdk);
            } else {
                LOGI("[%s] Build.VERSION SDK spoof skipped (sdk=%d)", g_app_name, real_sdk);
            }
            env->DeleteLocalRef(version);
        }
    }

    JNINativeMethod sp[] = {
        { "native_get", "(Ljava/lang/String;)Ljava/lang/String;", (void *)h_sp_get1 },
        { "native_get", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (void *)h_sp_get2 },
        { "native_get_int", "(Ljava/lang/String;I)I", (void *)h_sp_geti },
        { "native_get_long", "(Ljava/lang/String;J)J", (void *)h_sp_getl },
        { "native_get_boolean", "(Ljava/lang/String;Z)Z", (void *)h_sp_getb },
    };
    g_api->hookJniNativeMethods(env, "android/os/SystemProperties", sp, 5);
    if (sp[0].fnPtr != (void *)h_sp_get1)
        o_sp_get1 = (jstring (*)(JNIEnv *, jclass, jstring))sp[0].fnPtr;
    if (sp[1].fnPtr != (void *)h_sp_get2)
        o_sp_get2 = (jstring (*)(JNIEnv *, jclass, jstring, jstring))sp[1].fnPtr;
    if (sp[2].fnPtr != (void *)h_sp_geti)
        o_sp_geti = (jint (*)(JNIEnv *, jclass, jstring, jint))sp[2].fnPtr;
    if (sp[3].fnPtr != (void *)h_sp_getl)
        o_sp_getl = (jlong (*)(JNIEnv *, jclass, jstring, jlong))sp[3].fnPtr;
    if (sp[4].fnPtr != (void *)h_sp_getb)
        o_sp_getb = (jboolean (*)(JNIEnv *, jclass, jstring, jboolean))sp[4].fnPtr;
    LOGI("[%s] SystemProperties JNI hook installed", g_app_name);

    JNINativeMethod binder[] = {
        { "transactNative", "(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z",
          (void *)h_binder_transact },
    };
    g_api->hookJniNativeMethods(env, "android/os/BinderProxy", binder, 1);
    if (binder[0].fnPtr != (void *)h_binder_transact) {
        o_binder_transact = (jboolean (*)(JNIEnv *, jobject, jint, jobject,
                                          jobject, jint))binder[0].fnPtr;
        LOGI("[%s] BinderProxy.transactNative hook installed", g_app_name);
    } else {
        LOGW("[%s] BinderProxy.transactNative hook unavailable", g_app_name);
    }

    JNINativeMethod props_bridge[] = {
        { "nativeCollectSnapshot", "([Ljava/lang/String;)Ljava/lang/String;",
          (void *)h_duck_props_snapshot },
    };
    hook_duck_native_methods(env,
        "com/eltavine/duckdetector/features/systemproperties/data/native/SystemPropertiesNativeBridge",
        props_bridge, 1);

    JNINativeMethod pif_bridge[] = {
        { "nativeCollectSnapshot", "([Ljava/lang/String;)Ljava/lang/String;",
          (void *)h_duck_pif_snapshot },
    };
    hook_duck_native_methods(env,
        "com/eltavine/duckdetector/features/playintegrityfix/data/native/PlayIntegrityFixNativeBridge",
        pif_bridge, 1);

    JNINativeMethod dangerous_bridge[] = {
        { "nativeStatPackages", "([Ljava/lang/String;)Ljava/lang/String;",
          (void *)h_duck_dangerous_stat },
    };
    hook_duck_native_methods(env,
        "com/eltavine/duckdetector/features/dangerousapps/data/native/DangerousAppsNativeBridge",
        dangerous_bridge, 1);

    JNINativeMethod memory_bridge[] = {
        { "nativeCollectSnapshot", "()Ljava/lang/String;",
          (void *)h_duck_memory_snapshot },
    };
    hook_duck_native_methods(env,
        "com/eltavine/duckdetector/features/memory/data/native/MemoryNativeBridge",
        memory_bridge, 1);

    JNINativeMethod lsposed_bridge[] = {
        { "nativeCollectSnapshot", "()Ljava/lang/String;",
          (void *)h_duck_lsposed_snapshot },
    };
    hook_duck_native_methods(env,
        "com/eltavine/duckdetector/features/lsposed/data/native/LSPosedNativeBridge",
        lsposed_bridge, 1);

    JNINativeMethod zygisk_bridge[] = {
        { "nativeCollectSnapshot", "()Ljava/lang/String;",
          (void *)h_duck_zygisk_snapshot },
    };
    hook_duck_native_methods(env,
        "com/eltavine/duckdetector/features/zygisk/data/native/ZygiskNativeBridge",
        zygisk_bridge, 1);

    JNINativeMethod su_bridge[] = {
        { "nativeCollectSnapshot", "()Ljava/lang/String;",
          (void *)h_duck_su_snapshot },
    };
    hook_duck_native_methods(env,
        "com/eltavine/duckdetector/features/su/data/native/SuNativeBridge",
        su_bridge, 1);

    JNINativeMethod cgroup_bridge[] = {
        { "nativeCollectSnapshot", "()Ljava/lang/String;",
          (void *)h_duck_cgroup_snapshot },
    };
    hook_duck_native_methods(env,
        "com/eltavine/duckdetector/features/nativeroot/data/native/CgroupProcessLeakNativeBridge",
        cgroup_bridge, 1);

    JNINativeMethod native_root_bridge[] = {
        { "nativeCollectSnapshot", "(Z)Ljava/lang/String;",
          (void *)h_duck_native_root_snapshot },
    };
    hook_duck_native_methods(env,
        "com/eltavine/duckdetector/features/nativeroot/data/native/NativeRootNativeBridge",
        native_root_bridge, 1);
    LOGI("[%s] Duck native bridge hooks requested", g_app_name);
    g_jni_installed = true;
    pthread_mutex_unlock(&g_jni_lock);
}

static void install_jni_hooks_from_vm() {
    if (!g_vm) return;
    JNIEnv *env = nullptr;
    bool attached = false;
    jint env_rc = g_vm->GetEnv((void **)&env, JNI_VERSION_1_6);
    if (env_rc == JNI_EDETACHED) {
        if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK) return;
        attached = true;
    } else if (env_rc != JNI_OK || !env) {
        return;
    }
    install_jni_hooks(env);
    if (attached) g_vm->DetachCurrentThread();
}

static void *delayed_hook_worker(void *) {
    const unsigned int delays[] = { 1, 2, 3, 5, 8, 13, 21, 34 };
    for (unsigned int d : delays) {
        sleep(d);
        (void)register_plt_hooks();
        install_jni_hooks_from_vm();
        LOGD("[%s] delayed PLT pass done", g_app_name);
    }
    return nullptr;
}

static void start_delayed_hooks() {
    if (g_hooks_started) return;
    g_hooks_started = true;
    pthread_t t;
    if (pthread_create(&t, nullptr, delayed_hook_worker, nullptr) == 0) {
        pthread_detach(t);
    }
}

// ---------------------------------------------------------------------------
// Zygisk entry
// ---------------------------------------------------------------------------

class DuckVisibilityBypass : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        g_api = api;
        if (env) env->GetJavaVM(&g_vm);
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        target = should_install(env, args);
        if (!target && api) api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {
        if (!target) return;
        install_jni_hooks(env);
        int hooked = 0;
        int sdk = get_runtime_sdk(env);
        if (sdk >= 36) {
            LOGI("[%s] native PLT hooks skipped on sdk=%d", g_app_name, sdk);
        } else {
            hooked = register_plt_hooks();
            start_delayed_hooks();
        }
        LOGI("[%s] %s active, plt_libs=%d", g_app_name, MODULE_VERSION, hooked);
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *) override {
        if (api) api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    bool target = false;

    static bool jstr_has(JNIEnv *e, jstring s, const char *needle) {
        if (!e || !s || !needle) return false;
        const char *c = e->GetStringUTFChars(s, nullptr);
        if (!c) return false;
        bool hit = strstr(c, needle) != nullptr;
        e->ReleaseStringUTFChars(s, c);
        return hit;
    }

    static bool jstr_eq(JNIEnv *e, jstring s, const char *value) {
        if (!e || !s || !value) return false;
        const char *c = e->GetStringUTFChars(s, nullptr);
        if (!c) return false;
        bool hit = strcmp(c, value) == 0;
        e->ReleaseStringUTFChars(s, c);
        return hit;
    }

    bool should_install(JNIEnv *e, zygisk::AppSpecializeArgs *args) {
        if (!e || !args) return false;

        const bool is_child_zygote =
            (args->is_child_zygote && *args->is_child_zygote) ||
            jstr_has(e, args->nice_name, "_zygote");
        if (is_child_zygote) {
            LOGI("[duckdetector] skip child zygote process");
            return false;
        }

        if (jstr_eq(e, args->nice_name, "com.eltavine.duckdetector") ||
            jstr_has(e, args->nice_name, "com.eltavine.duckdetector:zygisk_fd_detector")) {
            snprintf(g_app_name, sizeof(g_app_name), "duckdetector");
            return true;
        }

        if (jstr_has(e, args->nice_name, "com.eltavine.duckdetector") ||
            jstr_has(e, args->app_data_dir, "com.eltavine.duckdetector")) {
            LOGI("[duckdetector] skip helper process outside allowlist");
        }
        return false;
    }
};

static void companion_handler(int) {}

REGISTER_ZYGISK_MODULE(DuckVisibilityBypass)
REGISTER_ZYGISK_COMPANION(companion_handler)
