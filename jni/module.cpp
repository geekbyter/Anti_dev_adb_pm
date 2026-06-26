// anti_dev_pm_zygisk v2.5.7
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

#define MODULE_VERSION "v2.5.7"
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
static pthread_mutex_t g_bridge_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_core_jni_installed = false;
static bool g_retry_started = false;
static bool g_inventory_sdk_spoofed = false;
static int g_real_sdk_before_spoof = -1;
static char g_app_name[128] = "?";

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

struct PropSpoof {
    const char *name;
    const char *value;
};

static const PropSpoof kPropSpoofs[] = {
    // ADB daemon state
    { "init.svc.adbd",               "stopped" },
    { "init.svc.adbd_root",          "stopped" },
    { "service.adb.root",            "0" },
    { "persist.service.adb.enable",  "0" },
    { "persist.adb.tcp.port",        "-1" },
    { "service.adb.tcp.port",        "-1" },
    // Developer settings
    { "persist.sys.development_settings_enabled", "0" },
    { "ro.allow.mock.location",      "0" },
    // Debuggable (commonly checked alongside ADB)
    { "ro.debuggable",               "0" },
    { "ro.secure",                   "1" },
    { "ro.adb.secure",               "1" },
    { nullptr, nullptr },
};

static const char * const kUsbConfigProps[] = {
    "persist.sys.usb.config",
    "sys.usb.config",
    "sys.usb.state",
    nullptr,
};

static bool is_usb_config_prop(const char *name) {
    if (!name || !*name) return false;
    for (const char * const *p = kUsbConfigProps; *p; ++p) {
        if (strcmp(name, *p) == 0) return true;
    }
    return false;
}

static const char *static_spoof_prop(const char *name) {
    if (!name || !*name) return nullptr;
    for (const PropSpoof *p = kPropSpoofs; p->name; ++p) {
        if (strcmp(name, p->name) == 0) return p->value;
    }
    return nullptr;
}

static bool prop_needs_spoof(const char *name) {
    return is_usb_config_prop(name) || static_spoof_prop(name) != nullptr;
}

static int copy_prop(char *dst, const char *val) {
    if (!dst || !val) return 0;
    size_t n = strlen(val);
    if (n >= PROP_VALUE_MAX) n = PROP_VALUE_MAX - 1;
    memcpy(dst, val, n);
    dst[n] = '\0';
    return (int)n;
}

static int read_real_system_property(const char *name, char *value) {
    if (!name || !value) return 0;
    value[0] = '\0';
    using prop_get_fn = int (*)(const char *, char *);
    static prop_get_fn real_get = nullptr;
    if (!real_get) {
        real_get = (prop_get_fn)dlsym(RTLD_DEFAULT, "__system_property_get");
    }
    return real_get ? real_get(name, value) : 0;
}

static bool token_is_adb(const char *s, size_t len) {
    if (len != 3) return false;
    char a = (s[0] >= 'A' && s[0] <= 'Z') ? (char)(s[0] + 32) : s[0];
    char d = (s[1] >= 'A' && s[1] <= 'Z') ? (char)(s[1] + 32) : s[1];
    char b = (s[2] >= 'A' && s[2] <= 'Z') ? (char)(s[2] + 32) : s[2];
    return a == 'a' && d == 'd' && b == 'b';
}

static void sanitize_usb_config_value(const char *real, char *out,
                                      size_t out_max) {
    if (!out || out_max == 0) return;
    out[0] = '\0';
    const char *src = (real && *real) ? real : "mtp";
    size_t pos = 0;
    const char *p = src;
    while (*p) {
        while (*p == ',' || *p == ' ') ++p;
        const char *start = p;
        while (*p && *p != ',') ++p;
        const char *end = p;
        while (end > start && end[-1] == ' ') --end;
        size_t len = (size_t)(end - start);
        if (len && !token_is_adb(start, len)) {
            if (pos && pos + 1 < out_max) out[pos++] = ',';
            for (size_t i = 0; i < len && pos + 1 < out_max; ++i) {
                out[pos++] = start[i];
            }
        }
        if (*p == ',') ++p;
    }
    if (pos == 0) {
        copy_prop(out, "mtp");
    } else {
        out[pos] = '\0';
    }
}

static bool make_spoof_prop_value(const char *name, const char *real_value,
                                  char *out, size_t out_max) {
    if (!name || !out || out_max == 0) return false;
    if (is_usb_config_prop(name)) {
        sanitize_usb_config_value(real_value, out, out_max);
        return true;
    }
    const char *s = static_spoof_prop(name);
    if (!s) return false;
    copy_prop(out, s);
    return true;
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

static bool set_static_int_field_if_at_least(JNIEnv *env, jclass cls,
                                             const char *name, jint floor,
                                             jint spoof_value,
                                             jint *old_value) {
    if (old_value) *old_value = -1;
    if (!env || !cls || !name) return false;

    jfieldID field = env->GetStaticFieldID(cls, name, "I");
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    if (!field) return false;

    jint cur = env->GetStaticIntField(cls, field);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    if (old_value) *old_value = cur;
    if (cur < floor) return false;

    env->SetStaticIntField(cls, field, spoof_value);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    return true;
}

static void install_inventory_sdk_spoof(JNIEnv *env) {
    if (!env) return;
    jclass version = env->FindClass("android/os/Build$VERSION");
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!version) {
        LOGW("[%s] Duck inventory SDK spoof unavailable: Build.VERSION missing",
             g_app_name);
        return;
    }

    jint old_sdk = -1;
    jint old_res_sdk = -1;
    // DuckDetector 的 inventory 判定只在 Android 30+ 启用；这里仅在
    // DuckDetector 进程内降到 29，避免 MIUI/HMA 时序把可见包数量裁成低值。
    bool sdk_changed = set_static_int_field_if_at_least(
        env, version, "SDK_INT", 30, 29, &old_sdk);
    bool res_changed = set_static_int_field_if_at_least(
        env, version, "RESOURCES_SDK_INT", 30, 29, &old_res_sdk);
    env->DeleteLocalRef(version);

    if (old_sdk > 0 && g_real_sdk_before_spoof < 0) {
        g_real_sdk_before_spoof = old_sdk;
    }
    g_inventory_sdk_spoofed = sdk_changed || res_changed;

    if (g_inventory_sdk_spoofed) {
        LOGI("[%s] Duck inventory SDK spoof active: SDK_INT %d->29 RESOURCES_SDK_INT %d->29",
             g_app_name, (int)old_sdk, (int)old_res_sdk);
    } else {
        LOGI("[%s] Duck inventory SDK spoof checked: SDK_INT=%d RESOURCES_SDK_INT=%d",
             g_app_name, (int)old_sdk, (int)old_res_sdk);
    }
}

static int (*o_sys_prop_get)(const char *, char *) = nullptr;
static const prop_info *(*o_sys_prop_find)(const char *) = nullptr;
static int (*o_prop_get)(const char *, char *, const char *) = nullptr;
static int (*o_sys_prop_read)(const prop_info *, char *, char *) = nullptr;
static void (*o_sys_prop_read_callback)(
    const prop_info *,
    void (*)(void *, const char *, const char *, uint32_t),
    void *) = nullptr;

static int h_sys_prop_get(const char *name, char *value) {
    if (!o_sys_prop_get) {
        if (value) value[0] = '\0';
        errno = ENOSYS;
        return 0;
    }
    char real[PROP_VALUE_MAX] = {};
    int rc = o_sys_prop_get(name, real);
    char spoofed[PROP_VALUE_MAX] = {};
    if (make_spoof_prop_value(name, real, spoofed, sizeof(spoofed))) {
        return copy_prop(value, spoofed);
    }
    if (value) copy_prop(value, real);
    return rc;
}

static const prop_info *h_sys_prop_find(const char *name) {
    return o_sys_prop_find ? o_sys_prop_find(name) : nullptr;
}

static int h_prop_get(const char *name, char *value, const char *def) {
    if (!o_prop_get) {
        char spoofed[PROP_VALUE_MAX] = {};
        if (make_spoof_prop_value(name, def, spoofed, sizeof(spoofed))) {
            return copy_prop(value, spoofed);
        }
        if (def) return copy_prop(value, def);
        if (value) value[0] = '\0';
        return 0;
    }
    char real[PROP_VALUE_MAX] = {};
    int rc = o_prop_get(name, real, def);
    char spoofed[PROP_VALUE_MAX] = {};
    if (make_spoof_prop_value(name, real, spoofed, sizeof(spoofed))) {
        return copy_prop(value, spoofed);
    }
    if (value) copy_prop(value, real);
    return rc;
}

static int h_sys_prop_read(const prop_info *pi, char *name, char *value) {
    int rc = o_sys_prop_read ? o_sys_prop_read(pi, name, value) : 0;
    char spoofed[PROP_VALUE_MAX] = {};
    if (make_spoof_prop_value(name, value, spoofed, sizeof(spoofed))) {
        return copy_prop(value, spoofed);
    }
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
    char spoofed[PROP_VALUE_MAX] = {};
    if (make_spoof_prop_value(name, value, spoofed, sizeof(spoofed))) {
        ctx->cb(ctx->cookie, name, spoofed, serial);
    } else {
        ctx->cb(ctx->cookie, name, value, serial);
    }
}

static void h_sys_prop_read_callback(
    const prop_info *pi,
    void (*cb)(void *, const char *, const char *, uint32_t),
    void *cookie) {
    if (!o_sys_prop_read_callback || !cb) return;
    PropReadCbCookie ctx{cb, cookie};
    o_sys_prop_read_callback(pi, prop_read_cb_bridge, &ctx);
}

static jstring (*o_sp_get1)(JNIEnv *, jclass, jstring) = nullptr;
static jstring (*o_sp_get2)(JNIEnv *, jclass, jstring, jstring) = nullptr;
static jint (*o_sp_geti)(JNIEnv *, jclass, jstring, jint) = nullptr;
static jlong (*o_sp_getl)(JNIEnv *, jclass, jstring, jlong) = nullptr;
static jboolean (*o_sp_getb)(JNIEnv *, jclass, jstring, jboolean) = nullptr;
static jint (*o_unix_fork_exec)(
    JNIEnv *, jobject, jbyteArray, jbyteArray, jint, jbyteArray, jint,
    jbyteArray, jintArray, jboolean) = nullptr;
static jint (*o_process_fork_exec)(
    JNIEnv *, jobject, jint, jbyteArray, jbyteArray, jbyteArray, jint,
    jbyteArray, jint, jbyteArray, jintArray, jboolean) = nullptr;

static bool make_java_prop_value(JNIEnv *env, jclass cls, jstring key,
                                 jstring def, char *out, size_t out_max) {
    if (!env || !key || !out || out_max == 0) return false;
    const char *name = env->GetStringUTFChars(key, nullptr);
    if (!name) return false;
    bool needs = prop_needs_spoof(name);
    if (!needs) {
        env->ReleaseStringUTFChars(key, name);
        return false;
    }

    char real[PROP_VALUE_MAX] = {};
    if (is_usb_config_prop(name)) {
        jstring real_j = nullptr;
        if (o_sp_get2) {
            real_j = o_sp_get2(env, cls, key, def);
        } else if (o_sp_get1) {
            real_j = o_sp_get1(env, cls, key);
        }
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            real_j = nullptr;
        }
        if (real_j) {
            const char *rs = env->GetStringUTFChars(real_j, nullptr);
            if (rs) {
                copy_prop(real, rs);
                env->ReleaseStringUTFChars(real_j, rs);
            }
            env->DeleteLocalRef(real_j);
        } else if (def) {
            const char *ds = env->GetStringUTFChars(def, nullptr);
            if (ds) {
                copy_prop(real, ds);
                env->ReleaseStringUTFChars(def, ds);
            }
        }
    }

    bool ok = make_spoof_prop_value(name, real, out, out_max);
    env->ReleaseStringUTFChars(key, name);
    return ok;
}

static jstring h_sp_get1(JNIEnv *env, jclass cls, jstring key) {
    char spoofed[PROP_VALUE_MAX] = {};
    if (make_java_prop_value(env, cls, key, nullptr, spoofed, sizeof(spoofed))) {
        return env->NewStringUTF(spoofed);
    }
    return o_sp_get1 ? o_sp_get1(env, cls, key) : env->NewStringUTF("");
}

static jstring h_sp_get2(JNIEnv *env, jclass cls, jstring key, jstring def) {
    char spoofed[PROP_VALUE_MAX] = {};
    if (make_java_prop_value(env, cls, key, def, spoofed, sizeof(spoofed))) {
        return env->NewStringUTF(spoofed);
    }
    if (o_sp_get2) return o_sp_get2(env, cls, key, def);
    return def ? (jstring)env->NewLocalRef(def) : env->NewStringUTF("");
}

static jint h_sp_geti(JNIEnv *env, jclass cls, jstring key, jint def) {
    (void)cls;
    char spoofed[PROP_VALUE_MAX] = {};
    if (make_java_prop_value(env, cls, key, nullptr, spoofed, sizeof(spoofed))) {
        return (jint)prop_to_long(spoofed, def);
    }
    return o_sp_geti ? o_sp_geti(env, cls, key, def) : def;
}

static jlong h_sp_getl(JNIEnv *env, jclass cls, jstring key, jlong def) {
    (void)cls;
    char spoofed[PROP_VALUE_MAX] = {};
    if (make_java_prop_value(env, cls, key, nullptr, spoofed, sizeof(spoofed))) {
        return (jlong)prop_to_long(spoofed, (long)def);
    }
    return o_sp_getl ? o_sp_getl(env, cls, key, def) : def;
}

static jboolean h_sp_getb(JNIEnv *env, jclass cls, jstring key, jboolean def) {
    (void)cls;
    char spoofed[PROP_VALUE_MAX] = {};
    if (make_java_prop_value(env, cls, key, nullptr, spoofed, sizeof(spoofed))) {
        return prop_to_bool(spoofed, def == JNI_TRUE) ? JNI_TRUE : JNI_FALSE;
    }
    return o_sp_getb ? o_sp_getb(env, cls, key, def) : def;
}

static bool byte_array_mentions_getprop(JNIEnv *env, jbyteArray arr) {
    if (!env || !arr) return false;
    jsize len = env->GetArrayLength(arr);
    if (len <= 0 || len > 4096) return false;
    char buf[4097];
    jsize n = len < 4096 ? len : 4096;
    env->GetByteArrayRegion(arr, 0, n, (jbyte *)buf);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    buf[n] = '\0';
    return strstr(buf, "getprop") != nullptr;
}

static jbyteArray new_bytes(JNIEnv *env, const char *data, size_t len) {
    if (!env || !data) return nullptr;
    jbyteArray arr = env->NewByteArray((jsize)len);
    if (!arr) return nullptr;
    env->SetByteArrayRegion(arr, 0, (jsize)len, (const jbyte *)data);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(arr);
        return nullptr;
    }
    return arr;
}

static jbyteArray new_c_string_bytes(JNIEnv *env, const char *s) {
    return new_bytes(env, s, strlen(s) + 1);
}

static jbyteArray new_sh_arg_block(JNIEnv *env) {
    static const char kArg0[] = "-c";
    static const char kCmd[] =
        "getprop | grep -v -E 'persist\\.sys\\.usb\\.config|sys\\.usb\\.config|"
        "sys\\.usb\\.state|init\\.svc\\.adbd|init\\.svc\\.adbd_root|"
        "service\\.adb\\.root|persist\\.service\\.adb\\.enable|"
        "persist\\.adb\\.tcp\\.port|service\\.adb\\.tcp\\.port|"
        "persist\\.sys\\.development_settings_enabled|ro\\.debuggable|"
        "ro\\.secure|ro\\.adb\\.secure'";
    const size_t len0 = sizeof(kArg0);
    const size_t len1 = sizeof(kCmd);
    char block[sizeof(kArg0) + sizeof(kCmd)];
    memcpy(block, kArg0, len0);
    memcpy(block + len0, kCmd, len1);
    return new_bytes(env, block, len0 + len1);
}

static jint h_unix_fork_exec(JNIEnv *env, jobject thiz, jbyteArray prog,
                             jbyteArray arg_block, jint argc,
                             jbyteArray env_block, jint envc,
                             jbyteArray dir, jintArray fds,
                             jboolean redirect_error_stream) {
    if (o_unix_fork_exec && byte_array_mentions_getprop(env, prog)) {
        jbyteArray sh = new_c_string_bytes(env, "/system/bin/sh");
        jbyteArray args = new_sh_arg_block(env);
        if (sh && args) {
            LOGD("[%s] redirected UNIXProcess getprop", g_app_name);
            jint rc = o_unix_fork_exec(env, thiz, sh, args, 2, env_block, envc,
                                       dir, fds, redirect_error_stream);
            env->DeleteLocalRef(sh);
            env->DeleteLocalRef(args);
            return rc;
        }
        if (sh) env->DeleteLocalRef(sh);
        if (args) env->DeleteLocalRef(args);
    }
    return o_unix_fork_exec ?
        o_unix_fork_exec(env, thiz, prog, arg_block, argc, env_block, envc,
                         dir, fds, redirect_error_stream) :
        -1;
}

static jint h_process_fork_exec(JNIEnv *env, jobject thiz, jint mode,
                                jbyteArray helper, jbyteArray prog,
                                jbyteArray arg_block, jint argc,
                                jbyteArray env_block, jint envc,
                                jbyteArray dir, jintArray fds,
                                jboolean redirect_error_stream) {
    if (o_process_fork_exec && byte_array_mentions_getprop(env, prog)) {
        jbyteArray sh = new_c_string_bytes(env, "/system/bin/sh");
        jbyteArray args = new_sh_arg_block(env);
        if (sh && args) {
            LOGD("[%s] redirected ProcessImpl getprop", g_app_name);
            jint rc = o_process_fork_exec(env, thiz, mode, helper, sh, args, 2,
                                          env_block, envc, dir, fds,
                                          redirect_error_stream);
            env->DeleteLocalRef(sh);
            env->DeleteLocalRef(args);
            return rc;
        }
        if (sh) env->DeleteLocalRef(sh);
        if (args) env->DeleteLocalRef(args);
    }
    return o_process_fork_exec ?
        o_process_fork_exec(env, thiz, mode, helper, prog, arg_block, argc,
                            env_block, envc, dir, fds, redirect_error_stream) :
        -1;
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
    bool direct_request_rewritten = false;
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
        if (direct_hidden_pkg) {
            unsigned char *copy = (unsigned char *)malloc((size_t)data_len);
            if (copy) {
                memcpy(copy, data_bytes, (size_t)data_len);
                if (sanitize_parcel_bytes(copy, (size_t)data_len, false)) {
                    direct_request_rewritten =
                        write_bytes_to_parcel(env, data, copy, data_len);
                    if (direct_request_rewritten) {
                        LOGD("[%s] rewrote direct PM request code=%d",
                             g_app_name, (int)code);
                    }
                }
                free(copy);
            }
        }
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
            if (direct_hidden_pkg && !direct_request_rewritten) {
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

static void append_text(char *out, size_t out_max, size_t *pos,
                        const char *text) {
    if (!out || !pos || !text || *pos >= out_max) return;
    size_t remaining = out_max - *pos;
    int n = snprintf(out + *pos, remaining, "%s", text);
    if (n > 0) {
        size_t used = (size_t)n;
        *pos += used < remaining ? used : remaining - 1;
    }
}

static void append_prop_line(JNIEnv *env, jobjectArray keys, jsize i,
                             char *out, size_t out_max, size_t *pos) {
    jstring key = (jstring)env->GetObjectArrayElement(keys, i);
    if (!key) return;
    const char *name = env->GetStringUTFChars(key, nullptr);
    if (!name) {
        env->DeleteLocalRef(key);
        return;
    }
    char real[PROP_VALUE_MAX] = {};
    char value[PROP_VALUE_MAX] = {};
    (void)read_real_system_property(name, real);
    if (!make_spoof_prop_value(name, real, value, sizeof(value))) {
        copy_prop(value, real);
    }

    char line[PROP_NAME_MAX + PROP_VALUE_MAX + 16];
    snprintf(line, sizeof(line), "PROP=%s|%s\n", name, value);
    append_text(out, out_max, pos, line);
    env->ReleaseStringUTFChars(key, name);
    env->DeleteLocalRef(key);
}

static jstring h_duck_props_snapshot(JNIEnv *env, jobject thiz,
                                     jobjectArray keys) {
    (void)thiz;
    char out[8192];
    size_t pos = 0;
    out[0] = '\0';
    append_text(out, sizeof(out), &pos,
        "AVAILABLE=1\n"
        "PROP_AREA_AVAILABLE=1\n"
        "PROP_AREA_CONTEXTS=0\n"
        "PROP_AREA_HOLES=0\n"
        "RO_HANDLE_AVAILABLE=1\n"
        "RO_HANDLE_CHECKED=1\n");
    if (env && keys) {
        jsize count = env->GetArrayLength(keys);
        for (jsize i = 0; i < count && pos + 64 < sizeof(out); ++i) {
            append_prop_line(env, keys, i, out, sizeof(out), &pos);
        }
    }
    return env->NewStringUTF(out);
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

static bool g_bridge_props = false;
static bool g_bridge_pif = false;
static bool g_bridge_dangerous = false;
static bool g_bridge_memory = false;
static bool g_bridge_lsposed = false;
static bool g_bridge_zygisk = false;
static bool g_bridge_su = false;
static bool g_bridge_cgroup = false;
static bool g_bridge_native_root = false;

static jclass load_app_class(JNIEnv *env, const char *dot_name) {
    if (!env || !dot_name) return nullptr;
    jclass at_cls = env->FindClass("android/app/ActivityThread");
    if (!at_cls) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return nullptr;
    }
    jmethodID current_app = env->GetStaticMethodID(
        at_cls, "currentApplication", "()Landroid/app/Application;");
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!current_app) {
        env->DeleteLocalRef(at_cls);
        return nullptr;
    }
    jobject app = env->CallStaticObjectMethod(at_cls, current_app);
    env->DeleteLocalRef(at_cls);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!app) return nullptr;

    jclass app_cls = env->GetObjectClass(app);
    jmethodID get_loader = app_cls ?
        env->GetMethodID(app_cls, "getClassLoader", "()Ljava/lang/ClassLoader;") :
        nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    jobject loader = get_loader ? env->CallObjectMethod(app, get_loader) : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (app_cls) env->DeleteLocalRef(app_cls);
    env->DeleteLocalRef(app);
    if (!loader) return nullptr;

    jclass loader_cls = env->FindClass("java/lang/ClassLoader");
    if (!loader_cls) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(loader);
        return nullptr;
    }
    jmethodID load_class = env->GetMethodID(
        loader_cls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(loader_cls);
    if (!load_class) {
        env->DeleteLocalRef(loader);
        return nullptr;
    }

    jstring name = env->NewStringUTF(dot_name);
    jobject clazz = name ? env->CallObjectMethod(loader, load_class, name) : nullptr;
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        clazz = nullptr;
    }
    if (name) env->DeleteLocalRef(name);
    env->DeleteLocalRef(loader);
    return (jclass)clazz;
}

static bool register_app_native_method(JNIEnv *env, const char *dot_name,
                                       const char *method_name,
                                       const char *signature, void *hook) {
    if (!env || !dot_name || !method_name || !signature || !hook) {
        return false;
    }
    jclass cls = load_app_class(env, dot_name);
    if (!cls) return false;
    JNINativeMethod method = { method_name, signature, hook };
    bool ok = env->RegisterNatives(cls, &method, 1) == JNI_OK;
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        ok = false;
    }
    env->DeleteLocalRef(cls);
    return ok;
}

static bool hook_bridge_method(JNIEnv *env, const char *dot_name,
                               const char *jadx_dot_name,
                               const char *method_name,
                               const char *signature, void *hook) {
    if (register_app_native_method(env, dot_name, method_name, signature, hook)) {
        return true;
    }
    return jadx_dot_name &&
           register_app_native_method(env, jadx_dot_name, method_name,
                                      signature, hook);
}

static int install_duck_bridge_hooks(JNIEnv *env) {
    if (!g_api || !env) return 0;
    pthread_mutex_lock(&g_bridge_lock);
    int newly = 0;

    if (!g_bridge_props &&
        hook_bridge_method(env,
            "com.eltavine.duckdetector.features.systemproperties.data.native.SystemPropertiesNativeBridge",
            "com.eltavine.duckdetector.features.systemproperties.data.p013native.SystemPropertiesNativeBridge",
            "nativeCollectSnapshot", "([Ljava/lang/String;)Ljava/lang/String;",
            (void *)h_duck_props_snapshot)) {
        g_bridge_props = true;
        ++newly;
    }

    if (!g_bridge_pif &&
        hook_bridge_method(env,
            "com.eltavine.duckdetector.features.playintegrityfix.data.native.PlayIntegrityFixNativeBridge",
            "com.eltavine.duckdetector.features.playintegrityfix.data.p010native.PlayIntegrityFixNativeBridge",
            "nativeCollectSnapshot", "([Ljava/lang/String;)Ljava/lang/String;",
            (void *)h_duck_pif_snapshot)) {
        g_bridge_pif = true;
        ++newly;
    }

    if (!g_bridge_dangerous &&
        hook_bridge_method(env,
            "com.eltavine.duckdetector.features.dangerousapps.data.native.DangerousAppsNativeBridge",
            "com.eltavine.duckdetector.features.dangerousapps.data.p004native.DangerousAppsNativeBridge",
            "nativeStatPackages", "([Ljava/lang/String;)Ljava/lang/String;",
            (void *)h_duck_dangerous_stat)) {
        g_bridge_dangerous = true;
        ++newly;
    }

    if (!g_bridge_memory &&
        hook_bridge_method(env,
            "com.eltavine.duckdetector.features.memory.data.native.MemoryNativeBridge",
            "com.eltavine.duckdetector.features.memory.data.p007native.MemoryNativeBridge",
            "nativeCollectSnapshot", "()Ljava/lang/String;",
            (void *)h_duck_memory_snapshot)) {
        g_bridge_memory = true;
        ++newly;
    }

    if (!g_bridge_lsposed &&
        hook_bridge_method(env,
            "com.eltavine.duckdetector.features.lsposed.data.native.LSPosedNativeBridge",
            "com.eltavine.duckdetector.features.lsposed.data.p006native.LSPosedNativeBridge",
            "nativeCollectSnapshot", "()Ljava/lang/String;",
            (void *)h_duck_lsposed_snapshot)) {
        g_bridge_lsposed = true;
        ++newly;
    }

    if (!g_bridge_zygisk &&
        hook_bridge_method(env,
            "com.eltavine.duckdetector.features.zygisk.data.native.ZygiskNativeBridge",
            "com.eltavine.duckdetector.features.zygisk.data.p016native.ZygiskNativeBridge",
            "nativeCollectSnapshot", "()Ljava/lang/String;",
            (void *)h_duck_zygisk_snapshot)) {
        g_bridge_zygisk = true;
        ++newly;
    }

    if (!g_bridge_su &&
        hook_bridge_method(env,
            "com.eltavine.duckdetector.features.su.data.native.SuNativeBridge",
            "com.eltavine.duckdetector.features.p002su.data.p012native.SuNativeBridge",
            "nativeCollectSnapshot", "()Ljava/lang/String;",
            (void *)h_duck_su_snapshot)) {
        g_bridge_su = true;
        ++newly;
    }

    if (!g_bridge_cgroup &&
        hook_bridge_method(env,
            "com.eltavine.duckdetector.features.nativeroot.data.native.CgroupProcessLeakNativeBridge",
            "com.eltavine.duckdetector.features.nativeroot.data.p009native.CgroupProcessLeakNativeBridge",
            "nativeCollectSnapshot", "()Ljava/lang/String;",
            (void *)h_duck_cgroup_snapshot)) {
        g_bridge_cgroup = true;
        ++newly;
    }

    if (!g_bridge_native_root &&
        hook_bridge_method(env,
            "com.eltavine.duckdetector.features.nativeroot.data.native.NativeRootNativeBridge",
            "com.eltavine.duckdetector.features.nativeroot.data.p009native.NativeRootNativeBridge",
            "nativeCollectSnapshot", "(Z)Ljava/lang/String;",
            (void *)h_duck_native_root_snapshot)) {
        g_bridge_native_root = true;
        ++newly;
    }

    const int total = (g_bridge_props ? 1 : 0) + (g_bridge_pif ? 1 : 0) +
        (g_bridge_dangerous ? 1 : 0) + (g_bridge_memory ? 1 : 0) +
        (g_bridge_lsposed ? 1 : 0) + (g_bridge_zygisk ? 1 : 0) +
        (g_bridge_su ? 1 : 0) + (g_bridge_cgroup ? 1 : 0) +
        (g_bridge_native_root ? 1 : 0);
    if (newly > 0 || total < 9) {
        LOGI("[%s] Duck native bridge hooks ready=%d/9 newly=%d",
             g_app_name, total, newly);
    }
    pthread_mutex_unlock(&g_bridge_lock);
    return total;
}

static int __attribute__((unused)) register_plt_hooks();
static void install_jni_hooks(JNIEnv *env);
static void install_jni_hooks_from_vm();


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

static int __attribute__((unused)) register_plt_hooks() {
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
    if (g_core_jni_installed) {
        pthread_mutex_unlock(&g_jni_lock);
        (void)install_duck_bridge_hooks(env);
        return;
    }

    install_inventory_sdk_spoof(env);

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

    JNINativeMethod unix_process[] = {
        { "forkAndExec", "([B[BI[BI[B[IZ)I", (void *)h_unix_fork_exec },
    };
    g_api->hookJniNativeMethods(env, "java/lang/UNIXProcess", unix_process, 1);
    if (unix_process[0].fnPtr != (void *)h_unix_fork_exec) {
        o_unix_fork_exec = (jint (*)(JNIEnv *, jobject, jbyteArray, jbyteArray,
                                     jint, jbyteArray, jint, jbyteArray,
                                     jintArray, jboolean))unix_process[0].fnPtr;
        LOGI("[%s] UNIXProcess.forkAndExec hook installed", g_app_name);
    } else if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }

    JNINativeMethod process_impl[] = {
        { "forkAndExec", "(I[B[B[BI[BI[B[IZ)I", (void *)h_process_fork_exec },
    };
    g_api->hookJniNativeMethods(env, "java/lang/ProcessImpl", process_impl, 1);
    if (process_impl[0].fnPtr != (void *)h_process_fork_exec) {
        o_process_fork_exec = (jint (*)(JNIEnv *, jobject, jint, jbyteArray,
                                        jbyteArray, jbyteArray, jint,
                                        jbyteArray, jint, jbyteArray,
                                        jintArray, jboolean))process_impl[0].fnPtr;
        LOGI("[%s] ProcessImpl.forkAndExec hook installed", g_app_name);
    } else if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }

    g_core_jni_installed = true;
    pthread_mutex_unlock(&g_jni_lock);
    (void)install_duck_bridge_hooks(env);
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
    const unsigned int delays_ms[] = {
        0, 40, 60, 100, 160, 240, 360, 520, 760, 1100, 1600, 2400, 3600, 5400
    };
    for (unsigned int d : delays_ms) {
        if (d) usleep(d * 1000);
        install_jni_hooks_from_vm();
        LOGD("[%s] delayed JNI bridge pass done", g_app_name);
    }
    return nullptr;
}

static void start_delayed_jni_hooks() {
    if (g_retry_started) return;
    g_retry_started = true;
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
        int sdk = g_real_sdk_before_spoof > 0 ?
            g_real_sdk_before_spoof : get_runtime_sdk(env);
        start_delayed_jni_hooks();
        LOGI("[%s] broad native PLT hooks disabled on sdk=%d", g_app_name, sdk);
        LOGI("[%s] %s active", g_app_name, MODULE_VERSION);
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
