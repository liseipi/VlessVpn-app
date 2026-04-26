#include <jni.h>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <unistd.h>
#include <dlfcn.h>
#include <android/log.h>
#include <tun2socks/tun2socks.h>

static const char *TAG = "tun2socks";

// ══════════════════════════════════════════════════════════════════════════════
// 修复方案说明：
//
// 问题：badvpn 内部有多个 static 全局变量，tun2socks_start() 退出后无法重置：
//   - blog_initialized    (base/BLog.c)
//   - bsignal_initialized (system/BSignal.c)
//   - bsignal_sigfd       (system/BSignal.c)
//   - quitting            (tun2socks/tun2socks.c) ← 已是全局，可被 dlsym 找到
//
// badvpn 源码修改（必须重新编译 .a 文件）：
//   base/BLog.c:    static int blog_initialized = 0;
//                → int blog_initialized = 0;
//   system/BSignal.c: static int bsignal_initialized = 0;
//                   → int bsignal_initialized = 0;
//                     static int bsignal_sigfd = -1;
//                   → int bsignal_sigfd = -1;
//
// 修改后重新编译 libtun2socks.a，这些符号就会被导出，dlsym 可以找到它们。
// ══════════════════════════════════════════════════════════════════════════════

static void reset_badvpn_globals() {
    // 按 tun2socks_start() 的初始化顺序逆序重置，确保安全

    // 1. 重置 quitting（tun2socks.c，通常已经是全局导出）
    const char *quit_names[] = {"tun2socks_should_terminate", "quitting", nullptr};
    for (int i = 0; quit_names[i]; i++) {
        void *sym = dlsym(RTLD_DEFAULT, quit_names[i]);
        if (sym) {
            int old = *reinterpret_cast<int*>(sym);
            *reinterpret_cast<int*>(sym) = 0;
            __android_log_print(ANDROID_LOG_INFO, TAG, "reset %s: %d -> 0", quit_names[i], old);
            break;
        }
    }

    // 2. 关闭并重置 bsignal_sigfd（避免 fd 泄漏）
    const char *sigfd_names[] = {"bsignal_sigfd", "bsignal_fd", nullptr};
    for (int i = 0; sigfd_names[i]; i++) {
        void *sym = dlsym(RTLD_DEFAULT, sigfd_names[i]);
        if (sym) {
            int fd = *reinterpret_cast<int*>(sym);
            if (fd > 2) {
                close(fd);
                __android_log_print(ANDROID_LOG_INFO, TAG,
                                    "closed %s fd=%d", sigfd_names[i], fd);
            }
            *reinterpret_cast<int*>(sym) = -1;
            break;
        }
    }

    // 3. 重置 bsignal_initialized
    void *sym = dlsym(RTLD_DEFAULT, "bsignal_initialized");
    if (sym) {
        int old = *reinterpret_cast<int*>(sym);
        *reinterpret_cast<int*>(sym) = 0;
        __android_log_print(ANDROID_LOG_INFO, TAG, "reset bsignal_initialized: %d -> 0", old);
    } else {
        __android_log_write(ANDROID_LOG_WARN, TAG,
                            "bsignal_initialized NOT FOUND via dlsym. "
                            "Recompile badvpn: remove 'static' from bsignal_initialized in BSignal.c");
    }

    // 4. 重置 blog_initialized（最重要！这是导致静默退出的根本原因）
    sym = dlsym(RTLD_DEFAULT, "blog_initialized");
    if (sym) {
        int old = *reinterpret_cast<int*>(sym);
        *reinterpret_cast<int*>(sym) = 0;
        __android_log_print(ANDROID_LOG_INFO, TAG, "reset blog_initialized: %d -> 0", old);
    } else {
        __android_log_write(ANDROID_LOG_WARN, TAG,
                            "blog_initialized NOT FOUND via dlsym. "
                            "Recompile badvpn: remove 'static' from blog_initialized in BLog.c");
    }
}

// ── stdout/stderr → logcat ────────────────────────────────────────────────

static int pipe_stdout[2] = {-1, -1};
static int pipe_stderr[2] = {-1, -1};
static volatile int redirect_initialized = 0;

static void *thread_stdout_func(void *) {
    char buf[2048]; ssize_t n;
    while ((n = read(pipe_stdout[0], buf, sizeof buf - 1)) > 0) {
        if (n > 0 && buf[n-1] == '\n') --n;
        buf[n] = 0;
        if (n > 0) __android_log_write(ANDROID_LOG_INFO, TAG, buf);
    }
    return nullptr;
}

static void *thread_stderr_func(void *) {
    char buf[2048]; ssize_t n;
    while ((n = read(pipe_stderr[0], buf, sizeof buf - 1)) > 0) {
        if (n > 0 && buf[n-1] == '\n') --n;
        buf[n] = 0;
        if (n > 0) __android_log_write(ANDROID_LOG_ERROR, TAG, buf);
    }
    return nullptr;
}

static void start_redirecting() {
    if (!__sync_bool_compare_and_swap(&redirect_initialized, 0, 1)) return;
    setvbuf(stdout, nullptr, _IONBF, 0);
    pipe(pipe_stdout); dup2(pipe_stdout[1], STDOUT_FILENO);
    setvbuf(stderr, nullptr, _IONBF, 0);
    pipe(pipe_stderr); dup2(pipe_stderr[1], STDERR_FILENO);
    pthread_t t;
    pthread_create(&t, nullptr, thread_stdout_func, nullptr); pthread_detach(t);
    pthread_create(&t, nullptr, thread_stderr_func, nullptr); pthread_detach(t);
}

// ── JNI ──────────────────────────────────────────────────────────────────

extern "C"
JNIEXPORT jint JNICALL
Java_com_musicses_vlessvpn_Tun2Socks_start_1tun2socks(JNIEnv *env, jclass clazz,
                                                      jobjectArray args) {
    reset_badvpn_globals();

    jsize argument_count = env->GetArrayLength(args);
    char **argv = (char **) calloc(argument_count + 1, sizeof(char *));
    if (!argv) { __android_log_write(ANDROID_LOG_ERROR, TAG, "OOM"); return -1; }

    for (jsize i = 0; i < argument_count; i++) {
        jstring jstr = (jstring) env->GetObjectArrayElement(args, i);
        const char *cstr = env->GetStringUTFChars(jstr, nullptr);
        argv[i] = strdup(cstr);
        env->ReleaseStringUTFChars(jstr, cstr);
    }
    argv[argument_count] = nullptr;

    start_redirecting();

    __android_log_write(ANDROID_LOG_INFO, TAG, "calling tun2socks_start()");
    int result = tun2socks_start((int) argument_count, argv);
    __android_log_print(ANDROID_LOG_INFO, TAG, "tun2socks_start() returned %d", result);

    for (jsize i = 0; i < argument_count; i++) free(argv[i]);
    free(argv);
    return jint(result);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_musicses_vlessvpn_Tun2Socks_stopTun2Socks(JNIEnv *env, jclass clazz) {
    __android_log_write(ANDROID_LOG_INFO, TAG, "calling tun2socks_terminate()");
    tun2socks_terminate();
}

extern "C"
JNIEXPORT void JNICALL
Java_com_musicses_vlessvpn_Tun2Socks_printTun2SocksHelp(JNIEnv *env, jclass clazz) {
    tun2socks_print_help("badvpn-tun2socks");
}

extern "C"
JNIEXPORT void JNICALL
Java_com_musicses_vlessvpn_Tun2Socks_printTun2SocksVersion(JNIEnv *env, jclass clazz) {
    tun2socks_print_version();
}