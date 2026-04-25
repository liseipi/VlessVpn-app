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
// 根本原因（精确定位）：
//
// badvpn tun2socks_start() 内部有多个全局状态变量（均为 static int）：
//   - blog_initialized    (BLog.c)
//   - bsignal_initialized (BSignal.c)
//   - quitting            (tun2socks.c)
//   以及 BReactor 实例 ss（可能是静态局部变量）
//
// 正常退出时，tun2socks_start() 会按 fail-chain 顺序清理这些状态。
// 但当 tun2socks_terminate() 被外部调用时，退出路径可能因为
// 各子系统的清理竞态，导致某个全局变量没有被正确归零。
//
// 症状：第三次 tun2socks_start() 调用后完全静默退出，连 stdout 第一行都没有。
// 原因：blog_initialized 仍为 1，BLog_InitStdout() 内部触发 ASSERT 或
//       在 NDEBUG 模式下直接 return，导致后续的所有输出通道未建立就退出。
//
// 修复：用 dlsym 找到所有已知全局状态变量，在每次 start 前强制重置。
//       这是比 fork() 更简洁且 Android 兼容的方案。
// ══════════════════════════════════════════════════════════════════════════════

static void reset_badvpn_globals() {
    struct { const char *name; const char *desc; } symbols[] = {
            {"tun2socks_should_terminate", "tun2socks_should_terminate"},
            {"quitting",                   "quitting"},
            {"blog_initialized",           "blog_initialized"},
            {"bsignal_initialized",        "bsignal_initialized"},
    };

    for (auto &s : symbols) {
        void *sym = dlsym(RTLD_DEFAULT, s.name);
        if (sym) {
            int old_val = *reinterpret_cast<int*>(sym);
            *reinterpret_cast<int*>(sym) = 0;
            __android_log_print(ANDROID_LOG_INFO, TAG,
                                "reset %s: %d -> 0", s.desc, old_val);
        }
    }

    // bsignal 持有一个 signalfd，重置前需要先关闭它
    // bsignal 全局结构：{ int initialized; int sigfd; BReactor* reactor; ... }
    // 我们通过查找 bsignal_fd 或 bsignal_sigfd 符号来获取它
    const char *sigfd_names[] = {
            "bsignal_sigfd", "bsignal_fd", "signal_fd", nullptr
    };
    for (int i = 0; sigfd_names[i]; i++) {
        void *sym = dlsym(RTLD_DEFAULT, sigfd_names[i]);
        if (sym) {
            int fd = *reinterpret_cast<int*>(sym);
            if (fd > 2) {  // 排除 stdin/stdout/stderr
                close(fd);
                *reinterpret_cast<int*>(sym) = -1;
                __android_log_print(ANDROID_LOG_INFO, TAG,
                                    "closed and reset %s (fd=%d)", sigfd_names[i], fd);
            }
            break;
        }
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
    // 每次启动前重置所有 badvpn 全局状态
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
    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "tun2socks_start() returned %d", result);

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