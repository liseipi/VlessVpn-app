#include <jni.h>
#include <string>
#include <cstdlib>
#include <pthread.h>
#include <unistd.h>
#include <android/log.h>
#include <tun2socks/tun2socks.h>

// Start threads to redirect stdout and stderr to logcat.
int pipe_stdout[2];
int pipe_stderr[2];
pthread_t thread_stdout;
pthread_t thread_stderr;
const char *ADBTAG = "tun2socks";

void *thread_stderr_func(void *) {
    ssize_t redirect_size;
    char buf[2048];
    while ((redirect_size = read(pipe_stderr[0], buf, sizeof buf - 1)) > 0) {
        if (buf[redirect_size - 1] == '\n') {
            --redirect_size;
        }
        buf[redirect_size] = 0;
        __android_log_write(ANDROID_LOG_ERROR, ADBTAG, buf);
    }
    return nullptr;
}

void *thread_stdout_func(void *) {
    ssize_t redirect_size;
    char buf[2048];
    while ((redirect_size = read(pipe_stdout[0], buf, sizeof buf - 1)) > 0) {
        if (buf[redirect_size - 1] == '\n') {
            --redirect_size;
        }
        buf[redirect_size] = 0;
        __android_log_write(ANDROID_LOG_INFO, ADBTAG, buf);
    }
    return nullptr;
}

// ★ 修复：只初始化一次，避免每次 start_tun2socks 重复 dup2 和创建线程导致 fd 泄漏
static volatile int redirect_initialized = 0;

int start_redirecting_stdout_stderr() {
    if (__sync_bool_compare_and_swap(&redirect_initialized, 0, 1)) {
        setvbuf(stdout, nullptr, _IONBF, 0);
        pipe(pipe_stdout);
        dup2(pipe_stdout[1], STDOUT_FILENO);

        setvbuf(stderr, nullptr, _IONBF, 0);
        pipe(pipe_stderr);
        dup2(pipe_stderr[1], STDERR_FILENO);

        if (pthread_create(&thread_stdout, nullptr, thread_stdout_func, nullptr) == -1) {
            return -1;
        }
        pthread_detach(thread_stdout);

        if (pthread_create(&thread_stderr, nullptr, thread_stderr_func, nullptr) == -1) {
            return -1;
        }
        pthread_detach(thread_stderr);
    }
    return 0;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_musicses_vlessvpn_Tun2Socks_start_1tun2socks(JNIEnv *env, jclass clazz,
                                                      jobjectArray args) {
    jsize argument_count = env->GetArrayLength(args);

    // 动态分配 argv 数组，避免 VLA
    char **argv = (char **) calloc(argument_count + 1, sizeof(char *));
    if (argv == nullptr) {
        __android_log_write(ANDROID_LOG_ERROR, ADBTAG, "Failed to allocate argv");
        return -1;
    }

    // 分配并复制每个参数
    for (jsize i = 0; i < argument_count; i++) {
        jstring jstr = (jstring) env->GetObjectArrayElement(args, i);
        const char *cstr = env->GetStringUTFChars(jstr, nullptr);
        argv[i] = strdup(cstr);                    // 使用 strdup 复制字符串
        env->ReleaseStringUTFChars(jstr, cstr);
    }
    argv[argument_count] = nullptr;  // argv 必须以 nullptr 结尾

    // 重定向 stdout/stderr 到 logcat
    if (start_redirecting_stdout_stderr() == -1) {
        __android_log_write(ANDROID_LOG_ERROR, ADBTAG,
                            "Couldn't start redirecting stdout and stderr to logcat.");
    }

    // 调用 tun2socks
    int result = tun2socks_start((int)argument_count, argv);

    // 清理内存
    for (jsize i = 0; i < argument_count; i++) {
        free(argv[i]);
    }
    free(argv);

    return jint(result);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_musicses_vlessvpn_Tun2Socks_stopTun2Socks(JNIEnv *env, jclass clazz) {
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