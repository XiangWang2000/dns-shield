#include <jni.h>
#include "hev-main.h"

JNIEXPORT jint JNICALL
Java_io_github_xiangwang2000_dnsshield_service_NativeDnsTcp_run(
    JNIEnv *env, jobject self, jstring config, jint fd) {
    const char *text = (*env)->GetStringUTFChars(env, config, NULL);
    if (!text) return -1;
    jsize length = (*env)->GetStringUTFLength(env, config);
    int result = hev_socks5_tunnel_main_from_str((const unsigned char *)text, length, fd);
    (*env)->ReleaseStringUTFChars(env, config, text);
    return result;
}

JNIEXPORT void JNICALL
Java_io_github_xiangwang2000_dnsshield_service_NativeDnsTcp_stop(
    JNIEnv *env, jobject self) {
    hev_socks5_tunnel_quit();
}
