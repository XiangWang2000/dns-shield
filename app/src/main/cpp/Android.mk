DNS_SHIELD_PATH := $(call my-dir)
include $(DNS_SHIELD_PATH)/../../../build/generated/hev/Android.mk
LOCAL_PATH := $(DNS_SHIELD_PATH)
include $(CLEAR_VARS)
LOCAL_MODULE := dns-shield-tcp
LOCAL_SRC_FILES := dns-shield-tcp.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/hev/src
LOCAL_SHARED_LIBRARIES := hev-socks5-tunnel
LOCAL_LDFLAGS := -Wl,-z,max-page-size=16384
include $(BUILD_SHARED_LIBRARY)
