LOCAL_PATH := $(call my-dir)

KERNELFLINGER_SSLSUPPORT_PATH := $(LOCAL_PATH)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := wrapper.c
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
FIRST_BUILD_ID := $(shell echo $(BUILD_ID) | cut -c 1)
#ifeq ($(FIRST_BUILD_ID),O)
LOCAL_CFLAGS := -I $(LOCAL_PATH)/../include/libkernelflinger
LOCAL_STATIC_LIBRARIES := libgnuefi libefi
#libkernelflinger-$(TARGET_BUILD_VARIANT) #cause dependency cycle error in Android O
#else
#LOCAL_STATIC_LIBRARIES := libgnuefi libefi libkernelflinger-$(TARGET_BUILD_VARIANT)
#endif
LOCAL_MODULE := libsslsupport
LOCAL_CFLAGS += -Wno-error
include $(BUILD_EFI_STATIC_LIBRARY)

ifeq ($(KERNELFLINGER_SSL_LIBRARY),)
    KERNELFLINGER_SSL_LIBRARY := boringssl
endif

ifneq (,$(filter boringssl, $(KERNELFLINGER_SSL_LIBRARY)))
    KERNELFLINGER_SSL_LIBRARY_PATH := external/boringssl
endif

ifneq (,$(filter openssl, $(KERNELFLINGER_SSL_LIBRARY)))
    KERNELFLINGER_SSL_LIBRARY_PATH := $(INTEL_PATH_VENDOR)/external/openssl
endif

include $(CLEAR_VARS)
LOCAL_PATH := $(KERNELFLINGER_SSL_LIBRARY_PATH)

ifneq (,$(filter openssl, $(KERNELFLINGER_SSL_LIBRARY)))
include $(LOCAL_PATH)/build-config-64.mk
include $(LOCAL_PATH)/build-config-32.mk
endif

ifeq ($(TARGET_UEFI_ARCH),x86_64)
LOCAL_ARCH := x86_64
LOCAL_2ND_ARCH := 64
else
LOCAL_ARCH := x86
LOCAL_2ND_ARCH := 32
endif

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libuefi_crypto_static
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/android-config.mk $(LOCAL_PATH)/Crypto.mk
ifneq (,$(filter openssl, $(KERNELFLINGER_SSL_LIBRARY)))
include $(LOCAL_PATH)/Crypto-config-target.mk
include $(LOCAL_PATH)/android-config.mk
# Replace cflags with static-specific cflags so we dont build in libdl deps
LOCAL_CFLAGS_32 := $(openssl_cflags_static_32)
LOCAL_CFLAGS_64 := $(openssl_cflags_static_64)
endif
ifneq (,$(filter boringssl, $(KERNELFLINGER_SSL_LIBRARY)))
include $(LOCAL_PATH)/crypto-sources.mk
endif
LOCAL_SRC_FILES := $(LOCAL_SRC_FILES_$(LOCAL_ARCH))
LOCAL_CFLAGS += $(LOCAL_CFLAGS_$(LOCAL_ARCH)) $(LOCAL_CFLAGS_$(LOCAL_2ND_ARCH)) $(openssl_cflags_static_$(LOCAL_2ND_ARCH)) -Wno-error
LOCAL_SRC_FILES_x86 :=
LOCAL_SRC_FILES_x86_64 :=
LOCAL_CFLAGS_32 :=
LOCAL_CFLAGS_64 :=
LOCAL_CFLAGS_x86 :=
LOCAL_CFLAGS_x86_64 :=

LOCAL_CFLAGS += -D__ANDROID_API__=21
LOCAL_CFLAGS += -Ibionic/libc/include
LOCAL_CFLAGS += -Ibionic/libc/kernel/uapi
LOCAL_CFLAGS += -Ibionic/libc/kernel/uapi/asm-x86
LOCAL_CFLAGS += -Ibionic/libc/kernel/android/uapi
LOCAL_CFLAGS += -D_LIBCPP_BUILDING_LIBRARY
LOCAL_CFLAGS += -DOPENSSL_NO_THREADS

LOCAL_ASFLAGS += -Werror=format-security -Wa,--noexecstack
include $(BUILD_EFI_STATIC_LIBRARY)

#######################################
# target static library
include $(CLEAR_VARS)
LOCAL_PATH := $(KERNELFLINGER_SSL_LIBRARY_PATH)

ifneq (,$(filter openssl, $(KERNELFLINGER_SSL_LIBRARY)))
include $(LOCAL_PATH)/build-config-64.mk
include $(LOCAL_PATH)/build-config-32.mk
endif

ifeq ($(TARGET_UEFI_ARCH),x86_64)
LOCAL_ARCH := x86_64
LOCAL_2ND_ARCH := 64
else
LOCAL_ARCH := x86
LOCAL_2ND_ARCH := 32
endif

ifneq (,$(filter openssl, $(KERNELFLINGER_SSL_LIBRARY)))
LOCAL_SRC_FILES += $(target_src_files)
LOCAL_CFLAGS += $(target_c_flags)
LOCAL_C_INCLUDES += $(target_c_includes)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/android-config.mk $(LOCAL_PATH)/Ssl.mk
include $(LOCAL_PATH)/Ssl-config-target.mk
include $(LOCAL_PATH)/android-config.mk
LOCAL_SRC_FILES := $(LOCAL_SRC_FILES_$(LOCAL_ARCH))
endif
ifneq (,$(filter boringssl, $(KERNELFLINGER_SSL_LIBRARY)))
include $(LOCAL_PATH)/sources.mk
LOCAL_SRC_FILES := $(crypto_sources) $(linux_$(LOCAL_ARCH)_sources)
#ifeq ($(FIRST_BUILD_ID),O)
LOCAL_C_INCLUDES += $(KERNELFLINGER_SSLSUPPORT_PATH)/borningssl
LOCAL_CFLAGS += -I$(KERNELFLINGER_SSLSUPPORT_PATH)/borningssl
LOCAL_CFLAGS += -Wno-error
#endif
endif
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libuefi_ssl_static
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_CFLAGS += $(LOCAL_CFLAGS_$(LOCAL_ARCH)) $(LOCAL_CFLAGS_$(LOCAL_2ND_ARCH)) $(openssl_cflags_static_$(LOCAL_2ND_ARCH))
LOCAL_SRC_FILES_x86 :=
LOCAL_SRC_FILES_x86_64 :=
LOCAL_CFLAGS_32 :=
LOCAL_CFLAGS_64 :=
LOCAL_CFLAGS_x86 :=
LOCAL_CFLAGS_x86_64 :=

LOCAL_CFLAGS += -std=c99
LOCAL_CFLAGS += -I$(LOCAL_PATH)/include
LOCAL_CFLAGS += -DOPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED
LOCAL_CFLAGS += -D__ANDROID_API__=21
LOCAL_CFLAGS += -Ibionic/libc/include
LOCAL_CFLAGS += -Ibionic/libc/kernel/uapi
LOCAL_CFLAGS += -Ibionic/libc/kernel/uapi/asm-x86
LOCAL_CFLAGS += -Ibionic/libc/kernel/android/uapi
LOCAL_CFLAGS += -D_LIBCPP_BUILDING_LIBRARY
LOCAL_CFLAGS += -DOPENSSL_NO_THREADS
include $(BUILD_EFI_STATIC_LIBRARY)
