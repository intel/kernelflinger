LIBEDK2_LOCAL_PATH := $(call my-dir)
include $(call all-subdir-makefiles)
LOCAL_PATH := $(LIBEDK2_LOCAL_PATH)

include $(CLEAR_VARS)

LOCAL_MODULE := libedk2_tpm
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include \
                               $(LOCAL_PATH)/../include/libkernelflinger
LOCAL_CFLAGS := -Wall -Wextra -Werror -mrdrnd \
                -DTARGET_BOOTLOADER_BOARD_NAME=\"$(TARGET_BOOTLOADER_BOARD_NAME)\"
LOCAL_STATIC_LIBRARIES := libgnuefi \
                          libefi

LOCAL_SRC_FILES := \
        Tpm2NVStorage.c \
        Tpm2Random.c \
        Tpm2Help.c \
        Tpm2Context.c \
        Tpm2EnhancedAuthorization.c \
        Tpm2Hierarchy.c \
        Tpm2Integrity.c \
        Tpm2Sequences.c \
        Tpm2Session.c \
        Tpm2Capability.c

ifeq ($(TARGET_USE_SBL),true)
LOCAL_SRC_FILES += \
       RegisterFilterLibNull.c \
       Tpm2Ptp.c \
       IoLib.c \
       Tpm2Tis.c
else
LOCAL_SRC_FILES += Tpm2DeviceLib.c
endif

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include \
                    $(LOCAL_PATH)/../include \
                    $(res_intermediates)

include $(BUILD_EFI_STATIC_LIBRARY)
