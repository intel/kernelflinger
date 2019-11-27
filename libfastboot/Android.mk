LOCAL_PATH := $(call my-dir)

SHARED_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/../include/libfastboot
SHARED_CFLAGS := \
	$(KERNELFLINGER_CFLAGS) \
	-DTARGET_BOOTLOADER_BOARD_NAME=\"$(TARGET_BOOTLOADER_BOARD_NAME)\"

SHARED_C_INCLUDES := $(LOCAL_PATH)/../include/libfastboot
SHARED_STATIC_LIBRARIES := \
	$(KERNELFLINGER_STATIC_LIBRARIES) \
	libefiusb-$(TARGET_BUILD_VARIANT) \
	libefitcp-$(TARGET_BUILD_VARIANT) \
	libtransport-$(TARGET_BUILD_VARIANT) \
	libkernelflinger-$(TARGET_BUILD_VARIANT) \
	libavb_kernelflinger-$(TARGET_BUILD_VARIANT)

ifeq ($(TARGET_USE_TPM),true)
    SHARED_STATIC_LIBRARIES += libedk2_tpm
endif

SHARED_SRC_FILES := \
	fastboot.c \
	fastboot_oem.c \
	fastboot_flashing.c \
	flash.c \
	sparse.c \
	info.c \
	intel_variables.c \
	bootmgr.c \
	hashes.c \
	bootloader.c \
	keybox_provision.c

ifneq ($(strip $(TARGET_BOOTLOADER_POLICY)),)
    SHARED_SRC_FILES += authenticated_action.c
endif

include $(CLEAR_VARS)

LOCAL_MODULE := libfastboot-$(TARGET_BUILD_VARIANT)
LOCAL_CFLAGS := $(SHARED_CFLAGS)
LOCAL_STATIC_LIBRARIES := $(SHARED_STATIC_LIBRARIES)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(SHARED_EXPORT_C_INCLUDE_DIRS)
LOCAL_C_INCLUDES := $(SHARED_C_INCLUDES) \
	$(addprefix $(LOCAL_PATH)/../,avb) \
	$(addprefix $(LOCAL_PATH)/../,libsslsupport)
LOCAL_SRC_FILES := $(SHARED_SRC_FILES) \
	fastboot_transport.c
ifneq ($(strip $(KERNELFLINGER_USE_UI)),false)
    LOCAL_SRC_FILES += fastboot_ui.c
endif

ifeq ($(TARGET_USE_SBL),true)
LOCAL_CFLAGS += -DUSE_SBL
endif

include $(BUILD_EFI_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE := libfastboot-for-installer-$(TARGET_BUILD_VARIANT)
LOCAL_CFLAGS := $(SHARED_CFLAGS)
LOCAL_STATIC_LIBRARIES := $(SHARED_STATIC_LIBRARIES)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(SHARED_EXPORT_C_INCLUDE_DIRS)
LOCAL_C_INCLUDES := $(SHARED_C_INCLUDES) \
	$(addprefix $(LOCAL_PATH)/../,libsslsupport)
LOCAL_SRC_FILES := $(SHARED_SRC_FILES)

ifeq ($(TARGET_USE_SBL),true)
LOCAL_CFLAGS += -DUSE_SBL
endif

include $(BUILD_EFI_STATIC_LIBRARY)

