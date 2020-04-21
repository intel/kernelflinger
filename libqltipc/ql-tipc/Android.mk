LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libqltipc-$(TARGET_BUILD_VARIANT)
LOCAL_CFLAGS := $(KERNELFLINGER_CFLAGS)

ifeq ($(TARGET_UEFI_ARCH),x86_64)
LOCAL_CFLAGS += -DARCH_X86_64=1
else
LOCAL_CFLAGS += -DARCH_X86_32=1
endif

LOCAL_STATIC_LIBRARIES := \
	$(KERNELFLINGER_STATIC_LIBRARIES) \
	libkernelflinger-$(TARGET_BUILD_VARIANT)

LOCAL_C_INCLUDES := $(KERNELFLINGER_LOCAL_PATH) \
                    $(LOCAL_PATH)/include \
                    $(LOCAL_PATH)/../interface/include \
                    $(KERNELFLINGER_LOCAL_PATH)/libsslsupport \
                    $(KERNELFLINGER_LOCAL_PATH)/avb

LOCAL_SRC_FILES := \
	ipc.c \
	ipc_dev.c \
	libtipc.c \
	rpmb_proxy.c \
	avb.c \
	arch/x86/trusty_dev.c \
	arch/x86/trusty_mem.c \
	storage_ops_osloader.c \
	sysdeps_osloader.c \
	util.c \
	keymaster.c \
	keymaster_serializable.c \
	rpmb_sim.c \

ifeq ($(KERNELFLINGER_TRUSTY_PLATFORM),vsbl)
LOCAL_CFLAGS += -DHYPERVISOR_ACRN
endif

include $(BUILD_EFI_STATIC_LIBRARY)
