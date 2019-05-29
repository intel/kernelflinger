#
# Copyright 2016, The Android Open Source Project
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

LOCAL_PATH := $(my-dir)

avb_common_cflags := \
    -D_FILE_OFFSET_BITS=64 \
    -D_POSIX_C_SOURCE=199309L \
    -Wa,--noexecstack \
    -Wall \
    -Wextra \
    -Wformat=2 \
    -Wno-psabi \
    -Wno-unused-parameter \
    -ffunction-sections \
    -fstack-protector-strong \
    -std=c99
avb_common_cppflags := \
    -Wnon-virtual-dtor \
    -fno-strict-aliasing
avb_common_ldflags := \
    -Wl,--gc-sections


# Build libavb for the target (for e.g. fs_mgr usage).
include $(CLEAR_VARS)
LOCAL_MODULE := libavb_kernelflinger-$(TARGET_BUILD_VARIANT)
LOCAL_MODULE_HOST_OS := linux
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
#LOCAL_CLANG := true
LOCAL_CFLAGS := $(avb_common_cflags) -DAVB_COMPILATION -DUSE_AVB -Wno-error

ifneq ($(KERNELFLINGER_DISABLE_DEBUG_PRINT),true)
    LOCAL_CFLAGS += -DAVB_ENABLE_DEBUG
endif

ifeq ($(KERNELFLINGER_USE_RPMB),true)
    LOCAL_CFLAGS += -DRPMB_STORAGE
endif

ifeq ($(KERNELFLINGER_USE_RPMB_SIMULATE),true)
    LOCAL_CFLAGS += -DRPMB_STORAGE -DRPMB_SIMULATE
endif

ifeq ($(KERNELFLINGER_NVME_RPMB),true)
    KERNELFLINGER_CFLAGS += -DPHY_NVME_RPMB
endif

ifeq ($(KERNELFLINGER_USE_RPMB_SIMULATE),true)
    LOCAL_CFLAGS += -DSECURE_STORAGE_EFIVAR
else  # KERNELFLINGER_USE_RPMB_SIMULATE == false
ifeq ($(KERNELFLINGER_USE_RPMB),true)
    LOCAL_CFLAGS += -DSECURE_STORAGE_RPMB
else  # KERNELFLINGER_USE_RPMB == false
    LOCAL_CFLAGS += -DSECURE_STORAGE_EFIVAR
endif  # KERNELFLINGER_USE_RPMB
endif  # KERNELFLINGER_USE_RPMB_SIMULATE

LOCAL_LDFLAGS := $(avb_common_ldflags)
LOCAL_STATIC_LIBRARIES := \
	$(KERNELFLINGER_STATIC_LIBRARIES) \
	libefiusb-$(TARGET_BUILD_VARIANT) \
	libefitcp-$(TARGET_BUILD_VARIANT) \
	libtransport-$(TARGET_BUILD_VARIANT) \
	libkernelflinger-$(TARGET_BUILD_VARIANT)

ifeq ($(KERNELFLINGER_USE_IPP_SHA256),true)
    LOCAL_CFLAGS += -DUSE_IPP_SHA256
    LOCAL_CFLAGS += -msse4 -msha
endif
ifneq ($(strip $(KERNELFLINGER_USE_UI)),false)
    LOCAL_CFLAGS += -DUSE_UI
endif

LOCAL_SRC_FILES := \
    libavb/avb_chain_partition_descriptor.c \
    libavb/avb_crc32.c \
    libavb/avb_crypto.c \
    libavb/avb_cmdline.c \
    libavb/avb_descriptor.c \
    libavb/avb_footer.c \
    libavb/avb_hash_descriptor.c \
    libavb/avb_hashtree_descriptor.c \
    libavb/avb_kernel_cmdline_descriptor.c \
    libavb/avb_property_descriptor.c \
    libavb/avb_rsa.c \
    libavb/avb_sha512.c \
    libavb/avb_slot_verify.c \
    libavb/uefi_avb_sysdeps.c \
    libavb/uefi_avb_ops.c \
    libavb/uefi_avb_util.c \
    libavb/avb_util.c \
    libavb/avb_vbmeta_image.c \
    libavb_ab/avb_ab_flow.c

ifeq ($(BUILD_ANDROID_THINGS),true)
LOCAL_SRC_FILES += \
    libavb_atx/avb_atx_validate.c
endif

ifeq ($(KERNELFLINGER_USE_IPP_SHA256),true)
LOCAL_SRC_FILES += \
    libavb/avb_sha256_ipps.c
else
LOCAL_SRC_FILES += \
    libavb/avb_sha256.c
endif

LOCAL_C_INCLUDES := \
	$(addprefix $(LOCAL_PATH)/,../libkernelflinger) \
	$(addprefix $(LOCAL_PATH)/,../libsslsupport)

include $(BUILD_EFI_STATIC_LIBRARY)

