LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libefiusb-$(TARGET_BUILD_VARIANT)
LOCAL_CFLAGS := $(KERNELFLINGER_CFLAGS)
LOCAL_STATIC_LIBRARIES := \
	$(KERNELFLINGER_STATIC_LIBRARIES) \
	libtransport-$(TARGET_BUILD_VARIANT) \
	libkernelflinger-$(TARGET_BUILD_VARIANT)

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/../include/libefiusb
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../include/libefiusb
LOCAL_SRC_FILES := \
	usb.c

ifeq ($(KERNELFLINGER_SUPPORT_SELF_USB_DEVICE_MODE_PROTOCOL),true)
LOCAL_CFLAGS += -DSUPPORT_SUPER_SPEED
LOCAL_CFLAGS += -DUSE_SELF_USB_DEVICE_MODE_PROTOCOL
LOCAL_SRC_FILES += \
	device_mode/cpuio.c \
	device_mode/UsbDeviceDxe.c \
	device_mode/UsbDeviceMode.c \
	device_mode/XdciDevice.c \
	device_mode/XdciDWC.c \
	device_mode/XdciTable.c \
	device_mode/XdciUtility.c
endif

include $(BUILD_EFI_STATIC_LIBRARY)
