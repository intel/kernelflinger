LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libadb-$(TARGET_BUILD_VARIANT)
LOCAL_CFLAGS := $(KERNELFLINGER_CFLAGS)
LOCAL_STATIC_LIBRARIES := \
	$(KERNELFLINGER_STATIC_LIBRARIES) \
	libefiusb-$(TARGET_BUILD_VARIANT) \
	libefitcp-$(TARGET_BUILD_VARIANT) \
	libtransport-$(TARGET_BUILD_VARIANT) \
	libkernelflinger-$(TARGET_BUILD_VARIANT)

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/../include/libadb
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../include/libadb
LOCAL_SRC_FILES := \
	adb.c \
	adb_socket.c \
	reboot_service.c \
	sync_service.c \
	reader.c \
	shell_service.c \
	devmem.c \
	lsacpi.c \
	hexdump.c \
	ioport.c \
	lspartition.c \
	pci_class.c \
	lspci.c

include $(BUILD_EFI_STATIC_LIBRARY)
