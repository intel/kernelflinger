KERNELFLINGER_LOCAL_PATH := $(call my-dir)
KERNELFLINGER_CFLAGS := -Wall -Wextra -Werror -mrdrnd

ifeq ($(KERNELFLINGER_NON-ANDROID),true)
KERNELFLINGER_CFLAGS += -DFASTBOOT_FOR_NON_ANDROID
endif

ifeq ($(BOARD_AVB_ENABLE),true)
    KERNELFLINGER_CFLAGS += -DAVB_AB_I_UNDERSTAND_LIBAVB_AB_IS_DEPRECATED
endif

ifeq ($(TARGET_UEFI_ARCH),x86_64)
    KERNELFLINGER_CFLAGS += -D__STDC_VERSION__=199901L
    KERNELFLINGER_CFLAGS += -DARCH_X86_64=1
endif

ifeq ($(TARGET_USE_TRUSTY),true)
    KERNELFLINGER_CFLAGS += -DUSE_TRUSTY
endif

ifeq ($(TARGET_USE_MULTIBOOT),true)
    KERNELFLINGER_CFLAGS += -DUSE_MULTIBOOT
endif

ifeq ($(TARGET_USE_ACPI),true)
    KERNELFLINGER_CFLAGS += -DUSE_ACPI
endif
ifeq ($(TARGET_USE_ACPIO),true)
    KERNELFLINGER_CFLAGS += -DUSE_ACPIO
endif

ifeq ($(TARGET_USE_PRODUCT),true)
    KERNELFLINGER_CFLAGS += -DUSE_PRODUCT
endif

ifeq ($(IOC_USE_SLCAN),true)
    KERNELFLINGER_CFLAGS += -DIOC_USE_SLCAN
else
ifeq ($(IOC_USE_CBC),true)
    KERNELFLINGER_CFLAGS += -DIOC_USE_CBC
endif
endif

ifeq ($(TARGET_BUILD_VARIANT),user)
    KERNELFLINGER_CFLAGS += -DUSER -DUSERDEBUG
endif

ifeq ($(TARGET_BUILD_VARIANT),userdebug)
    KERNELFLINGER_CFLAGS += -DUSERDEBUG
endif

ifeq ($(TARGET_USE_TPM),true)
    KERNELFLINGER_CFLAGS += -DUSE_TPM -DSOFT_FUSE
endif

ifeq ($(TARGET_NO_DEVICE_UNLOCK),true)
    KERNELFLINGER_CFLAGS += -DNO_DEVICE_UNLOCK
endif

ifeq ($(BUILD_ANDROID_THINGS),true)
    KERNELFLINGER_CFLAGS += -DBUILD_ANDROID_THINGS
endif

ifeq ($(HAL_AUTODETECT),true)
    KERNELFLINGER_CFLAGS += -DHAL_AUTODETECT
endif

ifeq ($(TARGET_USE_USERFASTBOOT),true)
    $(error Userfastboot is not supported anymore)
endif

ifeq ($(KERNELFLINGER_USE_POWER_BUTTON),true)
    KERNELFLINGER_CFLAGS += -DUSE_POWER_BUTTON
endif

KERNELFLINGER_CFLAGS += -DBOARD_BOOTIMAGE_PARTITION_SIZE=$(BOARD_BOOTIMAGE_PARTITION_SIZE)

# adb in crashmode allows to pull the entire RAM and MUST never be
# disabled allowed on a USER build for security reasons:
ifneq ($(TARGET_BUILD_VARIANT),user)
    KERNELFLINGER_CFLAGS += -DCRASHMODE_USE_ADB
endif

ifneq ($(strip $(KERNELFLINGER_USE_UI)),false)
    KERNELFLINGER_CFLAGS += -DUSE_UI
endif

ifneq ($(strip $(TARGET_BOOTLOADER_POLICY)),)
    KERNELFLINGER_CFLAGS += -DBOOTLOADER_POLICY=$(TARGET_BOOTLOADER_POLICY)
    # Double negation to enforce the use of the EFI variable storage
    # as the default behavior.
    ifneq ($(strip $(TARGET_BOOTLOADER_POLICY_USE_EFI_VAR)),False)
        KERNELFLINGER_CFLAGS += -DBOOTLOADER_POLICY_EFI_VAR
    endif
endif

ifeq ($(KERNELFLINGER_OS_SECURE_BOOT),true)
    KERNELFLINGER_CFLAGS += -DOS_SECURE_BOOT
endif

#Enable android verifed boot support(libavb)
ifeq ($(BOARD_AVB_ENABLE),true)
    KERNELFLINGER_CFLAGS += -DUSE_AVB
    ifneq ($(KERNELFLINGER_DISABLE_DEBUG_PRINT),true)
        ifeq ($(TARGET_BUILD_VARIANT),userdebug)
            KERNELFLINGER_CFLAGS += -DAVB_ENABLE_DEBUG
        endif
    endif
endif

ifeq ($(BOARD_SLOT_AB_ENABLE),true)
    KERNELFLINGER_CFLAGS += -DUSE_SLOT
endif

ifeq ($(KERNELFLINGER_SUPPORT_USB_STORAGE),true)
    KERNELFLINGER_CFLAGS += -DUSB_STORAGE
endif

ifeq ($(KERNELFLINGER_USE_RPMB),true)
    KERNELFLINGER_CFLAGS += -DRPMB_STORAGE
endif

ifeq ($(KERNELFLINGER_USE_RPMB_SIMULATE),true)
    KERNELFLINGER_CFLAGS += -DRPMB_STORAGE -DRPMB_SIMULATE
endif

ifeq ($(KERNELFLINGER_USE_NVME_RPMB),true)
    KERNELFLINGER_CFLAGS += -DNVME_RPMB
endif

ifeq ($(KERNELFLINGER_USE_RPMB_SIMULATE),true)
    KERNELFLINGER_CFLAGS += -DSECURE_STORAGE_EFIVAR
else  # KERNELFLINGER_USE_RPMB_SIMULATE == false
ifeq ($(KERNELFLINGER_USE_RPMB),true)
    KERNELFLINGER_CFLAGS += -DSECURE_STORAGE_RPMB
else  # KERNELFLINGER_USE_RPMB == false
    KERNELFLINGER_CFLAGS += -DSECURE_STORAGE_EFIVAR
endif  # KERNELFLINGER_USE_RPMB
endif  # KERNELFLINGER_USE_RPMB_SIMULATE

ifeq ($(BOARD_SD_PASS_THRU_ENABLE),true)
    KERNELFLINGER_CFLAGS += -DUSE_SD_PASS_THRU
endif

ifeq ($(PRODUCT_USE_DYNAMIC_PARTITIONS),true)
    KERNELFLINGER_CFLAGS += -DDYNAMIC_PARTITIONS
endif

ifeq ($(KERNELFLINGER_SUPPORT_KEYBOX_PROVISION),true)
    KERNELFLINGER_CFLAGS += -DFASTBOOT_KEYBOX_PROVISION
endif

KERNELFLINGER_STATIC_LIBRARIES := \
	libuefi_ssl_static \
	libuefi_crypto_static \
	libgnuefi \
	libsslsupport \
	libefi

include $(call all-subdir-makefiles)
LOCAL_PATH := $(KERNELFLINGER_LOCAL_PATH)

SHARED_CFLAGS := $(KERNELFLINGER_CFLAGS)
SHARED_STATIC_LIBRARIES := \
	$(KERNELFLINGER_STATIC_LIBRARIES) \
	libkernelflinger-$(TARGET_BUILD_VARIANT)

ifeq ($(TARGET_USE_TPM),true)
    SHARED_STATIC_LIBRARIES += libedk2_tpm
endif

include $(CLEAR_VARS)
LOCAL_MODULE := kernelflinger-$(TARGET_BUILD_VARIANT)


# if dm-verity is disabled for eng purpose skip the oem-cert
ifeq ($(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_SUPPORTS_VERITY), true)
kf_intermediates := $(call intermediates-dir-for,EFI,kernelflinger)

VERITY_CERT := $(kf_intermediates)/verity.cer
PADDED_VERITY_CERT := $(kf_intermediates)/verity.padded.cer
OEMCERT_OBJ := $(kf_intermediates)/oemcert.o

$(VERITY_CERT): $(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_VERITY_SIGNING_KEY).x509.pem $(OPENSSL)
	$(transform-pem-cert-to-der-cert)

$(PADDED_VERITY_CERT): $(VERITY_CERT)
	$(call pad-binary, 4096)

ifeq ($(TARGET_UEFI_ARCH),x86_64)
    ELF_OUTPUT := elf64-x86-64
else
    ELF_OUTPUT := elf32-i386
endif

sym_binary := $(shell echo _binary_$(PADDED_VERITY_CERT) | sed "s/[\/\.-]/_/g")
$(OEMCERT_OBJ): $(PADDED_VERITY_CERT)
	mkdir -p $(@D) && \
	$(EFI_OBJCOPY) --input binary --output $(ELF_OUTPUT) --binary-architecture i386 $< $@ && \
	$(EFI_OBJCOPY) --redefine-sym $(sym_binary)_start=_binary_oemcert_start \
                       --redefine-sym $(sym_binary)_end=_binary_oemcert_end \
                       --redefine-sym $(sym_binary)_size=_binary_oemcert_size \
                       --rename-section .data=.oemkeys $@ $@

LOCAL_GENERATED_SOURCES := $(OEMCERT_OBJ)
else # PRODUCT_SUPPORTS_VERITY
ifneq (,$(filter user userdebug, $(TARGET_BUILD_VARIANT)))

ifeq ($(BOARD_AVB_ENABLE),false)
fail_no_oem_cert:
	$(error Trying to build kernelflinger-$(TARGET_BUILD_VARIANT)\
without oem-cert, this is allowed only for eng builds)

LOCAL_GENERATED_SOURCES := fail_no_oem_cert
endif # BOARD_AVB_ENABLE
endif
endif # PRODUCT_SUPPORTS_VERITY

ifeq ($(BOARD_AVB_ENABLE),true)
kf_intermediates := $(call intermediates-dir-for,EFI,kernelflingeravb)

AVB_PK := $(kf_intermediates)/avb_pk.bin
PADDED_AVB_PK := $(kf_intermediates)/avb_pk.padded.bin
AVB_PK_OBJ := $(kf_intermediates)/avb_pk.o
ifndef BOARD_AVB_KEY_PATH
BOOTLOADER_AVB_KEY_PATH := external/avb/test/data/testkey_rsa4096.pem
else
BOOTLOADER_AVB_KEY_PATH := $(BOARD_AVB_KEY_PATH)
endif

$(AVB_PK): $(BOOTLOADER_AVB_KEY_PATH)
	external/avb/avbtool extract_public_key --key $< --output $@

$(PADDED_AVB_PK): $(AVB_PK)
	$(call pad-binary, 4096)

ifeq ($(TARGET_UEFI_ARCH),x86_64)
    ELF_OUTPUT := elf64-x86-64
else
    ELF_OUTPUT := elf32-i386
endif

avb_sym_binary := $(shell echo _binary_$(PADDED_AVB_PK) | sed "s/[\/\.-]/_/g")
$(AVB_PK_OBJ): $(PADDED_AVB_PK)
	mkdir -p $(@D) && \
	$(EFI_OBJCOPY) --input binary --output $(ELF_OUTPUT) --binary-architecture i386 $< $@ && \
	$(EFI_OBJCOPY) --redefine-sym $(avb_sym_binary)_start=_binary_avb_pk_start \
                       --redefine-sym $(avb_sym_binary)_end=_binary_avb_pk_end \
                       --redefine-sym $(avb_sym_binary)_size=_binary_avb_pk_size \
                       --rename-section .data=.oemkeys $@ $@

LOCAL_GENERATED_SOURCES += $(AVB_PK_OBJ)
LOCAL_C_INCLUDES := \
	$(addprefix $(LOCAL_PATH)/,avb)
endif  # BOARD_AVB_ENABLE


LOCAL_SRC_FILES := \
	kernelflinger.c
ifneq ($(strip $(KERNELFLINGER_USE_UI)),false)
	LOCAL_SRC_FILES += \
	ux.c
endif

LOCAL_STATIC_LIBRARIES := \
	libfastboot-$(TARGET_BUILD_VARIANT) \
	libefiusb-$(TARGET_BUILD_VARIANT) \
	libefitcp-$(TARGET_BUILD_VARIANT) \
	libtransport-$(TARGET_BUILD_VARIANT) \
	libheci-$(TARGET_BUILD_VARIANT)

ifeq ($(TARGET_USE_TRUSTY),true)
    LOCAL_STATIC_LIBRARIES += libqltipc-$(TARGET_BUILD_VARIANT)
endif

ifneq ($(TARGET_BUILD_VARIANT),user)
    LOCAL_STATIC_LIBRARIES += libadb-$(TARGET_BUILD_VARIANT)
endif

ifneq ($(TARGET_BUILD_VARIANT),user)
    LOCAL_SRC_FILES += unittest.c
endif

LOCAL_CFLAGS := $(SHARED_CFLAGS)

ifeq ($(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_SUPPORTS_VERITY), true)
LOCAL_OBJCOPY_FLAGS := -j .oemkeys
endif

ifeq ($(BOARD_AVB_ENABLE), true)
LOCAL_OBJCOPY_FLAGS := -j .oemkeys
endif

LOCAL_STATIC_LIBRARIES += $(SHARED_STATIC_LIBRARIES)
LOCAL_MODULE_STEM := kernelflinger

ifeq ($(BOARD_AVB_ENABLE),true)
LOCAL_STATIC_LIBRARIES += libavb_kernelflinger-$(TARGET_BUILD_VARIANT)
endif

LOCAL_C_INCLUDES += \
	$(addprefix $(LOCAL_PATH)/,libkernelflinger) \
	$(addprefix $(LOCAL_PATH)/,libsslsupport)
include $(BUILD_EFI_EXECUTABLE)  # For kernelflinger-$(TARGET_BUILD_VARIANT)


include $(CLEAR_VARS)
LOCAL_MODULE := installer-$(TARGET_BUILD_VARIANT)
LOCAL_STATIC_LIBRARIES := \
	$(SHARED_STATIC_LIBRARIES) \
	libtransport-$(TARGET_BUILD_VARIANT) \
	libfastboot-for-installer-$(TARGET_BUILD_VARIANT)
LOCAL_CFLAGS := $(SHARED_CFLAGS)
LOCAL_SRC_FILES := installer.c
LOCAL_MODULE_STEM := installer
LOCAL_C_INCLUDES := \
	$(addprefix $(LOCAL_PATH)/,libfastboot) \
	$(addprefix $(LOCAL_PATH)/,libsslsupport)

ifeq ($(BOARD_AVB_ENABLE),true)
kfins_intermediates := $(call intermediates-dir-for,EFI,kernelflingerins)

KFINS_AVB_PK := $(kfins_intermediates)/avb_pk.bin
KFINS_PADDED_AVB_PK := $(kfins_intermediates)/avb_pk.padded.bin
KFINS_AVB_PK_OBJ := $(kfins_intermediates)/avb_pk.o
ifndef BOARD_AVB_KEY_PATH
BOOTLOADER_AVB_KEY_PATH := external/avb/test/data/testkey_rsa4096.pem
else
BOOTLOADER_AVB_KEY_PATH := $(BOARD_AVB_KEY_PATH)
endif

$(KFINS_AVB_PK): $(BOOTLOADER_AVB_KEY_PATH)
	external/avb/avbtool extract_public_key --key $< --output $@

$(KFINS_PADDED_AVB_PK): $(KFINS_AVB_PK)
	$(call pad-binary, 4096)

ifeq ($(TARGET_UEFI_ARCH),x86_64)
    ELF_OUTPUT := elf64-x86-64
else
    ELF_OUTPUT := elf32-i386
endif

kfins_avb_sym_binary := $(shell echo _binary_$(KFINS_PADDED_AVB_PK) | sed "s/[\/\.-]/_/g")
$(KFINS_AVB_PK_OBJ): $(KFINS_PADDED_AVB_PK)
	mkdir -p $(@D) && \
	$(EFI_OBJCOPY) --input binary --output $(ELF_OUTPUT) --binary-architecture i386 $< $@ && \
	$(EFI_OBJCOPY) --redefine-sym $(kfins_avb_sym_binary)_start=_binary_avb_pk_start \
                       --redefine-sym $(kfins_avb_sym_binary)_end=_binary_avb_pk_end \
                       --redefine-sym $(kfins_avb_sym_binary)_size=_binary_avb_pk_size \
                       --rename-section .data=.oemkeys $@ $@

LOCAL_GENERATED_SOURCES += $(KFINS_AVB_PK_OBJ)
LOCAL_C_INCLUDES += $(addprefix $(LOCAL_PATH)/,avb)
LOCAL_STATIC_LIBRARIES += libavb_kernelflinger-$(TARGET_BUILD_VARIANT)
endif  # BOARD_AVB_ENABLE

include $(BUILD_EFI_EXECUTABLE) # For installer-$(TARGET_BUILD_VARIANT)

ifeq ($(BOOTLOADER_SLOT), true)
ifeq ($(BOARD_SLOT_AB_ENABLE),true)
ifeq ($(BOARD_AVB_ENABLE),true)
include $(CLEAR_VARS)
LOCAL_MODULE := kfld-$(TARGET_BUILD_VARIANT)
LOCAL_STATIC_LIBRARIES := \
	$(SHARED_STATIC_LIBRARIES)
LOCAL_CFLAGS := $(SHARED_CFLAGS)
LOCAL_SRC_FILES := kfld.c
LOCAL_MODULE_STEM := kfld
LOCAL_C_INCLUDES += $(addprefix $(LOCAL_PATH)/,avb)
LOCAL_C_INCLUDES += $(addprefix $(LOCAL_PATH)/,avb/libavb)
LOCAL_C_INCLUDES += $(addprefix $(LOCAL_PATH)/,avb/libavb_ab)

ifeq ($(TARGET_UEFI_ARCH),x86_64)
    ELF_OUTPUT := elf64-x86-64
else
    ELF_OUTPUT := elf32-i386
endif

include $(BUILD_EFI_EXECUTABLE) # For installer-$(TARGET_BUILD_VARIANT)
endif # BOARD_AVB_ENABLE
endif # BOARD_SLOT_AB_ENABLE
endif # BOOTLOADER_SLOT



ifeq ($(KERNELFLINGER_SUPPORT_NON_EFI_BOOT),true)

include $(CLEAR_VARS)
LOCAL_MODULE := kf4abl-$(TARGET_BUILD_VARIANT)
LOCAL_MODULE_STEM := kf4abl
LOCAL_CFLAGS := $(SHARED_CFLAGS)

ifeq ($(KERNELFLINGER_DISABLE_DEBUG_PRINT),true)
    LOCAL_CFLAGS += -D__DISABLE_DEBUG_PRINT
endif

LOCAL_STATIC_LIBRARIES += \
	libfastboot-$(TARGET_BUILD_VARIANT) \
	libefiusb-$(TARGET_BUILD_VARIANT) \
	libefitcp-$(TARGET_BUILD_VARIANT) \
	libtransport-$(TARGET_BUILD_VARIANT) \
	libheci-$(TARGET_BUILD_VARIANT) \
	$(SHARED_STATIC_LIBRARIES) \
	libpayload \
	libefiwrapper-$(TARGET_BUILD_VARIANT) \
	libefiwrapper_drivers-$(TARGET_BUILD_VARIANT) \
	efiwrapper-$(TARGET_BUILD_VARIANT) \
	libelfloader-$(TARGET_BUILD_VARIANT)

ifeq ($(TARGET_USE_TRUSTY),true)
    LOCAL_STATIC_LIBRARIES += libqltipc-$(TARGET_BUILD_VARIANT)
endif

ifeq ($(BOARD_AVB_ENABLE),true)
    LOCAL_STATIC_LIBRARIES += libavb_kernelflinger-$(TARGET_BUILD_VARIANT)
endif
ifneq ($(TARGET_BUILD_VARIANT),user)
    LOCAL_STATIC_LIBRARIES += libadb-$(TARGET_BUILD_VARIANT)
endif
LOCAL_SRC_FILES := \
	kf4abl.c

ifneq ($(strip $(KERNELFLINGER_USE_UI)),false)
    LOCAL_SRC_FILES += \
        ux.c
endif
ifeq ($(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_SUPPORTS_VERITY),true)
keys4abl_intermediates := $(call intermediates-dir-for,ABL,keys)

ABL_VERITY_CERT := $(keys4abl_intermediates)/verity.cer
ABL_PADDED_VERITY_CERT := $(keys4abl_intermediates)/verity.padded.cer
ABL_OEMCERT_OBJ := $(keys4abl_intermediates)/oemcert.o

$(ABL_VERITY_CERT): $(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_VERITY_SIGNING_KEY).x509.pem $(OPENSSL)
	$(transform-pem-cert-to-der-cert)

$(ABL_PADDED_VERITY_CERT): $(ABL_VERITY_CERT)
	$(call pad-binary, 4096)

ifeq ($(TARGET_IAFW_ARCH),x86_64)
    ELF_OUTPUT := elf64-x86-64
else
    ELF_OUTPUT := elf32-i386
endif

abl_sym_binary := $(shell echo _binary_$(ABL_PADDED_VERITY_CERT) | sed "s/[\/\.-]/_/g")
$(ABL_OEMCERT_OBJ): $(ABL_PADDED_VERITY_CERT)
	mkdir -p $(@D) && \
	$(EFI_OBJCOPY) --input binary --output $(ELF_OUTPUT) --binary-architecture i386 $< $@ && \
	$(EFI_OBJCOPY) --redefine-sym $(abl_sym_binary)_start=_binary_oemcert_start \
                       --redefine-sym $(abl_sym_binary)_end=_binary_oemcert_end \
                       --redefine-sym $(abl_sym_binary)_size=_binary_oemcert_size \
                       --rename-section .data=.oemkeys $@ $@

LOCAL_GENERATED_SOURCES := $(ABL_OEMCERT_OBJ)
endif #.PRODUCT_SUPPORTS_VERITY == true

ifeq ($(BOARD_AVB_ENABLE),true)
keys4abl_intermediates := $(call intermediates-dir-for,ABL,keys4abl)

ABL_AVB_PK := $(keys4abl_intermediates)/avb_pk.bin
ABL_PADDED_AVB_PK := $(keys4abl_intermediates)/avb_pk.padded.bin
ABL_AVB_PK_OBJ := $(keys4abl_intermediates)/avb_pk.o
ifndef BOARD_AVB_KEY_PATH
BOOTLOADER_AVB_KEY_PATH := external/avb/test/data/testkey_rsa4096.pem
else
BOOTLOADER_AVB_KEY_PATH := $(BOARD_AVB_KEY_PATH)
endif

$(ABL_AVB_PK): $(BOOTLOADER_AVB_KEY_PATH)
	external/avb/avbtool extract_public_key --key $< --output $@

$(ABL_PADDED_AVB_PK): $(ABL_AVB_PK)
	$(call pad-binary, 4096)

ifeq ($(TARGET_IAFW_ARCH),x86_64)
    ELF_OUTPUT := elf64-x86-64
else
    ELF_OUTPUT := elf32-i386
endif

avb_sym_binary := $(shell echo _binary_$(ABL_PADDED_AVB_PK) | sed "s/[\/\.-]/_/g")
$(ABL_AVB_PK_OBJ): $(ABL_PADDED_AVB_PK)
	mkdir -p $(@D) && \
	$(EFI_OBJCOPY) --input binary --output $(ELF_OUTPUT) --binary-architecture i386 $< $@ && \
	$(EFI_OBJCOPY) --redefine-sym $(avb_sym_binary)_start=_binary_avb_pk_start \
                       --redefine-sym $(avb_sym_binary)_end=_binary_avb_pk_end \
                       --redefine-sym $(avb_sym_binary)_size=_binary_avb_pk_size \
                       --rename-section .data=.oemkeys $@ $@

LOCAL_GENERATED_SOURCES += $(ABL_AVB_PK_OBJ)
LOCAL_C_INCLUDES := \
	$(addprefix $(LOCAL_PATH)/,avb)

endif
LOCAL_C_INCLUDES := \
	$(addprefix $(LOCAL_PATH)/,libkernelflinger)
LOCAL_C_INCLUDES := \
	$(addprefix $(LOCAL_PATH)/,libsslsupport)
include $(BUILD_ABL_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := fb4abl-$(TARGET_BUILD_VARIANT)
LOCAL_MODULE_STEM := fb4abl
LOCAL_CFLAGS := $(SHARED_CFLAGS)

LOCAL_CFLAGS += -D__FORCE_FASTBOOT

LOCAL_STATIC_LIBRARIES += \
	libfastboot-$(TARGET_BUILD_VARIANT) \
	libefiusb-$(TARGET_BUILD_VARIANT) \
	libefitcp-$(TARGET_BUILD_VARIANT) \
	libtransport-$(TARGET_BUILD_VARIANT) \
	libheci-$(TARGET_BUILD_VARIANT) \
	$(SHARED_STATIC_LIBRARIES) \
	libpayload \
	libefiwrapper-$(TARGET_BUILD_VARIANT) \
	libefiwrapper_drivers-$(TARGET_BUILD_VARIANT) \
	efiwrapper-$(TARGET_BUILD_VARIANT) \
	libelfloader-$(TARGET_BUILD_VARIANT)

ifeq ($(TARGET_USE_TRUSTY),true)
    LOCAL_STATIC_LIBRARIES += libqltipc-$(TARGET_BUILD_VARIANT)
endif

ifneq ($(TARGET_BUILD_VARIANT),user)
    LOCAL_STATIC_LIBRARIES += libadb-$(TARGET_BUILD_VARIANT)
endif
ifeq ($(BOARD_AVB_ENABLE),true)
    LOCAL_STATIC_LIBRARIES += libavb_kernelflinger-$(TARGET_BUILD_VARIANT)
endif
LOCAL_SRC_FILES := \
	kf4abl.c

ifneq ($(strip $(KERNELFLINGER_USE_UI)),false)
    LOCAL_SRC_FILES += \
        ux.c
endif

ifeq ($(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_SUPPORTS_VERITY),true)
LOCAL_GENERATED_SOURCES := $(ABL_OEMCERT_OBJ)
endif

ifeq ($(BOARD_AVB_ENABLE),true)
LOCAL_GENERATED_SOURCES += $(ABL_AVB_PK_OBJ)
LOCAL_C_INCLUDES := \
	$(addprefix $(LOCAL_PATH)/,avb)
endif
LOCAL_C_INCLUDES := \
	$(addprefix $(LOCAL_PATH)/,libkernelflinger)
LOCAL_C_INCLUDES := \
	$(addprefix $(LOCAL_PATH)/,libsslsupport)
include $(BUILD_ABL_EXECUTABLE)

endif  #KERNELFLINGER_SUPPORT_NON_EFI_BOOT


include $(CLEAR_VARS)
LOCAL_MODULE := kf4aic-$(TARGET_BUILD_VARIANT)
LOCAL_STATIC_LIBRARIES := \
	$(SHARED_STATIC_LIBRARIES)

LOCAL_CFLAGS := $(SHARED_CFLAGS)
LOCAL_SRC_FILES := kf4aic.c
LOCAL_MODULE_STEM := kf4aic

include $(BUILD_EFI_EXECUTABLE) # For kf4aic-$(TARGET_BUILD_VARIANT)

