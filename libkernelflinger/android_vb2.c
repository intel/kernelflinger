/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <efi.h>
#include <efilib.h>
#include <ui.h>

#include "android.h"
#include "efilinux.h"
#include "lib.h"
#include "security.h"
#include "vars.h"
#include "power.h"
#include "targets.h"
#include "gpt.h"
#include "storage.h"
#include "text_parser.h"
#include "watchdog.h"
#ifdef HAL_AUTODETECT
#include "blobstore.h"
#endif
#include "slot.h"
#include "pae.h"
#include "timer.h"
#include "acpi.h"

//Global AvbOps data structure
static AvbOps *ops = NULL;

AvbOps *avb_init(void)
{
        avb_print("UEFI AVB-based bootloader\n");

        if (ops != NULL) {
            return ops;
        }

        ops = uefi_avb_ops_new();
        if (!ops) {
                avb_fatal("Error allocating AvbOps.\n");
                return NULL;
        }

        return ops;
}

bool avb_update_stored_rollback_indexes_for_slot(AvbOps* ops, AvbSlotVerifyData* slot_data)
{
        int n;

        for (n = 0; n < AVB_MAX_NUMBER_OF_ROLLBACK_INDEX_LOCATIONS; n++) {
                uint64_t rollback_index = slot_data->rollback_indexes[n];
                if (rollback_index > 0) {
                        AvbIOResult io_ret;
                        uint64_t current_stored_rollback_index;

                        io_ret = ops->read_rollback_index(ops, n, &current_stored_rollback_index);
                        if (io_ret != AVB_IO_RESULT_OK)
                                return false;

                        if (rollback_index > current_stored_rollback_index) {
                                io_ret = ops->write_rollback_index(ops, n, rollback_index);
                                if (io_ret != AVB_IO_RESULT_OK)
                                        return false;
                        }
                }
        }
        return true;
}
#ifdef DYNAMIC_PARTITIONS
#define AVB_ROOTFS_PREFIX L"rootwait ro init=/init"
#else
#define AVB_ROOTFS_PREFIX L"skip_initramfs rootwait ro init=/init"
#endif
#define DISABLE_AVB_ROOTFS_PREFIX L" root="

static EFI_STATUS avb_prepend_command_line_rootfs(
                __attribute__((__unused__)) OUT CHAR16 **cmdline16,
                IN enum boot_target boot_target)
{
        EFI_STATUS ret = EFI_SUCCESS;

        if (boot_target == RECOVERY || boot_target == MEMORY)
                return ret;

        if (use_slot()) {
                ret = prepend_command_line(cmdline16, AVB_ROOTFS_PREFIX);
                if (EFI_ERROR(ret)) {
                        efi_perror(ret, L"Failed to add AVB rootfs prefix");
                        return ret;
                }
        }
        return ret;
}

EFI_STATUS prepend_slot_command_line(CHAR16 **cmdline16,
        enum boot_target boot_target,
        VBDATA *vb_data)
{
        EFI_STATUS ret = EFI_SUCCESS;
#ifndef DYNAMIC_PARTITIONS
        EFI_GUID system_uuid;
#endif

        avb_prepend_command_line_rootfs(cmdline16, boot_target);

        if (use_slot()) {
                if (slot_get_active()) {
                        ret = prepend_command_line(cmdline16,
                                L"androidboot.slot_suffix=%a",
                                slot_get_active());
                        if (EFI_ERROR(ret))
                                return ret;
                }

                if (vb_data && vb_data->cmdline &&
                        (!avb_strstr(vb_data->cmdline,"root=")))
                {
#ifndef DYNAMIC_PARTITIONS
                        ret = gpt_get_partition_uuid(slot_label(SYSTEM_LABEL),
                                &system_uuid, LOGICAL_UNIT_USER);
                        if (EFI_ERROR(ret)) {
                                efi_perror(ret,
                                        L"Failed to get %s partition UUID",
                                        SYSTEM_LABEL);
                                return ret;
                        }

                        ret = prepend_command_line(cmdline16,
                                DISABLE_AVB_ROOTFS_PREFIX "PARTUUID=%g",
                                &system_uuid);
                        if (EFI_ERROR(ret))
                                return ret;
#else
                        debug(L"Enable Dynamic Partitions\n");
#endif
                }
        }
        return ret;
}

UINTN get_vb_cmdlen(VBDATA *vb_data)
{
        if (vb_data && vb_data->cmdline)
                return strlen(vb_data->cmdline);
        return 0;
}

char *get_vb_cmdline(VBDATA *vb_data)
{
        return vb_data->cmdline;
}

EFI_STATUS android_query_image_from_avb_result(
                IN AvbSlotVerifyData *slot_data,
                IN const char *label,
                OUT VOID **image)
{
        AvbPartitionData *pdata = NULL;

        for (size_t n = 0; n < slot_data->num_loaded_partitions; ++n) {
                pdata = &slot_data->loaded_partitions[n];
                if (!strcmp(pdata->partition_name, label)) {
                        *image = pdata->data;
                        if (!strcmp(label, "boot") || !strcmp(label, "tos") ||
                                !strcmp(label, "recovery")) {
                                if (get_bootimage_header(*image))
                                        return EFI_SUCCESS;
                        } else
                            return EFI_SUCCESS;
                }
        }

        *image = NULL;
        return EFI_NOT_FOUND;
}

EFI_STATUS get_avb_flow_result(
                IN AvbSlotVerifyData *slot_data,
                IN bool allow_verification_error,
                IN AvbABFlowResult flow_result,
                IN OUT UINT8 *boot_state)
{
        if (!slot_data || !boot_state)
                return EFI_INVALID_PARAMETER;

        if (slot_data->num_loaded_partitions < 1) {
                avb_error("No avb partition.\n");
                return EFI_LOAD_ERROR;
        }

        switch (flow_result) {
        case AVB_AB_FLOW_RESULT_OK:
                if (allow_verification_error && *boot_state < BOOT_STATE_ORANGE)
                        *boot_state = BOOT_STATE_ORANGE;
                break;

        case AVB_AB_FLOW_RESULT_OK_WITH_VERIFICATION_ERROR:
        case AVB_AB_FLOW_RESULT_ERROR_OOM:
        case AVB_AB_FLOW_RESULT_ERROR_IO:
        case AVB_AB_FLOW_RESULT_ERROR_NO_BOOTABLE_SLOTS:
        case AVB_AB_FLOW_RESULT_ERROR_INVALID_ARGUMENT:
                if (allow_verification_error && *boot_state <= BOOT_STATE_ORANGE) {
                /* Do nothing since we allow this. */
                        avb_debugv("Allow avb ab flow with result ",
                        avb_ab_flow_result_to_string(flow_result),
                        " because |allow_verification_error| is true.\n",
                        NULL);
                        *boot_state = BOOT_STATE_ORANGE;
                } else
                        *boot_state = BOOT_STATE_RED;
                break;
        default:
                if (allow_verification_error && *boot_state <= BOOT_STATE_ORANGE)
                        *boot_state = BOOT_STATE_ORANGE;
                else
                        *boot_state = BOOT_STATE_RED;
                break;
        }

        return EFI_SUCCESS;
}

EFI_STATUS get_avb_result(
                IN AvbSlotVerifyData *slot_data,
                IN bool allow_verification_error,
                IN AvbSlotVerifyResult verify_result,
                IN OUT UINT8 *boot_state)
{
        if (!slot_data || !boot_state)
                return EFI_INVALID_PARAMETER;

        if (slot_data->num_loaded_partitions < 1) {
                avb_error("No avb partition.\n");
                return EFI_LOAD_ERROR;
        }

        switch (verify_result) {
        case AVB_SLOT_VERIFY_RESULT_OK:
                if (allow_verification_error && *boot_state < BOOT_STATE_ORANGE)
                        *boot_state = BOOT_STATE_ORANGE;
                break;

        case AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION:
        case AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX:
        case AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED:
                if (allow_verification_error && *boot_state <= BOOT_STATE_ORANGE) {
                /* Do nothing since we allow this. */
                        avb_debugv("Allow avb verified with result ",
                        avb_slot_verify_result_to_string(verify_result),
                        " because |allow_verification_error| is true.\n",
                        NULL);
                        *boot_state = BOOT_STATE_ORANGE;
                } else
                        *boot_state = BOOT_STATE_RED;
                break;
        default:
                if (allow_verification_error && *boot_state <= BOOT_STATE_ORANGE)
                        *boot_state = BOOT_STATE_ORANGE;
                else
                        *boot_state = BOOT_STATE_RED;
                break;
        }

        return EFI_SUCCESS;
}


EFI_STATUS android_install_acpi_table_avb(AvbSlotVerifyData *slot_data)
{
#if 0
        const char *acpi_part_names[] = {
#ifdef USE_ACPI
                "acpi",
#endif
#ifdef USE_ACPIO
                "acpio",
#endif
                NULL};
#endif
        VOID *image = NULL;
        EFI_STATUS ret = EFI_SUCCESS;
        struct boot_img_hdr *hdr;

        android_query_image_from_avb_result(slot_data, "boot", &image);
        if (image != NULL) {
                hdr = (struct boot_img_hdr *)image;
                if ((hdr->header_version == 2) && (hdr->acpi_size > 0)) {
                        VOID *acpi_addr = image +
                                pagealign(hdr, hdr->kernel_size) +
                                pagealign(hdr, hdr->ramdisk_size) +
                                pagealign(hdr, hdr->second_size) +
                                pagealign(hdr, hdr->recovery_acpio_size) +
                                hdr->page_size;
                        install_acpi_table_from_boot_acpi(acpi_addr, hdr->acpi_size);
                }
        }

        debug(L"Skip install apci table....\n");
#if 0
        for (int i = 0; acpi_part_names[i] != NULL; i++) {
                ret = android_query_image_from_avb_result(slot_data,
                                                    acpi_part_names[i], &image);
                if (EFI_ERROR(ret)) {
                        efi_perror(ret, L"'%a' image not found!", acpi_part_names[i]);
                        return ret;
                }
                ret = install_acpi_table_from_partitions(image,
                                                         acpi_part_names[i]);
                if (EFI_ERROR(ret)) {
                        efi_perror(ret, L"Failed to install acpi table from %a image",
                                   acpi_part_names[i]);
                        return ret;
                }
        }
#endif
        return ret;
}

EFI_STATUS android_image_load_partition_avb(
                IN const char *label,
                OUT VOID **bootimage_p,
                IN OUT UINT8* boot_state,
                AvbSlotVerifyData **slot_data)
{
        EFI_STATUS ret = EFI_SUCCESS;
        AvbOps *ops;
        const char *slot_suffix = "";
        AvbSlotVerifyResult verify_result = 0;
        AvbSlotVerifyFlags flags;
        const char *requested_partitions[] = {label,
#ifdef USE_ACPI
                "acpi",
#endif
#ifdef USE_ACPIO
                "acpio",
#endif
                NULL};
        bool allow_verification_error = device_is_unlocked();;

        ops = avb_init();
        if (! ops) {
                ret = EFI_OUT_OF_RESOURCES;
                goto fail;
        }

        if (use_slot()) {
                slot_suffix = slot_get_active();
                if (!slot_suffix) {
                        error(L"suffix is null");
                        slot_suffix = "";
                }
        }

        flags = AVB_SLOT_VERIFY_FLAGS_NONE;
        if (allow_verification_error)
                flags |= AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR;

        verify_result = avb_slot_verify(ops,
                        requested_partitions,
                        slot_suffix,
                        flags,
                        AVB_HASHTREE_ERROR_MODE_RESTART,
                        slot_data);

        debug(L"avb_slot_verify ret %d\n", verify_result);

        ret = get_avb_result(*slot_data,
                        allow_verification_error,
                        verify_result,
                        boot_state);

        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Failed to get avb result for boot");
                goto fail;
        }

        ret = android_query_image_from_avb_result(*slot_data, label, bootimage_p);
        if (EFI_ERROR(ret)) {
                avb_error("Cannot find android image partition!\n");
                goto fail;
        }

        ret = android_install_acpi_table_avb(*slot_data);
        if (EFI_ERROR(ret)) goto fail;

        return ret;
fail:
        *boot_state = BOOT_STATE_RED;
        return ret;
}


EFI_STATUS android_image_load_partition_avb_ab(
                IN const char *label,
                OUT VOID **bootimage_p,
                IN OUT UINT8* boot_state,
                AvbSlotVerifyData **slot_data)
{
#ifndef USE_SLOT
        return android_image_load_partition_avb(label, bootimage_p, boot_state, slot_data);
#else
        EFI_STATUS ret = EFI_SUCCESS;
        AvbABFlowResult flow_result;
        AvbSlotVerifyFlags flags;
        const char *requested_partitions[] = {label,
#ifdef USE_ACPI
                "acpi",
#endif
#ifdef USE_ACPIO
                "acpio",
#endif
                NULL};
        bool allow_verification_error = device_is_unlocked();

        flags = AVB_SLOT_VERIFY_FLAGS_NONE;
        if (allow_verification_error)
                flags |= AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR;

        flow_result = avb_ab_flow(&ab_ops, requested_partitions, flags, AVB_HASHTREE_ERROR_MODE_RESTART, slot_data);
        ret = get_avb_flow_result(*slot_data,
                allow_verification_error,
                flow_result,
                boot_state);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Failed to get avb slot a/b flow result for boot");
                goto fail;
        }
        slot_set_active_cached((*slot_data)->ab_suffix);

        ret = android_query_image_from_avb_result(*slot_data, label, bootimage_p);
        if (EFI_ERROR(ret)) {
                avb_error("Cannot find android image partition!\n");
                goto fail;
        }
        avb_debug("Image read success\n");

        ret = android_install_acpi_table_avb(*slot_data);
        if (EFI_ERROR(ret)) goto fail;

        return ret;
fail:
        *boot_state = BOOT_STATE_RED;
        return ret;
#endif // USE_SLOT
}
