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

#ifndef _ANDROID_VB2_H_
#define _ANDROID_VB2_H_

#include "libavb/libavb.h"
#include "libavb_user/uefi_avb_ops.h"
#include "libavb_ab/libavb_ab.h"

typedef AvbSlotVerifyData VBDATA;

AvbOps *avb_init(void);

bool avb_update_stored_rollback_indexes_for_slot(AvbOps* ops, AvbSlotVerifyData* slot_data);

EFI_STATUS prepend_slot_command_line(CHAR16 **cmdline16,
        enum boot_target boot_target,
        VBDATA *vb_data);

EFI_STATUS get_avb_flow_result(
                IN AvbSlotVerifyData *slot_data,
                IN bool allow_verification_error,
                IN AvbABFlowResult flow_result,
                IN OUT UINT8 *boot_state);

EFI_STATUS get_avb_result(
                IN AvbSlotVerifyData *slot_data,
                IN bool allow_verification_error,
                IN AvbSlotVerifyResult verify_result,
                IN OUT UINT8 *boot_state);

EFI_STATUS android_query_image_from_avb_result(
                IN AvbSlotVerifyData *slot_data,
                IN const char *label,
                OUT VOID **image);

EFI_STATUS android_install_acpi_table_avb(AvbSlotVerifyData *slot_data);

EFI_STATUS android_image_load_partition_avb(
                IN const char *label,
                OUT VOID **bootimage_p,
                IN OUT UINT8* boot_state,
                AvbSlotVerifyData **slot_data);

EFI_STATUS android_image_load_partition_avb_ab(
                IN const char *label,
                OUT VOID **bootimage_p,
                IN OUT UINT8* boot_state,
                AvbSlotVerifyData **slot_data);

UINTN get_vb_cmdlen(VBDATA *vb_data);

char *get_vb_cmdline(VBDATA *vb_data);

#endif
