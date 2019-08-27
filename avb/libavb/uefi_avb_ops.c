/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <efi.h>
#include <efilib.h>
#include "uefi_avb_ops.h"
#include "uefi_avb_util.h"
#include "vars.h"
#include "gpt.h"
#include "lib.h"
#include "log.h"
#ifdef RPMB_STORAGE
#include "rpmb_storage.h"
#endif

extern char _binary_avb_pk_start;
extern char _binary_avb_pk_end;
#define avb_pk (&_binary_avb_pk_start)
#define avb_pk_size (&_binary_avb_pk_end - &_binary_avb_pk_start)

static AvbIOResult read_from_partition(__attribute__((unused)) AvbOps* ops,
                                       const char* partition_name,
                                       int64_t offset_from_partition,
                                       size_t num_bytes,
                                       void* buf,
                                       size_t* out_num_read) {
  EFI_STATUS efi_ret;
  struct gpt_partition_interface gpart;
  int64_t partition_size;
  const CHAR16 *label;

  avb_assert(partition_name != NULL);
  avb_assert(buf != NULL);
  avb_assert(out_num_read != NULL);

  label = stra_to_str((const CHAR8 *)partition_name);

  if (!label) {
    error(L"out of memory");
    return AVB_IO_RESULT_ERROR_OOM;
  }

  efi_ret = gpt_get_partition_by_label(label, &gpart, LOGICAL_UNIT_USER);
  if (EFI_ERROR(efi_ret)) {
    error(L"Partition %s not found", label);
    return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
  }

  partition_size =
      (gpart.part.ending_lba - gpart.part.starting_lba + 1) *
      gpart.bio->Media->BlockSize;

  if (offset_from_partition < 0) {
    if ((-offset_from_partition) > partition_size) {
      avb_error("Offset outside range.\n");
      return AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION;
    }
    offset_from_partition = partition_size - (-offset_from_partition);
  }

  /* Check if num_bytes goes beyond partition end. If so, don't read beyond
   * this boundary -- do a partial I/O instead.
   */
  if (num_bytes > (size_t)(partition_size - offset_from_partition))
    *out_num_read = partition_size - offset_from_partition;
  else
    *out_num_read = num_bytes;

  efi_ret = uefi_call_wrapper(
      gpart.dio->ReadDisk,
      5,
      gpart.dio,
      gpart.bio->Media->MediaId,
      (gpart.part.starting_lba * gpart.bio->Media->BlockSize) +
          offset_from_partition,
      *out_num_read,
      buf);
  if (EFI_ERROR(efi_ret)) {
    avb_error("Could not read from Disk.\n");
    *out_num_read = 0;
    return AVB_IO_RESULT_ERROR_IO;
  }

  return AVB_IO_RESULT_OK;
}

static AvbIOResult write_to_partition(__attribute__((unused)) AvbOps* ops,
                                      const char* partition_name,
                                      int64_t offset_from_partition,
                                      size_t num_bytes,
                                      const void* buf) {
  EFI_STATUS efi_ret;
  struct gpt_partition_interface gpart;
  uint64_t partition_size;
  const CHAR16 * label;

  avb_assert(partition_name != NULL);
  avb_assert(buf != NULL);

  label = stra_to_str((const CHAR8 *)partition_name);
  if (!label) {
    error(L"out of memory");
    return AVB_IO_RESULT_ERROR_OOM;
  }

  efi_ret = gpt_get_partition_by_label(label, &gpart, LOGICAL_UNIT_USER);
  if (EFI_ERROR(efi_ret)) {
    error(L"Partition %s not found", label);
    return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
  }

  partition_size =
      (gpart.part.ending_lba - gpart.part.starting_lba + 1) *
      gpart.bio->Media->BlockSize;

  if (offset_from_partition < 0) {
    if ((-offset_from_partition) > (int)partition_size) {
      avb_error("Offset outside range.\n");
      return AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION;
    }
    offset_from_partition = partition_size - (-offset_from_partition);
  }

  /* Check if num_bytes goes beyond partition end. If so, error out -- no
   * partial I/O.
   */
  if (num_bytes > partition_size - offset_from_partition) {
    avb_error("Cannot write beyond partition boundary.\n");
    return AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION;
  }

  efi_ret = uefi_call_wrapper(
      gpart.dio->WriteDisk,
      5,
      gpart.dio,
      gpart.bio->Media->MediaId,
      (gpart.part.starting_lba * gpart.bio->Media->BlockSize) +
          offset_from_partition,
      num_bytes,
      (void *)buf);

  if (EFI_ERROR(efi_ret)) {
    avb_error("Could not write to Disk.\n");
    return AVB_IO_RESULT_ERROR_IO;
  }

  return AVB_IO_RESULT_OK;
}

static AvbIOResult get_size_of_partition(__attribute__((unused)) AvbOps* ops,
                                         const char* partition_name,
                                         uint64_t* out_size) {
  EFI_STATUS efi_ret;
  struct gpt_partition_interface gpart;
  uint64_t partition_size;
  const CHAR16 * label;

  avb_assert(partition_name != NULL);

  label = stra_to_str((const CHAR8 *)partition_name);
  if (!label) {
    error(L"out of memory");
    return AVB_IO_RESULT_ERROR_OOM;
  }

  efi_ret = gpt_get_partition_by_label(label, &gpart, LOGICAL_UNIT_USER);
  if (EFI_ERROR(efi_ret)) {
    error(L"Partition %s not found", label);
    return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
  }

  partition_size =
      (gpart.part.ending_lba - gpart.part.starting_lba + 1) *
      gpart.bio->Media->BlockSize;

  if (out_size != NULL) {
    *out_size = partition_size;
  }

  return AVB_IO_RESULT_OK;
}

static AvbIOResult validate_vbmeta_public_key(
    __attribute__((unused)) AvbOps* ops,
    const uint8_t* public_key_data,
    size_t public_key_length,
    __attribute__((unused)) const uint8_t* public_key_metadata,
    __attribute__((unused)) size_t public_key_metadata_length,
    bool* out_key_is_trusted) {

  if (out_key_is_trusted != NULL) {
    *out_key_is_trusted = false;
  }

  if ((!public_key_data) || (public_key_length == 0))
  {
    return AVB_IO_RESULT_ERROR_IO;
  }

  if ((public_key_length <= (size_t)avb_pk_size) && !memcmp(avb_pk, public_key_data, public_key_length))
  {
    if (out_key_is_trusted != NULL) {
      *out_key_is_trusted = true;
    }
  }
  return AVB_IO_RESULT_OK;
}

static AvbIOResult read_rollback_index(__attribute__((unused)) AvbOps* ops,
                                       size_t rollback_index_slot,
                                       uint64_t* out_rollback_index) {
  EFI_STATUS ret = AVB_IO_RESULT_OK;

  if (out_rollback_index == NULL)
    return ret;

  if (is_live_boot())
    ret = EFI_NOT_FOUND;
  else {
#if defined(SECURE_STORAGE_EFIVAR)
    ret = read_efi_rollback_index(rollback_index_slot, out_rollback_index);
#elif defined(SECURE_STORAGE_RPMB)
    ret = read_rpmb_rollback_index(rollback_index_slot, out_rollback_index);
#else
  *out_rollback_index = 0;
#endif
  }

  if (ret == EFI_NOT_FOUND) {
    *out_rollback_index = 0;
    ret = EFI_SUCCESS;
  }
  if (EFI_ERROR(ret)) {
    efi_perror(ret, L"Couldn't read rollback index");
    return AVB_IO_RESULT_ERROR_IO;
  }

  return ret;
}

static AvbIOResult write_rollback_index(__attribute__((unused)) AvbOps* ops,
                                        size_t rollback_index_slot,
                                        uint64_t rollback_index) {
  EFI_STATUS ret = AVB_IO_RESULT_OK;

  if (rollback_index == 0)
    return ret;

  if (is_live_boot())
    ret = EFI_SUCCESS;
  else {
#if defined(SECURE_STORAGE_EFIVAR)
    ret = write_efi_rollback_index(rollback_index_slot, rollback_index);
#elif defined(SECURE_STORAGE_RPMB)
    ret = write_rpmb_rollback_index(rollback_index_slot, rollback_index);
#endif
  }
  if (EFI_ERROR(ret)) {
    efi_perror(ret, L"Couldn't write rollback index");
    return AVB_IO_RESULT_ERROR_IO;
  }

  return ret;
}

static AvbIOResult read_is_device_unlocked(__attribute__((unused)) AvbOps* ops, bool* out_is_unlocked) {
  avb_debug("read_is_device_unlocked().\n");
  *out_is_unlocked = device_is_unlocked();
  return AVB_IO_RESULT_OK;
}

static void set_hex(char* buf, uint8_t value) {
  char hex_digits[17] = "0123456789abcdef";
  buf[0] = hex_digits[value >> 4];
  buf[1] = hex_digits[value & 0x0f];
}

static AvbIOResult get_unique_guid_for_partition(__attribute__((unused)) AvbOps* ops,
                                                 const char* partition,
                                                 char* guid_buf,
                                                 size_t guid_buf_size) {
  EFI_STATUS efi_ret;
  struct gpt_partition_interface gpart;
  uint8_t * unique_guid;
  const CHAR16 * label;



  avb_assert(partition != NULL);
  avb_assert(guid_buf != NULL);

  label = stra_to_str((const CHAR8 *)partition);
  if (!label) {
    error(L"out of memory");
    return AVB_IO_RESULT_ERROR_OOM;
  }

  efi_ret = gpt_get_partition_by_label(label, &gpart, LOGICAL_UNIT_USER);
  if (EFI_ERROR(efi_ret)) {
    error(L"Partition %s not found", label);
    return AVB_IO_RESULT_ERROR_IO;
  }

  if (guid_buf_size < 37) {
    avb_error("GUID buffer size too small.\n");
    return AVB_IO_RESULT_ERROR_IO;
  }

  unique_guid =(uint8_t *)&(gpart.part.unique);
  /* The GUID encoding is somewhat peculiar in terms of byte order. It
   * is what it is.
   */
  set_hex(guid_buf + 0, unique_guid[3]);
  set_hex(guid_buf + 2, unique_guid[2]);
  set_hex(guid_buf + 4, unique_guid[1]);
  set_hex(guid_buf + 6, unique_guid[0]);
  guid_buf[8] = '-';
  set_hex(guid_buf + 9, unique_guid[5]);
  set_hex(guid_buf + 11, unique_guid[4]);
  guid_buf[13] = '-';
  set_hex(guid_buf + 14, unique_guid[7]);
  set_hex(guid_buf + 16, unique_guid[6]);
  guid_buf[18] = '-';
  set_hex(guid_buf + 19, unique_guid[8]);
  set_hex(guid_buf + 21, unique_guid[9]);
  guid_buf[23] = '-';
  set_hex(guid_buf + 24, unique_guid[10]);
  set_hex(guid_buf + 26, unique_guid[11]);
  set_hex(guid_buf + 28, unique_guid[12]);
  set_hex(guid_buf + 30, unique_guid[13]);
  set_hex(guid_buf + 32, unique_guid[14]);
  set_hex(guid_buf + 34, unique_guid[15]);
  guid_buf[36] = '\0';
  return AVB_IO_RESULT_OK;
}

AvbOps* uefi_avb_ops_new(void) {
  UEFIAvbOpsData* data;
  EFI_STATUS err;
  //EFI_LOADED_IMAGE* loaded_app_image = NULL;
  //EFI_GUID loaded_image_protocol = LOADED_IMAGE_PROTOCOL;
  struct gpt_partition_interface gparti;

  err = gpt_get_root_disk(&gparti, LOGICAL_UNIT_USER);
  if (EFI_ERROR(err)) {
      avb_error("Failed to get disk information.\n");
      return NULL;
  }

  data = avb_calloc(sizeof(UEFIAvbOpsData));
  data->ops.user_data = data;
  data->ops.ab_ops = NULL;
  data->block_io = gparti.bio;
  data->disk_io  = gparti.dio;
  data->ops.read_from_partition = read_from_partition;
  data->ops.write_to_partition = write_to_partition;
  data->ops.get_size_of_partition = get_size_of_partition;
  data->ops.validate_vbmeta_public_key = validate_vbmeta_public_key;
  data->ops.read_rollback_index = read_rollback_index;
  data->ops.write_rollback_index = write_rollback_index;
  data->ops.read_is_device_unlocked = read_is_device_unlocked;
  data->ops.get_unique_guid_for_partition = get_unique_guid_for_partition;

  return &data->ops;
}

void uefi_avb_ops_free(AvbOps* ops) {
  UEFIAvbOpsData* data = ops->user_data;
  avb_free(data);
}
