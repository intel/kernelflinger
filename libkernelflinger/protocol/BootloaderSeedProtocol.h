/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 *
 * Author: Ming Tan <ming.tan@intel.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#ifndef _BOOTLOADER_SEED_PROTOCOL_H_
#define _BOOTLOADER_SEED_PROTOCOL_H_


#define BOOTLOADER_SEED_PROTOCOL_GUID \
  {0x3e764148, 0x316c, 0x41ba, { 0x9b, 0x85, 0x94, 0x3f, 0x92, 0xa3, 0xcc, 0x7f } }

typedef struct _BOOTLOADER_SEED_PROTOCOL BOOTLOADER_SEED_PROTOCOL;


/**
 * Tell the BIOS should end of the service of this protocol.
 *
 * Kernelflinger should call this function after call other functions.
 * Then BIOS should return EFI_ACCESS_DENIED if call the other functions again.
 */
typedef
EFI_STATUS
(EFIAPI *BLS_PROTOCOL_ENDOFSERVICE) ();


#define BOOTLOADER_SEED_LEN  64
typedef struct {
  UINT8 cse_svn;   // Always 0 for fixed seed
  UINT8 bios_svn;  // Always 0 for fixed seed.
                   // For SVN bound seed, populated in ICL, EHL and above.
  UINT8 Reserved[2];
  UINT8 seed[BOOTLOADER_SEED_LEN];
} BOOTLOADER_SEED_INFO;

#define BOOTLOADER_SEED_INFO_LIST_MAX_ENTRIES  10
typedef struct {
  UINT8                NumOfSeeds;
  BOOTLOADER_SEED_INFO SeedList[BOOTLOADER_SEED_INFO_LIST_MAX_ENTRIES];
} BOOTLOADER_SEED_INFO_LIST;

/**
 * Get the seed info list.
 *
 * Kernelflinger will prepare for the data buffer, and BIOS will copy the data to this buffer.
 */
typedef
EFI_STATUS
(EFIAPI *BLS_PROTOCOL_GET_SEED_INFO_LIST) (
  IN OUT BOOTLOADER_SEED_INFO_LIST *buf
  );


/* The max RPMB key size set to 64, and currently is 32 bytes in general, use rpmb_key[0-31]. */
#define BOOTLOADER_RPMB_MAX_KEY_SIZE  64
typedef struct {
  UINT8 rpmb_partition_no;  // This key is used for which RPMB partition, if the hardware has multi RPMB partitions.
  UINT8 rpmb_key_size;
  UINT8 rpmb_key[BOOTLOADER_RPMB_MAX_KEY_SIZE];
} BOOTLOADER_RPMB_KEY;

/**
 * Get the RPMB key.
 *
 * Kernelflinger will prepare for the data buffer, and BIOS will copy the data to this buffer.
 * If there are several RPMB partitions, then BIOS only put the RPMB keys to the RPMB partitions used by bootloader,
 * and set the other RPMB keys to all zero.
 *
 * @num_keys  IN   the entry size of buf, in general is 6 for max RPMB partitions/keys.
 *            OUT  the final output keys number, should <= the input value.
 *
 * @buf       IN   the input array of BOOTLOADER_RPMB_KEY, has num_keys entry.
 *            OUT  the BIOS will copy data to the input buffer.
 */
typedef
EFI_STATUS
(EFIAPI *BLS_PROTOCOL_GET_RPMB_KEY) (
  IN OUT UINT8 *num_keys,
  IN OUT BOOTLOADER_RPMB_KEY *buf
  );


#define BOOTLOADER_ATTKB_ENC_KEY_LEN  32
typedef struct {
  UINT8 attkb_enc_key[BOOTLOADER_ATTKB_ENC_KEY_LEN];
} BOOTLOADER_ATTKB_ENC_KEY;

/**
 * Get the encrypt key for attkb.
 *
 * Kernelflinger will prepare for the data buffer, and the BIOS will copy the data to this buffer.
 */
typedef
EFI_STATUS
(EFIAPI *BLS_PROTOCOL_GET_ATTKB_ENC_KEY) (
  IN OUT BOOTLOADER_ATTKB_ENC_KEY *buf
  );


struct _BOOTLOADER_SEED_PROTOCOL {
  BLS_PROTOCOL_ENDOFSERVICE             EndOfService;
  BLS_PROTOCOL_GET_SEED_INFO_LIST       GetSeedInfoList;
  BLS_PROTOCOL_GET_RPMB_KEY             GetRpmbKey;
  BLS_PROTOCOL_GET_ATTKB_ENC_KEY        GetAttKBEncKey;
};

#endif /* _BOOTLOADER_SEED_PROTOCOL_H_*/
