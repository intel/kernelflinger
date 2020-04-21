/*
 * Copyright (c) 2013, Intel Corporation
 * All rights reserved.
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

#ifndef __ACPI_H__
#define __ACPI_H__

#include <efi.h>
#include <efiapi.h>
#include <efilib.h>
#include "targets.h"

#pragma pack(1)

/** Generic ACPI table header **/
struct ACPI_DESC_HEADER {
	CHAR8   signature[4];		/* ASCII Table identifier */
	UINT32  length;			/* Length of the table, including the header */
	CHAR8   revision;		/* Revision of the structure */
	CHAR8   checksum;		/* Sum of all fields must be 0 */
	CHAR8   oem_id[6];		/* ASCII OEM identifier */
	CHAR8   oem_table_id[8];	/* ASCII OEM table identifier */
	UINT32  oem_revision;		/* OEM supplied revision number */
	CHAR8   creator_id[4];		/* Vendor ID of utility creator of the table */
	UINT32  creator_revision;	/* Revision of utility creator of the table */
};

struct RSDP_TABLE {
	CHAR8	signature[8];		/* "RSD PTR " */
	CHAR8	checksum;		/* RSDP Checksum (bytes 0-19) */
	CHAR8	oem_id[6];		/* OEM ID String */
	CHAR8	revision;		/* ACPI Revision (0=1.0,2=2.0) */
	UINT32	rsdt_address;		/* 32-bit RSDT Pointer */
	UINT32	length;			/* RSDP Length */
	UINT64	xsdt_address;		/* 64-bit XSDT Pointer */
	CHAR8	extended_checksum;	/* RSDP Checksum (full) */
	CHAR8	reserved[3];		/* Reserved */
};

struct XSDT_TABLE {
	struct ACPI_DESC_HEADER header;
	UINT64 entry[1];		/* Table Entries */
};

/* Minimal definition of the FACP to get the DSDT memory address. */
struct FACP_TABLE {
	struct ACPI_DESC_HEADER header;
	UINT32 firmware_ctrl;		/* Physical memory address of the FACS. */
	UINT32 DSDT;			/* Physical memory address (0-4 GB) of the DSDT. */
					/* [...] */
};

struct RSCI_TABLE {
	struct ACPI_DESC_HEADER header;
	CHAR8 wake_source;		/* How system woken up from S4 or S5 */
	CHAR8 reset_source;		/* How system was reset */
	CHAR8 reset_type;		/* Identify type of reset */
	CHAR8 shutdown_source;		/* How system was last shutdown */
	UINT32 indicators;		/* Bitmap with additional info */
	UINT32 reset_extra_info;	/* Reports system specific reset sources */
};

enum {
	OEM1_USE_IA_APPS_CAP,
	OEM1_USE_IA_APPS_RUN
};

struct OEM1_TABLE {
	struct ACPI_DESC_HEADER header;
	UINT8 fixedoptions0;		/* Fixed Platform Options 0 */
	UINT8 fixedoptions1;		/* Fixed Platform Options 1*/
	UINT8 dbiingpio;		/* DBIIN GPIO number */
	UINT8 dbioutgpio;		/* DBIOUT GPIO number */
	UINT8 batchptyp;       		/* Identification / Authentication chip
					 * inside the battery */
	UINT16 ia_apps_run;		/* Minimum battery voltage required to
					 * boot the platform if FG has been
					 * reset */
	UINT8 batiddbibase;		/* Resistance in KOhms for BSI used to
					 * indicate a digital battery */
	UINT8 batidanlgbase;		/* Resistance in KOhms for BSI beyond
					 * which the battery is an analog
					 * battery */
	UINT8 ia_apps_cap; 		/* Minimum capacity at which to boot to Main
					 * OS */
	UINT16 vbattfreqlmt;		/* Battery Voltage up to which the CPU
					 * frequency should be limited */
	UINT8 capfreqidx;   		/* Index into the Frequency table at which
					 * the CPU Frequency should be capped. */
	UINT8 rsvd1;			/* Reserved */
	UINT8 battidx; 			/* Battery Index: Charging profile to use in
					 * case of fixed battery */
	UINT8 ia_apps_to_use;		/* Whether to use the IA_APPS_RUN (value
					 * = 1) or IA_APPS_CAP (value = 0) to
					 * while booting */
	UINT8 turbochrg;		/* Maximum Turbo charge supported (in
					 * multiples of 100mA). Zero means no Turbo
					 * charge */
	UINT8 rsvd2[11];		/* Reserved */
};

/* BERT (Boot Error Record Table) as defined in ACPI spec, APEI chapter */
struct BERT_TABLE {
	struct ACPI_DESC_HEADER header;
	UINT32 region_length;		/* Length of BERT region */
	UINT64 region;			/* Physical address of BERT region */
};


struct ACPI_INFO {
	UINT32 MediaId;
	UINT32 img_size;		/* ACPI or ACPIO image size */
	UINT64 partition_start;
	UINT64 partition_size;
};

#pragma pack()

enum acpi_src_type {
	BOOT_ACPI = 0,
	ACPIO,
	ACPI_SRC_TYPE_MAX
};

/* Some ACPI table signatures, SSDT for instance, might appear several
 * times.  An extra table number can be appended to the supplied
 * SIGNATURE to specify which one is required.  For instance, with
 * SIGNATURE set to "SSDT2", the second SSDT table is returned.  */
EFI_STATUS get_acpi_table(const CHAR8 *signature, VOID **table);
UINT16 oem1_get_ia_apps_run(void);
UINT8 oem1_get_ia_apps_cap(void);
UINT8 oem1_get_ia_apps_to_use(void);

#define ACPI_TABLE_MAGIC		0x41435049
#define ACPI_TABLE_MAGIC_SIZE		4
#define ACPI_TABLE_MAX_LOAD_NUM		256

EFI_STATUS install_acpi_table_from_partitions(VOID *image,
					      const char *part_name);
EFI_STATUS install_acpi_table_from_recovery_acpio(VOID *image);
EFI_STATUS install_acpi_table(VOID *acpi_table, UINTN acpi_table_size,
			      UINTN *tablekey);
EFI_STATUS acpi_parse_selected_table_id(CHAR8 *selected_id_str,
					UINT32 selected_id_str_len);
EFI_STATUS acpi_image_get_length(const CHAR16 *label, struct ACPI_INFO **acpi_info);
CHAR8 *acpi_loaded_table_idx_to_string(enum acpi_src_type type);
EFI_STATUS install_acpi_table_from_boot_acpi(VOID *acpiimage, UINTN total_size);

VOID acpi_set_boot_target(enum boot_target target);

#endif /* __ACPI_H__ */
