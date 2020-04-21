/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef DT_TABLE_H
#define DT_TABLE_H

#include <efi.h>
/*
 * For the image layout, refer README.md for the detail
 */

#define DT_TABLE_MAGIC 0xd7b7ab1e
#define DT_TABLE_DEFAULT_PAGE_SIZE 2048
#define DT_TABLE_DEFAULT_VERSION 0

struct dt_table_header {
	UINT32 magic;             /* DT_TABLE_MAGIC */
	UINT32 total_size;        /* includes dt_table_header + all dt_table_entry
				     and all dtb/dtbo */
	UINT32 header_size;       /* sizeof(dt_table_header) */

	UINT32 dt_entry_size;     /* sizeof(dt_table_entry) */
	UINT32 dt_entry_count;    /* number of dt_table_entry */
	UINT32 dt_entries_offset; /* offset to the first dt_table_entry
				     from head of dt_table_header.
				     The value will be equal to header_size if
				     no padding is appended */

	UINT32 page_size;         /* flash page size we assume */
	UINT32 version;           /* DTBO image version, the current version is 0.
				     The version will be incremented when the
				     dt_table_header struct is updated. */
};

struct dt_table_entry {
	UINT32 dt_size;
	UINT32 dt_offset;         /* offset from head of dt_table_header */

	UINT32 id;                /* optional, must be zero if unused */
	UINT32 rev;               /* optional, must be zero if unused */
	UINT32 custom[4];         /* optional, must be zero if unused */
};

#endif
