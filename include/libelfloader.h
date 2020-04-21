/*******************************************************************************
* Copyright (c) 2017 Intel Corporation
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
*******************************************************************************/

#ifndef _LIBELFLOADER_H_
#define _LIBELFLOADER_H_

#include "efi.h"
#include "efilib.h"

BOOLEAN relocate_elf_image(	IN uint64_t ld_addr,
				IN uint64_t ld_size,
				IN uint64_t rt_addr,
				IN uint64_t rt_size,
				OUT uint64_t *p_entry);

#endif /* _LIBELFLOADER_H_ */
