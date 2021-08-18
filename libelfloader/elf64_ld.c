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

#include "elf64_ld.h"
#include "elf_ld.h"

#define local_print(fmt, ...)
//#define local_print(fmt, ...) debug(fmt, ##__VA_ARGS__)

BOOLEAN
elf64_get_segment_info(const elf64_ehdr_t *ehdr,
				uint16_t segment_no, elf_segment_info_t *p_info)
{
	const uint8_t *phdrtab;
	const elf64_phdr_t *phdr;
	if (segment_no < ehdr->e_phnum) {
		phdrtab = (const uint8_t *)ehdr + ehdr->e_phoff;
		phdr = (const elf64_phdr_t *)GET_PHDR(ehdr,
			phdrtab,
			segment_no);

		p_info->address = (char *)(UINTN)phdr->p_paddr;
		p_info->size = (uint32_t)phdr->p_memsz;
		if (PT_LOAD == phdr->p_type) {
			p_info->attribute =
				phdr->p_flags &
				(ELF_ATTR_EXECUTABLE | ELF_ATTR_WRITABLE |
				 ELF_ATTR_READABLE);
		} else {
			p_info->attribute = 0;
		}
		return TRUE;
	}
	return FALSE;
}
/* prototypes of the real elf parsing functions */
static BOOLEAN
elf64_update_rela_section(uint16_t e_type, uint64_t relocation_offset, elf64_dyn_t *dyn_section, uint64_t dyn_section_sz)
{
	elf64_rela_t *rela = NULL;
	uint64_t rela_sz = 0;
	uint64_t rela_entsz = 0;
	elf64_sym_t *symtab = NULL;
	uint64_t symtab_entsz = 0;
	uint64_t i;
	uint64_t d_tag = 0;

	if (!dyn_section){
		local_print(L"failed to read dynamic section from file\n");
		return FALSE;
	}

	/* locate rela address, size, entry size */
	for (i = 0; i < dyn_section_sz / sizeof(elf64_dyn_t); ++i) {
		d_tag = dyn_section[i].d_tag;

		if(DT_RELA == d_tag) {
			rela = (elf64_rela_t *)(UINTN)(uint64_t)(dyn_section[i].d_un.d_ptr +
					relocation_offset);
		}
		else if((DT_RELASZ == d_tag) || (DT_RELSZ == d_tag)) {
			rela_sz = dyn_section[i].d_un.d_val;
		}
		else if(DT_RELAENT == d_tag) {
			rela_entsz = dyn_section[i].d_un.d_val;
		}
		else if(DT_SYMTAB == d_tag) {
			symtab = (elf64_sym_t *)(UINTN)(uint64_t)(dyn_section[i].d_un.d_ptr +
					relocation_offset);
		}
		else if(DT_SYMENT == d_tag) {
			symtab_entsz = dyn_section[i].d_un.d_val;
		}
		else { continue; }
	}

	if (NULL == rela
		|| 0 == rela_sz
		|| NULL == symtab
		|| sizeof(elf64_rela_t) != rela_entsz
		|| sizeof(elf64_sym_t) != symtab_entsz) {

		if (e_type == ET_DYN) {
			local_print(L"for DYN type relocation section is optional\n");
			return TRUE;
		}else {
			local_print(L"for EXEC type missed mandatory dynamic information\n");
			return FALSE;
		}
	}

	for (i = 0; i < rela_sz / rela_entsz; ++i) {
		uint64_t *target_addr =
			(uint64_t *)(UINTN)(uint64_t)(rela[i].r_offset +
						 relocation_offset);
		uint32_t symtab_idx;

		switch (rela[i].r_info & 0xFF) {
		/* Formula for R_x86_64_32 and R_X86_64_64 are same: S + A  */
		case R_X86_64_32:
		case R_X86_64_64:
			*target_addr = rela[i].r_addend + relocation_offset;
			symtab_idx = (uint32_t)(rela[i].r_info >> 32);
			*target_addr += symtab[symtab_idx].st_value;
			break;
		case R_X86_64_RELATIVE:
			*target_addr = rela[i].r_addend + relocation_offset;
			break;
		case 0:        /* do nothing */
			break;
		default:
			local_print(L"Unsupported Relocation %#x\n", rela[i].r_info & 0xFF);
			return FALSE;
		}
	}

	return TRUE;
}

static void elf64_update_segment_table(module_file_info_t *file_info, uint64_t relocation_offset)
{
	elf64_ehdr_t *ehdr;
	uint8_t *phdrtab;
	uint32_t i;
	ehdr = (elf64_ehdr_t *)(UINTN)(uint64_t)file_info->runtime_addr;
	phdrtab = (uint8_t *)(UINTN)(uint64_t)(file_info->runtime_addr + ehdr->e_phoff);

	for (i = 0; i < (uint16_t)ehdr->e_phnum; ++i) {
		elf64_phdr_t *phdr = (elf64_phdr_t *)GET_PHDR(ehdr, phdrtab, i);

		if (0 != phdr->p_memsz) {
			phdr->p_paddr += relocation_offset;
			phdr->p_vaddr += relocation_offset;
		}
	}
}
/*
 *  FUNCTION  : elf64_load_executable
 *  PURPOSE   : Load and relocate ELF x86-64 executable to memory
 *  ARGUMENTS : elf_load_info_t *p_info - contains load-related data
 *  RETURNS   :
 *  NOTES     : Load map (addresses grow from up to bottom)
 *            :        elf header
 *            :        loadable program segments
 *            :        section headers table (optional)
 *            :        loaded sections        (optional)
 */
BOOLEAN
elf64_load_executable(module_file_info_t *file_info, uint64_t *p_entry)
{
	elf64_ehdr_t *ehdr;
	uint8_t *phdrtab;
	uint64_t phsize;
	elf64_phdr_t *phdr;
	uint64_t low_addr = (uint64_t) ~0;
	uint64_t max_addr = 0;
	uint64_t addr;
	uint64_t memsz;
	uint64_t filesz;
	uint16_t i;
	elf64_phdr_t *phdr_dyn = NULL;
	elf64_dyn_t *dyn_section;
	uint64_t relocation_offset;
	uint64_t offset_0_addr = (uint64_t)~0;

	/* map ELF header to ehdr */
	ehdr = (elf64_ehdr_t *)(uint8_t *)image_offset(file_info, 0,
			sizeof(elf64_ehdr_t));
	if (!ehdr){
		return FALSE;
	}

	/* map Program Segment header Table to phdrtab */
	phsize = ehdr->e_phnum * sizeof(elf64_phdr_t);
	phdrtab = (uint8_t *)image_offset(file_info, (uint64_t)ehdr->e_phoff,
			(uint64_t)phsize);
	if (!phdrtab){
		return FALSE;
	}

	/* Calculate amount of memory required. First calculate size of all
	 * loadable segments */
	for (i = 0; i < (uint16_t)ehdr->e_phnum; ++i) {
		phdr = (elf64_phdr_t *)GET_PHDR(ehdr, phdrtab, i);

		addr = phdr->p_paddr;
		memsz = phdr->p_memsz;

		if (PT_LOAD != phdr->p_type || 0 == phdr->p_memsz) {
			continue;
		}

		if (addr < low_addr) {
			low_addr = addr;
		}
		if (addr + memsz > max_addr) {
			max_addr = addr + memsz;
		}
	}

	/* check the memory size */
	if (0 != (low_addr & PAGE_4K_MASK)) {
		local_print(L"failed because kernel low address "
			"not page aligned, low_addr = %#p\n", low_addr);
		return FALSE;
	}
	file_info->runtime_image_size = PAGE_ALIGN_4K(max_addr - low_addr);

	if (file_info->runtime_total_size < file_info->runtime_image_size ||
		0 == file_info->runtime_image_size) {
		local_print(L"memory is smaller than required or it is zero\n");
		return FALSE;
	}

	relocation_offset = (uint64_t)file_info->runtime_addr - low_addr;

	/* now actually copy image to its target destination */
	for (i = 0; i < (uint16_t)ehdr->e_phnum; ++i) {
		phdr = (elf64_phdr_t *)GET_PHDR(ehdr, phdrtab, i);

		if (PT_DYNAMIC == phdr->p_type) {
			phdr_dyn = phdr;
			continue;
		}

		if (PT_LOAD != phdr->p_type || 0 == phdr->p_memsz) {
			continue;
		}

		if (0 == phdr->p_offset)
			/* the p_paddr of the segment whose p_offset is 0 */
			offset_0_addr = phdr->p_paddr;

		filesz = phdr->p_filesz;
		addr = phdr->p_paddr;
		memsz = phdr->p_memsz;

		/* make sure we only load what we're supposed to! */
		if (filesz > memsz) {
			filesz = memsz;
		}

		if (!image_copy((void *)(UINTN)(uint64_t)(addr + relocation_offset),
				file_info, (uint64_t)phdr->p_offset, (uint64_t)filesz)) {
			local_print(L"failed to read segment from file\n");
			return FALSE;
		}

		if (filesz < memsz) {
			/* zero BSS if exists */
			memset_s((void *)(UINTN)(uint64_t)(addr + filesz +
						    relocation_offset), (uint64_t)(memsz - filesz), 0,
				(uint64_t)(memsz - filesz));
		}
	}

	/* if there's a segment whose p_offset is 0, elf header and
	 * segment headers are in this segment and will be relocated
	 * to target location with this segment. if such segment exists,
	 * offset_0_addr will be updated to hold the p_paddr. usually
	 * this p_paddr is the minimal address (=low_addr).
	 * add a check here to detect violation.
	 */
	if (offset_0_addr != (uint64_t)~0) {
		if (offset_0_addr != low_addr) {
			local_print(L"elf header is relocated to wrong place\n");
			return FALSE;
		}
		elf64_update_segment_table(file_info, relocation_offset);
	}

	if (NULL != phdr_dyn) {
		dyn_section = (elf64_dyn_t *)(UINTN)image_offset
			(file_info, (uint64_t)phdr_dyn->p_offset, (uint64_t)phdr_dyn->p_filesz);
		if (!elf64_update_rela_section(ehdr->e_type, relocation_offset, dyn_section, phdr_dyn->p_filesz))
			return FALSE;
	}

	/* get the relocation entry addr */
	*p_entry = ehdr->e_entry + relocation_offset;

	return TRUE;
}
