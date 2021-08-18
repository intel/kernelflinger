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

#include "elf32_ld.h"
#include "elf_ld.h"

#define local_print(fmt, ...)
//#define local_print(fmt, ...) debug(fmt, ##__VA_ARGS__)

BOOLEAN
elf32_get_segment_info(const elf32_ehdr_t *ehdr,
				uint16_t segment_no, elf_segment_info_t *p_info)
{
	const uint8_t *phdrtab;
	const elf32_phdr_t *phdr;
	if (segment_no < ehdr->e_phnum) {
		phdrtab = (const uint8_t *)ehdr + ehdr->e_phoff;
		phdr = (const elf32_phdr_t *)GET_PHDR(ehdr,
			phdrtab,
			segment_no);

		p_info->address = (char *)(UINTN)phdr->p_paddr;
		p_info->size = phdr->p_memsz;

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
elf32_update_rela_section(uint32_t relocation_offset, elf32_dyn_t *dyn_section, uint64_t dyn_section_sz)
{
	elf32_rela_t *rela = NULL;
	uint32_t rela_sz = 0;
	uint32_t rela_entsz = 0;
	elf32_sym_t *symtab = NULL;
	uint32_t symtab_entsz = 0;
	uint32_t i;
	elf32_rel_t *rel = NULL;
	uint32_t rel_sz = 0;
	uint32_t rel_entsz = 0;

	if (!dyn_section) {
		local_print(L"failed to read dynamic section from file.\n");
		return FALSE;
	}

	/* locate rela address, size, entry size */
	for (i = 0; i < dyn_section_sz / sizeof(elf32_dyn_t); ++i) {
		if (DT_RELA == dyn_section[i].d_tag) {
			rela =
				(elf32_rela_t *)(UINTN)((uint64_t)dyn_section[i].d_un.d_ptr +
							 (uint64_t)relocation_offset);
		}

		if (DT_RELASZ == dyn_section[i].d_tag) {
			rela_sz = dyn_section[i].d_un.d_val;
		}

		if (DT_RELAENT == dyn_section[i].d_tag) {
			rela_entsz = dyn_section[i].d_un.d_val;
		}

		if (DT_SYMTAB == dyn_section[i].d_tag) {
			symtab =
				(elf32_sym_t *)(UINTN)((uint64_t)dyn_section[i].d_un.d_ptr +
							(uint64_t)relocation_offset);
		}

		if (DT_SYMENT == dyn_section[i].d_tag) {
			symtab_entsz = dyn_section[i].d_un.d_val;
		}

		if (DT_REL == dyn_section[i].d_tag) {
			rel =
				(elf32_rel_t *)(UINTN)((uint64_t)dyn_section[i].d_un.d_ptr +
							(uint64_t)relocation_offset);
		}

		if (DT_RELSZ == dyn_section[i].d_tag) {
			rel_sz = dyn_section[i].d_un.d_val;
		}

		if (DT_RELENT == dyn_section[i].d_tag) {
			rel_entsz = dyn_section[i].d_un.d_val;
		}
	}

	/* handle DT_RELA tag: */
	if ((NULL != rela)
		&& rela_sz && (NULL != symtab)
		&& (sizeof(elf32_rela_t) == rela_entsz)
		&& (sizeof(elf32_sym_t) == symtab_entsz)) {
		for (i = 0; i < rela_sz / rela_entsz; ++i) {
			uint32_t *target_addr =
				(uint32_t *)(UINTN)((uint64_t)rela[i].r_offset +
						 (uint64_t)relocation_offset);
			uint32_t symtab_idx;

			switch (rela[i].r_info & 0xFF) {
			case R_386_32:
				*target_addr = rela[i].r_addend + relocation_offset;
				symtab_idx = rela[i].r_info >> 8;
				*target_addr += symtab[symtab_idx].st_value;
				break;
			case R_386_RELATIVE:
				*target_addr = rela[i].r_addend + relocation_offset;
				break;
			case 0: /* do nothing */
				break;
			default:
				local_print(
					L"Unsupported Relocation. rlea.r_info = %#x\n", rela[i].r_info & 0xFF);
				return FALSE;
			}
		}

		return TRUE;
	}

	/* handle DT_REL tag: */
	if ((NULL != rel) && (NULL != symtab)
		&& rel_sz && (sizeof(elf32_rel_t) == rel_entsz)) {
		/* Only elf32_rela_t and elf64_rela_t entries contain an explicit addend.
		 * Entries of type elf32_rel_t and elf64_rel_t store an implicit addend in
		 * the location to be modified. Depending on the processor
		 * architecture, one form or the other might be necessary or more
		 * convenient. Consequently, an implementation for a particular machine
		 * may use one form exclusively or either form depending on context. */
		for (i = 0; i < rel_sz / rel_entsz; ++i) {
			uint32_t *target_addr =
				(uint32_t *)(UINTN)((uint64_t)rel[i].r_offset +
						 (uint64_t)relocation_offset);
			uint32_t symtab_idx;

			switch (rel[i].r_info & 0xFF) {
			case R_386_32:
				*target_addr += relocation_offset;
				symtab_idx = rel[i].r_info >> 8;
				*target_addr += symtab[symtab_idx].st_value;
				break;

			case R_386_RELATIVE:
				/* read the dword at this location, add it to the run-time
				 * start address of this module; deposit the result back into
				 * this dword */
				*target_addr += relocation_offset;
				break;

			default:
				local_print(
					L"Unsupported Relocation, rel.r_info = %#x\n", rel[i].r_info & 0xFF);
				return FALSE;
			}
		}

		return TRUE;
	}

	return FALSE;
}

static void elf32_update_segment_table(module_file_info_t *file_info, uint32_t relocation_offset)
{
	elf32_ehdr_t *ehdr;
	uint8_t *phdrtab;
	uint32_t i;
	ehdr = (elf32_ehdr_t *)(UINTN)(uint64_t)file_info->runtime_addr;
	phdrtab = (uint8_t *)(UINTN)(uint64_t)(file_info->runtime_addr + ehdr->e_phoff);

	for (i = 0; i < (uint16_t)ehdr->e_phnum; ++i) {
		elf32_phdr_t *phdr = (elf32_phdr_t *)GET_PHDR(ehdr, phdrtab, i);

		if (0 != phdr->p_memsz) {
			phdr->p_paddr += relocation_offset;
			phdr->p_vaddr += relocation_offset;
		}
	}
}


/*
 *  FUNCTION  : elf32_load_executable
 *  PURPOSE   : Load and relocate ELF-x32 executable to memory
 *  ARGUMENTS : mem_image_info_t *image - describes image to load
 *            : elf_load_info_t *p_info - contains load-related data
 *  RETURNS   :
 *  NOTES     : Load map (addresses grow from up to bottom)
 *            :        elf header
 *            :        loadable program segments
 *            :        section headers table (optional)
 *            :        loaded sections        (optional)
 */
BOOLEAN
elf32_load_executable(module_file_info_t *file_info, uint64_t *p_entry)
{
	elf32_ehdr_t *ehdr;             /* ELF header */
	uint8_t *phdrtab;               /* Program Segment header Table */
	uint32_t phsize;            /* Program Segment header Table size */
	uint32_t low_addr = (uint32_t) ~0;
	uint32_t max_addr = 0;
	uint32_t addr;
	uint32_t memsz;
	uint32_t filesz;
	uint16_t i;
	elf32_phdr_t *phdr_dyn = NULL;
	elf32_dyn_t *dyn_section;
	uint32_t relocation_offset;
	uint64_t offset_0_addr = (uint64_t)~0;

	/* map ELF header to ehdr */
	ehdr = (elf32_ehdr_t *)(uint8_t *)image_offset(file_info, 0,
			sizeof(elf32_ehdr_t));
	if (!ehdr) {
		return FALSE;
	}

	/* map Program Segment header Table to phdrtab */
	phsize = ehdr->e_phnum * sizeof(elf32_phdr_t);
	phdrtab = (uint8_t *)image_offset
			(file_info, (uint64_t)ehdr->e_phoff, (uint64_t)phsize);
	if (!phdrtab){
		return FALSE;
	}

	/* Calculate amount of memory required. First calculate size of all
		 * loadable segments */
	for (i = 0; i < (uint16_t)ehdr->e_phnum; ++i) {
		elf32_phdr_t *phdr = (elf32_phdr_t *)GET_PHDR(ehdr, phdrtab, i);

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
		local_print(
			L"Failed because kernel low address is not page aligned, low_addr = %#p", low_addr);
		return FALSE;
	}

	file_info->runtime_image_size = PAGE_ALIGN_4K(max_addr - low_addr);
	if (file_info->runtime_total_size < file_info->runtime_image_size ||
		0 == file_info->runtime_image_size) {
		local_print(L"dest memory is smaller than required or it is zero\n");
		return FALSE;
	}

	relocation_offset = (uint32_t)file_info->runtime_addr - low_addr;

	/* now actually copy image to its target destination */
	for (i = 0; i < (uint16_t)ehdr->e_phnum; ++i) {
		elf32_phdr_t *phdr = (elf32_phdr_t *)GET_PHDR(ehdr, phdrtab, i);
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

		if (!image_copy((void *)(UINTN)((uint64_t)addr + (uint64_t)relocation_offset),
				file_info, (uint64_t)phdr->p_offset, (uint64_t)filesz)) {
			local_print(L"failed to read segment from file\n");
			return FALSE;
		}

		if (filesz < memsz) { /* zero BSS if exists */
			memset_s((void *)(UINTN)((uint64_t)addr + (uint64_t)filesz +
						    (uint64_t)relocation_offset), memsz - filesz, 0,
				memsz - filesz);
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
		elf32_update_segment_table(file_info, relocation_offset);
	}

	if (NULL != phdr_dyn) {
		dyn_section = (elf32_dyn_t *)image_offset
				   (file_info, (uint64_t)phdr_dyn->p_offset, (uint64_t)phdr_dyn->p_filesz);
		if (!elf32_update_rela_section(relocation_offset, dyn_section, phdr_dyn->p_filesz))
				return FALSE;
	}

	/* get the relocation entry addr */
	*p_entry = ehdr->e_entry + relocation_offset;

	return TRUE;
}
