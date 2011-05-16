/*
 * PE32+ Editor
 * 
 * Copyright (C) by Wilco Baan Hofman 2010-2011
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef __FORMAT_H_
#define __FORMAT_H_

struct data {
	uint16_t strlen;
	uint8_t *data;
};

struct rsrc_value {
	uint32_t data_off;
	uint32_t size;
	uint32_t codepage;
	uint32_t reserved; /* 0 */
	/* Internal */
	uint8_t *data;
	uint32_t offset;
};

		

struct rsrc_directorytable {
	uint32_t flags;
	uint32_t timestamp;
	uint16_t major_version;
	uint16_t minor_version;
	uint16_t num_name_entries;
	uint16_t num_id_entries;
	/* Internal */
	struct rsrc_entry *entries;
	uint32_t offset;
};

/* This represents the file layout aside from the pointers */
struct rsrc_entry {
	union {                      /* High bit means name */
		uint32_t id;
		uint32_t name_off;
	};
	uint32_t entry_off;          /* High bit means directory */

	/* Internal */
	union {
		struct rsrc_directorytable *directory;
		struct rsrc_value *value;
	};
	char *name;
};

#define SECTION_TYPE_REG		0
#define SECTION_TYPE_DSECT		(1<<0)
#define SECTION_TYPE_NOLOAD		(1<<1)
#define SECTION_TYPE_GROUP		(1<<2)
#define SECTION_TYPE_NOPAD		(1<<3)
#define SECTION_TYPE_COPY		(1<<4)
#define SECTION_CNT_CODE		(1<<5)
#define SECTION_CNT_INITIALIZED_DATA	(1<<6)
#define SECTION_CNT_UNINITIALIZED_DATA	(1<<7)
#define SECTION_LNK_OTHER		(1<<8)
#define SECTION_LNK_INFO		(1<<9)
#define SECTION_TYPE_OVER		(1<<10)
#define SECTION_LNK_REMOVE		(1<<11)
#define SECTION_LNK_COMDAT		(1<<12)
/* XXX Gap in my data */
#define SECTION_MEM_FARDATA		(1<<15)
/* XXX Gap in my data */
#define SECTION_MEM_16BIT		(1<<17)
#define SECTION_MEM_LOCKED		(1<<18)
#define SECTION_MEM_PRELOAD		(1<<19)
/* XXX This alignment stuff doesn't seem right to me */
#define SECTION_ALIGN_1BYTES		(1<<20)
#define SECTION_ALIGN_2BYTES		(1<<21)
#define SECTION_ALIGN_8BYTES		(1<<22)
#define SECTION_ALIGN_128BYTES		(1<<23)
#define SECTION_LNK_NRELOC_OVFL		(1<<24)
#define SECTION_MEM_DISCARDABLE		(1<<25)
#define SECTION_NOT_CACHED		(1<<26)
#define SECTION_NOT_PAGED		(1<<27)
#define SECTION_MEM_SHARED		(1<<28)
#define SECTION_MEM_EXECUTE		(1<<29)
#define SECTION_MEM_READ		(1<<30)
#define SECTION_MEM_WRITE		(1<<31)



struct section {
	char name[8];
	uint32_t virtual_size;
	uint32_t virtual_address;
	uint32_t data_size;
	uint32_t data_off;
	uint32_t relocs_off;
	uint32_t lineno_off;
	uint32_t num_relocs;
	uint32_t num_lineno;
	uint32_t flags;
	/* Internal */
	uint16_t padding_size;
	uint8_t *padding;
	uint8_t *data;
	struct rsrc_directorytable *dtable;
};


struct directory {
	uint32_t address;
	uint32_t size;
};

enum machine_type {
	UNKNOWN_TYPE = 0,
	AM33 = 0x1d3,
	AMD64 = 0x8664,
	ARM = 0x1c0,
	EBC = 0xebc,
	I386 = 0x14c,
	IA64 = 0x200,
	M32R = 0x9041,
	MIPS16 = 0x266,
	MIPSFPU = 0x366,
	MIPSFPU16 = 0x466,
	POWERPC = 0x1f0,
	POWERPCFP = 0x1f1,
	R4000 = 0x166,
	SH3 = 0x1a2,
	SH3DSP = 0x1a3,
	SH4 = 0x1a6,
	SH5 = 0x1a8,
	THUMB = 0x1c2
};


enum pe_subsystem {
	UNKNOWN_SUBSYSTEM = 0,
	NATIVE = 1,
	WINDOWS_GUI = 2,
	WINDOWS_CUI = 3,
	POSIX_CIU = 7,
	WINDOWS_CE_GUI = 9,
	EFI_APPLICATION = 10,
	EFI_BOOT_SERVICE_DRIVER = 11,
	EFI_RUNTIME_DRIVER = 12,
	EFI_ROM = 13,
	XBOX = 14
};

#define DLL_FLAG_NO_BIND	(1<<11)
#define DLL_FLAG_WDM_DRIVER	(1<<13)
#define DLL_FLAG_TS_AWARE	(1<<15)

struct pe32_data {
	uint8_t major_link_version;
	uint8_t minor_link_version;
	uint32_t code_size;
	uint32_t initialized_data_size;
	uint32_t uninitialized_data_size;
	uint32_t entry_point_off;
	uint32_t base_of_code;
	uint32_t base_of_data; /* PE32 only */
	uint32_t image_base;
	uint32_t section_alignment;
	uint32_t file_alignment;
	uint16_t major_os_version;
	uint16_t minor_os_version;
	uint16_t major_image_version;
	uint16_t minor_image_version;
	uint16_t major_subsystem_version;
	uint16_t minor_subsystem_version;
	uint8_t padding[4];
	uint32_t image_size;
	uint32_t headers_size;
	uint32_t checksum;
	enum pe_subsystem subsystem;
	uint16_t dll_flags;
	uint32_t reserved_stack_size;
	uint32_t stack_commit_size;
	uint32_t reserved_heap_size;
	uint32_t heap_commit_size;
	uint32_t loader_flags;
	uint32_t num_directories;
	/* Internal */
	struct directory *directories;
};

struct pe32plus_data {
	uint8_t major_linker_version;
	uint8_t minor_linker_version;
	uint32_t code_size;
	uint32_t initialized_data_size;
	uint32_t uninitialized_data_size;
	uint32_t entry_point_off;
	uint32_t base_of_code;
	uint64_t image_base; /* 32-bit in PE32 */
	uint32_t section_alignment;
	uint32_t file_alignment;
	uint16_t major_os_version;
	uint16_t minor_os_version;
	uint16_t major_image_version;
	uint16_t minor_image_version;
	uint16_t major_subsystem_version;
	uint16_t minor_subsystem_version;
	uint8_t padding[4];
	uint32_t image_size;
	uint32_t headers_size;
	uint32_t checksum;
	enum pe_subsystem subsystem;
	uint16_t dll_flags;
	uint64_t reserved_stack_size; /* 32-bit on PE32 */
	uint64_t stack_commit_size; /* 32-bit on PE32 */
	uint64_t reserved_heap_size; /* 32-bit on PE32 */
	uint64_t heap_commit_size; /* 32-bit on PE32 */
	uint32_t loader_flags;
	uint32_t num_directories;
	/* Internal */
	struct directory *directories;
};
enum pe_type{
	PE32 = 0x10b,
	PE32PLUS = 0x20b
};
struct pe_header {
	enum pe_type pe_type;
	union {
		struct pe32_data *pe32;
		struct pe32plus_data *pe32plus;
	};
};

#define COFF_OPT_RELOCS_STRIPPED		(1<<0)
#define COFF_OPT_EXECUTABLE_IMAGE		(1<<1)
#define COFF_OPT_LINE_NUMS_STRIPPED		(1<<2)
#define COFF_OPT_LOCAL_SYMS_STRIPPED		(1<<3)
#define COFF_OPT_AGGRESSIVE_WS_TRIM		(1<<4)
#define COFF_OPT_LARGE_ADDRESS_AWARE		(1<<5)
#define COFF_OPT_MACHINE_16BIT			(1<<6)
#define COFF_OPT_BYTES_REVERSED_LO		(1<<7)
#define COFF_OPT_MACHINE_32BIT			(1<<8)
#define COFF_OPT_DEBUG_STRIPPED			(1<<9)
#define COFF_OPT_REMOVABLE_RUN_FROM_SWAP	(1<<10)
#define COFF_OPT_SYSTEM				(1<<11)
#define COFF_OPT_DLL				(1<<12)
#define COFF_OPT_UNIPROCESSOR_ONLY		(1<<13)
#define COFF_OPT_BIG_ENDIAN_MACHINE		(1<<14)

struct image_nt_header {
	char header[2]; /* should be "PE" */
	uint8_t padding[2];
	enum machine_type machine_type;
	uint16_t num_sections;
	uint32_t timestamp;
	uint32_t symbol_table_off;
	uint32_t num_symbols;
	uint16_t opt_header_size; /* refers to PE header */
	uint16_t options;
	/* Internal */
	struct pe_header *pe; /* image optional header */
	struct symbol_table *symbol_table;
	struct section *sections;
};

struct msdos_header {
	char header[2]; /* "MZ" */
	uint16_t partpag;
	uint16_t page_count;
	uint16_t relocation_count;
	uint16_t header_size;
	uint16_t mem_min;
	uint16_t mem_max;
	uint16_t init_ss;
	uint16_t init_sp;
	uint16_t checksum;
	uint16_t init_cs;
	uint16_t relocation_stackseg;
	uint16_t table_off;
	uint16_t overlay;
	uint16_t res[4];
	uint16_t oem_id;
	uint16_t oem_info;
	uint16_t res2[10];
	uint32_t image_nt_header_off;
	/* Internal */
	uint8_t *assembly_code;
	struct image_nt_header *nth;
};


#endif /* __FORMAT_H_ */
