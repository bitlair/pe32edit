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
#define _BSD_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include <talloc.h>
#include "inc/includes.h"
#include "lib/status.h"

#define PADDING "PADDINGXX"


#define HIWORD(x) ((uint16_t)((uint32_t)(x) >> 16))
#define LOWORD(x) ((uint16_t)((uint32_t)(x) & 0xffff))


#define memcpy_uint16(dst, src, off) { \
	off -= sizeof(uint16_t); \
	*(uint16_t *)((dst)+(off)) = htole16(src); }
#define memcpy_uint32(dst, src, off) { \
	off -= sizeof(uint32_t); \
	*(uint32_t *)((dst)+(off)) = htole32(src); }
#define memcpy_uint64(dst, src, off) { \
	off -= sizeof(uint64_t); \
	*(uint64_t *)((dst)+(off)) = htole64(src); }

uint16_t calc_checksum(uint32_t start_value, void *base, int cnt)
{
	uint32_t i;
	uint32_t sum;
	uint32_t *ptr;

	ptr = (uint32_t *)base;
	sum = start_value;
	for (i = 0; i < cnt; i++) {
		sum += *ptr;
		if (HIWORD(sum) != 0) {
			sum = LOWORD(sum) + HIWORD(sum);
		}
		ptr++;
	}
	
	return (uint16_t)(HIWORD(sum) + LOWORD(sum));
}

inline uint32_t aligned_size (uint32_t size)
{
	return (size + 3) & ~3;
}
uint32_t unicode_strlen(char *string)
{
	uint32_t ret = 0;
	uint32_t i;

	for (i = 0; string[i] != 0;i += 2) {
		ret++;
	}
	return ret;
}

uint8_t *aligned_blk(TALLOC_CTX *mem_ctx, struct data data)
{
	uint32_t size = aligned_size(sizeof(uint16_t) + (data.strlen * 2));
	uint8_t *blk = talloc_array(mem_ctx, uint8_t, size);
	uint32_t i;

	/* Write the string length to the start of the block as a 16-bit
	 * little endian integer */
	*(uint16_t *)blk = htole16((uint16_t)data.strlen);

	for (i = 0; i / 2 <  data.strlen; i++) {
		blk[i + sizeof(uint16_t)] = data.data[i];
	}

	/* Pad the block */
	memcpy(&blk[i], PADDING, size - i);
	return blk;
}

char *str_from_unicode(TALLOC_CTX *mem_ctx, char *string) 
{
	char *name_tmp = NULL;
	int j;

	for (j = 0; string[j*2] != '\0';j++) {
		if (j % 10 == 0) {
			name_tmp = talloc_realloc(mem_ctx, name_tmp, char, j+10);
		}
		name_tmp[j] = string[j*2];
	}

	name_tmp[j] = '\0';
	return name_tmp;
}

char *strn_from_unicode(TALLOC_CTX *mem_ctx, char *string, int len) 
{
	char *name_tmp;
	int j;

	name_tmp = talloc_array(mem_ctx, char, len+1);
	for (j = 0; j < len;j++) {
		name_tmp[j] = string[j*2];
	}

	name_tmp[j] = '\0';
	return name_tmp;
}

STATUS content_size(TALLOC_CTX *parent_ctx, struct rsrc_directorytable *dtable, uint32_t *size) 
{
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);
	int i;
	STATUS status;
	uint32_t size_content = 0; 
	
	size_content = 16; /* flags,timestamp,major,minor,num_name,num_id */

	/* Add id/name_off and data_off for every entry */
	size_content += (dtable->num_name_entries + dtable->num_id_entries) * 8;

	for (i = 0; i < dtable->num_name_entries + dtable->num_id_entries; i++) {
		if (dtable->entries[i].entry_off & 0x80000000) {
			uint32_t tmp_size;

			if (dtable->entries[i].name_off & 0x80000000) {
				/* uint16_t len + unicode string */
				size_content += aligned_size(2+(strlen(str_from_unicode(mem_ctx, dtable->entries[i].name))*2));
			}

			status = content_size(mem_ctx, dtable->entries[i].directory, &tmp_size);
			if (status != STATUS_OK) return status;

			size_content += tmp_size;
		} else {
			size_content += 16 + aligned_size(dtable->entries[i].value->size); /* aligned data */
		}
	}
	talloc_free(mem_ctx);

	*size = size_content;
	return STATUS_OK;
}

STATUS parse_value(int fd, uint32_t data_off, struct rsrc_value *entry)
{
	read_uint32(fd, &entry->data_off);
	read_uint32(fd, &entry->size);
	read_uint32(fd, &entry->codepage);
	read_uint32(fd, &entry->reserved);

	/* FIXME: Find out why the !%$#&!GRR this is off by 4096 bytes. */
	lseek(fd, (data_off + entry->data_off) - 0x1000, SEEK_SET);
	entry->data = talloc_array(entry, uint8_t, entry->size);
	NO_MEMORY_RETURN(entry->data);
	read_fixed_array(fd, entry->data, entry->size);


	return STATUS_OK;
}

static STATUS parse_directory_table(
                                    int fd,
                                    uint32_t data_off,
                                    struct rsrc_directorytable *dtable,
                                    int depth)
{
	int i, cur_entry;
	STATUS status;
	
	read_uint32(fd, &dtable->flags);
	read_uint32(fd, &dtable->timestamp);
	read_uint16(fd, &dtable->major_version);
	read_uint16(fd, &dtable->minor_version);
	read_uint16(fd, &dtable->num_name_entries);
	read_uint16(fd, &dtable->num_id_entries);
	
	dtable->entries = talloc_zero_array(dtable, struct rsrc_entry, (dtable->num_name_entries + 
			dtable->num_id_entries));
	NO_MEMORY_RETURN(dtable->entries);

	cur_entry = 0;
	for (i = 0; i < dtable->num_name_entries;i++) {
		read_uint32(fd, &dtable->entries[cur_entry].name_off);
		read_uint32(fd, &dtable->entries[cur_entry].entry_off);
		cur_entry++;
	}
	for (i = 0; i < dtable->num_id_entries;i++) {
		read_uint32(fd, &dtable->entries[cur_entry].id);
		read_uint32(fd, &dtable->entries[cur_entry].entry_off);
		cur_entry++;
	}

	/* Do this after reading the table because of all the seeking */
	for (i = 0; i < cur_entry; i++) {

		if (dtable->entries[i].name_off & 0x80000000) {
			uint16_t name_len;
			char *name;
			off_t offset;

			/* This is a name, read the name from fd */
			offset = lseek(fd, data_off + (dtable->entries[i].name_off ^ 0x80000000), 
					SEEK_SET);
			read_uint16(fd, &name_len);
			dtable->entries[i].name = talloc_array(dtable->entries, char, (name_len*2) + 2);
			NO_MEMORY_RETURN(dtable->entries[i].name);
			read_fixed_array(fd, dtable->entries[i].name, (name_len*2));
			
			name = strn_from_unicode(NULL, dtable->entries[i].name, name_len);
			printf("name: %s at 0x%04ld\n", name, offset);
			talloc_free(name);
		} else {
			/* This is an id, no action required */
			printf("id: %d\n", dtable->entries[i].id);
		}

		if (dtable->entries[i].entry_off & 0x80000000) {
			/* This is a directory */
			printf("This is a directory at 0x%04x\n", data_off + (dtable->entries[i].entry_off ^0x80000000));
			lseek(fd, data_off + (dtable->entries[i].entry_off ^ 0x80000000), SEEK_SET);

			dtable->entries[i].directory = talloc_zero(dtable->entries, struct rsrc_directorytable);
			status = parse_directory_table(fd, data_off, dtable->entries[i].directory, depth+1);
			if (status != STATUS_OK) {
				fprintf(stderr, "Failed to parse directory table at offset 0x%x\n", data_off + dtable->entries[i].entry_off);
				return status;
			}
		} else {
			/* This is a value */
			printf("This is a value at 0x%04x\n", data_off + dtable->entries[i].entry_off);
			lseek(fd, data_off + dtable->entries[i].entry_off, SEEK_SET);

			dtable->entries[i].value = talloc_zero(dtable->entries, struct rsrc_value);
			status = parse_value(fd, data_off, dtable->entries[i].value);
			if (status != STATUS_OK) {
				fprintf(stderr, "Failed to parse directory value at offset 0x%x\n", data_off+dtable->entries[i].entry_off);
				return status;
			}
		}
	}
	return STATUS_OK;
}

static STATUS parse_sections(int fd, struct image_nt_header *nth) 
{
	uint16_t i;
	off_t offset;
	size_t size;
	STATUS status;

	nth->sections = talloc_zero_array(nth, struct section, nth->num_sections);
	NO_MEMORY_RETURN(nth->sections);

	for (i = 0; i < nth->num_sections; i++) {
		struct section *section = &nth->sections[i];

		read_fixed_array(fd, &section->name, 8);
		read_uint32(fd, &section->virtual_size);
		read_uint32(fd, &section->virtual_address);
		read_uint32(fd, &section->data_size);
		read_uint32(fd, &section->data_off);
		read_uint32(fd, &section->relocs_off);
		read_uint32(fd, &section->lineno_off);
		read_uint16(fd, &section->num_lineno);
		read_uint16(fd, &section->num_relocs);
		read_uint32(fd, &section->flags);

		/* FIXME TEST: this may or may not work with multiple sections */
		offset = lseek(fd, 0, SEEK_CUR);
		size = section->data_off - offset;
		section->padding_size = size;
		if (size > 0) {
			section->padding = talloc_array(nth->sections, uint8_t, size);
			NO_MEMORY_RETURN(section->padding);
			read_fixed_array(fd, section->padding, size);
		}
		if (size < 0) {
			return STATUS_FILE_CORRUPT;
		}
		
		if (strncmp(section->name, ".rsrc", 8) == 0) {
			/* Seek past this entry. We parse this manually */
			lseek(fd, section->data_size, SEEK_CUR);
		} else {
			/* Just store non-resource sections as data */
			section->data = talloc_array(nth->sections, uint8_t, section->data_size);
			NO_MEMORY_RETURN(section->data);
			read_fixed_array(fd, section->data, section->data_size);
		}
	}
	/* After storing all sections, parse the .rsrc section */
	for (i = 0; i < nth->num_sections; i++) {
		struct section *section = &nth->sections[i];

		if (strncmp(section->name, ".rsrc", 8) == 0) {
			/* Parse the resource tree */
			lseek(fd, section->data_off, SEEK_SET);
			section->dtable = talloc_zero(nth->sections, struct rsrc_directorytable);
			status = parse_directory_table(fd, section->data_off, section->dtable, 0);
			if (status != STATUS_OK) {
				fprintf(stderr, "Failed to parse resource tree: %s\n",
						get_friendly_status_string(status));
				return status;
			}
		}
	}
	return STATUS_OK;
}


static STATUS parse_pe32plus(int fd, struct pe32plus_data *pe) 
{
	uint16_t tmp;
	uint16_t i;

	read_fixed_array(fd, &pe->major_linker_version, 1);
	read_fixed_array(fd, &pe->minor_linker_version, 1);
	read_uint32(fd, &pe->code_size);
	read_uint32(fd, &pe->initialized_data_size);
	read_uint32(fd, &pe->uninitialized_data_size);
	read_uint32(fd, &pe->entry_point_off);
	read_uint32(fd, &pe->base_of_code);
	read_uint64(fd, &pe->image_base);
	read_uint32(fd, &pe->section_alignment);
	read_uint32(fd, &pe->file_alignment);
	read_uint16(fd, &pe->major_os_version);
	read_uint16(fd, &pe->minor_os_version);
	read_uint16(fd, &pe->major_image_version);
	read_uint16(fd, &pe->minor_image_version);
	read_uint16(fd, &pe->major_subsystem_version);
	read_uint16(fd, &pe->minor_subsystem_version);
	read_fixed_array(fd, &pe->padding, 4);
	read_uint32(fd, &pe->image_size);
	read_uint32(fd, &pe->headers_size);
	read_uint32(fd, &pe->checksum);

	read_uint16(fd, &tmp);
	pe->subsystem = (enum pe_subsystem) tmp;

	read_uint16(fd, &pe->dll_flags);
	read_uint64(fd, &pe->reserved_stack_size);
	read_uint64(fd, &pe->stack_commit_size);
	read_uint64(fd, &pe->reserved_heap_size);
	read_uint64(fd, &pe->heap_commit_size);
	read_uint32(fd, &pe->loader_flags);
	read_uint32(fd, &pe->num_directories);

	pe->directories = talloc_array(pe, struct directory, pe->num_directories);
	NO_MEMORY_RETURN(pe->directories);
	for (i = 0; i < pe->num_directories;i++) {
		read_fixed_array(fd, &pe->directories[i], 8);
	}
	
	return STATUS_OK;
}

static STATUS parse_image_nt_header(int fd, off_t offset, struct image_nt_header *nth) 
{
	off_t off;
	uint16_t tmp;
	STATUS status;
	
	off = lseek(fd, offset, SEEK_SET);
	if (off != offset) {
		return STATUS_GENERAL_ERROR;
	}

	read_fixed_array(fd, &nth->header, 2);
	if (strncmp("PE", nth->header, 2) != 0) 
		return STATUS_FILE_CORRUPT;
	read_fixed_array(fd, &nth->padding, 2);

	read_uint16(fd, &tmp);
	nth->machine_type = (enum machine_type) tmp;

	read_uint16(fd, &nth->num_sections);
	read_uint32(fd, &nth->timestamp);
	read_uint32(fd, &nth->symbol_table_off);
	read_uint32(fd, &nth->num_symbols);
	read_uint16(fd, &nth->opt_header_size);
	read_uint16(fd, &nth->options);
	
	read_uint16(fd, &tmp);
	nth->pe = talloc_zero(nth, struct pe_header);
	nth->pe->pe_type = (enum pe_type) tmp;
	
	if (nth->pe->pe_type != PE32PLUS) {
		fprintf(stderr, "Can't open PE32 files right now. Only PE32+.\n");
		return STATUS_NOT_IMPLEMENTED;
	}

	nth->pe->pe32plus = talloc_zero(nth, struct pe32plus_data);
	status = parse_pe32plus(fd, nth->pe->pe32plus);
	if (status != STATUS_OK) {
		return status;
	}
	return STATUS_OK;
}

static STATUS parse_file(int fd, struct msdos_header *msdos) 
{
	off_t offset;
	uint16_t assembly_size;
	STATUS status;

	offset = lseek(fd, 0, SEEK_SET);
	if (offset != 0) {
		return STATUS_GENERAL_ERROR;
	}
	read_fixed_array(fd, &msdos->header, 2);
	if (strncmp("MZ", msdos->header, 2) != 0) 
		return STATUS_FILE_CORRUPT;
	read_uint16(fd, &msdos->partpag);
	read_uint16(fd, &msdos->page_count);
	read_uint16(fd, &msdos->relocation_count);
	read_uint16(fd, &msdos->header_size);
	read_uint16(fd, &msdos->mem_min);
	read_uint16(fd, &msdos->mem_max);
	read_uint16(fd, &msdos->init_ss);
	read_uint16(fd, &msdos->init_sp);
	read_uint16(fd, &msdos->checksum);
	read_uint16(fd, &msdos->init_cs);
	read_uint16(fd, &msdos->relocation_stackseg);
	read_uint16(fd, &msdos->table_off);
	read_uint16(fd, &msdos->overlay);
	read_uint16(fd, &msdos->res[0]);
	read_uint16(fd, &msdos->res[1]);
	read_uint16(fd, &msdos->res[2]);
	read_uint16(fd, &msdos->res[3]);
	read_uint16(fd, &msdos->oem_id);
	read_uint16(fd, &msdos->oem_info);
	read_fixed_array(fd, &msdos->res2, sizeof(msdos->res2));
	read_uint32(fd, &msdos->image_nt_header_off);

	offset = lseek(fd, 0, SEEK_CUR);
	assembly_size = msdos->image_nt_header_off - offset;
	msdos->assembly_code = talloc_array(msdos, uint8_t, assembly_size);
	NO_MEMORY_RETURN(msdos->assembly_code);
	read_fixed_array(fd, msdos->assembly_code, assembly_size);

	msdos->nth = talloc_zero(msdos, struct image_nt_header);
	status = parse_image_nt_header(fd, msdos->image_nt_header_off, msdos->nth);
	if (status != STATUS_OK) {
		fprintf(stderr, "Failed to parse IMAGE_NT_HEADER: %s\n",
				get_friendly_status_string(status));
		return status;
	}

	status = parse_sections(fd, msdos->nth);
	if (status != STATUS_OK) {
		fprintf(stderr, "Failed to parse sections: %s\n",
				get_friendly_status_string(status));
		return status;
	}

	

	return STATUS_OK;
}
STATUS write_value(TALLOC_CTX *mem_ctx, struct rsrc_value *dtable, uint8_t *data_blob, uint32_t *data_off)
{
	/*uint32_t offset;*/


	printf("Value\n");
	return STATUS_OK;
}

STATUS write_directory(TALLOC_CTX *mem_ctx, struct rsrc_directorytable *dtable, uint8_t *data_blob, uint32_t *data_off)
{
	uint32_t i;
	uint32_t *offsets;
	offsets = talloc_zero_array(mem_ctx, uint32_t, dtable->num_id_entries+dtable->num_name_entries);

	for (i = dtable->num_id_entries - 1;i >= 0; i--) {
		if (dtable->entries[i].entry_off & 0x80000000) {
			write_directory(mem_ctx, dtable->entries[i].directory, data_blob, data_off);
		} else {
			write_value(mem_ctx, dtable->entries[i].value, data_blob, data_off);
		}
	}
	for (i = dtable->num_name_entries - 1;i >= 0; i--) {
		if (dtable->entries[i].entry_off & 0x80000000) {
			write_directory(mem_ctx, dtable->entries[i].directory, data_blob, data_off);
		} else {
			write_value(mem_ctx, dtable->entries[i].value, data_blob, data_off);
		}
		
	}
#if 0
	for (i = 0; i < dtable->num_name_entries; i++) {
		block = unicode_aligned_blk(mem_ctx, string, len);
	}
#endif
	printf("Directory\n");
#if 0
	/* Store reversed, we write from the end of the memory */
	memcpy_uint16(data_blob, dtable->num_id_entries, *data_off);
	memcpy_uint16(data_blob, dtable->num_name_entries, *data_off);
	memcpy_uint16(data_blob, dtable->minor_version, *data_off);
	memcpy_uint16(data_blob, dtable->major_version, *data_off);
	memcpy_uint32(data_blob, dtable->timestamp, *data_off);
	memcpy_uint32(data_blob, dtable->flags, *data_off);
#endif

	return STATUS_OK;
}
static STATUS write_to_disk(TALLOC_CTX *mem_ctx, struct msdos_header *msdos, const char *filename) 
{
	int fd;
	uint16_t i;
	size_t assembly_size;
	off_t offset;
	struct image_nt_header *nth = msdos->nth;
	struct pe32plus_data *pe = nth->pe->pe32plus;
	struct stat st;
	STATUS status;
	
	if (stat(filename, &st) == 0) {
		unlink(filename);
	}
	fd = open(filename, O_WRONLY | O_CREAT);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s for writing\n", filename);
		return STATUS_GENERAL_ERROR;
	}

	write_fixed_array(fd, &msdos->header, 2);
	write_uint16(fd, &msdos->partpag);
	write_uint16(fd, &msdos->page_count);
	write_uint16(fd, &msdos->relocation_count);
	write_uint16(fd, &msdos->header_size);
	write_uint16(fd, &msdos->mem_min);
	write_uint16(fd, &msdos->mem_max);
	write_uint16(fd, &msdos->init_ss);
	write_uint16(fd, &msdos->init_sp);
	write_uint16(fd, &msdos->checksum);
	write_uint16(fd, &msdos->init_cs);
	write_uint16(fd, &msdos->relocation_stackseg);
	write_uint16(fd, &msdos->table_off);
	write_uint16(fd, &msdos->overlay);
	write_uint16(fd, &msdos->res[0]);
	write_uint16(fd, &msdos->res[1]);
	write_uint16(fd, &msdos->res[2]);
	write_uint16(fd, &msdos->res[3]);
	write_uint16(fd, &msdos->oem_id);
	write_uint16(fd, &msdos->oem_info);
	write_fixed_array(fd, &msdos->res2, sizeof(msdos->res2));
	write_uint32(fd, &msdos->image_nt_header_off);

	offset = lseek(fd, 0, SEEK_CUR);
	assembly_size = msdos->image_nt_header_off - offset;
	write_fixed_array(fd, msdos->assembly_code, assembly_size);
		
	write_fixed_array(fd, &nth->header, 2);
	write_fixed_array(fd, &nth->padding, 2);
	write_uint16(fd, &nth->machine_type);
	write_uint16(fd, &nth->num_sections);
	write_uint32(fd, &nth->timestamp);
	write_uint32(fd, &nth->symbol_table_off);
	write_uint32(fd, &nth->num_symbols);
	write_uint16(fd, &nth->opt_header_size);
	write_uint16(fd, &nth->options);
	
	write_uint16(fd, &nth->pe->pe_type);
	
	/* FIXME Should be fixed to support PE32 as well */
	write_fixed_array(fd, &pe->major_linker_version, 1);
	write_fixed_array(fd, &pe->minor_linker_version, 1);
	write_uint32(fd, &pe->code_size);
	write_uint32(fd, &pe->initialized_data_size);
	write_uint32(fd, &pe->uninitialized_data_size);
	write_uint32(fd, &pe->entry_point_off);
	write_uint32(fd, &pe->base_of_code);
	write_uint64(fd, &pe->image_base);
	write_uint32(fd, &pe->section_alignment);
	write_uint32(fd, &pe->file_alignment);
	write_uint16(fd, &pe->major_os_version);
	write_uint16(fd, &pe->minor_os_version);
	write_uint16(fd, &pe->major_image_version);
	write_uint16(fd, &pe->minor_image_version);
	write_uint16(fd, &pe->major_subsystem_version);
	write_uint16(fd, &pe->minor_subsystem_version);
	write_fixed_array(fd, &pe->padding, 4);
	write_uint32(fd, &pe->image_size);
	write_uint32(fd, &pe->headers_size);

	/* FIXME This is a hack which removes the checksum */
	pe->checksum = 0;
	write_uint32(fd, &pe->checksum);

	write_uint16(fd, &pe->subsystem);

	write_uint16(fd, &pe->dll_flags);
	write_uint64(fd, &pe->reserved_stack_size);
	write_uint64(fd, &pe->stack_commit_size);
	write_uint64(fd, &pe->reserved_heap_size);
	write_uint64(fd, &pe->heap_commit_size);
	write_uint32(fd, &pe->loader_flags);
	write_uint32(fd, &pe->num_directories);

	for (i = 0; i < pe->num_directories;i++) {
		write_fixed_array(fd, &pe->directories[i], 8);
	}
	for (i = 0; i < nth->num_sections;i++) {
		struct section *section = &nth->sections[i];

		write_fixed_array(fd, &section->name, 8);
		write_uint32(fd, &section->virtual_size);
		write_uint32(fd, &section->virtual_address);
		write_uint32(fd, &section->data_size);
		write_uint32(fd, &section->data_off);
		write_uint32(fd, &section->relocs_off);
		write_uint32(fd, &section->lineno_off);
		write_uint16(fd, &section->num_lineno);
		write_uint16(fd, &section->num_relocs);
		write_uint32(fd, &section->flags);
		write_fixed_array(fd, section->padding, section->padding_size);
		if (strncmp(section->name, ".rsrc", 8) != 0) {
			write_fixed_array(fd, section->data, section->data_size);
		} else {
			struct rsrc_directorytable *dtable = section->dtable;
			uint32_t dtable_size;
			uint8_t *data_blob = NULL;
			uint32_t data_off;

			status = content_size(mem_ctx, dtable, &dtable_size);
			data_blob = talloc_zero_array(mem_ctx, uint8_t, dtable_size);

			write_directory(mem_ctx, dtable, data_blob, &data_off);
		}

	}
	
	
	close(fd);
	return STATUS_OK;
}

int main (int argc, char **argv) 
{
	int fd;
	struct msdos_header *msdos;
	STATUS status;
	off_t offset;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("pe32edit");


	msdos = talloc_zero(mem_ctx, struct msdos_header);

	
	fd = open("authui.dll.mui", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open authui.dll.mui\n");
		return 1;
	}
	
	status = parse_file(fd, msdos);
	if (status != STATUS_OK) {
		fprintf(stderr, "Failed to parse file: %s\n",
				get_friendly_status_string(status));
		return 1;
	}




	offset = lseek(fd, 0, SEEK_CUR);
	printf("Offset: 0x%lX/%ld\n", offset, offset);

	status = write_to_disk(mem_ctx, msdos, "new.mui");
	if (status != STATUS_OK) {
		fprintf(stderr, "Failed to write to disk: %s\n",
				get_friendly_status_string(status));
		return 1;
	}

	close(fd);
	talloc_free(mem_ctx);
	printf("OK tot nu toe\n");
	return 0;	
}
