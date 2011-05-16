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
#include <sys/types.h>
#include <errno.h>
#include "inc/includes.h"

struct stringmap {
	const char *str;
	STATUS status;
};

const struct stringmap status_string[] = {
	{ "STATUS_OK", STATUS_OK },
	{ "STATUS_GENERAL_ERROR", STATUS_GENERAL_ERROR },
	{ "STATUS_FILE_NOT_FOUND", STATUS_FILE_NOT_FOUND },
	{ "STATUS_SHORT_READ", STATUS_SHORT_READ },
	{ "STATUS_SHORT_WRITE", STATUS_SHORT_WRITE },
	{ "STATUS_NO_MEMORY", STATUS_NO_MEMORY },
	{ "STATUS_FILE_CORRUPT", STATUS_FILE_CORRUPT },
	{ "STATUS_NOT_SUPPORTED", STATUS_NOT_SUPPORTED },
	{ "STATUS_NOT_IMPLEMENTED", STATUS_NOT_IMPLEMENTED },
	{ "STATUS_BAD_FILE_DESCRIPTOR", STATUS_BAD_FILE_DESCRIPTOR },
	{ "STATUS_MEMORY_CORRUPTION", STATUS_MEMORY_CORRUPTION },
	{ "STATUS_INTERRUPTED", STATUS_INTERRUPTED },
	{ "STATUS_IO_ERROR", STATUS_IO_ERROR },
	{ NULL, 0 }
};
const struct stringmap friendly_status_string[] = {
	{ "Status OK", STATUS_OK },
	{ "General error", STATUS_GENERAL_ERROR },
	{ "Path/file not found", STATUS_FILE_NOT_FOUND },
	{ "Short read (did not read all bytes)", STATUS_SHORT_READ },
	{ "Short write (did not write all bytes)", STATUS_SHORT_WRITE },
	{ "Out of memory", STATUS_NO_MEMORY },
	{ "File is corrupt or has unsupported file format", STATUS_FILE_CORRUPT },
	{ "Function not supported", STATUS_NOT_SUPPORTED },
	{ "Function not yet implemented", STATUS_NOT_IMPLEMENTED },
	{ "Bad file descriptor", STATUS_BAD_FILE_DESCRIPTOR },
	{ "Memory corruption", STATUS_MEMORY_CORRUPTION },
	{ "Call interrupted", STATUS_INTERRUPTED },
	{ "I/O error", STATUS_IO_ERROR },
	{ NULL, 0 }
};

const char * get_status_string(STATUS status) 
{
	uint8_t i;

	for (i = 0; status_string[i].str != NULL; i++) {
		if (status_string[i].status == status) {
			return status_string[i].str;
		}
	}
	return "STATUS_UNKNOWN";
}

const char * get_friendly_status_string(STATUS status) 
{
	uint8_t i;

	for (i = 0; friendly_status_string[i].str != NULL; i++) {
		if (friendly_status_string[i].status == status) {
			return friendly_status_string[i].str;
		}
	}
	return "Unknown status";
}
STATUS map_errno_status(int err_no) 
{
	switch (err_no) {
		case EBADF:
			return STATUS_BAD_FILE_DESCRIPTOR;
		case EIO:
			return STATUS_IO_ERROR;
		case EINTR:
			return STATUS_INTERRUPTED;
		case EFAULT:
			return STATUS_MEMORY_CORRUPTION;
		default:
			return STATUS_GENERAL_ERROR;
	}
}	
