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
 */
#include <unistd.h>
#include <errno.h>
#include "inc/includes.h"
#include "lib/status.h"

STATUS _read_fixed_array(int fd, void *buf, int cnt) {
	int nread, to_read, total_read;


	total_read = 0;
	while (total_read < cnt) {
		/* Make sure we don't exceed the maximum buffer length, but 
		   also that we don't read too much */
		to_read = MIN(MAX_BUF_LEN, cnt - total_read);

		nread = read(fd, (uint8_t *)buf + total_read, to_read);
		if (nread == -1) {
			return map_errno_status(errno);
		}
		total_read += nread;
	}
	if (total_read != cnt) return STATUS_SHORT_READ;
	return STATUS_OK;
}
