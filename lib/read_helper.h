#ifndef __READ_HELPER_H_
#define __READ_HELPER_H_

#define MAX_BUF_LEN 1024

/* These are little endian read and write macro's with return status */
#define read_fixed_array(fd, buf, cnt) {{ \
	STATUS macrostatus; \
	macrostatus = _read_fixed_array(fd,buf,cnt); \
	if (macrostatus != STATUS_OK) return macrostatus; }}

STATUS _read_fixed_array(int fd, void *buf, int cnt);

/*#define read_fixed_array(fd, buf, cnt) {{ \
	int macrobytes_read, macro_to_read, macro_nread; \
	macro_to_read = MIN(MAX_BUF_LEN,cnt); \
	macrobytes_read = 0; \
	while ((macro_nread = read(fd, buf[macrobytes_read], macro_to_read)) != -1) { \
		macrobytes_read += macrobytes_read;\
	}\

*/
#define write_fixed_array(fd, buf, cnt) {{ \
	int macrobytes_written; \
	macrobytes_written = write(fd, buf, cnt); \
	if (macrobytes_written != cnt) return STATUS_SHORT_WRITE;  }}
#define read_uint16(fd, buf) {{ \
	int macrobytes_read; \
	macrobytes_read = read(fd, buf, sizeof(uint16_t)); \
	*buf = le16toh(*buf); \
	if (macrobytes_read != sizeof(uint16_t)) return STATUS_SHORT_READ; }}
#define write_uint16(fd, buf) {{ \
	int macrobytes_written; \
	macrobytes_written = write(fd, buf, sizeof(uint16_t)); \
	*buf = htole16(*buf); \
	if (macrobytes_written != sizeof(uint16_t)) return STATUS_SHORT_WRITE; }}
#define read_uint32(fd, buf) {{ \
	int macrobytes_read; \
	macrobytes_read = read(fd, buf, sizeof(uint32_t)); \
	*buf = le32toh(*buf); \
	if (macrobytes_read != sizeof(uint32_t)) return STATUS_SHORT_READ; }}
#define write_uint32(fd, buf) {{ \
	int macrobytes_written; \
	macrobytes_written = write(fd, buf, sizeof(uint32_t)); \
	*buf = htole32(*buf); \
	if (macrobytes_written != sizeof(uint32_t)) return STATUS_SHORT_WRITE; }}
#define read_uint64(fd, buf) {{ \
	int macrobytes_read; \
	macrobytes_read = read(fd, buf, sizeof(uint64_t)); \
	*buf = le64toh(*buf); \
	if (macrobytes_read != sizeof(uint64_t)) return STATUS_SHORT_READ; }}
#define write_uint64(fd, buf) {{ \
	int bytes_written; \
	bytes_written = write(fd, buf, sizeof(uint64_t)); \
	*buf = htole64(*buf); \
	if (bytes_written != sizeof(uint64_t)) return STATUS_SHORT_WRITE; }}

#endif /* __READ_HELPER_H_ */
