#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "get_phys_addr.h"

#define PAGEMAP_FILE "/proc/self/pagemap"

#define KB * 1024ULL

/*
 * Get physical address from virtual address addr.
 * Function taken from DPDK, (c) Intel Corp, BSD-3 license
 */
uint64_t get_phys_addr(const void *addr)
{
	unsigned int page_sz;
	int fd;
	off_t offset;
	int  read_bytes;
	uint64_t page;
	uint64_t phys_addr;

	/* get normal page sizes: */
	page_sz = 4 KB;

	/* read 8 bytes (uint64_t) at position N*8, where N is addr/page_sz */
	fd = open(PAGEMAP_FILE, O_RDONLY);
	if (fd < 0) {
		perror("open()");
		return PHYS_ADDR_INVALID;
	}

	offset = ((unsigned long)addr / page_sz) * sizeof(uint64_t);
	if (lseek(fd, offset, SEEK_SET) == (off_t)-1) {
		perror("lseek");
		close(fd);
		return PHYS_ADDR_INVALID;
	}

	read_bytes = read(fd, &page, sizeof(uint64_t));
	close(fd);
	if (read_bytes < 0) {
		fprintf(stderr, "cannot read " PAGEMAP_FILE ": %s\n",
			strerror(errno));
		return PHYS_ADDR_INVALID;
	} else if (read_bytes != sizeof(uint64_t)) {
		fprintf(stderr, "read %d bytes from " PAGEMAP_FILE " "
			"but expected %d:\n",
			read_bytes, sizeof(uint64_t));
		return PHYS_ADDR_INVALID;
	}

	/* some kernel return PFN zero when permission is denied: */
	if (!(page & 0x7fffffffffffffULL))
		return PHYS_ADDR_INVALID;

	/*
	 * the pfn (page frame number) are bits 0-54 (see
	 * pagemap.txt in linux Documentation)
	 */
	phys_addr = ((page & 0x7fffffffffffffULL) * page_sz)
		+ ((unsigned long)addr % page_sz);

	return phys_addr;
}

