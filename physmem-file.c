/* (c) 2017 Linaro Inc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>

#define K * 1024ULL
#define M * 1024ULL K
#define G * 1024ULL M
#define T * 1024ULL G

#ifndef HERE
#define HERE() fprintf(stderr, "%s:%d\n", __FILE__, __LINE__)
#endif

#define PAGEMAP_FILE "/proc/self/pagemap"
#define HUGEPAGES_PATH "/dev/hugepages/"
#define PHYS_ADDR_INVALID ((uint64_t)-1)

/* must be on a huge page boundary */
#define VIRTUAL_PHYSICAL_ANCHOR (16 T)
static uint64_t anchor_addr = VIRTUAL_PHYSICAL_ANCHOR;

/* make hugepage_info 128 bytes long */
#define FILENAME_PATH_MAX 88

struct hugepage_info {
	struct hugepage_info *next; /* used when part of a block */
	struct block *block; /* the block this hugepage belongs to */
	void *va; /* virtual address this hugepage is mapped to */
	uint64_t pa; /* the Physical Address of this hugepage */
	uint32_t size; /* size of hugepage, probably redundant */
	int fd; /* the fd returned by open, for the hugepages file */
	char filename[FILENAME_PATH_MAX];
};

/* a block is a chunk of physically contiguous memory */
struct block {
	struct block *next;
	struct hugepage_info *first; /* list of physically contiguous hp
       					forming this block */
	void *va; /* virtual address where the block is mapped */
	uint64_t pa; /* physical address where it starts */
	uint64_t size; /* the size of this memory block */
	uint32_t count; /* number of hugepages in this block */
	uint32_t page_size; /* the size of the hugepages */
	uint32_t id; /* internal ID of this block, debug purposes */
};

#define MAX_HUGEPAGES 128

struct block_data {
	struct block block[MAX_HUGEPAGES];
	struct block *avail[MAX_HUGEPAGES];
	unsigned int count;
};

static struct hugepage_info pages[MAX_HUGEPAGES];
static struct block_data block_data;

/*
 * Get physical address from virtual address addr.
 * Function taken from DPDK, (c) Intel Corp, BSD-3 license
 */
static uint64_t get_phys_addr(const void *addr)
{
	unsigned int page_sz;
	int fd;
	off_t offset;
	int  read_bytes;
	uint64_t page;
	uint64_t phys_addr;

	/* get normal page sizes: */
	page_sz = 4 K;

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

static int alloc_hugepage(struct hugepage_info *hp)
{
	static int file_id = 0;
	int len;

	if (hp == NULL)
		return -1;

	len = snprintf(hp->filename, sizeof(hp->filename),
		       HUGEPAGES_PATH "odp-%d", file_id);
	if (len >= sizeof(hp->filename)) {
		fprintf(stderr, "Filename too large (%d)\n", len);
		return -1;
	}

	hp->fd = open(hp->filename, O_CREAT | O_RDWR, 0755);
	if (hp->fd == -1) {
		perror("open");
		return -1;
	}

	hp->va = mmap(NULL, 2 M, PROT_READ | PROT_WRITE, MAP_SHARED, hp->fd, 0);
	if (hp->va == MAP_FAILED) {
		perror("mmap");
		close(hp->fd);
		unlink(hp->filename);
		return -1;
	}

	/* Force memory commitment */
	*((int *)(hp->va)) = hp->fd;

	hp->size = 2 M; /* FIXME: defaulting to 2MB huge pages */
	hp->pa = get_phys_addr(hp->va);
	if (hp->pa == PHYS_ADDR_INVALID)
		fprintf(stderr, "Could not discover PA\n");

	hp->next = NULL;
	hp->block = NULL;

	file_id++;

	return 0;
}

static int comp_hp(const void *_a, const void *_b)
{
	const struct hugepage_info *a = _a;
	const struct hugepage_info *b = _b;

	if (a->pa > b->pa)
		return 1;
	else if (a->pa < b->pa)
		return -1;
	else
		return 0;
}

static int comp_block(const void *_a, const void *_b)
{
	const struct block *a = _a;
	const struct block *b = _b;

	if (a->size > b->size)
		return 1;
	else if (a->size < b->size)
		return -1;
	else
		return 0;
}
/*
 * hp is a SORTED array of count elements of struct hugepage_info,
 * it is sorted per physical address in ascending order.
 * size is the size of the huge pages (probably redundant)
 * This returns a linked list of struct block, each block containing
 * a list of physically contiguous huge pages.
 */
static int sort_by_block(struct hugepage_info *hp_array, int count,
			 uint32_t size)
{
	int block_id;
	int hp_id;
	struct block *block;
	struct hugepage_info *hp_prev;

	if (hp_array == NULL || count == 0)
		return -EINVAL;

	block_id = 0;
	hp_id = 0;
	do {
		uint64_t pa_expected;
		struct hugepage_info *hp = &hp_array[hp_id];

		block = &block_data.block[block_id];
		block->next = NULL;
		block->first = hp;
		block->size = hp->size;
		block->pa = hp->pa;
		block->va = NULL;
		block->count = 1;
		block->id = block_id++;

		block_data.count++;

		hp->block = block;
		hp->next = NULL;

		printf("New block %d\n", block->id);
		printf("\t%03d: VA: %016" PRIx64 ", PA: %016" PRIx64 "\n",
		       hp->fd, hp->va, hp->pa);

		pa_expected = block->pa + hp->size;
		hp_prev = block->first;

		/* keep adding huge pages to this block as long as their
		 * physical address coincides with the expected one */
		while (++hp_id < count) {
			hp = &hp_array[hp_id];

			if (hp->pa != pa_expected)
				break;

			printf("\t%03d: VA: %016" PRIx64 ", PA: %016" PRIx64 "\n",
			       hp->fd, hp->va, hp->pa);

			hp->next = NULL;
			hp->block = block;
			hp_prev->next = hp;

			block->count++;
			block->size += hp->size;

			pa_expected += hp->size;

			hp_prev = hp;
		}
		printf("\tSize: %" PRIu64 " MB\n", (block->size / (1 M)));
	} while (hp_id < count);

	qsort(block_data.block, block_data.count, sizeof(block_data.block[0]),
	      comp_block);

	/* link sorted blocks together */
	for (block_id = 0; block_id < (block_data.count - 1); ) {
		block_data.avail[block_id] = &block_data.block[block_id];
		block_data.block[block_id].next =
			&block_data.block[++block_id];
	}
	block_data.avail[block_id] = &block_data.block[block_id];

	return 0;
}

static void dump_array(struct hugepage_info *hp, int size)
{

	while (size--) {
		printf("%03d:"
		       " VA: 0x%016" PRIx64
		       " PA: 0x%016" PRIx64
		       "\n",
		       hp->fd,
		       hp->va,
		       hp->pa);
		hp++;
	}
}

static void dump_blocks(void)
{
	unsigned int count = 0;
	struct block *block;

	while (count < block_data.count) {
		block = &block_data.block[count++];

		printf("Block %" PRIu32 "\n", block->id);
		printf("\tSize: %" PRIu64 " MB\n", block->size / (1 M));
		printf("\tVA start: 0x%016" PRIx64 "\n", block->va);
		printf("\tPA start: 0x%016" PRIx64 "\n", block->pa);
		printf("\tcount: %u hugepages\n", block->count);
		block = block->next;
	}
}

static int map_block(struct block *block)
{
	void *addr;
	void *next = NULL;
	struct hugepage_info *hp;
	size_t page_size;

	if (block == NULL)
		return -1;

	/* find a place in VA space for this block */
	addr = (void *)anchor_addr;
	addr = mmap(addr, block->size,
		    PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED,
		    -1, 0);

	if (addr == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	/* leave one hugepage gap so we don't overwrite the next one by mistake */
	anchor_addr += block->size + block->page_size;
	/* FIXME: check upper boundary */

	hp = block->first;
	page_size = hp->size;
	block->va = addr;

	printf("Mapping block %d at %p\n", block->id, block->va);

	while (hp != NULL) {
		if (munmap(addr, hp->size) != 0) {
			perror("munmap");
			fprintf(stderr, "Handle this error....\n");
			HERE();
			exit(EXIT_FAILURE);
		}

		void *tmp;

		tmp = mmap(addr, hp->size,
			   PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_FIXED,
			   hp->fd, 0);
		if (tmp == MAP_FAILED) {
			perror("mmap");
			fprintf(stderr, "Error remapping PA:0x%" PRIu64 " to %p\n",
				hp->pa, tmp);
			HERE();
			exit(EXIT_FAILURE);
		}

		int fd = *((int *)tmp);
		if (fd != hp->fd) {
			fprintf(stderr, "Mismatch!\n");
			exit(EXIT_FAILURE);
		}

		uint64_t pa = get_phys_addr(tmp);
		if (pa != hp->pa) {
			printf("Remapping hp %d (fd old: %d) (fd new: %d) "
			       "failed?\n", hp->fd, fd, *((int *)hp->va));
			printf("PA orig: 0x%016" PRIx64 "\n"
			       "PA  new: 0x%016" PRIx64 "\n", hp->pa, pa);
		}

		printf("\t%03d: VA: 0x%016" PRIx64 " -> 0x%016" PRIx64 ", "
		       "PA: 0x%016" PRIx64 "\n", hp->fd, hp->va, tmp, hp->pa);

		if (munmap(hp->va, page_size) != 0) {
			munmap(tmp, page_size);
			perror("munmap");
			fprintf(stderr, "Error unmapping hp->va: %p\n", hp->va);
			HERE();
			exit(EXIT_FAILURE);
		}

		hp->va = addr;

		addr = (void *)((char *)addr + hp->size);
		hp = hp->next;
	}

	return 0;
}

/* this is just to demonstrate that we can actually write to the blocks
 * contiguously mapped
 */
static void zero_block(struct block *block)
{
	if (block == NULL || block->va == NULL)
		return;

	/* if this works... */
	printf("Zeroing out block %d, size %lu MB\n",
	       block->id, block->size / (1 M));
	memset(block->va, 0, block->size);
}

/* this checks */
static int check_va_area(const void *va, uint64_t size, uint64_t page_size)
{
	uint64_t pa;
	uint64_t expected_pa;
	uint64_t offset;

	pa = get_phys_addr(va);
	if (pa == PHYS_ADDR_INVALID)
		return -1;
	printf("VA: %016" PRIx64 " -> PA: %016" PRIx64 "\n", va, pa);


	expected_pa = pa + page_size;
	offset = page_size;
	while (offset < size) {
		va = (void *)((char *)va + offset);
		pa = get_phys_addr(va);

		if (pa == PHYS_ADDR_INVALID)
			return -1;

		printf("VA: %016" PRIx64 " -> PA: %016" PRIx64 "\n", va, pa);

		if (pa != expected_pa) {
			fprintf(stderr,
				"ERRROR: not expected PA %016" PRIx64 "...\n",
				expected_pa);
			return -1;
		}

		expected_pa += page_size;
	}

	return 0;
}

static void do_atexit(void)
{
	int count = 0;

	for (int i = 0; i < MAX_HUGEPAGES; ++i) {
		if (pages[i].fd == 0)
			continue;
		close(pages[i].fd);
		unlink(pages[i].filename);
		count++;
	}
	fprintf(stderr, "Removed %d files:\n", count);
}

static int hp_init(void)
{
	memset(&block_data, 0, sizeof(block_data));
	memset(pages, 0, sizeof(pages));
	atexit(do_atexit);

	for (int i = 0; i < MAX_HUGEPAGES; ++i) {
		if (alloc_hugepage(&pages[i]) != 0) {
			fprintf(stderr, "Could not allocate hugepages\n");
			return -1;
		}
	}

	qsort(pages, MAX_HUGEPAGES, sizeof(pages[0]), comp_hp);

	if (sort_by_block(pages, MAX_HUGEPAGES, 2 M) != 0)
		return -1;

	return 0;
}

int main(void)
{
	if (hp_init() != 0)
		exit(EXIT_FAILURE);

	dump_blocks();

	exit(EXIT_SUCCESS);
}

