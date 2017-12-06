/* (c) 2017 Linaro Inc. */
/* BSD-3 license */

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
#include <sys/queue.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>

#define KB * 1024ULL
#define MB * 1024ULL KB
#define GB * 1024ULL MB
#define TB * 1024ULL GB

#ifndef HERE
#define HERE() fprintf(stderr, "%s:%d\n", __FILE__, __LINE__)
#endif

#define ROUNDUP_ALIGN(x, align) \
	((align) * (((x) + (align) - 1) / (align)))

#define lock_list()
#define unlock_list()

#define PAGEMAP_FILE "/proc/self/pagemap"
#define HUGEPAGES_PATH "/dev/hugepages/"
#define PHYS_ADDR_INVALID ((uint64_t)-1)

typedef enum {
	BLOCK_EMPTY = 0,
	BLOCK_AVAIL,
	BLOCK_USED
} block_type;

/* must be on a huge page boundary */
#define VIRTUAL_PHYSICAL_ANCHOR (16 TB)
static uint64_t anchor_addr = VIRTUAL_PHYSICAL_ANCHOR;

/* make hugepage_info 128 bytes long */
#define FILENAME_PATH_MAX 96

struct hugepage_info {
	struct block *block; /* the block this hugepage belongs to */
	void *va; /* virtual address this hugepage is mapped to */
	uint64_t pa; /* the Physical Address of this hugepage */
	uint32_t size; /* size of hugepage, probably redundant */
	int fd; /* the fd returned by open, for the hugepages file */
	char filename[FILENAME_PATH_MAX];
};

/* a block is a chunk of physically contiguous memory that can be
 * made of one or more huge pages
 * */
struct block {
	LIST_ENTRY(block) next;
	void *va; /* virtual address where the block is mapped */
	uint64_t pa; /* physical address where it starts */
	uint64_t size; /* the size of this memory block */
	uint32_t first; /* index of first hugepage belonging to this block
			 * in pages[] */
	uint32_t count; /* number of hugepages in this block */
	uint32_t hp_size; /* the size of the hugepages */
	uint32_t id; /* internal ID of this block, debug purposes */
	block_type type;
};

#define MAX_HUGEPAGES 128

typedef LIST_HEAD(block_list, block) block_list_t;

struct block_data {
	struct block block[MAX_HUGEPAGES];
	block_list_t avail; /* blocks of huge pages ready to use */
	block_list_t used;  /* blocks allocated and being in use */
	block_list_t empty; /* blocks without any hugepages, size 0 */
	uint32_t hp_size;
	uint32_t count;
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

	hp->va = mmap(NULL, 2 MB, PROT_READ | PROT_WRITE, MAP_SHARED, hp->fd,
		      0);
	if (hp->va == MAP_FAILED) {
		perror("mmap");
		close(hp->fd);
		unlink(hp->filename);
		return -1;
	}

	/* Force memory commitment */
	*((int *)(hp->va)) = hp->fd;

	hp->size = 2 MB; /* FIXME: defaulting to 2MB huge pages */
	hp->pa = get_phys_addr(hp->va);
	if (hp->pa == PHYS_ADDR_INVALID)
		fprintf(stderr, "Could not discover PA\n");

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

static int init_hugepages(void)
{
	memset(pages, 0, sizeof(pages));

	for (int i = 0; i < MAX_HUGEPAGES; ++i) {
		if (alloc_hugepage(&pages[i]) != 0) {
			fprintf(stderr, "Could not allocate hugepages\n");
			return -1;
		}
	}

	qsort(pages, MAX_HUGEPAGES, sizeof(pages[0]), comp_hp);

	return 0;
}

static int comp_block(const void *_a, const void *_b)
{
	const struct block *a = _a;
	const struct block *b = _b;

	if (a->count > b->count)
		return 1;
	else if (a->count < b->count)
		return -1;
	else
		return 0;
}

/*
 * hp is a SORTED array of count elements of struct hugepage_info,
 * it is sorted per physical address in ascending order.
 * This returns a linked list of struct block, each block containing
 * a reference to physically contiguous huge pages.
 */
static int sort_in_blocks(struct hugepage_info *hp_array, int count)
{
	int block_id;
	int hp_id;
	struct block *block;
	struct hugepage_info *hp;

	if (hp_array == NULL || count == 0)
		return -EINVAL;

	block_id = 0;
	hp_id = 0;
	hp = &hp_array[0];
	do {
		uint64_t pa_expected;

		block = &block_data.block[block_id];
		block->first = hp_id;
		block->size = hp->size;
		block->pa = hp->pa;
		block->va = NULL;
		block->count = 1;
		block->id = block_id++;
		block->hp_size = hp->size;
		block->type = BLOCK_AVAIL;

		block_data.count++;

		printf("New block %d\n", block->id);
		printf("\t%03d: VA: %016" PRIx64 ", PA: %016" PRIx64 "\n",
		       hp->fd, hp->va, hp->pa);

		pa_expected = block->pa + hp->size;

		/* keep adding huge pages to this block as long as their
		 * physical address coincides with the expected one */
		while (++hp_id < count) {
			hp++;

			if (hp->pa != pa_expected)
				break;

			printf("\t%03d: VA: %016" PRIx64 ", "
			       "PA: %016" PRIx64 "\n",
			       hp->fd, hp->va, hp->pa);

			block->count++;
			block->size += hp->size;

			pa_expected += hp->size;
		}
		printf("\tSize: %" PRIu64 " MB\n", (block->size / (1 MB)));
	} while (hp_id < count);

	qsort(block_data.block, block_data.count, sizeof(block_data.block[0]),
	      comp_block);

	/* link sorted blocks together */
	struct block *last = &block_data.block[0];
	pages[last->first].block = last;
	pages[last->first + last->count - 1].block = last;
	LIST_INSERT_HEAD(&block_data.avail, last, next);
	for (block_id = 1; block_id < block_data.count; ++block_id) {
		block = &block_data.block[block_id];
		pages[block->first].block = block;
		pages[block->first + block->count - 1].block = block;
		LIST_INSERT_AFTER(last, block, next);
		last = block;
	}

	/* insert rest of blocks into the empty list */
	for (block_id = block_data.count; block_id < MAX_HUGEPAGES; ++block_id){
		block = &block_data.block[block_id];
		block->id = block_id;
		block->type = BLOCK_EMPTY;
		LIST_INSERT_HEAD(&block_data.empty, block, next);
	}

	block_data.hp_size = block_data.block[0].hp_size;

	return 0;
}

static struct block *block_get(void)
{
	struct block *block;

	if (LIST_EMPTY(&block_data.empty))
		return NULL;

	block = LIST_FIRST(&block_data.empty);
	LIST_REMOVE(block, next);

	return block;
}

static const struct block *block_alloc(uint64_t size)
{
	int i;
	struct block *block;
	struct block *ret = NULL;
	uint32_t num_hp;

	size = ROUNDUP_ALIGN(size, block_data.hp_size);
	num_hp = size / block_data.hp_size;

	lock_list();

	LIST_FOREACH(block, &block_data.avail, next) {
		if (block->count < num_hp)
			continue;
		else if (block->count == num_hp) {
			LIST_REMOVE(block, next);
			ret = block;
			break;
		} else {
			struct hugepage_info *hp;

			ret = block_get();
			if (ret == NULL)
				break;

			/* slice num_hp pages from this block */
			block->count -= num_hp;
			block->size = block->count * block->hp_size;

			ret->first = block->first + block->count;
			ret->count = num_hp;
			ret->hp_size = block->hp_size;
			ret->size = ret->hp_size * num_hp;
			ret->va = NULL;

			/* reassign pages to their corresponding block
			 * only the borders need to be updated */
			hp = &pages[ret->first];
			hp->block = ret;
			ret->pa = hp->pa;
			hp--; /* last page of the block we just sliced */
			hp->block = block;
			hp += num_hp; /* last page of the block we just allocated */
			hp->block = ret;

			/* place the sliced block back into the list at correct position */
			LIST_REMOVE(block, next);

			if (LIST_EMPTY(&block_data.avail)) {
				LIST_INSERT_HEAD(&block_data.avail, block, next);
			} else {
				struct block *last = NULL;
				struct block *tmp;

				LIST_FOREACH(tmp, &block_data.avail, next) {
					if (tmp->count >= block->count) {
						LIST_INSERT_BEFORE(tmp, block, next);
						last = NULL;
						break;
					}
					last = tmp;
				}
				if (last)
					LIST_INSERT_AFTER(last, block, next);
			}

			break;
		}
	}

	if (ret != NULL) {
		ret->type = BLOCK_USED;
		LIST_INSERT_HEAD(&block_data.used, ret, next);
	}

	unlock_list();

	return ret;
}

static void block_free(struct block *block)
{
	if (block == NULL) {
		printf("B is null\n");
		return;
	}

	lock_list();

	LIST_REMOVE(block, next);
	printf("Block %u removed from list\n", block->id);

	/* append this block to left block if available */
	if (block->first != 0) {
		struct hugepage_info *left_hp, *first_hp;
		struct block *left_block;
		uint64_t expected_pa;

		first_hp = &pages[block->first];
		left_hp = first_hp - 1;
		left_block = left_hp->block;
		expected_pa = left_hp->pa + left_hp->size;

		if (left_block->type == BLOCK_AVAIL && block->pa == expected_pa) {
			/* put the pages belonging to this block in to the left one */
			left_block->count += block->count;
			left_block->size = left_block->count * left_block->hp_size;

			pages[left_block->first + left_block->count - 1].block = left_block;

			block->size = 0;
			block->pa = 0;
			block->va = 0;
			block->first = 0;
			block->count = 0;
			block->type = BLOCK_EMPTY;
			LIST_INSERT_HEAD(&block_data.empty, block, next);

			block = left_block;
			LIST_REMOVE(block, next);
			printf("Block %u removed from list\n", block->id);
		}
	}

	/* join with right block if available */
	uint32_t right_idx = block->first + block->count;
	if (right_idx < MAX_HUGEPAGES) {
		struct hugepage_info *last_hp;
		struct hugepage_info *right_hp;
		struct block *right_block;
		uint64_t expected_pa;

		right_hp = &pages[right_idx];
		last_hp = right_hp - 1;
		right_block = right_hp->block;
		expected_pa = last_hp->pa + last_hp->size;

		if (right_block->type == BLOCK_AVAIL
		    && expected_pa == right_block->pa) {
			block->count += right_block->count;
			block->size = block->count * block->hp_size;

			pages[block->first + block->count - 1].block = block;

			LIST_REMOVE(right_block, next);
			right_block->size = 0;
			right_block->pa = 0;
			right_block->va = 0;
			right_block->first = 0;
			right_block->count = 0;
			right_block->type = BLOCK_EMPTY;
			LIST_INSERT_HEAD(&block_data.empty, right_block, next);
		}
	}

	block->type = BLOCK_AVAIL;
	if (LIST_EMPTY(&block_data.avail)) {
			LIST_INSERT_HEAD(&block_data.avail, block, next);
	} else {
		struct block *tmp, *last = NULL;

		LIST_FOREACH(tmp, &block_data.avail, next) {
			if (tmp->count >= block->count) {
				LIST_INSERT_BEFORE(tmp, block, next);
				last = NULL;
				break;
			}
			last = tmp;
		}
		if (last != NULL) {
			printf("inserting last %u\n", block->id);
			LIST_INSERT_AFTER(last, block, next);
		}
	}

	unlock_list();
}

static void dump_hp_array(struct hugepage_info *hp, int size)
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
		printf("\tSize: %" PRIu64 " MB\n", block->size / (1 MB));
		printf("\tVA start: 0x%016" PRIx64 "\n", block->va);
		printf("\tPA start: 0x%016" PRIx64 "\n", block->pa);
		printf("\tcount: %u hugepages\n", block->count);
	}
}

static int map_block(struct block *block)
{
	void *addr;
	void *next = NULL;
	struct hugepage_info *hp;
	size_t page_size;

	printf("WAAAAAAARN!\n");
	return 0;

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

	/* leave one hugepage gap */
	anchor_addr += block->size + block->hp_size;
	/* FIXME: check upper boundary */

	hp = &pages[block->first];
	page_size = hp->size;
	block->va = addr;

	printf("Mapping block %d at %p\n", block->id, block->va);

	while (hp != NULL) {
		if (munmap(addr, hp->size) != 0) {
			perror("munmap");
			fprintf(stderr, "Handle this error....\n");
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
			exit(EXIT_FAILURE);
		}

		hp->va = addr;

		addr = (void *)((char *)addr + hp->size);
		hp++;
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
	       block->id, block->size / (1 MB));
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
}

static void init_blocks(void)
{
	memset(&block_data, 0, sizeof(block_data));

	LIST_INIT(&block_data.avail);
	LIST_INIT(&block_data.used);
	LIST_INIT(&block_data.empty);
}

static int hp_init(void)
{
	init_blocks();

	init_hugepages();

	atexit(do_atexit);

	if (sort_in_blocks(pages, MAX_HUGEPAGES) != 0)
		return -1;

	return 0;
}

static int check_block(const struct block *block)
{
	struct hugepage_info *first, *last;
	int ret = 0;

	first = &pages[block->first];
	last = &pages[block->first + block->count - 1];
	if (first->block != block) {
		ret = 1;
		printf("\tfirst block does not match, got %u\n",
			first->block->id);
	}
	if (last->block != block) {
		ret = 1;
		printf("\tlast block does not match, got %u\n",
			last->block->id);
	}
	return ret;
}

static int test_alloc(void)
{
	const struct block *block;
	uint64_t size = 1 MB;

	block = block_alloc(size);
	while (block != NULL) {
		printf("-- Allocated block %d, count: %" PRIu32 "\n",
			block->id, block->count);
		if (check_block(block)) {
			printf("Error: check failed\n");
			break;
		}
		size += 1 MB;
		block = block_alloc(size);
	}
	printf("Failed to allocate block for size %" PRIu32 "MB\n",
		size / (1 MB));
	return 0;
}

static int test_free(void)
{
	while (!LIST_EMPTY(&block_data.used)) {
		struct block *b = LIST_FIRST(&block_data.used);
		block_free(b);
	}

	return 0;
}

static void print_block_list(block_list_t *list)
{
	struct block *block;

	LIST_FOREACH(block, list, next) {
		printf("Block %" PRIu32 "\n", block->id);
		printf("\tSize: %" PRIu64 " MB\n", block->size / (1 MB));
		printf("\tVA start: 0x%016" PRIx64 "\n", block->va);
		printf("\tPA start: 0x%016" PRIx64 "\n", block->pa);
		printf("\tHP start: %u-%u\n", block->first, block->first + block->count - 1);
		printf("\tcount: %u hugepages\n", block->count);
	}
}

int main(void)
{
	if (hp_init() != 0)
		exit(EXIT_FAILURE);

	dump_blocks();

	test_alloc();

	printf("AVAIL:\n");
	print_block_list(&block_data.avail);

	printf("USED:\n");
	print_block_list(&block_data.used);

	printf("-----------\n");

	sleep(2);
	test_free();
	printf("-----------\n");
	printf("AVAIL:\n");
	print_block_list(&block_data.avail);

	printf("USED:\n");
	print_block_list(&block_data.used);


	exit(EXIT_SUCCESS);
}

