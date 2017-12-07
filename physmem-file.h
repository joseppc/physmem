#ifndef PHYSMEM_FILE_H
#define PHYSMEM_FILE_H

#include <sys/queue.h>
#include <stdint.h>

/* make hugepage_info 128 bytes long */
#define FILENAME_PATH_MAX 96

struct hugepage_info {
	struct block *block; /* the block this hugepage belongs to */
	void *va; /* virtual address this hugepage is mapped to */
	uint64_t pa; /* the physical address of this hugepage */
	uint32_t size; /* size of hugepage */
	int fd; /* the fd returned by open, for the hugepages file */
	char filename[FILENAME_PATH_MAX];
};

typedef enum {
	BLOCK_EMPTY = 0,
	BLOCK_AVAIL,
	BLOCK_USED
} block_type;

/* a block is a chunk of physically contiguous memory that can be
 * made of one or more huge pages
 */
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

struct block *block_alloc(uint64_t);
void block_free(struct block *);
int block_module_init(void);

#endif
