#ifndef PHYSMEM_FILE_H
#define PHYSMEM_FILE_H

#include <sys/queue.h>
#include <stdint.h>

typedef enum {
	BLOCK_EMPTY = 0,
	BLOCK_AVAIL,
	BLOCK_USED
} block_type_t;

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
	block_type_t type;
};

struct block *block_alloc(uint64_t);
void block_free(struct block *);
int block_module_init(void);
int block_check(const struct block *);
int block_map(struct block *block, void *addr);
int block_unmap(struct block *block);

/* if pages is not 0, it will print the pages associated to each block */
void block_dump(block_type_t, int pages);

#endif
