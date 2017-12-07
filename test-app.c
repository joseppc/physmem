#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/queue.h>
#include <inttypes.h>
#include <string.h>

#include "physmem-file.h"

#define KB * 1024ULL
#define MB * 1024ULL KB
#define GB * 1024ULL MB
#define TB * 1024ULL GB

/* must be on a huge page boundary */
#define VIRTUAL_PHYSICAL_ANCHOR (16 TB)
static uint64_t anchor_addr = VIRTUAL_PHYSICAL_ANCHOR;

struct entry {
	LIST_ENTRY(entry) entries;
	struct block *block;
};

LIST_HEAD(listhead, entry) head =
         LIST_HEAD_INITIALIZER(head);

static int test_alloc(void)
{
	struct entry *entry;
	struct block *block;
	uint64_t size = 1 MB;

	entry = malloc(sizeof(*entry));
	if (entry == NULL)
		return -1;

	block = block_alloc(size);
	while (block != NULL) {
		printf("-- Allocated block %d, count: %" PRIu32 "\n",
		       block->id, block->count);
		entry->block = block;
		LIST_INSERT_HEAD(&head, entry, entries);
		size += 1 MB;
		entry = malloc(sizeof(*entry));
		if (entry == NULL)
			break;
		block = block_alloc(size);
	}
	free(entry);
	printf("Failed to allocate block for size %" PRIu32 "MB\n",
		size / (1 MB));

	return 0;
}

static int test_free(void)
{
	while (!LIST_EMPTY(&head)) {
		struct entry *entry = LIST_FIRST(&head);
		block_free(entry->block);
		LIST_REMOVE(entry, entries);
		free(entry);
	}

	return 0;
}

static int test_map_unmap(void)
{
	struct entry *entry;
	int ret;

	entry = LIST_FIRST(&head);
	if (!entry)
		return -1;

	ret = block_map(entry->block, (void *)anchor_addr);
	if (ret)
		return ret;

	ret = *(int *)(entry->block->va);
	printf("Poison: %d\n", ret);

	memset(entry->block->va, 0, entry->block->size);

	return block_unmap(entry->block);
}

int main(void)
{
	int ret;

	if (block_module_init()) {
		fprintf(stderr, "Could not initialize modue\n");
		exit(EXIT_FAILURE);
	}

	block_dump(BLOCK_AVAIL, 1);

	if (test_alloc()) {
		fprintf(stderr, "Failed to allocate memory\n");
		exit(EXIT_FAILURE);
	}

	block_dump(BLOCK_USED, 0);
	block_dump(BLOCK_AVAIL, 0);

	printf("-----\nMAPPING\n----\n");
	ret = test_map_unmap();
	if (ret) {
		fprintf(stderr, "Failed to map: %d\n", ret);
	}


	printf("-----\nFREEING\n----\n");
	test_free();

	block_dump(BLOCK_AVAIL, 0);
	block_dump(BLOCK_USED, 0);

	exit(EXIT_SUCCESS);
}
