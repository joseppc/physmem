#ifndef GET_PHYS_ADDR_H
#define GET_PHYS_ADDR_H

#include <stdint.h>

#define PHYS_ADDR_INVALID ((uint64_t)-1)

uint64_t get_phys_addr(const void *);

#endif
