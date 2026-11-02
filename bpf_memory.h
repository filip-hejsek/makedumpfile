/*
 * bpf_memory.h
 *
 * Read the memory of the running kernel with BPF.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef _BPF_MEMORY_H
#define _BPF_MEMORY_H

#include <linux/types.h>

/*
 * Shared between the BPF program and makedumpfile.
 */

/* Size of the buffer the BPF program copies memory into. */
#define BPF_MEMORY_BUF_SIZE	(64 * 1024)

/* Context passed to the read_phys program. */
struct bpf_memory_read_args {
	__u64 paddr;
	__u32 size;
	__u32 reserved;
};

#ifndef __bpf__

#include <sys/types.h>

/* --bpf is implemented only for x86_64 so far. */
#if defined(USEBPF) && defined(__x86_64__)
#define BPF_MEMORY_SUPPORTED
#endif

int bpf_memory_open(void);
int bpf_memory_is_data(off_t offset);
int bpf_memory_read(off_t offset, void *bufptr, unsigned long size);
void bpf_memory_close(void);

#endif /* __bpf__ */

#endif /* _BPF_MEMORY_H */
