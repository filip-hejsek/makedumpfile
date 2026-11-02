// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * bpf_memory.bpf.c
 *
 * BPF programs used by makedumpfile --bpf to read the memory of the
 * running kernel.  Physical memory is read through the kernel's direct
 * mapping of RAM.  Userspace runs the programs with BPF_PROG_RUN and
 * reads the results from the mmapped .bss map.
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include "bpf_memory.h"

char LICENSE[] SEC("license") = "GPL";

/* Virtual address of physical address 0 in the direct mapping. */
__u64 direct_map_base;

/* Output of read_phys. */
char buf[BPF_MEMORY_BUF_SIZE];

#ifdef __TARGET_ARCH_x86
/* Randomized base of the direct mapping (CONFIG_DYNAMIC_MEMORY_LAYOUT). */
extern const void page_offset_base __ksym __weak;
#endif

/*
 * Find the base of the direct mapping.  Returns -ENOENT when the kernel
 * doesn't have a variable for it; userspace then keeps the default it
 * set in direct_map_base.
 */
SEC("syscall")
int init(void *ctx)
{
#ifdef __TARGET_ARCH_x86
	if (!&page_offset_base)
		return -ENOENT;
	return bpf_probe_read_kernel(&direct_map_base, sizeof(direct_map_base),
				     &page_offset_base);
#else
	return -ENOENT;
#endif
}

/*
 * Copy args->size bytes at physical address args->paddr into buf.
 * Returns 0, or -EFAULT if the memory isn't mapped.
 */
SEC("syscall")
int read_phys(struct bpf_memory_read_args *args)
{
	__u32 size = args->size;

	if (size > sizeof(buf))
		return -E2BIG;

	return bpf_probe_read_kernel(buf, size,
				     (void *)(direct_map_base + args->paddr));
}
