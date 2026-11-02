/*
 * bpf_memory.c
 *
 * Read the memory of the running kernel with BPF (--bpf), as an
 * alternative to /proc/kcore.
 *
 * makedumpfile reads memory through the ELF code, so this file builds
 * an ELF header in a memfd that looks like /proc/vmcore:
 *
 *  - a PT_NOTE segment containing the kernel's vmcoreinfo note, and
 *  - one PT_LOAD segment for each "System RAM" range in /proc/iomem.
 *
 * The PT_LOAD segments have p_offset = BPF_DATA_OFFSET + p_paddr.
 * Those offsets don't exist in the memfd; read_from_vmcore() sends reads
 * at or above BPF_DATA_OFFSET to bpf_memory_read(), which reads the
 * memory with a BPF program.
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
#define _GNU_SOURCE
#include "bpf_memory.h"
#ifdef BPF_MEMORY_SUPPORTED

#include <stdarg.h>
#include <sys/mman.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "makedumpfile.h"
#include "print_info.h"
#include "bpf_memory.skel.h"

#define BPF_DATA_OFFSET		(1ULL << 40)

#define BPF_ELF_MACHINE		EM_X86_64
/* Direct mapping base of 4-level kernels without page_offset_base. */
#define DEFAULT_DIRECT_MAP_BASE	0xffff888000000000ULL

struct ram_range {
	unsigned long long start;
	unsigned long long end;		/* exclusive */
};

static struct bpf_memory_bpf *skel;
static unsigned long nr_unreadable;

static int
libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG && !(message_level & ML_PRINT_DEBUG_MSG))
		return 0;
	return vfprintf(stderr, fmt, args);
}

/*
 * Read up to BPF_MEMORY_BUF_SIZE bytes of physical memory.
 * Returns 0 or a negative errno.
 */
static int
read_phys(unsigned long long paddr, void *bufptr, unsigned long size)
{
	struct bpf_memory_read_args args = {
		.paddr = paddr,
		.size = size,
	};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .ctx_in = &args,
		    .ctx_size_in = sizeof(args));
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.read_phys),
				     &opts);
	if (err)
		return err;
	if (opts.retval)
		return (int)opts.retval;

	memcpy(bufptr, skel->bss->buf, size);
	return 0;
}

static int
find_direct_map_base(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err, ret;

	skel->bss->direct_map_base = DEFAULT_DIRECT_MAP_BASE;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.init), &opts);
	ret = err ? err : (int)opts.retval;
	if (ret == -ENOENT) {
		DEBUG_MSG("bpf: page_offset_base not found, using default\n");
		skel->bss->direct_map_base = DEFAULT_DIRECT_MAP_BASE;
	} else if (ret) {
		ERRMSG("Can't find the direct mapping base with BPF. %s\n",
		       strerror(-ret));
		return FALSE;
	}

	DEBUG_MSG("bpf: direct mapping base: %llx\n",
		  (unsigned long long)skel->bss->direct_map_base);
	return TRUE;
}

/*
 * Get the "System RAM" ranges from /proc/iomem.  Only top-level entries
 * are used; nested ones are parts of a top-level range.
 */
static int
get_ram_ranges(struct ram_range **ranges, int *nr_ranges)
{
	char line[BUFSIZE_FGETS];
	struct ram_range *r = NULL, *tmp;
	int n = 0, cap = 0, nonzero = FALSE;
	unsigned long long start, end;
	char *name;
	int pos;
	FILE *fp;

	if (!(fp = fopen("/proc/iomem", "r"))) {
		ERRMSG("Can't open /proc/iomem. %s\n", strerror(errno));
		return FALSE;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (line[0] == ' ')
			continue;
		pos = 0;
		if (sscanf(line, "%llx-%llx : %n", &start, &end, &pos) != 2
		    || !pos)
			continue;
		name = line + pos;
		name[strcspn(name, "\n")] = '\0';
		if (strcmp(name, "System RAM"))
			continue;

		if (n == cap) {
			cap = cap ? cap * 2 : 16;
			tmp = realloc(r, cap * sizeof(*r));
			if (!tmp) {
				ERRMSG("Can't allocate memory. %s\n",
				       strerror(errno));
				goto error;
			}
			r = tmp;
		}
		r[n].start = start;
		r[n].end = end + 1;
		if (start || end)
			nonzero = TRUE;
		n++;
	}

	if (!n) {
		ERRMSG("No System RAM in /proc/iomem.\n");
		goto error;
	}
	/* Addresses are shown as zeros to users without CAP_SYS_ADMIN. */
	if (!nonzero) {
		ERRMSG("/proc/iomem doesn't show addresses. Are you root?\n");
		goto error;
	}

	fclose(fp);
	*ranges = r;
	*nr_ranges = n;
	return TRUE;

error:
	fclose(fp);
	free(r);
	return FALSE;
}

/*
 * Read the vmcoreinfo note.  This also checks that the direct mapping
 * base is right, because the note must start with the VMCOREINFO name.
 */
static int
read_vmcoreinfo_note(void **note, unsigned long *note_size)
{
	uint64_t addr, len;
	Elf64_Nhdr *nhdr;
	unsigned long size;
	void *buf;
	int err;

	if (!get_sys_kernel_vmcoreinfo(&addr, &len)) {
		ERRMSG("Can't get the vmcoreinfo address from /sys/kernel/vmcoreinfo.\n");
		return FALSE;
	}
	if (len < sizeof(Elf64_Nhdr) || len > BPF_MEMORY_BUF_SIZE) {
		ERRMSG("Invalid vmcoreinfo size: %llx\n",
		       (unsigned long long)len);
		return FALSE;
	}

	buf = malloc(len);
	if (!buf) {
		ERRMSG("Can't allocate memory. %s\n", strerror(errno));
		return FALSE;
	}

	err = read_phys(addr, buf, len);
	if (err) {
		ERRMSG("Can't read vmcoreinfo at %llx with BPF. %s\n",
		       (unsigned long long)addr, strerror(-err));
		goto error;
	}

	nhdr = buf;
	size = sizeof(*nhdr) + roundup(nhdr->n_namesz, 4)
		+ roundup(nhdr->n_descsz, 4);
	if (nhdr->n_namesz != sizeof("VMCOREINFO") || size > len
	    || memcmp(nhdr + 1, "VMCOREINFO", sizeof("VMCOREINFO"))) {
		ERRMSG("No vmcoreinfo note at %llx. The direct mapping base (%llx) may be wrong.\n",
		       (unsigned long long)addr,
		       (unsigned long long)skel->bss->direct_map_base);
		goto error;
	}

	*note = buf;
	*note_size = size;
	return TRUE;

error:
	free(buf);
	return FALSE;
}

/*
 * Build the ELF header described at the top of this file and return a
 * memfd containing it.
 */
static int
create_elf_memfd(struct ram_range *ranges, int nr_ranges,
		 void *note, unsigned long note_size)
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	size_t hdr_size, total, done;
	ssize_t ret;
	char *buf;
	int i, fd;

	hdr_size = sizeof(*ehdr) + (1 + nr_ranges) * sizeof(*phdr);
	total = hdr_size + note_size;

	buf = calloc(1, total);
	if (!buf) {
		ERRMSG("Can't allocate memory. %s\n", strerror(errno));
		return -1;
	}

	ehdr = (Elf64_Ehdr *)buf;
	memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
	ehdr->e_ident[EI_CLASS] = ELFCLASS64;
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_ident[EI_VERSION] = EV_CURRENT;
	ehdr->e_ident[EI_OSABI] = ELFOSABI_NONE;
	ehdr->e_type = ET_CORE;
	ehdr->e_machine = BPF_ELF_MACHINE;
	ehdr->e_version = EV_CURRENT;
	ehdr->e_phoff = sizeof(*ehdr);
	ehdr->e_ehsize = sizeof(*ehdr);
	ehdr->e_phentsize = sizeof(*phdr);
	ehdr->e_phnum = 1 + nr_ranges;

	phdr = (Elf64_Phdr *)(buf + sizeof(*ehdr));
	phdr[0].p_type = PT_NOTE;
	phdr[0].p_offset = hdr_size;
	phdr[0].p_filesz = note_size;
	phdr[0].p_memsz = note_size;

	for (i = 0; i < nr_ranges; i++) {
		Elf64_Phdr *p = &phdr[1 + i];
		unsigned long long size = ranges[i].end - ranges[i].start;

		p->p_type = PT_LOAD;
		p->p_flags = PF_R | PF_W | PF_X;
		p->p_offset = BPF_DATA_OFFSET + ranges[i].start;
		p->p_vaddr = skel->bss->direct_map_base + ranges[i].start;
		p->p_paddr = ranges[i].start;
		p->p_filesz = size;
		p->p_memsz = size;
	}

	memcpy(buf + hdr_size, note, note_size);

	fd = memfd_create("makedumpfile-bpf", MFD_CLOEXEC);
	if (fd < 0) {
		ERRMSG("Can't create a memfd. %s\n", strerror(errno));
		goto out;
	}
	for (done = 0; done < total; done += ret) {
		ret = write(fd, buf + done, total - done);
		if (ret < 0) {
			ERRMSG("Can't write to the memfd. %s\n",
			       strerror(errno));
			close(fd);
			fd = -1;
			goto out;
		}
	}
out:
	free(buf);
	return fd;
}

/*
 * Load the BPF programs and create the ELF header.  Returns a file
 * descriptor to be used as info->fd_memory, or -1 on error.
 */
int
bpf_memory_open(void)
{
	struct ram_range *ranges = NULL;
	int nr_ranges, fd = -1;
	unsigned long note_size;
	void *note = NULL;

	libbpf_set_print(libbpf_print);

	skel = bpf_memory_bpf__open_and_load();
	if (!skel) {
		ERRMSG("Can't load the BPF program. %s\n", strerror(errno));
		return -1;
	}

	if (!find_direct_map_base())
		goto error;
	if (!get_ram_ranges(&ranges, &nr_ranges))
		goto error;
	if (!read_vmcoreinfo_note(&note, &note_size))
		goto error;

	fd = create_elf_memfd(ranges, nr_ranges, note, note_size);
	if (fd < 0)
		goto error;

	free(ranges);
	free(note);
	return fd;

error:
	free(ranges);
	free(note);
	bpf_memory_close();
	return -1;
}

int
bpf_memory_is_data(off_t offset)
{
	return skel && offset >= BPF_DATA_OFFSET;
}

/*
 * Read memory at a PT_LOAD file offset.  Memory that can't be read
 * (removed from the direct mapping) is filled with zeros, like
 * /proc/kcore does.
 */
int
bpf_memory_read(off_t offset, void *bufptr, unsigned long size)
{
	unsigned long long paddr = offset - BPF_DATA_OFFSET;
	unsigned long chunk;
	char *p = bufptr;
	int err;

	while (size) {
		chunk = MIN(size, BPF_MEMORY_BUF_SIZE);
		err = read_phys(paddr, p, chunk);
		if (err == -EFAULT) {
			DEBUG_MSG("bpf: Can't read memory at %llx\n", paddr);
			nr_unreadable++;
			memset(p, 0, chunk);
		} else if (err) {
			ERRMSG("Can't read memory at %llx with BPF. %s\n",
			       paddr, strerror(-err));
			return FALSE;
		}
		paddr += chunk;
		p += chunk;
		size -= chunk;
	}

	return TRUE;
}

void
bpf_memory_close(void)
{
	/* E.g. KFENCE guard pages or secretmem; /proc/kcore zero-fills them too. */
	if (nr_unreadable)
		MSG("%lu reads of memory that isn't mapped in the kernel were filled with zeros.\n",
		    nr_unreadable);
	bpf_memory_bpf__destroy(skel);
	skel = NULL;
}

#endif /* BPF_MEMORY_SUPPORTED */
