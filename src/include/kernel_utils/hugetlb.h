/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Xilinx, Inc. */
/*
 ****************************************************************************
 *
 * A library to allocate hugepages in the kernelspace
 * (which is not encouraged and not straightforward).
 *
 * How it works: the userspace donates a memfd file to the kernel module via
 * ioctl(). Then the library calls ftruncate(), fallocate(), mmap(),
 * pin_user_pages() and munmap() to get an instance of a 2 MiB hugepage,
 * which we can give to NIC after dma_map_single(). For older kernels without
 * the memfd support, the library calls hugetlb_file_setup() directly.
 *
 * Ideally, the userspace should do the allocation itself, i.e. ftruncate(),
 * fallocate(), mmap(), and then make an ioctl() with the virtual address.
 * In this case, we become aligned with the kernel API, and the library
 * degenerates into a single pin_user_pages() call. This may require
 * significant workflow refactoring in Onload.
 *
 ****************************************************************************
 */

#ifndef __HUGETLB_H__
#define __HUGETLB_H__

#include <onload/common.h>
#include <onload/atomics.h>

#define HUGEPAGE_SIZE (2 * 1024 * 1024)

struct hugetlb_allocator {
	struct file *filp;
	off_t offset;
	atomic_t refcnt;
};

struct hugetlb_page {
	struct file *filp;
	struct page *page;
};

/* Create/destroy the memory allocator. */

/*
 * hugetlb_allocator_create - Create a hugepage allocator.
 *
 * Parameters:
 *   fd:             A donated memfd file descriptor to use for hugepage
 *                   allocation or -1 on systems without memfd_create().
 *
 * Return:
 *   On success, get a file reference identified by the file descriptor
 *   or open a pseudo file with hugetlb_file_setup(), and return a valid
 *   pointer to use later for allocation.
 *
 *   On failure, return a negative error number:
 *     ENOSYS: Unable to find or call hugetlb_file_setup() in absence of memfd.
 *     ENOMEM: Kernel memory allocation failure.
 *     EINVAL: User error, e.g. a wrong file descriptor.
 *     Those, returned by hugetlb_file_setup().
 *
 * Notes:
 *   EINVAL should be treated as a fatal error indicating a software defect.
 */
extern struct hugetlb_allocator *hugetlb_allocator_create(int fd);

extern struct hugetlb_allocator *
hugetlb_allocator_get(struct hugetlb_allocator *);

extern void hugetlb_allocator_put(struct hugetlb_allocator *);

static inline void
hugetlb_page_reset(struct hugetlb_page *page)
{
	page->filp = NULL;
	page->page = NULL;
}

/* Allocate/free one hugepage. */

extern int
hugetlb_page_alloc_raw(struct hugetlb_allocator *,
		struct file **, struct page **);

/*
 * hugetlb_page_alloc - Allocate one hugepage HUGEPAGE_SIZE bytes.
 *
 * Return:
 *   0 on success or a negative error number otherwise. Additionally,
 *   reset an instance of hugetlb_page so that hugetlb_page_valid()
 *   returns False, if allocation fails.
 *
 * Notes:
 *   The hugepage allocator does not implement locking. The user must
 *   serialise accesses to the allocator to prevent race conditions.
 *
 *   The hugepage instance is not tied to the allocator lifespan,
 *   i.e. the users can legally destroy the allocator while the
 *   hugepage is still in use.
 *
 *   Allocation happens on behalf of the userspace process and is not
 *   suitable for the GFP_ATOMIC contexts.
 */
static inline int
hugetlb_page_alloc(struct hugetlb_allocator *alloc,
		struct hugetlb_page *page)
{
	return hugetlb_page_alloc_raw(alloc, &page->filp, &page->page);
}

extern void hugetlb_page_free_raw(struct file *, struct page *);

static inline void hugetlb_page_free(struct hugetlb_page *page)
{
	hugetlb_page_free_raw(page->filp, page->page);
	hugetlb_page_reset(page);
}

/* Misc. */

/*
 * hugetlb_pages_prealloc - Preallocate number of hugepages
 * to support EF_PREALLOC_PACKETS.
 *
 * Return:
 *   0 on success, or an error number returned by vfs_truncate()
 *   or vfs_fallocate().
 */
extern int
hugetlb_pages_prealloc(struct hugetlb_allocator *, int);

static inline bool
hugetlb_page_valid(struct hugetlb_page *page)
{
	return page->filp && page->page;
}

#endif /* __HUGETLB_H__ */
