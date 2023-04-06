/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Xilinx, Inc. */

#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <uapi/linux/falloc.h>
#include <kernel_utils/hugetlb.h>
#include <ci/driver/kernel_compat.h> /* For pin_user_pages(). */
#include <ci/efrm/sysdep.h> /* For efrm_find_ksym(). */

#ifdef EFRM_HAVE_NEW_KALLSYMS
/*
 * __hugetlb_file_setup - Create a pseudo hugetlb file.
 *
 * This fallback only exists on old kernels, but that's fine: new kernels
 * all have memfd_create, and there's considerable overlap between 'old'
 * and 'new' (e.g. RHEL8) so we can deal with potential oddballs.
 *
 * Return:
 *   A file struct on success or an error code.
 */
static struct file *__hugetlb_file_setup(void)
{
	static __typeof__(hugetlb_file_setup)* fn_hugetlb_file_setup;

	if (!fn_hugetlb_file_setup)
		fn_hugetlb_file_setup = efrm_find_ksym("hugetlb_file_setup");

	if (fn_hugetlb_file_setup) {
		struct user_struct* user;
		return fn_hugetlb_file_setup(HUGETLB_ANON_FILE,
				HUGEPAGE_SIZE, 0, &user,
				HUGETLB_ANONHUGE_INODE,
				ilog2(HUGEPAGE_SIZE));
	}

	return ERR_PTR(-ENOSYS);
}
#else
static struct file *__hugetlb_file_setup(void)
{
	return ERR_PTR(-ENOSYS);
}
#endif


static struct hugetlb_allocator *
do_hugetlb_allocator_create(struct file *filp)
{
	struct hugetlb_allocator *allocator;

	/* This assertion and others in this file should probably become a
	 * user-friendly EINVAL as a return value, but since hugetlb is an
	 * internal library with limited use, doing assertions for now. */
	EFRM_ASSERT(filp);

	allocator = kmalloc(sizeof(*allocator), GFP_KERNEL);
	if (!allocator) {
		return ERR_PTR(-ENOMEM);
	}

	allocator->filp = filp;
	allocator->offset = 0;
	atomic_set(&allocator->refcnt, 1);

	return allocator;
}

struct hugetlb_allocator *hugetlb_allocator_create(int fd)
{
	struct hugetlb_allocator *allocator;
	struct file *filp;
	int rc;

	/* Either use the given (memfd) file or try create a new pseudo file.*/
	if (fd >= 0) {
		filp = fget(fd);
		if (!filp) {
			rc = -EINVAL;
			goto fail_setup;
		}
	} else {
		filp = __hugetlb_file_setup();
		if (IS_ERR(filp)) {
			rc = PTR_ERR(filp);
			goto fail_setup;
		}
	}

	/* Call the allocator constructor with the set up file. */
	allocator = do_hugetlb_allocator_create(filp);
	if (IS_ERR(allocator)) {
		rc = PTR_ERR(allocator);
		goto fail_alloc;
	}

	return allocator;

fail_alloc:
	fput(filp);

fail_setup:
	allocator = ERR_PTR(rc);
	return allocator;
}
EXPORT_SYMBOL(hugetlb_allocator_create);

struct hugetlb_allocator *
hugetlb_allocator_get(struct hugetlb_allocator *allocator)
{
	EFRM_ASSERT(allocator);

	atomic_inc(&allocator->refcnt);
	get_file(allocator->filp);

	return allocator;
}
EXPORT_SYMBOL(hugetlb_allocator_get);

void hugetlb_allocator_put(struct hugetlb_allocator *allocator)
{
	EFRM_ASSERT(allocator);
	EFRM_ASSERT(allocator->filp);

	fput(allocator->filp);

	if (atomic_dec_and_test(&allocator->refcnt))
		kfree(allocator);
}
EXPORT_SYMBOL(hugetlb_allocator_put);

int
hugetlb_page_alloc_raw(struct hugetlb_allocator *allocator,
		struct file **filp_out, struct page **page_out)
{
	struct inode* inode;
	unsigned long addr;
	int rc;

	EFRM_ASSERT(allocator);
	EFRM_ASSERT(allocator->filp);
	EFRM_ASSERT(filp_out);
	EFRM_ASSERT(page_out);

	*filp_out = get_file(allocator->filp);

	/* Allocate one huge page at the current allocator's offset. */
	inode = file_inode(allocator->filp);
	if (i_size_read(inode) < allocator->offset + HUGEPAGE_SIZE) {
		rc = (int)vfs_truncate(&allocator->filp->f_path,
				allocator->offset + HUGEPAGE_SIZE);
		if (rc < 0) {
			EFRM_ERR("%s: ftruncate() failed: %d", __func__, rc);
			goto fail_vfs;
		}
	}

	rc = vfs_fallocate(allocator->filp, 0, allocator->offset,
			HUGEPAGE_SIZE);
	if (rc < 0) {
		EFRM_ERR("%s: fallocate() failed: %d", __func__, rc);
		goto fail_vfs;
	}

	/* Get the user address on behalf of the current process so we could
	 * call pin_user_pages(). Alternatively, we could find_get_page()
	 * without mapping, but this would not migrate a page from a
	 * potentially movable zone as the hugepages may be allocated with
	 * GFP_HIGHUSER_MOVABLE. */
	addr = vm_mmap(*filp_out, 0, HUGEPAGE_SIZE, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_HUGETLB | MAP_HUGE_2MB,
			allocator->offset);

	if (IS_ERR((void*)addr)) {
		rc = PTR_ERR((void*)addr);
		goto fail_vfs;
	}

	mmap_read_lock(current->mm);
	rc = pin_user_pages(addr, 1, FOLL_WRITE, page_out, NULL);
	mmap_read_unlock(current->mm);

	vm_munmap(addr, HUGEPAGE_SIZE);

	/* Did we get a good hugepage? */
	if (rc != 1) {
		EFRM_ERR("%s: Unable to pin page at 0x%08lx rc=%d", __func__,
				allocator->offset, rc);
		goto fail_vfs;
	}

	if (!(*page_out)) {
		EFRM_ERR("%s: Unable to create hugepage at 0x%08lx", __func__,
				allocator->offset);
		rc = -ENOMEM;
		goto fail_vfs;
	}

	/* memfd originated in userspace, so we have to check we actually
	 * got what we thought we would. */
	if (!PageHuge(*page_out) || PageTail(*page_out)) {
		EFRM_ERR("%s: hugepage was badly created (0x%08lx / %d / %d)",
				__func__, (*page_out)->index * HUGEPAGE_SIZE,
				PageHuge(*page_out), PageTail(*page_out));
		rc = -ENOMEM;
		goto fail_check;
	}

	allocator->offset = allocator->offset + HUGEPAGE_SIZE;

	return 0;

fail_check:
	unpin_user_page(*page_out);

fail_vfs:
	*page_out = NULL;

	fput(*filp_out);
	*filp_out = NULL;

	return rc;
}
EXPORT_SYMBOL(hugetlb_page_alloc_raw);

void hugetlb_page_free_raw(struct file *filp, struct page *page)
{
	off_t offset;
	int rc;

	EFRM_ASSERT(filp);
	EFRM_ASSERT(page);

	offset = page->index * HUGEPAGE_SIZE;

	unpin_user_page(page);
	rc = vfs_fallocate(filp, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
			offset, HUGEPAGE_SIZE);
	if (rc)
		EFRM_WARN("%s: vfs_fallocate() failed: %d", __func__, rc);

	fput(filp);
}
EXPORT_SYMBOL(hugetlb_page_free_raw);

int
hugetlb_pages_prealloc(struct hugetlb_allocator *allocator,
		int nr_pages)
{
	struct inode* inode;
	int rc;

	EFRM_ASSERT(allocator);
	EFRM_ASSERT(!allocator->offset);

	inode = file_inode(allocator->filp);
	if (i_size_read(inode) < nr_pages * HUGEPAGE_SIZE) {
		rc = (int)vfs_truncate(&allocator->filp->f_path,
				nr_pages * HUGEPAGE_SIZE);
		if (rc < 0) {
			EFRM_ERR("%s: ftruncate() failed: %d", __func__, rc);
			return rc;
		}
	}

	return vfs_fallocate(allocator->filp, 0, 0,
			nr_pages * HUGEPAGE_SIZE);
}
EXPORT_SYMBOL(hugetlb_pages_prealloc);
