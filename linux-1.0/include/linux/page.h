#ifndef _LINUX_PAGE_H
#define _LINUX_PAGE_H

			/* PAGE_SHIFT determines the page size */
#define PAGE_SHIFT			12
#define PAGE_SIZE			((unsigned long)1<<PAGE_SHIFT)	/* 页面大小为 4kB */

#ifdef __KERNEL__

			/* number of bits that fit into a memory pointer */
#define BITS_PER_PTR			(8*sizeof(unsigned long))
			/* to mask away the intra-page address bits */
#define PAGE_MASK			(~(PAGE_SIZE-1))
			/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr)		(((addr)+PAGE_SIZE-1)&PAGE_MASK)
			/* to align the pointer to a pointer address */
#define PTR_MASK			(~(sizeof(void*)-1))

					/* sizeof(void*)==1<<SIZEOF_PTR_LOG2 */
					/* 64-bit machines, beware!  SRB. */
#define SIZEOF_PTR_LOG2			2

			/* to find an entry in a page-table-directory */
/*
 *	PAGE_DIR_OFFSET(base, address): base 是页目录表的物理内存基地址，address 是该页目录表负责
 * 映射的某一个线性地址。
 *
 *	这个宏用于获取页目录表中的某一个页目录项的内存地址，这个页目录项负责映射线性地址 address
 * 所在的线性页面。
 *
 *	对于一个给定的线性地址，在页目录表中有且仅有一个页目录项(有且仅有一个页表)负责映射该线性地址。
 */
#define PAGE_DIR_OFFSET(base,address)	((unsigned long*)((base)+\
  ((unsigned long)(address)>>(PAGE_SHIFT-SIZEOF_PTR_LOG2)*2&PTR_MASK&~PAGE_MASK)))

			/* to find an entry in a page-table */
/*
 *	PAGE_PTR(address): address 是某一个线性地址。
 *
 *	这个宏用于获取页表中的某一个页表项相对于页表基地址的偏移地址，这个偏移地址 + 页表基地址才是
 * 这个页表项在物理内存中的真正地址。这个页表项负责映射线性地址 address 所在的线性页面。
 *
 *	对于一个给定的线性地址，在唯一的页表中有且仅有一个页表项负责将该线性地址映射到唯一的页面中。
 */
#define PAGE_PTR(address)		\
  ((unsigned long)(address)>>(PAGE_SHIFT-SIZEOF_PTR_LOG2)&PTR_MASK&~PAGE_MASK)

			/* the no. of pointers that fit on a page */
/*
 *	PTRS_PER_PAGE: 一页内存中可以存放的页表项的个数。
 */
#define PTRS_PER_PAGE			(PAGE_SIZE/sizeof(void*))

#endif /* __KERNEL__ */

#endif /* _LINUX_PAGE_H */
