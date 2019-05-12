#ifndef _LINUX_HEAD_H
#define _LINUX_HEAD_H

/*
 *	desc_struct: 描述符表中的描述符结构，每个描述符占 8 个字节。
 *	desc_table: 描述符表，由 256 个描述符组成。
 */
typedef struct desc_struct {
	unsigned long a,b;
} desc_table[256];

extern unsigned long swapper_pg_dir[1024];	/* 内核空间的页目录表 */
extern desc_table idt,gdt;	/* IDT 表和 GDT 表，位于 head.S 中的 _idt 和 _gdt 处。 */

#define GDT_NUL 0
#define GDT_CODE 1
#define GDT_DATA 2
#define GDT_TMP 3

#define LDT_NUL 0
#define LDT_CODE 1
#define LDT_DATA 2

#endif
