#ifndef __ASM_SYSTEM_H
#define __ASM_SYSTEM_H

#include <linux/segment.h>

#define move_to_user_mode() \
__asm__ __volatile__ ("movl %%esp,%%eax\n\t" \
	"pushl %0\n\t" \
	"pushl %%eax\n\t" \
	"pushfl\n\t" \
	"pushl %1\n\t" \
	"pushl $1f\n\t" \
	"iret\n" \
	"1:\tmovl %0,%%eax\n\t" \
	"mov %%ax,%%ds\n\t" \
	"mov %%ax,%%es\n\t" \
	"mov %%ax,%%fs\n\t" \
	"mov %%ax,%%gs" \
	: /* no outputs */ :"i" (USER_DS), "i" (USER_CS):"ax")

#define sti() __asm__ __volatile__ ("sti": : :"memory")	/* 开启外部硬件中断 */
#define cli() __asm__ __volatile__ ("cli": : :"memory")	/* 禁止外部硬件中断，但不能禁止使用 INT 指令产生的软件中断 */
#define nop() __asm__ __volatile__ ("nop")

/*
 * Clear and set 'TS' bit respectively
 */
#define clts() __asm__ __volatile__ ("clts")
#define stts() \
__asm__ __volatile__ ( \
	"movl %%cr0,%%eax\n\t" \
	"orl $8,%%eax\n\t" \
	"movl %%eax,%%cr0" \
	: /* no outputs */ \
	: /* no inputs */ \
	:"ax")


extern inline int tas(char * m)
{
	char res;

	__asm__("xchgb %0,%1":"=q" (res),"=m" (*m):"0" (0x1));
	return res;
}

#define save_flags(x) \
__asm__ __volatile__("pushfl ; popl %0":"=r" (x): /* no input */ :"memory")

#define restore_flags(x) \
__asm__ __volatile__("pushl %0 ; popfl": /* no output */ :"r" (x):"memory")

#define iret() __asm__ __volatile__ ("iret": : :"memory")

/*
 *	中断描述符表 IDT 中可以存放 3 种类型的门描述符: 中断门、陷阱门、任务门，
 * _set_gate 宏只用于设置中断门和陷阱门。因调用门的格式与中断门和陷阱门类似，故
 * 这个宏也可以设置调用门，但是调用门传入的参数 gate_addr 有所区别。
 */
#define _set_gate(gate_addr,type,dpl,addr) \
__asm__ __volatile__ ("movw %%dx,%%ax\n\t" \
	"movw %2,%%dx\n\t" \
	"movl %%eax,%0\n\t" \
	"movl %%edx,%1" \
	:"=m" (*((long *) (gate_addr))), \
	 "=m" (*(1+(long *) (gate_addr))) \
	:"i" ((short) (0x8000+(dpl<<13)+(type<<8))), \
	 "d" ((char *) (addr)),"a" (KERNEL_CS << 16) \
	:"ax","dx")

/*
 *	set_intr_gate: 设置 IDT 表中的中断门描述符。
 *
 * 入参: n --- 中断号。
 *	 addr --- 中断处理程序的地址。
 * 传参: &idt[n] --- 中断号 n 对应的中断描述符的地址。
 *	 14 --- 描述符类型，表示中断门描述符。
 *	 0 --- 描述符的特权级，表明中断处理函数只能在 0 特权级下执行。
 */
#define set_intr_gate(n,addr) \
	_set_gate(&idt[n],14,0,addr)

/*
 *	set_trap_gate: 设置 IDT 表中的陷阱门描述符。
 *
 * 入参: n --- 中断号。
 *	 addr --- 陷阱处理程序的地址。
 * 传参: &idt[n] --- 中断号 n 对应的中断描述符的地址。
 *	 15 --- 描述符类型，表示陷阱门描述符。
 *	 0 --- 描述符的特权级，表明陷阱处理函数只能在 0 特权级下执行。
 */
#define set_trap_gate(n,addr) \
	_set_gate(&idt[n],15,0,addr)

/*
 *	set_system_gate: 设置 IDT 表中的系统陷阱门描述符。
 *
 * 入参: n --- 中断号。
 *	 addr --- 陷阱处理程序的地址。
 * 传参: &idt[n] --- 中断号 n 对应的中断描述符的地址。
 *	 15 --- 描述符类型，表示陷阱门描述符。
 *	 3 --- 描述符的特权级。表明陷阱处理函数能够被所有程序执行。
 */
#define set_system_gate(n,addr) \
	_set_gate(&idt[n],15,3,addr)

#if 0
/*
 *	set_call_gate: 设置系统调用门描述符。
 *
 * 入参: a --- 调用门描述符的地址。
 *	 addr --- 调用门处理程序的地址。
 * 传参: 12 --- 描述符类型，表示调用门描述符。
 *	 3 --- 描述符的特权级。表明调用门处理函数能够被所有程序执行。
 */
#endif
#define set_call_gate(a,addr) \
	_set_gate(a,12,3,addr)

#define _set_seg_desc(gate_addr,type,dpl,base,limit) {\
	*((gate_addr)+1) = ((base) & 0xff000000) | \
		(((base) & 0x00ff0000)>>16) | \
		((limit) & 0xf0000) | \
		((dpl)<<13) | \
		(0x00408000) | \
		((type)<<8); \
	*(gate_addr) = (((base) & 0x0000ffff)<<16) | \
		((limit) & 0x0ffff); }

#define _set_tssldt_desc(n,addr,limit,type) \
__asm__ __volatile__ ("movw $" #limit ",%1\n\t" \
	"movw %%ax,%2\n\t" \
	"rorl $16,%%eax\n\t" \
	"movb %%al,%3\n\t" \
	"movb $" type ",%4\n\t" \
	"movb $0x00,%5\n\t" \
	"movb %%ah,%6\n\t" \
	"rorl $16,%%eax" \
	: /* no output */ \
	:"a" (addr+0xc0000000), "m" (*(n)), "m" (*(n+2)), "m" (*(n+4)), \
	 "m" (*(n+5)), "m" (*(n+6)), "m" (*(n+7)) \
	)

#define set_tss_desc(n,addr) _set_tssldt_desc(((char *) (n)),((int)(addr)),235,"0x89")
#define set_ldt_desc(n,addr,size) \
	_set_tssldt_desc(((char *) (n)),((int)(addr)),((size << 3) - 1),"0x82")


#endif
