#ifndef __ASM_SYSTEM_H
#define __ASM_SYSTEM_H

#include <linux/segment.h>

/*
 *	move_to_user_mode: 移动到用户模式运行，用于内核在初始化结束时人工切换到初始进程(任务 0)中去执行，
 * 也就是从特权级 0 的代码转移到特权级 3 的代码中去运行。所使用的方法是模拟中断调用返回过程，即利用 iret
 * 指令来实现特权级的变更和堆栈的切换，从而把 CPU 执行控制流转移到初始任务 0 的环境中运行。
 *
 *	使用 iret 进行控制权转移的原因: CPU 保护机制允许低特权级的代码通过调用门、中断、陷阱门来调用或者
 * 转移到高特权级的代码中去运行，反之则不允许，故内核采用了这种模拟 iret 返回低特权级代码的方法。
 *
 *	iret 指令执行时，会从当前 SS:ESP 指示的栈中依次弹出 CS:EIP、EFLAGS，CS:EIP 是 iret 指令执行后将要
 * 执行的代码的位置，EFLAGS 是其对应的标志寄存器的值。因为特权级要从 0 变更到 3，所以还需要弹出
 * SS:ESP(新的特权级所对应的栈)，因此在执行 iret 指令之前需要先将这些寄存器压入栈中，然后执行 iret 指令。
 *
 *
 *	|---------------| SP0 <--- 执行 move_to_user_mode 之前的栈的位置 [ user_stack 中 ]
 *	|	|   SS	|
 *	-----------------
 *	|      ESP	|	===> 压入栈中的 SS:ESP 指向 SP0，因此 iret 弹出 SS:ESP 之后，栈的位置又
 *	-----------------	     回到了 SP0，也就是执行 move_to_user_mode 之前的栈的位置，即栈的位置
 *	|    EFLAGS	|	     在执行 move_to_user_mode 前后未发生变化。
 *	-----------------
 *	|	|  CS	|	===> 压入栈中的 CS:EIP 指向 iret 的后面一条指令的位置，因此 iret 弹出
 *	-----------------	     CS:EIP 之后，将从 iret 指令的后面一条指令处继续向下执行。
 *	|      EIP	|
 *	|---------------| SP1 <--- 执行 iret 之前的栈的位置 [ user_stack 中 ]
 *
 */
#define move_to_user_mode() \
__asm__ __volatile__ ("movl %%esp,%%eax\n\t" \		/* 当前的 esp(SP0) ===> eax */
	"pushl %0\n\t" \		/* 任务 0 用户态堆栈段选择符 SS (USER_DS) 入栈，段特权级为 3 */
	"pushl %%eax\n\t" \		/* 堆栈段指针 ESP 入栈 */
	"pushfl\n\t" \			/* 标志寄存器 EFLAGS 入栈 */
	"pushl %1\n\t" \		/* 任务 0 代码段选择符 CS (USER_CS) 入栈，段特权级为 3 */
	"pushl $1f\n\t" \		/* 代码段指针 EIP (iret 指令后标号 1 的偏移地址) 入栈 */
	"iret\n" \
			/*
			 *	执行 iret 指令前，处理器的特权级为 0，所使用的栈为 head.S 中设置的
			 * user_stack。执行 iret 指令之后，CS:EIP 指向了 iret 后面一条指令，执行流程
			 * 并未发生变化，栈的位置回到了执行 move_to_user_mode 之前的位置，也未发生变化。
			 *
			 *	唯一发生变化的是: 代码段和堆栈段的特权等级，由 0 变成了 3，即执行流从
			 * 原来的内核态切换到了用户态的任务 0 中。
			 *
			 *	也可以理解为: move_to_user_mode 之前的代码是在任务 0 的内核态执行，之后
			 * 的代码是在任务 0 的用户态执行，虽然并不是绝对准确。
			 *
			 *	这里的 iret 指令并不会造成 CPU 去执行真正的任务切换操作，因为在 sched_init
			 * 中已将 EFLAGS 中的 NT 标志复位。在 NT 复位时执行 iret 指令不会造成 CPU 执行任务
			 * 切换操作，因此，任务 0 的执行是人工直接启动的。
			 */
	"1:\tmovl %0,%%eax\n\t" \
	"mov %%ax,%%ds\n\t" \
	"mov %%ax,%%es\n\t" \
	"mov %%ax,%%fs\n\t" \
	"mov %%ax,%%gs" \
			/*
			 *	处理器的特权级从 0 到 3 发生了变化，DS、ES、FS、GS 的值将变为无效值，
			 * CPU 会将这些寄存器清 0，因此在执行 iret 后需要用 USER_DS 重新加载它们，用于
			 * 选择任务 0 的用户态数据段。
			 *	CS 和 SS 的值由 iret 引发的弹栈操作来设置。
			 */
	: /* no outputs */ :"i" (USER_DS), "i" (USER_CS):"ax")


/*
 *	sti(): 开启处理器响应外部硬件中断请求功能。
 *
 *	cli(): 关闭处理器响应外部硬件中断请求功能，但外部硬件中断仍可正常产生，只是处理器不响应而已。
 * cli 指令只对外部硬件中断有效，不能禁止使用 INT 指令产生的软件中断。
 */
#define sti() __asm__ __volatile__ ("sti": : :"memory")	/* 开中断 */
#define cli() __asm__ __volatile__ ("cli": : :"memory")	/* 关中断 */
#define nop() __asm__ __volatile__ ("nop")		/* 空操作 */

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

/*
 *	save_flags(x): 将标志寄存器 EFLAGS 中的值保存到 x 中。
 */
#define save_flags(x) \
__asm__ __volatile__("pushfl ; popl %0":"=r" (x): /* no input */ :"memory")

/*
 *	restore_flags(x): 将 x 中的值恢复到标志寄存器 EFLAGS 中。
 */
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
 *	set_intr_gate: 设置 IDT 表中的中断门描述符。主要用于设置中断号为 0x20
 * 以上的外设中断的处理函数。
 *
 * 入参: n --- 中断号。
 *	 addr --- 中断处理程序的地址。
 * 传参: &idt[n] --- 中断号 n 对应的中断描述符的地址。
 *	 14 --- 描述符类型，表示中断门描述符。
 *	 0 --- 描述符的特权级。
 *
 *	当中断是由外设产生时，中断门的 DPL 是被忽略的，处理器直接切换为 0 特权
 * 级，在 0 特权级下执行中断处理函数。如果在特权级为 3 的用户空间通过 INT 指令
 * 触发这种类型的中断，因中断门的 DPL = 0，所以由 INT 指令触发的中断会因特权级
 * 低而不能穿过中断门被拦下来。
 */
#define set_intr_gate(n,addr) \
	_set_gate(&idt[n],14,0,addr)

/*
 *	set_trap_gate: 设置 IDT 表中的陷阱门描述符。主要用于设置中断号为 0x20
 * 以下的由 CPU 产生的异常。
 *
 * 入参: n --- 中断号。
 *	 addr --- 陷阱处理程序的地址。
 * 传参: &idt[n] --- 中断号 n 对应的中断描述符的地址。
 *	 15 --- 描述符类型，表示陷阱门描述符。
 *	 0 --- 描述符的特权级。
 *
 *	当 CPU 产生异常时，陷阱门的 DPL 是被忽略的，处理器直接切换为 0 特权级，
 * 在 0 特权级下执行异常处理函数。如果在特权级为 3 的用户空间通过 INT 指令触发
 * 这种类型的异常，因陷阱门的 DPL = 0，所以由 INT 指令触发的异常会因特权级低而
 * 不能穿过陷阱门被拦下来。
 */
#define set_trap_gate(n,addr) \
	_set_gate(&idt[n],15,0,addr)

/*
 *	set_system_gate: 设置 IDT 表中的系统陷阱门描述符。主要用于设置可以在
 * 特权级为 3 的用户空间使用的由软件触发的异常，最主要的是系统调用 INT 0x80。
 *
 * 入参: n --- 中断号。
 *	 addr --- 陷阱处理程序的地址。
 * 传参: &idt[n] --- 中断号 n 对应的中断描述符的地址。
 *	 15 --- 描述符类型，表示陷阱门描述符。
 *	 3 --- 描述符的特权级。
 *
 *	因为系统调用是在用户空间通过 INT 0x80 触发的，所以只有将陷阱门的 DPL
 * 设置为 3 才能让系统调用顺利穿过陷阱门，进而触发处理器切换到特权级 0 去执行
 * 对应的系统调用过程。
 */
#define set_system_gate(n,addr) \
	_set_gate(&idt[n],15,3,addr)

/*
 *	set_call_gate: 设置系统调用门描述符。
 *
 * 入参: a --- 调用门描述符的地址。
 *	 addr --- 调用门处理程序的地址。
 * 传参: 12 --- 描述符类型，表示调用门描述符。
 *	 3 --- 描述符的特权级。
 */
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

/*
 *	_set_tssldt_desc: 设置 GDT 表中任务对应的 TSS 段和 LDT 段的段描述符:
 *
 * 入参: n --- GDT 表中描述符项的偏移值。
 *	 addr --- 段所在物理内存的基地址，因为 TSS 段在任务的 task_struct 结构中，LDT 段位于内核空间，
 *		  而内核空间的地址映射是基于偏移量的一对一映射，所以最后生成的段的线性基地址为
 *		  0xC0000000 + addr。
 *	 limit --- 段限长，limit = 段大小 - 1，TSS 段和 LDT 段不等长。
 *	 type --- 描述符中的标志类型，主要用于说明描述符描述的是 TSS 段还是 LDT 段。
 */
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

/*
 *	set_tss_desc: 在 GDT 表中设置任务的 TSS 段的段描述符。
 *
 * 入参: n --- GDT 表中描述符项的偏移值。
 *	 addr --- 段所在物理内存的基地址。
 * 传参: 235 --- TSS 段的段限长，TSS 段的最小尺寸是 236(tss_struct 结构中一直到 io_bitmap 结束) 字节，
 *		 所以段限长 = 236 - 1 = 235 字节。
 *	 0x89 --- TSS 段的描述符类型。
 */
#define set_tss_desc(n,addr) _set_tssldt_desc(((char *) (n)),((int)(addr)),235,"0x89")

/*
 *	set_ldt_desc: 在 GDT 表中设置任务的 LDT 段的段描述符。
 *
 * 入参: n --- GDT 表中描述符项的偏移值。
 *	 addr --- 段所在物理内存的基地址。
 *	 size --- desc_struct 结构的个数，每个 desc_struct 结构占 8 字节。
 * 传参: ((size << 3) - 1) --- LDT 段的段限长，段限长 = 段大小 - 1。
 *	 0x82 --- LDT 段的描述符类型。
 */
#define set_ldt_desc(n,addr,size) \
	_set_tssldt_desc(((char *) (n)),((int)(addr)),((size << 3) - 1),"0x82")


#endif
