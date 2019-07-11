#ifndef _ASM_IRQ_H
#define _ASM_IRQ_H

/*
 *	linux/include/asm/irq.h
 *
 *	(C) 1992, 1993 Linus Torvalds
 */

#include <linux/segment.h>
#include <linux/linkage.h>

extern void disable_irq(unsigned int);
extern void enable_irq(unsigned int);

/*
 *	#x: 将 x 做字符串化操作，使其变成一个字符串。
 */
#define __STR(x) #x
#define STR(x) __STR(x)

/*
 *	SAVE_ALL: 与 sys_call.S 中的 SAVE_ALL 基本一致，用于普通中断，因为普通中断的尾部要跳转
 * 到 ret_from_sys_call 去处理当前正在运行任务的信号，且处理完毕后要从 ret_from_sys_call 中使用
 * RESTORE_ALL 退出中断，所以此处的 SAVE_ALL 需和 sys_call.S 中的 SAVE_ALL 一致才行。
 *
 *	1. 手动保存 GS ---> EBX 寄存器的值。
 *	2. 设置 DS = ES = KERNEL_DS 用于访问内核数据段，设置 FS = USER_DS 用于访问用户数据段。
 * 即普通中断处理过程中，DS 和 ES 用于访问内核空间，FS 用于访问用户空间。
 *	3. 设置 %db7 = 0，禁止硬件调试。
 */
#define SAVE_ALL \
	"cld\n\t" \
	"push %gs\n\t" \
	"push %fs\n\t" \
	"push %es\n\t" \
	"push %ds\n\t" \
	"pushl %eax\n\t" \
	"pushl %ebp\n\t" \
	"pushl %edi\n\t" \
	"pushl %esi\n\t" \
	"pushl %edx\n\t" \
	"pushl %ecx\n\t" \
	"pushl %ebx\n\t" \
	"movl $" STR(KERNEL_DS) ",%edx\n\t" \
	"mov %dx,%ds\n\t" \
	"mov %dx,%es\n\t" \
	"movl $" STR(USER_DS) ",%edx\n\t" \
	"mov %dx,%fs\n\t"   \
	"movl $0,%edx\n\t"  \
	"movl %edx,%db7\n\t"

/*
 * SAVE_MOST/RESTORE_MOST is used for the faster version of IRQ handlers,
 * installed by using the SA_INTERRUPT flag. These kinds of IRQ's don't
 * call the routines that do signal handling etc on return, and can have
 * more relaxed register-saving etc. They are also atomic, and are thus
 * suited for small, fast interrupts like the serial lines or the harddisk
 * drivers, which don't actually need signal handling etc.
 *
 * Also note that we actually save only those registers that are used in
 * C subroutines (%eax, %edx and %ecx), so if you do something weird,
 * you're on your own. The only segments that are saved (not counting the
 * automatic stack and code segment handling) are %ds and %es, and they
 * point to kernel space. No messing around with %fs here.
 */
/*
 *	SAVE_MOST/RESTORE_MOST 用于通过使用 SA_INTERRUPT 标志安装的快速中断处理程序。快速中断
 * 在退出之前不会调用信号处理流程，并且可以有更宽松的寄存器保存方案，这种寄存器的保存和恢复
 * 也是原子的，因此适用于小型、快速中断，比如串行中断或硬盘驱动器中断等，这些中断实际上不需要
 * 信号处理。
 *
 *	除了处理器在进入中断时自动保存的现场信息以外，此处代码只保存在中断 C 处理函数中用到的
 * 那些寄存器(%eax, %edx 和 %ecx)，还保存 ES 和 DS，它们用于指向内核空间，因快速中断不需要和
 * 用户空间交互数据，因此此处不对 FS 做设置。
 */

/*
 *	SAVE_MOST: 快速中断中手动保存的寄存器，处理器自动保存的寄存器与 sys_call.S 中一致，
 * 此处手动保存 ES -> ECX，并设置 DS = ES = KERNEL_DS 用于访问内核空间。
 */
#define SAVE_MOST \
	"cld\n\t" \
	"push %es\n\t" \
	"push %ds\n\t" \
	"pushl %eax\n\t" \
	"pushl %edx\n\t" \
	"pushl %ecx\n\t" \
	"movl $" STR(KERNEL_DS) ",%edx\n\t" \
	"mov %dx,%ds\n\t" \
	"mov %dx,%es\n\t"

/*
 *	RESTORE_MOST: 手动恢复快速中断中保存的寄存器 ECX -> ES，并执行 iret 指令退出中断，
 * iret 指令执行时处理器会自动恢复中断前的现场。
 */
#define RESTORE_MOST \
	"popl %ecx\n\t" \
	"popl %edx\n\t" \
	"popl %eax\n\t" \
	"pop %ds\n\t" \
	"pop %es\n\t" \
	"iret"

/*
 * The "inb" instructions are not needed, but seem to change the timings
 * a bit - without them it seems that the harddisk driver won't work on
 * all hardware. Arghh.
 */
/*
 *	ACK_FIRST(mask): 向主 8259A 芯片做应答。mask 可以取 8 个值，表示主 8259A 芯片上的
 * 8 个中断。
 *
 *	1. 屏蔽 mask 对应的中断请求，使中断控制器不能发出该中断的中断请求信号。
 *	2. 向主 8259A 中断控制器发送 EOI 指令，结束硬件中断。如果不发送 EOI，则表示当前中断
 * 信号未结束，其它中断信号不能发送。
 */
#define ACK_FIRST(mask) \
	"inb $0x21,%al\n\t" \
	"jmp 1f\n" \
	"1:\tjmp 1f\n" \
	"1:\torb $" #mask ",_cache_21\n\t" \	/* cache_21 中 mask 对应的位置 1 */
	"movb _cache_21,%al\n\t" \
	"outb %al,$0x21\n\t" \		/* 0x21 端口写 cache_21，屏蔽 mask 对应的中断请求 */
	"jmp 1f\n" \
	"1:\tjmp 1f\n" \
	"1:\tmovb $0x20,%al\n\t" \
	"outb %al,$0x20\n\t"		/* 0x20 端口写 0x20，向主 8259A 中断控制器发送 EOI 指令 */

/*
 *	ACK_SECOND(mask): 向从 8259A 芯片做应答。mask 可以取 8 个值，表示从 8259A 芯片上的
 * 8 个中断。
 *
 *	1. 屏蔽 mask 对应的中断请求，使中断控制器不能发出该中断的中断请求信号。
 *	2. 向从 8259A 中断控制器发送 EOI 指令。
 *	3. 向主 8259A 中断控制器发送 EOI 指令。因为从 8259A 连接在主 8259A 上，从 8259A 的
 * 中断信号会先发送到主 8259A，再通过主 8259A 发送到处理器，所以需要给两个芯片都发送 EOI。
 */
#define ACK_SECOND(mask) \
	"inb $0xA1,%al\n\t" \
	"jmp 1f\n" \
	"1:\tjmp 1f\n" \
	"1:\torb $" #mask ",_cache_A1\n\t" \	/* cache_A1 中 mask 对应的位置 1 */
	"movb _cache_A1,%al\n\t" \
	"outb %al,$0xA1\n\t" \		/* 0xA1 端口写 cache_A1，屏蔽 mask 对应的中断请求 */
	"jmp 1f\n" \
	"1:\tjmp 1f\n" \
	"1:\tmovb $0x20,%al\n\t" \
	"outb %al,$0xA0\n\t" \		/* 0xA0 端口写 0x20，向从 8259A 中断控制器发送 EOI 指令 */
	"jmp 1f\n" \
	"1:\tjmp 1f\n" \
	"1:\toutb %al,$0x20\n\t"	/* 0x20 端口写 0x20，向主 8259A 中断控制器发送 EOI 指令 */

/*
 *	UNBLK_FIRST(mask): 使能主 8259A 芯片上 mask 对应的中断请求，使中断控制器可以发出该
 * 中断的中断请求信号。mask 可以取 8 个值，表示主 8259A 芯片上的 8 个中断。
 */
#define UNBLK_FIRST(mask) \
	"inb $0x21,%al\n\t" \
	"jmp 1f\n" \
	"1:\tjmp 1f\n" \
	"1:\tandb $~(" #mask "),_cache_21\n\t" \	/* cache_21 中 mask 对应的位清 0 */
	"movb _cache_21,%al\n\t" \
	"outb %al,$0x21\n\t"		/* 0x21 端口写 cache_21，使能 mask 对应的中断请求 */

/*
 *	UNBLK_SECOND(mask): 使能从 8259A 芯片上 mask 对应的中断请求，使中断控制器可以发出该
 * 中断的中断请求信号。mask 可以取 8 个值，表示从 8259A 芯片上的 8 个中断。
 */
#define UNBLK_SECOND(mask) \
	"inb $0xA1,%al\n\t" \
	"jmp 1f\n" \
	"1:\tjmp 1f\n" \
	"1:\tandb $~(" #mask "),_cache_A1\n\t" \	/* cache_A1 中 mask 对应的位清 0 */
	"movb _cache_A1,%al\n\t" \
	"outb %al,$0xA1\n\t"		/* 0xA1 端口写 cache_A1，使能 mask 对应的中断请求 */

/*
 *	以中断编号 nr = 0 为例
 */
#define IRQ_NAME2(nr) nr##_interrupt(void)
#define IRQ_NAME(nr) IRQ_NAME2(IRQ##nr)			/* nr = 0: IRQ0_interrupt(void) */
#define FAST_IRQ_NAME(nr) IRQ_NAME2(fast_IRQ##nr)	/* nr = 0: fast_IRQ0_interrupt(void) */
#define BAD_IRQ_NAME(nr) IRQ_NAME2(bad_IRQ##nr)		/* nr = 0: bad_IRQ0_interrupt(void) */

/*
 *	BUILD_IRQ(chip,nr,mask):
 *
 *	入参:	chip: 取值为 FIRST 或 SECOND，表示两个 8259A 中断控制芯片中的哪一个。
 *		nr  : 取值为 0 - 15，是 16 个外部硬件中断的中断编号。
 *		mask: 中断信号位，表示该中断信号连接在主 8259A 或 从 8259A 芯片的哪个引脚上。
 *
 * 	1. 该宏用于实现中断号 nr 对应的三个中断处理函数，分别是普通中断、快速中断、无效中断。
 *	2. 每个中断在初始化时可以设置为三个中断中的任意一个，且对应的中断处理函数会被设置到
 * 中断对应的中断描述符表中。
 *	3. 当中断产生时，会通过中断描述符表直接找到对应的中断处理函数来执行。
 *
 *	例如 0 号中断，也就是定时器中断:
 *
 *	1. BUILD_IRQ 宏会实现 0 号中断对应的三个中断处理函数，分别是普通中断 void IRQ0_interrupt(void)，
 * 快速中断 void fast_IRQ0_interrupt(void)，无效中断 void bad_IRQ0_interrupt(void)。
 *	2. 在 sched_init 将 0 号中断通过 request_irq 注册为普通中断，中断描述符表中 0 号中断对应的
 * 位置处会保存 IRQ0_interrupt 函数的信息。
 *	3. 当定时器中断产生时，处理器会执行 0 号中断对应的普通中断的中断处理函数 IRQ0_interrupt()。
 *	4. 同样，如果将 0 号中断注册为快速中断或无效中断，则 0 号中断产生时会执行 fast_IRQ0_interrupt
 * 或 bad_IRQ0_interrupt。
 */
#define BUILD_IRQ(chip,nr,mask) \
asmlinkage void IRQ_NAME(nr); \			/* nr = 0: void IRQ0_interrupt(void) */	\
asmlinkage void FAST_IRQ_NAME(nr); \		/* nr = 0: void fast_IRQ0_interrupt(void) */	\
asmlinkage void BAD_IRQ_NAME(nr); \		/* nr = 0: void bad_IRQ0_interrupt(void) */	\
__asm__( \
/*
 *	IRQ0_interrupt: 0 号中断对应的普通中断处理函数。[ nr = 0 -> 15 ]
 */
"\n.align 4\n" \
"_IRQ" #nr "_interrupt:\n\t" \		/* void IRQ0_interrupt(void) 函数实现 */

	"pushl $-"#nr"-2\n\t" \
	SAVE_ALL \
			/*
			 *	sys_call.S 中在执行 SAVE_ALL 之前保存了一个 ORIG_EAX，这里为了使用 sys_call.S
			 * 中的 ret_from_sys_call 并从中通过 RESTORE_ALL 退出中断，也需要在 SAVE_ALL 之前保存
			 * 一个值，这里保存的是一个与中断号相关的立即数，每个中断这里的值都是不一样的，但是没
			 * 看明白保存的值的意思是什么。
			 */
	ACK_##chip(mask) \
			/*
			 *	ACK_FIRST(mask) 或 ACK_SECOND(mask): 首先屏蔽该中断的中断请求，使中断控制器
			 * 不再发出该中断的中断请求信号，以防在处理该中断的过程中再次触发该中断。然后向中断
			 * 控制器发送 EOI 指令，结束硬件中断，使其它中断的请求信号可以正常发送。
			 */
	"incl _intr_count\n\t"\
	"sti\n\t" \
			/*
			 *	intr_count++;
			 *	sti; 使能处理器响应外部硬件中断，即普通中断的执行过程可以被打断，支持中断嵌套。
			 * 但是该中断的中断请求信号已经在上面屏蔽了，即不支持中断重入。
			 */
	"movl %esp,%ebx\n\t" \
	"pushl %ebx\n\t" \
	"pushl $" #nr "\n\t" \
			/*
			 *	当前栈指针(sys_call.S 中的 esp0) 作为 do_IRQ 的第二个参数入栈，esp0 在 do_IRQ
			 * 中被转换为 struct pt_regs，栈中的内容与 struct pt_regs 中的成员一一对应，do_IRQ 中
			 * 通过 struct pt_regs 来访问栈中的内容。
			 *
			 *	中断号 nr 作为 do_IRQ 的第一个参数入栈。
			 */
	"call _do_IRQ\n\t" \
	"addl $8,%esp\n\t" \
			/*
			 *	call do_IRQ(nr, esp0): 调用通用的普通中断处理函数 do_IRQ，在 do_IRQ 中会根据
			 * 中断号来执行具体的中断处理函数。
			 *
			 *	中断执行完毕后，将栈中传递给 do_IRQ 的两个参数丢弃，栈指针回到 esp0。
			 */
	"cli\n\t" \
			/*
			 *	cli; 禁止处理器响应外部硬件中断，以保证下面的操作是原子的，中断响应会在
			 * ret_from_sys_call 中用 sti 开启，或者在最后执行 iret 指令时由 EFLAGS 寄存器来恢复。
			 */
	UNBLK_##chip(mask) \
			/*
			 *	UNBLK_FIRST(mask) 或 UNBLK_SECOND(mask): 使能该中断的中断请求，使中断控制器
			 * 可以正常发出该中断的中断请求信号。
			 */
	"decl _intr_count\n\t" \
	"jmp ret_from_sys_call\n" \
			/*
			 *	intr_count--;
			 *	最后跳转到 ret_from_sys_call 处去处理当前正在运行任务 current 的信号并从中
			 * 退出中断，即普通中断运行的尾部会处理当前正在运行任务的信号。
			 */

/*
 *	fast_IRQ0_interrupt: 0 号中断对应的快速中断处理函数。[ nr = 0 -> 15 ]
 */
"\n.align 4\n" \
"_fast_IRQ" #nr "_interrupt:\n\t" \	/* void fast_IRQ0_interrupt(void) 函数实现 */

	SAVE_MOST \
	ACK_##chip(mask) \
			/*
			 *	保存必要的寄存器。
			 *	向该中断对应的中断控制器发送应答。
			 */
	"incl _intr_count\n\t" \
	"pushl $" #nr "\n\t" \
			/*
			 *	intr_count++;
			 *	中断号 nr 作为 do_fast_IRQ 的唯一参数入栈。
			 */
	"call _do_fast_IRQ\n\t" \
	"addl $4,%esp\n\t" \
			/*
			 *	call do_fast_IRQ(nr): 调用通用的快速中断处理函数 do_fast_IRQ，在 do_fast_IRQ
			 * 中会根据中断号来执行具体的中断处理函数。
			 *
			 *	快速中断处理函数执行完毕后丢弃传递给 do_fast_IRQ 的参数，栈指针回到 esp0。
			 */
	"cli\n\t" \
			/*
			 *	cli; 禁止外部硬件中断，以保证下面的操作是原子的，中断状态会在最后执行 iret
			 * 时由 EFLAGS 寄存器来恢复。
			 */
	UNBLK_##chip(mask) \
	"decl _intr_count\n\t" \
	RESTORE_MOST \
			/*
			 *	使能该中断的中断请求。
			 *	intr_count--;
			 *	快速中断的尾部不处理信号，直接调用 RESTORE_MOST 恢复寄存器并退出中断。
			 */

/*
 *	bad_IRQ0_interrupt: 0 号中断对应的无效中断处理函数。[ nr = 0 -> 15 ]
 */
"\n\n.align 4\n" \
"_bad_IRQ" #nr "_interrupt:\n\t" \	/* void bad_IRQ0_interrupt(void) 函数实现 */
	SAVE_MOST \
	ACK_##chip(mask) \
	RESTORE_MOST);
			/*
			 *	如果某一个中断被系统注册为无效中断，则向中断对应的中断控制芯片做应答后直接
			 * 退出，做应答时会将该中断的中断请求信号屏蔽掉，使中断控制器以后不再发出该中断的
			 * 请求信号。
			 */

#endif
