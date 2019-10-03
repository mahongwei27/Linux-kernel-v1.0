/*
 *  linux/kernel/sys_call.S
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * sys_call.S  contains the system-call and fault low-level handling routines.
 * This also contains the timer-interrupt handler, as well as all interrupts
 * and faults that can result in a task-switch.
 *
 * NOTE: This code handles signal-recognition, which happens every time
 * after a timer-interrupt and after each system call.
 *
 * I changed all the .align's to 4 (16 byte alignment), as that's faster
 * on a 486.
 *
 * Stack layout in 'ret_from_system_call':
 * 	ptrace needs to have all regs on the stack.
 *	if the order here is changed, it needs to be 
 *	updated in fork.c:copy_process, signal.c:do_signal,
 *	ptrace.c and ptrace.h
 *
 *	 0(%esp) - %ebx
 *	 4(%esp) - %ecx
 *	 8(%esp) - %edx
 *       C(%esp) - %esi
 *	10(%esp) - %edi
 *	14(%esp) - %ebp
 *	18(%esp) - %eax
 *	1C(%esp) - %ds
 *	20(%esp) - %es
 *      24(%esp) - %fs
 *	28(%esp) - %gs
 *	2C(%esp) - orig_eax
 *	30(%esp) - %eip
 *	34(%esp) - %cs
 *	38(%esp) - %eflags
 *	3C(%esp) - %oldesp
 *	40(%esp) - %oldss
 */

#include <linux/segment.h>

EBX		= 0x00
ECX		= 0x04
EDX		= 0x08
ESI		= 0x0C
EDI		= 0x10
EBP		= 0x14
EAX		= 0x18
DS		= 0x1C
ES		= 0x20
FS		= 0x24
GS		= 0x28
ORIG_EAX	= 0x2C
EIP		= 0x30
CS		= 0x34
EFLAGS		= 0x38
OLDESP		= 0x3C
OLDSS		= 0x40

CF_MASK		= 0x00000001	/* EFLAGS 中的 bit0 --- 进位标志 */
IF_MASK		= 0x00000200	/* EFLAGS 中的 bit9 --- 中断开关标志 */
NT_MASK		= 0x00004000	/* EFLAGS 中的 bit14 --- 嵌套任务标志 */
VM_MASK		= 0x00020000	/* EFLAGS 中的 bit17 --- 虚拟 8086 方式标志 */

/*
 * these are offsets into the task-struct.
 */
state		=  0		/*  task_struct->state  */
counter		=  4		/*  task_struct->counter  */
priority	=  8		/*  task_struct->priority  */
signal		= 12		/*  task_struct->signal  */
blocked		= 16		/*  task_struct->blocked  */
flags		= 20		/*  task_struct->flags  */
errno		= 24		/*  task_struct->errno  */
dbgreg6		= 52		/*  task_struct->debugreg[6]  */
dbgreg7		= 56		/*  task_struct->debugreg[7]  */

ENOSYS = 38

.globl _system_call,_lcall7
.globl _device_not_available, _coprocessor_error
.globl _divide_error,_debug,_nmi,_int3,_overflow,_bounds,_invalid_op
.globl _double_fault,_coprocessor_segment_overrun
.globl _invalid_TSS,_segment_not_present,_stack_segment
.globl _general_protection,_reserved
.globl _alignment_check,_page_fault
.globl ret_from_sys_call

/*
 *	系统调用是一种软中断，且只会在特权级为 3 的代码中触发，也就是当前正在运行任务的用户态代码中通过
 * int 0x80 触发，中断产生后，处理器特权级切换为 0，同时使用的栈切换为特权级 0 对应的栈，也就是当前正在
 * 运行任务的内核态栈。伴随着特权级和栈的切换，当前任务也从用户态陷入了内核态。
 *
 *	每次触发系统调用，处理器的特权级都会从 3 切换到 0，因此处理器会从当前正在运行任务的 TSS 段中得到
 * 特权级 0 对应的堆栈段选择符和栈指针，然后将当前的 SS:ESP 的值，也就是进入内核态之前的堆栈段选择符和栈
 * 指针保存在特权级 0 的堆栈中。之后会用特权级 0 的堆栈段选择符和栈指针覆盖 SS:ESP，使 SS:ESP 指向任务的
 * 内核态栈，接着处理器将 EFLAGS，CS 和 EIP 的当前值保存到内核态栈中。然后 CS:EIP 指向系统调用的中断处理
 * 函数 system_call，进而执行真正的系统调用过程。
 *
 *	因系统调用使得处理器特权级发生了变化，所以内核态的堆栈段选择符和栈指针在每次进入内核态时都会从当
 * 前正在运行任务的 TSS 段中获取，而 TSS 段中的特权级 0 对应的 SS:ESP 是固定不变的，永远指向任务内核态栈
 * 的栈底。因此任务每次进入内核态时，内核态的栈都是空的，当然，退出内核态时，会恢复到空的状态。
 *
 *	原 SS:ESP、EFLAGS、CS:EIP 都是处理器在进入系统调用中断时自动保存的，退出系统调用中断返回用户态时，
 * 这些寄存器的值也会被处理器自动恢复。
 *
 *	在执行某个系统调用对应的系统调用函数之前，代码中会手动保存一些寄存器，从 ORIG_EAX ---> EBX，当
 * 系统调用函数执行结束，准备退回到用户态时，这些寄存器也需要手动恢复。
 *
 *	【当前正在运行任务对应的内核栈中的信息如下】:
 *
 *	-----------------  <--- 任务的内核态栈底
 * 0x40	|	| OLDSS	|
 *	-----------------	<=== 原 SS:ESP 指向进入系统调用之前的任务的用户态栈的位置
 * 0x3C	|     OLDESP	|
 *	-----------------
 * 0x38	|     EFLAGS	|	<=== EFLAGS 是进入系统调用之前的标志寄存器的值，该内容在系统调用中可能会
 *	-----------------		被更改。
 * 0x34	|	|  CS	|	<=== CS:EIP 保存从系统调用返回之后要执行的代码的位置，这个指针指向
 *	-----------------		int 0x80 指令的后面一条指令。
 * 0x30	|	EIP	|
 *	-----------------------------------------------------------------------------
 * 0x2C	|    ORIG_EAX	|	<=== 系统调用号，用于在信号处理程序中重启系统调用。这个地方的值也被用来
 *	----------------------		检测是不是系统调用，>= 0 表示是系统调用，-1 表示是中断。
 * 0x28	|	|  GS	|
 *	-----------------
 * 0x24	|	|  FS	|	<=== GS - DS: 系统调用执行过程中，DS 和 ES 用于指向内核数据空间，FS 被
 *	-----------------			设置为指向用户数据空间，这样内核就可以利用 FS 寄存器来
 * 0x20	|	|  ES	|			访问用户数据空间，进而在内核空间与用户空间之间传递数据。
 *	-----------------
 * 0x1C	|	|  DS	|
 *	----------------------
 * 0x18	|	EAX	|	<=== 此处保存系统调用的返回值
 *	----------------------
 * 0x14	|	EBP	|
 *	-----------------
 * 0x10	|	EDI	|
 *	-----------------	<=== EBX - EBP: 系统调用从用户空间传递过来的参数
 * 0x0C	|	ESI	|
 *	-----------------
 * 0x08 |	EDX	|
 *	-----------------
 * 0x04	|	ECX	|
 *	-----------------
 * 0x00	|	EBX	|
 *	-----------------  <--- 保存完所有寄存器后的 SS:ESP 的指向(esp0)
 *	|		|
 *	-----------------
 *	|		|
 *	-----------------
 */


/*
 *	SAVE_ALL: 手动保存 GS ---> EBX 寄存器的值，并设置 DS = ES = KERNEL_DS 用于访问
 * 内核数据段，设置 FS = USER_DS 用于访问用户数据段。
 */
#define SAVE_ALL \
	cld; \
	push %gs; \
	push %fs; \
	push %es; \
	push %ds; \
	pushl %eax; \
	pushl %ebp; \
	pushl %edi; \
	pushl %esi; \
	pushl %edx; \
	pushl %ecx; \
	pushl %ebx; \
	movl $(KERNEL_DS),%edx; \
	mov %dx,%ds; \
	mov %dx,%es; \
	movl $(USER_DS),%edx; \
	mov %dx,%fs;

/*
 *	RESTORE_ALL: 手动恢复 EBX ---> GS 寄存器的值。并执行 iret 指令退出中断。
 */
#define RESTORE_ALL \
	cmpw $(KERNEL_CS),CS(%esp); \
	je 1f;   \
	movl _current,%eax; \
	movl dbgreg7(%eax),%ebx; \
	movl %ebx,%db7;	\	/* 要退回到用户态时用 current->debugreg[7] 恢复 %db7(当前任务的硬件调试状态) */
1:	popl %ebx; \
	popl %ecx; \
	popl %edx; \
	popl %esi; \
	popl %edi; \
	popl %ebp; \
	popl %eax; \	/* 系统调用的返回值通过 eax 寄存器传递，中断返回时这个值无特殊意义 */
	pop %ds; \
	pop %es; \
	pop %fs; \
	pop %gs; \
	addl $4,%esp; \	/* esp 跳过系统调用的 ORIG_EAX(或中断的 ERROR_CODE) */
	iret
			/*
			 *	最后执行 iret 指令退出中断，处理器自动恢复 CS:EIP 和 EFLAGS 和可选的 SS:ESP。
			 */

/*
 *	_lcall7: 调用门 default_ldt 对应的中断处理函数。
 */
.align 4
_lcall7:
	pushfl			# We get a different stack layout with call gates,
	pushl %eax		# which has to be cleaned up later..
	SAVE_ALL
	movl EIP(%esp),%eax	# due to call gates, this is eflags, not eip..
	movl CS(%esp),%edx	# this is eip..
	movl EFLAGS(%esp),%ecx	# and this is cs..
	movl %eax,EFLAGS(%esp)	#
	movl %edx,EIP(%esp)	# Now we move them to their "normal" places
	movl %ecx,CS(%esp)	#
	movl %esp,%eax
	pushl %eax
	call _iABI_emulate
	popl %eax
	jmp ret_from_sys_call

/*
 *	handle_bottom_half: 处理中断的下半部，在 ret_from_sys_call 中执行，执行完后回到 ret_from_sys_call
 * 中继续向下执行，处理当前正在运行任务的信号。
 */
.align 4
handle_bottom_half:
	pushfl
	incl _intr_count
	sti
	call _do_bottom_half
	popfl
	decl _intr_count
	jmp 9f

/*
 *	reschedule: 重新调度新的任务运行，当前任务被暂停在 schedule 中。重新调度之前将 ret_from_sys_call
 * 压栈，则当前任务恢复执行后从 ret_from_sys_call 处重新开始向下执行，重新处理当前任务的信号。
 */
.align 4
reschedule:
	pushl $ret_from_sys_call
	jmp _schedule

/*
 *	_system_call: 系统调用总入口。主要完成两个工作，一是根据系统调用号调用对应的系统调用处理函数，
 * 二是在系统调用处理函数执行完毕后，也就是系统调用过程的尾部对当前正在运行任务的信号进行处理。
 */
.align 4
_system_call:
	pushl %eax			# save orig_eax
	SAVE_ALL
	movl $-ENOSYS,EAX(%esp)
			/*
			 *	首先保存系统调用号 ORIG_EAX，然后用 SAVE_ALL 保存 GS -> EBX 寄存器的值，
			 * 最后在 0x18 处的 EAX 的位置中填入 -ENOSYS，表示默认的系统调用返回值为 -ENOSYS。
			 */
	cmpl _NR_syscalls,%eax
	jae ret_from_sys_call
			/*
			 *	if (%eax >= NR_syscalls) goto ret_from_sys_call;
			 *
			 *	如果系统调用号超出范围，则跳转到信号处理的地方处理信号
			 */
	movl _current,%ebx
	andl $~CF_MASK,EFLAGS(%esp)	# clear carry - assume no errors
	movl $0,errno(%ebx)
			/*
			 *	首先清除 0x38 处 EFLAGS 中的进位标志 CF，表示系统调用的处理函数执行过程中
			 * 没有错误发生，如果有错误发生，会在后面重新设置。然后设置 current->errno = 0。
			 */
	movl %db6,%edx
	movl %edx,dbgreg6(%ebx)  # save current hardware debugging status
			/*
			 *	current->debugreg[6] = %db6;
			 *
			 *	保存当前正在运行任务的硬件调试状态。%db6 是第 5 个调试寄存器的值。
			 * 6 个调试寄存器: %db0 %db1 %db2 %db3 %db6 %db7。
			 */
	testb $0x20,flags(%ebx)		# PF_TRACESYS
	jne 1f
			/*
			 *	if (current->flags & PF_TRACESYS) goto 1f;
			 *
			 *	当前任务的 PF_TRACESYS 标志置位，则需要跟踪当前任务的系统调用。
			 */

	call _sys_call_table(,%eax,4)
			/*
			 *	call [ sys_call_table + %eax * 4 ]: 根据系统调用号调用对应的系统调用函数。
			 * 如: fork 系统调用对应的调用号为 __NR_fork = 2，sys_call_table[2] = sys_fork，
			 * 因此系统调用 fork 对应的系统调用处理函数为 sys_fork。
			 *
			 *	系统调用处理函数的参数依次排列在当前内核态栈的栈顶部分，即从 esp0 开始的
			 * 地方，系统调用处理函数执行时将会按顺序依次使用这里的参数。
			 */
	movl %eax,EAX(%esp)		# save the return value
			/*
			 *	0x18 处的 EAX 的位置处保存系统调用的返回值
			 */

	movl errno(%ebx),%edx
			/*
			 *	edx = current->errno: 系统调用处理函数执行完毕后，判断 current->errno 的值
			 * 以确定系统调用处理函数的执行过程中是否有错误发生。
			 */
	negl %edx
	je ret_from_sys_call
			/*
			 *	if (current->errno == 0) goto ret_from_sys_call;
			 *
			 *	如果没有错误发生，则直接去处理信号
			 */
	movl %edx,EAX(%esp)
	orl $(CF_MASK),EFLAGS(%esp)	# set carry to indicate error
	jmp ret_from_sys_call
			/*
			 *	有错误发生时，做以下两件事情，然后去处理信号
			 *
			 *	1. 0x18 处的 EAX 的位置保存该错误值，正常情况下这个位置会保存系统调用返回值。
			 *	2. 设置 0x38 处 EFLAGS 中的进位标志 CF 以表明系统调用处理函数执行过程中有
			 * 错误发生。
			 */

/*
 *	1f: 跟踪当前正在运行任务的系统调用过程。
 */
.align 4
1:	call _syscall_trace
			/*
			 *	执行系统调用跟踪函数 syscall_trace
			 */
	movl ORIG_EAX(%esp),%eax
	call _sys_call_table(,%eax,4)
	movl %eax,EAX(%esp)		# save the return value
			/*
			 *	根据系统调用号执行具体的系统调用处理函数并保存其返回值
			 */
	movl _current,%eax
	movl errno(%eax),%edx
	negl %edx
	je 1f
	movl %edx,EAX(%esp)
	orl $(CF_MASK),EFLAGS(%esp)	# set carry to indicate error
			/*
			 *	通过判断 current->errno 来确定系统调用处理函数执行过程中是否有错误发生，
			 * 若有则保存错误信息并设置错误标志。
			 */
1:	call _syscall_trace
			/*
			 *	系统调用处理函数执行完毕后，再执行一次 syscall_trace，返回后继续向下执行
			 * ret_from_sys_call，进行信号处理。
			 */

/*
 *	ret_from_sys_call: 这段代码将对当前正在运行的任务的信号进行处理，处理信号之前会先处理活跃的
 * 中断下半部，这是系统中唯一处理中断下半部的地方。
 *
 *	系统对信号的处理并不是实时的，而是有延迟的，并且每次处理只能处理当前正在运行任务 current 的信号，
 * 系统中有三个地方会跳转到这里进行信号的处理:
 *	1. 系统调用的尾部
 *	2. 处理器自身产生的异常的尾部
 *	3. irq.h 中普通中断的尾部，快速中断 fast_IRQ 的尾部不进行信号处理
 *
 *	系统对信号的处理有固定的时机，带有一定的延迟，但延迟不是很大。因为系统有一个每隔 10ms 触发一次的
 * 定时器中断，这个中断也是操作系统的运行节拍，即便之前的条件都不能触发，系统也会在下一个节拍中断的尾部
 * 对 current 的信号进行处理。所以理论上系统对当前任务信号处理的最大延迟为 10ms。
 */
	.align 4,0x90
ret_from_sys_call:
	cmpl $0,_intr_count
	jne 2f
			/*
			 *	if (intr_count != 0) goto 2f;
			 *
			 *	当前的流程位于中断中，则向下跳转到 2f 处退出，中断中不处理信号，只有中断的
			 * 尾部才会去处理信号。
			 */
	movl _bh_mask,%eax
	andl _bh_active,%eax
	jne handle_bottom_half
			/*
			 *	if (bh_mask & bh_active != 0) goto handle_bottom_half;
			 *
			 *	有中断下半部处于 active 状态，表示某些中断有下半部需要处理，则先去处理
			 * 中断的下半部，处理完了之后再回到这里继续向下执行处理信号。
			 */
9:	movl EFLAGS(%esp),%eax		# check VM86 flag: CS/SS are
	testl $(VM_MASK),%eax		# different then
	jne 1f
			/*
			 *	如果进入系统调用或中断之前处理器处于虚拟 8086 模式。则跳过下面的两条语句，
			 * 下面两条语句只有在保护模式下有效。
			 */
	cmpw $(KERNEL_CS),CS(%esp)	# was old code segment supervisor ?
	je 2f
			/*
			 *	如果进入系统调用或中断之前处理器处于保护模式，且系统处于内核态，则表示是在
			 * 任务的内核态产生了中断进入到这里，则跳转到下面的 2f 处直接退出。
			 *
			 *	这个版本的内核，任务在内核态执行时不可抢占，除非任务在内核态主动放弃处理器，
			 * 否则任务将一直占有处理器，而信号的处理有可能会导致任务状态的改变，切换其它任务
			 * 运行，所以对于这种情况，不能处理信号。
			 */
1:	sti
	orl $(IF_MASK),%eax		# these just try to make sure
	andl $~NT_MASK,%eax		# the program doesn't do anything
	movl %eax,EFLAGS(%esp)		# stupid
			/*
			 *	sti: 开启外部硬件中断，后续的流程可以正常响应外部中断。
			 *
			 *	对 0x38 处的 EFLAGS: 设置 IF 标志，表示中断退出后，可以响应可屏蔽中断。
			 * 清除 NT 标志，表示执行 iret 指令时不产生任务切换，执行常规的中断返回流程。
			 */
	cmpl $0,_need_resched
	jne reschedule
			/*
			 *	if (need_resched != 0) goto reschedule;
			 *
			 *	需要重新调度新的任务运行，则跳转到 reschedule 处。
			 */
	movl _current,%eax
	cmpl _task,%eax			# task[0] cannot have signals
	je 2f
			/*
			 *	if (current == task[0]) goto 2f;
			 *
			 *	当前任务是任务 0，则向前跳转到 2f 处退出，不能对任务 0 进行信号处理。
			 */
	cmpl $0,state(%eax)		# state
	jne reschedule
			/*
			 *	if (current->state != TASK_RUNNING) goto reschedule;
			 *
			 *	当前任务已不在运行态，则跳转到 reschedule 处调度新的任务运行。做这个判断
			 * 的原因是系统调用处理函数中有可能会改变当前正在运行任务的状态。
			 */
	cmpl $0,counter(%eax)		# counter
	je reschedule
			/*
			 *	if (current->counter == 0) goto reschedule;
			 *
			 *	当前任务的时间片已经用完了，则需要重新调度新的任务来运行。
			 */
	movl blocked(%eax),%ecx
	movl %ecx,%ebx			# save blocked in %ebx for signal handling
	notl %ecx
	andl signal(%eax),%ecx
	jne signal_return
			/*
			 *	if ((current->signal & (~current->blocked)) != 0) goto signal_return;
			 *
			 *	如果当前任务有信号需要处理，且信号未被屏蔽，则跳转到 signal_return 处去处理
			 * 当前任务的信号并返回，否则继续向下执行直接返回。
			 *	ebx 中保存的是 current->blocked，这个在后面会作为 do_signal 的第一个参数使用。
			 */
2:	RESTORE_ALL
			/*
			 *	恢复寄存器并执行 iret 指令退出中断
			 */
/*
 *	signal_return: 保护模式下的信号处理。
 */
.align 4
signal_return:
	movl %esp,%ecx
	pushl %ecx
			/*
			 *	当前的栈指针 esp0 是传给 do_signal 的第二个参数，栈指针指向的栈中的内容
			 * (EBX -> OLDSS)在 do_signal 中被转换为 struct pt_regs，栈中的内容与 struct pt_regs
			 * 中的成员一一对应。do_signal 中通过 pt_regs 来访问栈中的内容。
			 */
	testl $(VM_MASK),EFLAGS(%ecx)
	jne v86_signal_return
			/*
			 *	如果进入中断前处理器处于虚拟 8086 模式，则跳转到 v86_signal_return 处。
			 * 上一步压在栈中的 esp0 将作为 save_v86_state 函数的参数。
			 */
	pushl %ebx
			/*
			 *	%ebx = current->blocked，也就是当前任务的现在的信号屏蔽码，是传给 do_signal
			 * 的第一个参数。
			 */
	call _do_signal
			/*
			 *	call do_signal(current->blocked, esp0); 调用信号处理函数去处理信号
			 */
	popl %ebx
	popl %ebx
	RESTORE_ALL
			/*
			 *	信号处理函数执行完毕后，弹出栈中传递给 do_signal 的两个参数，并恢复所有的
			 * 寄存器，然后执行 iret 指令退出中断或系统调用。
			 */
/*
 *	v86_signal_return: 虚拟 8086 模式下的信号处理。
 */
.align 4
v86_signal_return:
	call _save_v86_state
			/*
			 *	call save_v86_state(esp0); 保存虚拟 8086 模式的状态。esp0 被转换为
			 * struct vm86_regs，栈中的内容与结构体中的内容一一对应。
			 */
	movl %eax,%esp
			/*
			 *	虚拟 8086 模式的状态已保存，更改栈指针 esp 的指向，使当前的 SS:ESP 指向
			 * save_v86_state 返回的栈的位置。
			 */
	pushl %eax
	pushl %ebx
	call _do_signal
			/*
			 *	do_signal 的两个参数压栈并调用 do_signal 处理信号。第一个参数与 signal_return
			 * 中一致，是 current->blocked，第二个参数是 save_v86_state 函数返回的栈指针。
			 */
	popl %ebx
	popl %ebx
	RESTORE_ALL
			/*
			 *	信号处理函数执行完毕后，弹出栈中传递给 do_signal 的两个参数，并恢复所有的
			 * 寄存器，然后执行 iret 指令退出中断或系统调用。
			 */


/*
 *	以下是处理器自身产生的中断(异常)的处理流程，这些中断门的向量都在 0x20 以下。
 *
 *	中断在处理器的特权级为 0 或 3 的情况下都有可能发生，也就是任务的内核态或用户态都有可能触发中断，
 * 处理器只能在 0 特权级下处理中断，并且中断处理过程中会使用当前正在运行任务的内核态栈。
 *
 *	如果产生中断时任务处于用户态，则处理器刚开始的流程和系统调用一致，先得到当前正在运行任务的内核态
 * 栈，将任务的用户态栈指针压入内核态栈的栈底，然后压入 EFLAGS 和 CS:EIP。如果中断带出错码，则处理器会自动
 * 将出错码压到 EIP 之后。然后跳转到中断处理函数处开始执行中断。
 *
 *	如果产生中断时任务处于内核态，这时候特权级已经为 0，所使用的栈已经是任务的内核态栈了，所以处理器
 * 不需要切换栈，也就不需要将任务的用户态栈指针压入内核态中了。这时处理器只将 EFLAGS 和中断产生时的 CS:EIP
 * 压入内核态栈中，如果中断带出错码，则处理器会自动将出错码压到 EIP 之后。然后跳转到中断处理函数处开始执行
 * 中断。
 *
 *	不管是在任务的用户态还是内核态产生中断，最开始的信息的保存都是处理器自动完成的，在退出中断的时候
 * 会执行 iret 指令，处理器会自动恢复这些信息，并恢复中断产生之前的现场。所以此处不需要关注自动保存的这些
 * 信息。
 *
 *	以在用户态产生中断为例，说明中断处理过程中的寄存器的保存和恢复。
 *
 *	【当前正在运行任务对应的内核栈中的信息如下】:
 *
 *	-----------------  <--- 任务的内核态栈底
 * 0x40	|	| OLDSS	|
 *	-----------------	<=== 原 SS:ESP 指向中断产生之前的任务的用户态栈的位置。如果是在内核态产生
 * 0x3C	|     OLDESP	|		中断，则没有 OLDSS 和 OLDESP。且此处不会是内核态的栈底。
 *	-----------------
 * 0x38	|     EFLAGS	|	<=== EFLAGS 是中断产生之前的标志寄存器的值
 *	-----------------
 * 0x34	|	|  CS	|
 *	-----------------	<=== CS:EIP 保存从中断返回之后要执行的代码的位置。
 * 0x30	|	EIP	|
 *	-----------------------------------------------------------------------------
 * 0x2C	|   ERROR_CODE	|	<=== 错误码，如果中断带错误码，则处理器会在此处自动保存错误码，如果不带
 *	----------------------		错误码，则代码中会手动填入 0 以表示没有错误码。(最后会被填入 -1)
 * 0x28	|   C_FUNCTION	|	<=== 中断的 C 处理函数地址，这个 C 函数将真正处理中断。代码执行过程中，
 *	----------------------		这个地方的值会被替换为 GS 寄存器的值。
 * 0x24	|	|  FS	|	<=== FS - DS: 中断执行过程中，DS 和 ES 用于指向内核数据空间，FS 被
 *	-----------------			设置为指向用户数据空间，这样内核就可以利用 FS 寄存器来
 * 0x20	|	|  ES	|			访问用户数据空间，进而在内核空间与用户空间之间传递数据。
 *	-----------------
 * 0x1C	|	|  DS	|
 *	----------------------
 * 0x18	|	EAX	|
 *	-----------------	<=== EAX - EBX，中断中保存这些寄存器主要作用是为了与 SAVE_ALL 保持一致，
 * 0x14	|	EBP	|		因为中断执行的尾部会跳转到 ret_from_sys_call 处去处理当前运行
 *	-----------------		任务的信号，处理完后会用 RESTORE_ALL 退出中断。
 * 0x10	|	EDI	|
 *	-----------------
 * 0x0C	|	ESI	|
 *	-----------------
 * 0x08	|	EDX	|
 *	-----------------
 * 0x04	|	ECX	|
 *	-----------------
 * 0x00	|	EBX	|
 *	-------------------------------------  <--- 保存完所有寄存器后的 SS:ESP 的指向(esp0)
 *  -4	|	esp0	|
 *	-----------------	<=== 这两个位置用于保存传递给中断 C 函数的两个参数，中断 C 函数执行完毕后
 *  -8	|   ERROR_CODE	|		会丢弃这两个参数，栈指针回到 esp0 处。
 *	-----------------
 */


/*
 *	divide_error: 除 0 异常
 */
.align 4
_divide_error:
	pushl $0		# no error code
			/*
			 *	在 ERROR_CODE 的位置手动压入 0 表示没有出错码
			 */
	pushl $_do_divide_error
			/*
			 *	C_FUNCTION 的位置压入该异常对应的 C 处理函数的地址
			 */
.align 4,0x90
error_code:
	push %fs
	push %es
	push %ds
	pushl %eax
	pushl %ebp
	pushl %edi
	pushl %esi
	pushl %edx
	pushl %ecx
	pushl %ebx
			/*
			 *	手动保存 FS -> EBX，GS 与 C_FUNCTION 对应。
			 */
	movl $0,%eax
	movl %eax,%db7			# disable hardware debugging...
			/*
			 *	%db7 = 0，禁止硬件调试，会在 RESTORE_ALL 中恢复当前任务的硬件调试状态。
			 */
	cld
	movl $-1, %eax
	xchgl %eax, ORIG_EAX(%esp)	# orig_eax (get the error code. )
			/*
			 *	eax 中填入 -1，并将 eax 中的值与 ERROR_CODE 互换，互换后 eax 中是中断的
			 * 错误码，ERROR_CODE 处变为 -1。
			 *
			 *	这个地方的 ERROR_CODE 与系统调用的 ORIG_EAX 相对应，填入 -1 表示不是系统
			 * 调用，而是中断。在信号处理的过程中会检测这个地方的值，用于确定是不是系统调用，
			 * 进而确定是不是需要重启系统调用。对中断来讲，根本就没有重启系统调用的概念。
			 */
	xorl %ebx,%ebx			# zero ebx
	mov %gs,%bx			# get the lower order bits of gs
	xchgl %ebx, GS(%esp)		# get the address and save gs.
			/*
			 *	ebx 中放入当前的 GS 寄存器的值，并将 ebx 中的值与 C_FUNCTION 互换，互换后
			 * ebx 中是中断的 C 处理函数地址，C_FUNCTION 处变为 GS。
			 */
	pushl %eax			# push the error code
			/*
			 *	中断错误码 ERROR_CODE 作为传给中断 C 函数的第二个参数入栈。
			 */
	lea 4(%esp),%edx
	pushl %edx
			/*
			 *	将当前 esp - 4 的值(esp0)作为传给中断 C 函数的第一个参数入栈，这个参数在
			 * 中断 C 函数中会被转换为 struct pt_regs，该参数指示的栈中的内容与 struct pt_regs
			 * 中的成员一一对应，C 函数中通过 pt_regs 访问栈中的内容。
			 */
	movl $(KERNEL_DS),%edx
	mov %dx,%ds
	mov %dx,%es
	movl $(USER_DS),%edx
	mov %dx,%fs
			/*
			 *	中断执行过程中，DS = ES = KERNEL_DS 用于访问内核数据段，FS = USER_DS 用于
			 * 访问用户数据段。
			 */
	pushl %eax
	movl _current,%eax
	movl %db6,%edx
	movl %edx,dbgreg6(%eax)  # save current hardware debugging status
	popl %eax
			/*
			 *	current->debugreg[6] = %db6; 保存当前任务的调试状态。
			 */

	call *%ebx
			/*
			 *	call C_FUNCTION(esp0, ERROR_CODE); 调用中断对应的 C 处理函数，真正的处理中断。
			 */
	addl $8,%esp
			/*
			 *	中断处理的 C 函数执行完毕后，将栈中传递给 C 函数的两个参数丢弃。
			 */

	jmp ret_from_sys_call
			/*
			 *	中断处理的尾部去处理当前正在运行任务的信号，并从中退出中断。
			 */

.align 4
_coprocessor_error:
	pushl $0
	pushl $_do_coprocessor_error
	jmp error_code

.align 4
_device_not_available:
	pushl $-1		# mark this as an int
	SAVE_ALL
	pushl $ret_from_sys_call
	movl %cr0,%eax
	testl $0x4,%eax			# EM (math emulation bit)
	je _math_state_restore
	pushl $0		# temporary storage for ORIG_EIP
	call _math_emulate
	addl $4,%esp
	ret

.align 4
_debug:
	pushl $0
	pushl $_do_debug
	jmp error_code

.align 4
_nmi:
	pushl $0
	pushl $_do_nmi
	jmp error_code

.align 4
_int3:
	pushl $0
	pushl $_do_int3
	jmp error_code

.align 4
_overflow:
	pushl $0
	pushl $_do_overflow
	jmp error_code

.align 4
_bounds:
	pushl $0
	pushl $_do_bounds
	jmp error_code

.align 4
_invalid_op:
	pushl $0
	pushl $_do_invalid_op
	jmp error_code

.align 4
_coprocessor_segment_overrun:
	pushl $0
	pushl $_do_coprocessor_segment_overrun
	jmp error_code

.align 4
_reserved:
	pushl $0
	pushl $_do_reserved
	jmp error_code

.align 4
_double_fault:
	pushl $_do_double_fault
	jmp error_code

.align 4
_invalid_TSS:
	pushl $_do_invalid_TSS
	jmp error_code

.align 4
_segment_not_present:
	pushl $_do_segment_not_present
	jmp error_code

.align 4
_stack_segment:
	pushl $_do_stack_segment
	jmp error_code

.align 4
_general_protection:
	pushl $_do_general_protection
	jmp error_code

.align 4
_alignment_check:
	pushl $_do_alignment_check
	jmp error_code

/*
 *	page_fault: 页错误中断处理函数，对应的 C 处理函数为 do_page_fault，这个中断会带有错误码，处理器
 * 会自动压入栈中，错误码用于表明是缺页异常或页写保护异常中的哪一种异常。
 *
 *	页错误属于异常中的故障(Fault)，Fault 是一种可被纠正的异常，且一旦纠正程序就可以继续运行，当出现
 * 一个 Fault 时，处理器会把机器状态恢复到产生 Fault 的指令之前的状态，此时异常处理程序的返回地址(处理器
 * 自动保存在栈中的 CS:EIP)会指向产生 Fault 的指令，而不是其后面一条指令。因此在返回后产生 Fault 的指令
 * 将被重新执行。
 *
 *	即: 缺页异常或页写保护异常处理完毕后，引起异常的那条指令将被重新执行。
 */
.align 4
_page_fault:
	pushl $_do_page_fault
	jmp error_code
