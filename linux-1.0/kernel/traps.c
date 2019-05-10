/*
 *  linux/kernel/traps.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * 'Traps.c' handles hardware traps and faults after we have saved some
 * state in 'asm.s'. Currently mostly a debugging-aid, will be extended
 * to mainly kill the offending process (probably by giving it a signal,
 * but possibly by killing it outright if necessary).
 */
#include <linux/head.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/segment.h>
#include <linux/ptrace.h>

#include <asm/system.h>
#include <asm/segment.h>
#include <asm/io.h>

static inline void console_verbose(void)
{
	extern int console_loglevel;
	console_loglevel = 15;
}

#define DO_ERROR(trapnr, signr, str, name, tsk) \
asmlinkage void do_##name(struct pt_regs * regs, long error_code) \
{ \
	tsk->tss.error_code = error_code; \
	tsk->tss.trap_no = trapnr; \
	if (signr == SIGTRAP && current->flags & PF_PTRACED) \
		current->blocked &= ~(1 << (SIGTRAP-1)); \
	send_sig(signr, tsk, 1); \
	die_if_kernel(str,regs,error_code); \
}

#define get_seg_byte(seg,addr) ({ \
register char __res; \
__asm__("push %%fs;mov %%ax,%%fs;movb %%fs:%2,%%al;pop %%fs" \
	:"=a" (__res):"0" (seg),"m" (*(addr))); \
__res;})

#define get_seg_long(seg,addr) ({ \
register unsigned long __res; \
__asm__("push %%fs;mov %%ax,%%fs;movl %%fs:%2,%%eax;pop %%fs" \
	:"=a" (__res):"0" (seg),"m" (*(addr))); \
__res;})

#define _fs() ({ \
register unsigned short __res; \
__asm__("mov %%fs,%%ax":"=a" (__res):); \
__res;})

void page_exception(void);

asmlinkage void divide_error(void);
asmlinkage void debug(void);
asmlinkage void nmi(void);
asmlinkage void int3(void);
asmlinkage void overflow(void);
asmlinkage void bounds(void);
asmlinkage void invalid_op(void);
asmlinkage void device_not_available(void);
asmlinkage void double_fault(void);
asmlinkage void coprocessor_segment_overrun(void);
asmlinkage void invalid_TSS(void);
asmlinkage void segment_not_present(void);
asmlinkage void stack_segment(void);
asmlinkage void general_protection(void);
asmlinkage void page_fault(void);
asmlinkage void coprocessor_error(void);
asmlinkage void reserved(void);
asmlinkage void alignment_check(void);

/*static*/ void die_if_kernel(char * str, struct pt_regs * regs, long err)
{
	int i;
	unsigned long esp;
	unsigned short ss;

	esp = (unsigned long) &regs->esp;
	ss = KERNEL_DS;
	if ((regs->eflags & VM_MASK) || (3 & regs->cs) == 3)
		return;
	if (regs->cs & 3) {
		esp = regs->esp;
		ss = regs->ss;
	}
	console_verbose();
	printk("%s: %04lx\n", str, err & 0xffff);
	printk("EIP:    %04x:%08lx\nEFLAGS: %08lx\n", 0xffff & regs->cs,regs->eip,regs->eflags);
	printk("eax: %08lx   ebx: %08lx   ecx: %08lx   edx: %08lx\n",
		regs->eax, regs->ebx, regs->ecx, regs->edx);
	printk("esi: %08lx   edi: %08lx   ebp: %08lx   esp: %08lx\n",
		regs->esi, regs->edi, regs->ebp, esp);
	printk("ds: %04x   es: %04x   fs: %04x   gs: %04x   ss: %04x\n",
		regs->ds, regs->es, regs->fs, regs->gs, ss);
	store_TR(i);
	printk("Pid: %d, process nr: %d (%s)\nStack: ", current->pid, 0xffff & i, current->comm);
	for(i=0;i<5;i++)
		printk("%08lx ", get_seg_long(ss,(i+(unsigned long *)esp)));
	printk("\nCode: ");
	for(i=0;i<20;i++)
		printk("%02x ",0xff & get_seg_byte(regs->cs,(i+(char *)regs->eip)));
	printk("\n");
	do_exit(SIGSEGV);
}

DO_ERROR( 0, SIGFPE,  "divide error", divide_error, current)
DO_ERROR( 3, SIGTRAP, "int3", int3, current)
DO_ERROR( 4, SIGSEGV, "overflow", overflow, current)
DO_ERROR( 5, SIGSEGV, "bounds", bounds, current)
DO_ERROR( 6, SIGILL,  "invalid operand", invalid_op, current)
DO_ERROR( 7, SIGSEGV, "device not available", device_not_available, current)
DO_ERROR( 8, SIGSEGV, "double fault", double_fault, current)
DO_ERROR( 9, SIGFPE,  "coprocessor segment overrun", coprocessor_segment_overrun, last_task_used_math)
DO_ERROR(10, SIGSEGV, "invalid TSS", invalid_TSS, current)
DO_ERROR(11, SIGSEGV, "segment not present", segment_not_present, current)
DO_ERROR(12, SIGSEGV, "stack segment", stack_segment, current)
DO_ERROR(13, SIGSEGV, "general protection", general_protection, current)
DO_ERROR(15, SIGSEGV, "reserved", reserved, current)
DO_ERROR(17, SIGSEGV, "alignment check", alignment_check, current)

asmlinkage void do_nmi(struct pt_regs * regs, long error_code)
{
	printk("Uhhuh. NMI received. Dazed and confused, but trying to continue\n");
	printk("You probably have a hardware problem with your RAM chips\n");
}

asmlinkage void do_debug(struct pt_regs * regs, long error_code)
{
	if (current->flags & PF_PTRACED)
		current->blocked &= ~(1 << (SIGTRAP-1));
	send_sig(SIGTRAP, current, 1);
	current->tss.trap_no = 1;
	current->tss.error_code = error_code;
	if((regs->cs & 3) == 0) {
	  /* If this is a kernel mode trap, then reset db7 and allow us to continue */
	  __asm__("movl $0,%%edx\n\t" \
		  "movl %%edx,%%db7\n\t" \
		  : /* no output */ \
		  : /* no input */ :"dx");

	  return;
	};
	die_if_kernel("debug",regs,error_code);
}

/*
 * Allow the process which triggered the interrupt to recover the error
 * condition.
 *  - the status word is saved in the cs selector.
 *  - the tag word is saved in the operand selector.
 *  - the status word is then cleared and the tags all set to Empty.
 *
 * This will give sufficient information for complete recovery provided that
 * the affected process knows or can deduce the code and data segments
 * which were in force when the exception condition arose.
 *
 * Note that we play around with the 'TS' bit to hopefully get
 * the correct behaviour even in the presense of the asynchronous
 * IRQ13 behaviour
 */
void math_error(void)
{
	struct i387_hard_struct * env;

	clts();
	if (!last_task_used_math) {
		__asm__("fnclex");
		return;
	}
	env = &last_task_used_math->tss.i387.hard;
	send_sig(SIGFPE, last_task_used_math, 1);
	last_task_used_math->tss.trap_no = 16;
	last_task_used_math->tss.error_code = 0;
	__asm__ __volatile__("fnsave %0":"=m" (*env));
	last_task_used_math = NULL;
	stts();
	env->fcs = (env->swd & 0x0000ffff) | (env->fcs & 0xffff0000);
	env->fos = env->twd;
	env->swd &= 0xffff3800;
	env->twd = 0xffffffff;
}

asmlinkage void do_coprocessor_error(struct pt_regs * regs, long error_code)
{
	ignore_irq13 = 1;
	math_error();
}

/*
 *	trap_init: 异常(陷阱)中断程序初始化，设置它们的中断调用门，trap 和 system 都使用
 * 了 IDT 表中的陷阱门。不同的是 trap 设置的 DPL = 0，system 设置的 DPL = 3。
 *
 *	trap 和 system 所设置的一种是由 CPU 自身产生的异常，比如除数为 0，页面错误等。另
 * 一种是用户程序通过 INT 指令产生的中断(陷阱)，主要用来产生系统调用。这些中断门的向量除
 * 用于系统调用的 0x80 以外全都在 0x20 以下，0x20 以上的都是用于外设的通用中断门，这些在
 * 后面的 init_IRQ 中设置。
 *
 *	trap 中设置 DPL = 0 是为了阻止在特权级为 3 的用户空间中通过 INT 指令触发的异常穿
 * 过陷阱门，system 中设置 DPL = 3 是为了让在特权级为 3 的用户空间中通过 INT 指令触发的
 * 异常可是顺利穿过陷阱门。
 */
void trap_init(void)
{
	int i;

	set_trap_gate(0,&divide_error);
	set_trap_gate(1,&debug);
	set_trap_gate(2,&nmi);
	set_system_gate(3,&int3);	/* int3-5 can be called from all */
	set_system_gate(4,&overflow);
	set_system_gate(5,&bounds);
	set_trap_gate(6,&invalid_op);
	set_trap_gate(7,&device_not_available);
	set_trap_gate(8,&double_fault);
	set_trap_gate(9,&coprocessor_segment_overrun);
	set_trap_gate(10,&invalid_TSS);
	set_trap_gate(11,&segment_not_present);
	set_trap_gate(12,&stack_segment);
	set_trap_gate(13,&general_protection);
	set_trap_gate(14,&page_fault);	/* 页错误，缺页异常或页写保护异常 */
	set_trap_gate(15,&reserved);
	set_trap_gate(16,&coprocessor_error);
	set_trap_gate(17,&alignment_check);
	for (i=18;i<48;i++)
		set_trap_gate(i,&reserved);
			/*
			 *	0x20 以下，也就是 0 - 31 号中断是处理器使用及系统保留的，
			 * 32 - 255 号中断用于外部中断或 INTn 指令产生的软中断。目前系统
			 * 只有 16 个外部中断，编号为 32 - 47，在后面的 init_IRQ 中初始化。
			 * 0x80 号中断用于系统调用，在后面的 sched_init 中初始化。
			 */
}
