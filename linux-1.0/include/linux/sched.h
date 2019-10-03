#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

#define NEW_SWAP

/*
 * define DEBUG if you want the wait-queues to have some extra
 * debugging code. It's not normally used, but might catch some
 * wait-queue coding errors.
 *
 *  #define DEBUG
 */

/*
 *	HZ: 定义系统的时钟节拍(滴答)频率为 100HZ，即系统的 tick 周期为 10ms，时钟节拍是通过 sched_init
 * 函数中初始化的外部硬件定时器来实现的，1 tick = 10ms。
 */
#define HZ 100

/*
 * System setup flags..
 */
extern int hard_math;
extern int x86;
extern int ignore_irq13;
extern int wp_works_ok;

/*
 * Bus types (default is ISA, but people can check others with these..)
 * MCA_bus hardcoded to 0 for now.
 */
extern int EISA_bus;
#define MCA_bus 0

#include <linux/tasks.h>
#include <asm/system.h>

/*
 * User space process size: 3GB. This is hardcoded into a few places,
 * so don't change it unless you know what you are doing.
 */
/*
 *	TASK_SIZE: 任务用户态空间的大小，每个任务的线性地址空间为 4GB，0 - 3GB 为任务的用户态空间，
 * 3GB - 4GB 为任务的内核态空间。
 */
#define TASK_SIZE	0xc0000000

/*
 * Size of io_bitmap in longwords: 32 is ports 0-0x3ff.
 */
#define IO_BITMAP_SIZE	32

/*
 * These are the constant used to fake the fixed-point load-average
 * counting. Some notes:
 *  - 11 bit fractions expand to 22 bits by the multiplies: this gives
 *    a load-average precision of 10 bits integer + 11 bits fractional
 *  - if you want to count load-averages more often, you need more
 *    precision, or rounding will get you. With 2-second counting freq,
 *    the EXP_n values would be 1981, 2034 and 2043 if still using only
 *    11 bit fractions.
 */
extern unsigned long avenrun[];		/* Load averages */

#define FSHIFT		11		/* nr of bits of precision */
#define FIXED_1		(1<<FSHIFT)	/* 1.0 as fixed-point */
#define LOAD_FREQ	(5*HZ)		/* 5 sec intervals */
#define EXP_1		1884		/* 1/exp(5sec/1min) as fixed-point */
#define EXP_5		2014		/* 1/exp(5sec/5min) */
#define EXP_15		2037		/* 1/exp(5sec/15min) */

#define CALC_LOAD(load,exp,n) \
	load *= exp; \
	load += n*(FIXED_1-exp); \
	load >>= FSHIFT;

#define CT_TO_SECS(x)	((x) / HZ)
#define CT_TO_USECS(x)	(((x) % HZ) * 1000000/HZ)

#define FIRST_TASK task[0]
#define LAST_TASK task[NR_TASKS-1]

#include <linux/head.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/signal.h>
#include <linux/time.h>
#include <linux/param.h>
#include <linux/resource.h>
#include <linux/vm86.h>
#include <linux/math_emu.h>

/*
 *	任务的状态:
 *
 *	TASK_RUNNING: 以下三种情况下任务的状态都是 TASK_RUNNING。
 *		      1. 任务在用户态运行
 *		      2. 任务在内核态运行
 *		      3. 任务已准备就绪，处于就绪态
 *
 *	TASK_INTERRUPTIBLE: 可中断睡眠状态。处于这种状态下的任务可以被信号唤醒，唤醒后进入 TASK_RUNNING 状态。
 *
 *	TASK_UNINTERRUPTIBLE: 不可中断睡眠状态。处于这种状态下的任务不能被信号唤醒，只能被 wake_up() 函数
 *			      唤醒，唤醒后进入 TASK_RUNNING 状态。
 *
 *	TASK_ZOMBIE: 僵尸态。任务已停止运行，所占有的大部分资源都已经释放，但是任务占有的 task_struct 结构
 *		     和 task_struct 结构所在的内存页面还未释放，正在等待其父任务回收该任务，父任务回收时需要
 *		     用到该任务的 task_struct 结构，并最终会释放该任务的 task_struct 结构和 task_struct 结构
 *		     所占有的内存页面，父任务回收后，该任务将真正消失。
 *
 *	TASK_STOPPED: 暂停状态。暂时停止运行。
 *
 *	TASK_SWAPPING:
 */
#define TASK_RUNNING		0
#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE	2
#define TASK_ZOMBIE		3
#define TASK_STOPPED		4
#define TASK_SWAPPING		5

#ifndef NULL
#define NULL ((void *) 0)
#endif

#ifdef __KERNEL__

extern void sched_init(void);
extern void show_state(void);
extern void trap_init(void);

asmlinkage void schedule(void);

#endif /* __KERNEL__ */

struct i387_hard_struct {
	long	cwd;
	long	swd;
	long	twd;
	long	fip;
	long	fcs;
	long	foo;
	long	fos;
	long	st_space[20];	/* 8*10 bytes for each FP-reg = 80 bytes */
};

struct i387_soft_struct {
	long	cwd;
	long	swd;
	long	twd;
	long	fip;
	long	fcs;
	long	foo;
	long	fos;
	long    top;
	struct fpu_reg	regs[8];	/* 8*16 bytes for each FP-reg = 128 bytes */
	unsigned char	lookahead;
	struct info	*info;
	unsigned long	entry_eip;
};

union i387_union {
	struct i387_hard_struct hard;
	struct i387_soft_struct soft;
};

/*
 *	tss_struct: 任务状态段(Task State Segment)数据结构，存储任务的上下文信息，用于保存和恢复
 * 任务的现场。任务调出时，处理器会自动将任务的当前现场信息保存在任务的 TSS 段中，任务调入时，处
 * 理器会自动从任务的 TSS 段中恢复之前保存的现场信息进而切换到该任务继续运行。
 *
 *	任务的 TSS 段的最小大小为 104 字节(0x64 位置处)，104 字节以内的信息严格遵循任务状态段 TSS
 * 的格式，以外的信息可以根据具体需求灵活设计。
 *
 *	TSS 段中 104 字节以内的字段可以分为动态字段和静态字段两大类:
 *
 *	动态字段: 当任务调出时，处理器会自动更新动态字段的内容，包括通用寄存器字段、段选择符字段、
 * 标志寄存器字段、指令指针字段、先前任务链接字段，这些信息是在任务的执行过程中动态变化的。
 *
 *	静态字段: 这些字段的内容在任务被创建时设置，处理器会读取这些字段的内容，但通常不会更改它们，
 * 静态字段的值在任务调出时不会被更新，处理器只有在需要它们时才会从相应的位置上去读取它们的值。
 * 包括 LDT 段选择符字段、页目录基地址寄存器字段、特权级 0/1/2 的堆栈指针字段、调试陷阱、I/O 位图
 * 基地址字段，这些信息在任务的执行过程中是不会动态变化的。
 *
 *	104 字节以外的字段，是需要在程序运行的过程中手动读写的，也就没有动态和静态之分。
 *
 *	TSS 段格式如下:
 *
 *	|31	      16|15	       0|
 *	+-------------------------------+----------
 *	|				|
 *	|				|	I387_INFO: 存储任务浮点相关的寄存器。
 *	|	     I387_INFO		|
 *	|				|
 *	|				|
 *	+-------------------------------+----------
 *	|	     ERROR_CODE		|	ERROR_CODE: 存储导致异常的错误码。
 *	+-------------------------------+----------
 *	|	      TRAP_NO		|	TRAP_NO: 存储异常类型编号。
 *	+-------------------------------+----------
 *	|		CR2		|	CR2: 页错误线性地址字段，存储导致页错误的线性地址。
 *	+-------------------------------+----------
 *	|		TR		|	TR: 任务寄存器字段。存储任务的 TSS 段选择符，该字段的值在任务
 *	+-------------------------------+---------- 创建时设置，任务调入调出时不会重写，任务切换时会用到这个值。
 *	|				|
 *	|				|	IO_BITMAP: I/O 许可位图字段，该字段的大小取决于 IO_BITMAP_SIZE
 *	|				|		   的配置。
 *	|				|
 *	|				|
 *	|				|
 *	|	    IO_BITMAP		|
 *	|				|
 *	|				|     ----------------------------------------------------------------
 *	|				|     |	BIT_MAP: I/O 位图基地址字段，存储从 TSS 段开始处到 I/O 许可
 *	|				|     |		 位图处的 16 位偏移值。这个地方的值在任务创建时被设
 *	|				|     |		 置，任务调入调出时不会更改这个地方的值。
 *	|				|     |	T: 调试陷阱标志字段，该字段位于 TSS 段的偏移 0x64 处的 bit0
 *	+-------------------------------+------	   处，当设置了该位时，处理器切换到该任务的操作将会产生一个
 * 0x64	|    BIT_MAP	|	      |T|	   调试异常。内核未使用该字段。
 *	+-------------------------------+----------
 * 0x60	|		|	LDT	|	LDT: LDT 段选择符字段，保存任务的 LDT 段的选择符，每个任务的
 *	+-------------------------------+----------  LDT 段在任务创建时就已经确定，任务生命周期内不会更改，
 * 0x5C	|		|	GS	|	  |  任务调入调出时不会更改此处的值，如有需要，处理器会从此处
 *	+-------------------------------+	  |  获取任务的 LDT 段的段选择符。
 * 0x58	|		|	FS	|	  -----------------------------------------------------------
 *	+-------------------------------+	GS -> ES: 段选择符字段。任务调出时，处理器自动将这些寄存器的
 * 0x54	|		|	DS	|		  信息保存在此处，任务再次调入时，处理器自动从此处
 *	+-------------------------------+		  恢复这些寄存器的信息。
 * 0x50	|		|	SS	|
 *	+-------------------------------+
 * 0x4C	|		|	CS	|
 *	+-------------------------------+
 * 0x48	|		|	ES	|
 *	+-------------------------------+----------
 * 0x44	|	       EDI		|
 *	+-------------------------------+
 * 0x40	|	       ESI		|
 *	+-------------------------------+	EDI -> EAX: 通用寄存器字段。任务调出时，处理器自动将这些寄存器
 * 0x3C	|	       EBP		|		    的信息保存在此处，任务再次调入时，处理器自动从此处
 *	+-------------------------------+		    恢复这些寄存器的信息。
 * 0x38	|	       ESP		|
 *	+-------------------------------+	SS:ESP  指向任务调出时的栈的位置。如果任务在用户态被调出，则其
 * 0x34	|	       EBX		|		指向用户态栈中的某一位置，如果任务在内核态被调出，则其
 *	+-------------------------------+		指向内核态栈中的某一位置。
 * 0x30	|	       EDX		|
 *	+-------------------------------+
 * 0x2C	|	       ECX		|
 *	+-------------------------------+
 * 0x28	|	       EAX		|
 *	+-------------------------------+----------
 * 0x24	|	      EFLAGS		|	EFLAGS: 标志寄存器字段。任务调出时保存标志寄存器 EFLAGS 的值。
 *	+-------------------------------+----------	处理器自动保存和恢复 EFLAGS。
 * 0x20	|	       EIP		|	EIP: 指令指针字段。CS:EIP 指向任务调出时的代码的执行位置。处理
 *	+-------------------------------+----------  器自动保存和恢复 EIP 寄存器的内容。
 * 0x1C	|	     CR3(PDBR)		|	CR3: 页目录基地址寄存器字段。每个任务都有自己的一套页表，记录着
 *	+-------------------------------+----------  每个任务的线性地址与物理地址的映射关系，每个任务都有一个页
 * 0x18	|		|	SS2	|	  |  目录表，但页目录表在任务创建的时候就已经确定了，且在任务的
 *	+-------------------------------+	  |  生命周期内不会改变。因此，这个位置的 CR3 只在任务创建的时候
 * 0x14	|	       ESP2		|	  |  写入，任务调出时处理器不会重写，任务重新调入时处理器会读取
 *	+-------------------------------+	  |  这个地方的值并加载到 CR3 寄存器中。
 * 0x10	|		|	SS1	|	  -----------------------------------------------------------
 *	+-------------------------------+	SS2 -> ESP0: 特权级 0、1、2 的堆栈指针字段。Linux 内核只用到了
 * 0x0C	|	       ESP1		|		     特权级 0 的 SS0:ESP0，用于指示任务的内核态栈的栈
 *	+-------------------------------+		     底。这个值只在任务创建时设置，任务调入调出时均不
 * 0x08	|		|	SS0	|		     更改，只有在任务从用户态陷入内核态时，处理器会从
 *	+-------------------------------+		     此处获取 SS0:ESP0 的值并加载到 SS:ESP 寄存器中，
 * 0x04	|	       ESP0		|		     作为任务在内核态执行时的栈的初始位置。
 *	+-------------------------------+----------
 * 0x00	|		|   BACK_LINK	|	BACK_LINK: 先前任务链接字段，含有前一个任务的 TSS 段选择符，
 *	+-------------------------------+		   该字段允许任务使用 IRET 指令切换到前一个任务，Linux
 *							   内核并未使用这个功能。
 */
struct tss_struct {
	unsigned short	back_link,__blh;
	unsigned long	esp0;
	unsigned short	ss0,__ss0h;
	unsigned long	esp1;
	unsigned short	ss1,__ss1h;
	unsigned long	esp2;
	unsigned short	ss2,__ss2h;
	unsigned long	cr3;
	unsigned long	eip;
	unsigned long	eflags;
	unsigned long	eax,ecx,edx,ebx;
	unsigned long	esp;
	unsigned long	ebp;
	unsigned long	esi;
	unsigned long	edi;
	unsigned short	es, __esh;
	unsigned short	cs, __csh;
	unsigned short	ss, __ssh;
	unsigned short	ds, __dsh;
	unsigned short	fs, __fsh;
	unsigned short	gs, __gsh;
	unsigned short	ldt, __ldth;
	unsigned short	trace, bitmap;
	unsigned long	io_bitmap[IO_BITMAP_SIZE+1];
	unsigned long	tr;
	unsigned long	cr2, trap_no, error_code;
	union i387_union i387;
};

/*
 *	task_struct: 任务(进程)控制块，每个任务都由一个唯一的 task_struct 结构来管理。
 * 任务和进程的概念是通用的。
 */
struct task_struct {
/* these are hardcoded - don't touch */
	volatile long state;	/* -1 unrunnable, 0 runnable, >0 stopped */
			/*
			 *	state: 任务的状态，0 表示运行或可运行，>0 的状态都是未运行状态。
			 */
	long counter;
			/*
			 *	counter: 任务运行时间片，单位为 tick，时间片减到 0 时必须让出处理器，进而
			 * 调度新的任务执行。后续调度器会在适当时机重新设置 counter 的值。
			 */
	long priority;
			/*
			 *	priority: 任务的优先级，单位为 tick，priority 将参与 counter 的设置，而
			 * counter 值越大，该任务被优先调度的可能性越大，执行的时间也越长，所以这个值称为
			 * 优先级。
			 *
			 *	任务开始运行时 counter = priority。
			 */
	unsigned long signal;
			/*
			 *	signal: 任务的信号位图，每一位代表一种信号，表示任务收到的信号。
			 * 信号值 = 位偏移值 + 1。
			 */
	unsigned long blocked;	/* bitmap of masked signals */
			/*
			 *	blocked: 任务的信号屏蔽码，与信号位图相对应，哪个位置 1，表示任务屏蔽
			 * (不响应)该位对应的那个信号。
			 */
	unsigned long flags;	/* per process flags, defined below */
	int errno;
	int debugreg[8];  /* Hardware debugging registers */
/* various fields */
	struct task_struct *next_task, *prev_task;
			/*
			 *	next_task 和 prev_task 用于将系统中所有的任务链接成一个双向循环链表。
			 * 这个链表将用于遍历系统中所有的任务，遍历时从 init_task 开始。可以称这个
			 * 链表为系统中所有任务的遍历链表，init_task 是这个链表的头结点。
			 */
	struct sigaction sigaction[32];
			/*
			 *	sigaction: 信号执行属性结构，每个信号对应一个这样的结构，该结构中有信号
			 * 对应的操作函数和标志等信息。
			 */
	unsigned long saved_kernel_stack;
	unsigned long kernel_stack_page;
			/*
			 *	saved_kernel_stack:
			 *
			 *	kernel_stack_page: 任务的内核态栈所在物理内存页面的基地址。
			 */
	int exit_code, exit_signal;
			/*
			 *	exit_code: 任务的退出码，表示任务因为什么原因而退出。
			 *
			 *	exit_signal: 任务的退出信号，表示当任务退出时该向其父任务发送一个什么信号。
			 *
			 *	任务的退出指的是任务退出 TASK_RUNNING 状态，不再参与系统调度，而并不仅仅
			 * 表示是任务的彻底消失，所以任务停止运行也属于退出。
			 */
	int elf_executable:1;
	int dumpable:1;
	int swappable:1;
	int did_exec:1;
	unsigned long start_code,end_code,end_data,start_brk,brk,start_stack,start_mmap;
	unsigned long arg_start, arg_end, env_start, env_end;
	int pid,pgrp,session,leader;
	int	groups[NGROUPS];
			/*
			 *	pid: 进程号。
			 *	pgrp: 进程组号。
			 *	session: 会话号。
			 *	leader: 当前进程是否是会话首领进程。
			 *	groups[NGROUPS]: 当前进程所属组号，一个进程可以属于多个进程组，一个
			 * 进程最多可以属于 NGROUPS 个进程组。
			 */
	/* 
	 * pointers to (original) parent process, youngest child, younger sibling,
	 * older sibling, respectively.  (p->father can be replaced with 
	 * p->p_pptr->pid)
	 */
	struct task_struct *p_opptr,*p_pptr, *p_cptr, *p_ysptr, *p_osptr;
			/*
			 *	p_opptr: 指向原始父任务。
			 *	p_pptr: 指向现在父任务。
			 *	p_cptr: 指向最新的子任务。
			 *	p_ysptr: 指向比自己后创建的相邻任务。
			 *	p_osptr: 指向比自己早创建的相邻任务。
			 */
	struct wait_queue *wait_chldexit;	/* for wait4() */
	/*
	 * For ease of programming... Normal sleeps don't need to
	 * keep track of a wait-queue: every task has an entry of its own
	 */
	unsigned short uid,euid,suid;
	unsigned short gid,egid,sgid;
			/*
			 *	uid: 用户 ID，表示任务是由哪个用户创建的。
			 *	euid: 有效用户 ID，表示任务当前属于哪个用户。
			 */
	unsigned long timeout;
			/*
			 *	timeout: 任务的超时定时值，单位为 tick，设置 timeout 时，
			 * timeout = 当前 jiffies + 用户期望的超时时间，当 jiffies >= timeout 时，
			 * 任务的超时定时到期。
			 */
	unsigned long it_real_value, it_prof_value, it_virt_value;
	unsigned long it_real_incr, it_prof_incr, it_virt_incr;
			/*
			 *	这 6 个变量都与任务的间隔定时器有关，间隔定时器的三种类型及原理
			 * 在 time.h 文件中描述。
			 *
			 *	1. ITIMER_REAL: 真实间隔定时器。
			 *	it_real_incr: 真实间隔定时器的间隔计数器的初始值。
			 *	it_real_value: 真实间隔定时器的间隔计数器的当前值。
			 *
			 *	2. ITIMER_VIRTUAL: 虚拟间隔定时器，也称为任务的用户态间隔定时器。
			 *	it_virt_incr: 虚拟间隔定时器的间隔计数器的初始值。
			 *	it_virt_value: 虚拟间隔定时器的间隔计数器的当前值。
			 *
			 *	3. ITIMER_PROF: PROF 间隔定时器。
			 *	it_prof_incr: PROF 间隔定时器的间隔计数器的初始值。
			 *	it_prof_value: PROF 间隔定时器的间隔计数器的当前值。
			 */
	long utime,stime,cutime,cstime,start_time;
			/*
			 *	utime: 任务的用户态运行时间，单位为 tick。
			 *	stime: 任务的内核态运行时间，单位为 tick。
			 *	cutime: 任务的所有子任务的用户态运行时间，单位为 tick。
			 *	cstime: 任务的所有子任务的内核态运行时间，单位为 tick。
			 *	start_time: 任务开始存在的时间，这个时间是相对于系统启动的时间，
			 * 也就是当前 jiffies 的值，单位为 tick。
			 */
	unsigned long min_flt, maj_flt;
	unsigned long cmin_flt, cmaj_flt;
	struct rlimit rlim[RLIM_NLIMITS]; 
	unsigned short used_math;
	unsigned short rss;	/* number of resident pages */
			/*
			 *	rss: 任务常驻内存的页面个数。
			 */
	char comm[16];
	struct vm86_struct * vm86_info;
	unsigned long screen_bitmap;
/* file system info */
	int link_count;
	int tty;		/* -1 if no tty, so it must be signed */
	unsigned short umask;
	struct inode * pwd;
	struct inode * root;
	struct inode * executable;
	struct vm_area_struct * mmap;
	struct shm_desc *shm;
	struct sem_undo *semun;
	struct file * filp[NR_OPEN];
	fd_set close_on_exec;
/* ldt for this task - used by Wine.  If NULL, default_ldt is used */
	struct desc_struct *ldt;
			/*
			 *	ldt: 指向任务自己的 LDT 段，如果 ldt = NULL，则任务将使用系统默认的 LDT 段
			 * default_ldt。LDT 段中的内容由若干个 desc_struct 结构组成，所以这里是指向 desc_struct
			 * 结构的指针。
			 *	任务的 TSS 段在任务的 task_struct 结构中，但任务的 LDT 段在其它地方，这里只是
			 * 指向 LDT 段起始位置的指针。
			 */
/* tss for this task */
	struct tss_struct tss;
			/*
			 *	tss: 任务的 TSS 段，保存任务的上下文信息。
			 */
#ifdef NEW_SWAP
	unsigned long old_maj_flt;	/* old value of maj_flt */
	unsigned long dec_flt;		/* page fault count of the last time */
	unsigned long swap_cnt;		/* number of pages to swap on next pass */
	short swap_table;		/* current page table */
	short swap_page;		/* current page */
#endif NEW_SWAP
	struct vm_area_struct *stk_vma;
};

/*
 * Per process flags
 */
#define PF_ALIGNWARN	0x00000001	/* Print alignment warning msgs */
					/* Not implemented yet, only for 486*/
#define PF_PTRACED	0x00000010	/* set if ptrace (0) has been called. */
#define PF_TRACESYS	0x00000020	/* tracing system calls */

/*
 * cloning flags:
 */
#define CSIGNAL		0x000000ff	/* signal mask to be sent at exit */
#define COPYVM		0x00000100	/* set if VM copy desired (like normal fork()) */
#define COPYFD		0x00000200	/* set if fd's should be copied, not shared (NI) */

/*
 *  INIT_TASK is used to set up the first task table, touch at
 * your own risk!. Base=0, limit=0x1fffff (=2MB)
 */
/*
 *	INIT_TASK: 用于初始化任务 0 的 task_struct 结构，任务 0 是系统中最原始的第一个任务，
 * 也是系统中唯一一个手动初始化的任务，任务 0 将 fork 出任务 1，也就是那个 init 进程，进而
 * fork 出越来越多的进程。
 */
#define INIT_TASK \
/* state etc */	{ 0,15,15,0,0,0,0, \
				/*
				 *	state = TASK_RUNNING。
				 *	counter = 15，任务 0 的初始时间片为 15 个 tick。
				 *	priority = 15，任务 0 的初始优先级数为 15 个 tick。
				 */
/* debugregs */ { 0, },            \
/* schedlink */	&init_task,&init_task, \
				/*
				 *	初始时系统中只有 init_task 一个任务，故 init_task 的 next_task 和
				 * prev_task 都指向自己。此处初始化系统中所有任务的遍历链表的头结点。
				 */
/* signals */	{{ 0, },}, \
/* stack */	0,(unsigned long) &init_kernel_stack, \
				/*
				 *	kernel_stack_page = init_kernel_stack，任务 0 的内核态栈所在物理
				 * 内存页面基地址。init_kernel_stack 数组并不一定在页边界对齐，此处只是用
				 * 内核态栈的起始地址填充。
				 */
/* ec,brk... */	0,0,0,0,0,0,0,0,0,0,0,0,0, \
/* argv.. */	0,0,0,0, \
/* pid etc.. */	0,0,0,0, \
/* suppl grps*/ {NOGROUP,}, \
/* proc links*/ &init_task,&init_task,NULL,NULL,NULL,NULL, \
				/*
				 *	init_task 的原始父任务和现在父任务都是 init_task 自己。
				 */
/* uid etc */	0,0,0,0,0,0, \
/* timeout */	0,0,0,0,0,0,0,0,0,0,0,0, \
/* min_flt */	0,0,0,0, \
/* rlimits */   { {LONG_MAX, LONG_MAX}, {LONG_MAX, LONG_MAX},  \
		  {LONG_MAX, LONG_MAX}, {LONG_MAX, LONG_MAX},  \
		  {       0, LONG_MAX}, {LONG_MAX, LONG_MAX}}, \
/* math */	0, \
/* rss */	2, \
				/*
				 *	rss = 2，任务 0 有 2 个页面常驻内存，分别是任务 0 的用户态栈
				 * user_stack 和任务 0 的内核态栈 init_kernel_stack，这两个数组并不一定
				 * 在页边界对齐。
				 */
/* comm */	"swapper", \
/* vm86_info */	NULL, 0, \
/* fs info */	0,-1,0022,NULL,NULL,NULL,NULL, \
/* ipc */	NULL, NULL, \
/* filp */	{NULL,}, \
/* cloe */	{{ 0, }}, \
/* ldt */	NULL, \
/*tss*/	{0,0, \
	 sizeof(init_kernel_stack) + (long) &init_kernel_stack, KERNEL_DS, 0, \
				/*
				 *	tss.esp0 指向 init_kernel_stack 数组的尾部，也就是任务 0 的内核态栈
				 * 的栈底。
				 *
				 *	tss.ss0 = KERNEL_DS，表示任务 0 的内核态栈位于内核数据段中。
				 */
	 0,0,0,0,0,0, \
	 (long) &swapper_pg_dir, \
				/*
				 *	tss.cr3 指向 swapper_pg_dir，表示任务 0 的页目录表是 swapper_pg_dir。
				 */
	 0,0,0,0,0,0,0,0,0,0, \
	 USER_DS,0,USER_DS,0,USER_DS,0,USER_DS,0,USER_DS,0,USER_DS,0, \
				/*
				 *	6 个段选择符的值都是 USER_DS。
				 */
	 _LDT(0),0, \
				/*
				 *	tss.ldt = _LDT(0): 任务 0 的 LDT 段选择符的值。
				 */
	 0, 0x8000, \
				/*
				 *	tss.trace = 0 禁止调试陷阱。
				 *	tss.bitmap = 0x8000
				 */
/* ioperm */ 	{~0, }, \
	 _TSS(0), 0, 0,0, \
				/*
				 *	tss.tr = _TSS(0): 任务 0 的 TSS 段选择符的值。
				 */
/* 387 state */	{ { 0, }, } \
	} \
}

extern struct task_struct init_task;
extern struct task_struct *task[NR_TASKS];
extern struct task_struct *last_task_used_math;
extern struct task_struct *current;
extern unsigned long volatile jiffies;
extern unsigned long itimer_ticks;
extern unsigned long itimer_next;
extern struct timeval xtime;
extern int need_resched;

/*
 *	CURRENT_TIME: 当前时间，定义为从 1970 年 1 月 1 日 0 时起到现在所经过的秒数。
 */
#define CURRENT_TIME (xtime.tv_sec)

extern void sleep_on(struct wait_queue ** p);
extern void interruptible_sleep_on(struct wait_queue ** p);
extern void wake_up(struct wait_queue ** p);
extern void wake_up_interruptible(struct wait_queue ** p);

extern void notify_parent(struct task_struct * tsk);
extern int send_sig(unsigned long sig,struct task_struct * p,int priv);
extern int in_group_p(gid_t grp);

extern int request_irq(unsigned int irq,void (*handler)(int));
extern void free_irq(unsigned int irq);
extern int irqaction(unsigned int irq,struct sigaction * sa);

/*
 * Entry into gdt where to find first TSS. GDT layout:
 *   0 - nul
 *   1 - kernel code segment
 *   2 - kernel data segment
 *   3 - user code segment
 *   4 - user data segment
 * ...
 *   8 - TSS #0
 *   9 - LDT #0
 *  10 - TSS #1
 *  11 - LDT #1
 */
/*
 *	第一个任务，也就是任务 0 的 TSS 段和 LDT 段的描述符在 GDT 表中的偏移位置。
 */
#define FIRST_TSS_ENTRY 8
#define FIRST_LDT_ENTRY (FIRST_TSS_ENTRY+1)
/*
 *	_TSS(n)，_LDT(n): 根据任务号 n 计算段选择符的值，这个选择符将用于选择 GDT 表中
 * 任务 n 的 TSS 段和 LDT 段的段描述符。
 */
#define _TSS(n) ((((unsigned long) n)<<4)+(FIRST_TSS_ENTRY<<3))
#define _LDT(n) ((((unsigned long) n)<<4)+(FIRST_LDT_ENTRY<<3))
/*
 *	load_TR(n)，load_ldt(n): 将根据任务号 n 得到的段选择符的值加载到 TR 和 LDTR 寄存器中。
 * TR 和 LDTR 中的选择符用于选择 GDT 表中任务 n 对应的 TSS 段和 LDT 段的描述符。
 */
#define load_TR(n) __asm__("ltr %%ax": /* no output */ :"a" (_TSS(n)))
#define load_ldt(n) __asm__("lldt %%ax": /* no output */ :"a" (_LDT(n)))

#define store_TR(n) \
__asm__("str %%ax\n\t" \
	"subl %2,%%eax\n\t" \
	"shrl $4,%%eax" \
	:"=a" (n) \
	:"0" (0),"i" (FIRST_TSS_ENTRY<<3))
/*
 *	switch_to(n) should switch tasks to task nr n, first
 * checking that n isn't the current task, in which case it does nothing.
 * This also clears the TS-flag if the task we switched to has used
 * tha math co-processor latest.
 */
/*
 *	switch_to: 切换到下一个任务运行。
 *
 *	tsk: 指向下一个将要运行的任务的 task_struct 结构。
 */
#define switch_to(tsk) \
__asm__("cmpl %%ecx,_current\n\t" \
	"je 1f\n\t" \
			/*
			 *	如果要切换的下一个任务是当前正在运行的任务 current，则直接向前跳转
			 * 到 "1:" 处退出，什么也不做。
			 */
	"cli\n\t" \
	"xchgl %%ecx,_current\n\t" \
			/*
			 *	1. 关中断，任务切换的流程不允许被打断，这里的关中断和任务被重新调度
			 * 回来时的开中断一一对应。这个中断状态只是当前任务的中断状态，在任务切换时
			 * 会保存下来，不影响其它的任务。
			 *
			 *	2. 设置 current = tsk。ecx 寄存器中保存即将被切换出去的这个任务。
			 */
	"ljmp %0\n\t" \
			/*
			 *	ljmp: 长跳转指令，长跳转至 TSS 段选择符将造成处理器执行任务切换操作，
			 * 当前任务的现场被暂停在下一条指令处(sti)，当前任务下一次被切换回来之后，将
			 * 从下一条指令(sti)处继续向下执行。
			 *
			 *	长跳转指令会将新任务的 16 位 TSS 段选择符加载到任务寄存器 TR 中，这个
			 * 动作将触发两个操作，进而完成任务上下文的切换。
			 *
			 *	1. 根据 TR 中当前任务的 TSS 段选择符在 GDT 表中选择当前任务的 TSS 段
			 * 描述符，根据该描述符找到当前任务的 TSS 段，并将当前任务的现场，也就是当前
			 * 寄存器的信息保存在当前任务的 TSS 段中。
			 *
			 *	2. 根据新任务的 TSS 段选择符在 GDT 表中选择新任务的 TSS 段描述符，根据
			 * 该描述符找到新任务的 TSS 段，并从新任务的 TSS 段中恢复新任务的现场信息到对应
			 * 的寄存器中。
			 */

/***************************************************************************************************/

	"sti\n\t" \
			/*
			 *	原任务重新调度执行时首先打开在之前调出时关闭的中断。
			 */
	"cmpl %%ecx,_last_task_used_math\n\t" \
	"jne 1f\n\t" \
	"clts\n" \
			/*
			 *	如果原任务是最近使用协处理器的任务，即原任务上次使用完协处理器之后一直
			 * 到这个地方都没有其它任务再使用协处理器，则清 CR0 寄存器中的任务切换标志 TS。
			 *
			 *	处理器在每次任务切换时都会设置 CR0 中的 TS 标志，表示任务切换时未保存
			 * 协处理器的内容，当后续有新任务使用协处理器时需要先保存协处理器的状态。
			 */
	"1:" \
			/*
			 *	"1:" --- switch_to 结束。
			 */
	: /* no output */ \
	:"m" (*(((char *)&tsk->tss.tr)-4)), \
	 "c" (tsk) \
			/*
			 *	input:
			 *
			 *	"m" --- 长跳转指令的操作数，代码中通过 %0 访问。
			 *
			 *	长跳转指令 ljmp 的操作数由 4 字节的偏移地址与 2 字节的段选择符组成，其格式为
			 * jmp 16位段选择符 : 32位偏移地址。但在内存中操作数的表示顺序与这里是相反的，所以内存
			 * 中操作数的前 4 字节为 32 位偏移地址，后 2 字节为 16 位段选择符。对于造成任务切换的
			 * 长跳转，4 字节的 32 位偏移地址是没有用的，所以偏移地址可以设置为任意值。
			 *
			 *	tsk->tss.tr 的低 2 字节已经保存的是任务 tsk 的 16 位 TSS 段选择符的值，将指针从
			 * tsk->tss.tr 处向前偏移 4 个字节，这时从指针 ((char *)&tsk->tss.tr)-4 处开始的 6 个
			 * 字节刚好构成 ljmp 的操作数。前 4 个字节的值是一个任意值，作为偏移地址，后 2 个字节，
			 * 也就是 tsk->tss.tr 的低 2 字节是段选择符。
			 *
			 *	"c" --- ecx 寄存器保存的是指向将要执行的下一个任务的 task_struct 结构的指针 tsk。
			 */
	:"cx")
			/*
			 *	change: ecx 寄存器的值会被修改。
			 */

#define _set_base(addr,base) \
__asm__("movw %%dx,%0\n\t" \
	"rorl $16,%%edx\n\t" \
	"movb %%dl,%1\n\t" \
	"movb %%dh,%2" \
	: /* no output */ \
	:"m" (*((addr)+2)), \
	 "m" (*((addr)+4)), \
	 "m" (*((addr)+7)), \
	 "d" (base) \
	:"dx")

#define _set_limit(addr,limit) \
__asm__("movw %%dx,%0\n\t" \
	"rorl $16,%%edx\n\t" \
	"movb %1,%%dh\n\t" \
	"andb $0xf0,%%dh\n\t" \
	"orb %%dh,%%dl\n\t" \
	"movb %%dl,%1" \
	: /* no output */ \
	:"m" (*(addr)), \
	 "m" (*((addr)+6)), \
	 "d" (limit) \
	:"dx")

#define set_base(ldt,base) _set_base( ((char *)&(ldt)) , base )
#define set_limit(ldt,limit) _set_limit( ((char *)&(ldt)) , (limit-1)>>12 )

/*
 * The wait-queues are circular lists, and you have to be *very* sure
 * to keep them correct. Use only these two functions to add/remove
 * entries in the queues.
 */
extern inline void add_wait_queue(struct wait_queue ** p, struct wait_queue * wait)
{
	unsigned long flags;

#ifdef DEBUG
	if (wait->next) {
		unsigned long pc;
		__asm__ __volatile__("call 1f\n"
			"1:\tpopl %0":"=r" (pc));
		printk("add_wait_queue (%08x): wait->next = %08x\n",pc,(unsigned long) wait->next);
	}
#endif
	save_flags(flags);
	cli();
	if (!*p) {
		wait->next = wait;
		*p = wait;
	} else {
		wait->next = (*p)->next;
		(*p)->next = wait;
	}
	restore_flags(flags);
}

extern inline void remove_wait_queue(struct wait_queue ** p, struct wait_queue * wait)
{
	unsigned long flags;
	struct wait_queue * tmp;
#ifdef DEBUG
	unsigned long ok = 0;
#endif

	save_flags(flags);
	cli();
	if ((*p == wait) &&
#ifdef DEBUG
	    (ok = 1) &&
#endif
	    ((*p = wait->next) == wait)) {
		*p = NULL;
	} else {
		tmp = wait;
		while (tmp->next != wait) {
			tmp = tmp->next;
#ifdef DEBUG
			if (tmp == *p)
				ok = 1;
#endif
		}
		tmp->next = wait->next;
	}
	wait->next = NULL;
	restore_flags(flags);
#ifdef DEBUG
	if (!ok) {
		printk("removed wait_queue not on list.\n");
		printk("list = %08x, queue = %08x\n",(unsigned long) p, (unsigned long) wait);
		__asm__("call 1f\n1:\tpopl %0":"=r" (ok));
		printk("eip = %08x\n",ok);
	}
#endif
}

extern inline void select_wait(struct wait_queue ** wait_address, select_table * p)
{
	struct select_table_entry * entry;

	if (!p || !wait_address)
		return;
	if (p->nr >= __MAX_SELECT_TABLE_ENTRIES)
		return;
 	entry = p->entry + p->nr;
	entry->wait_address = wait_address;
	entry->wait.task = current;
	entry->wait.next = NULL;
	add_wait_queue(wait_address,&entry->wait);
	p->nr++;
}

extern void __down(struct semaphore * sem);

extern inline void down(struct semaphore * sem)
{
	if (sem->count <= 0)
		__down(sem);
	sem->count--;
}

extern inline void up(struct semaphore * sem)
{
	sem->count++;
	wake_up(&sem->wait);
}	

static inline unsigned long _get_base(char * addr)
{
	unsigned long __base;
	__asm__("movb %3,%%dh\n\t"
		"movb %2,%%dl\n\t"
		"shll $16,%%edx\n\t"
		"movw %1,%%dx"
		:"=&d" (__base)
		:"m" (*((addr)+2)),
		 "m" (*((addr)+4)),
		 "m" (*((addr)+7)));
	return __base;
}

#define get_base(ldt) _get_base( ((char *)&(ldt)) )

static inline unsigned long get_limit(unsigned long segment)
{
	unsigned long __limit;
	__asm__("lsll %1,%0"
		:"=r" (__limit):"r" (segment));
	return __limit+1;
}

/*
 *	REMOVE_LINKS: 删除任务的链接关系，将任务 p 从两个链表中删除。
 *
 *	1. 将 p 从系统中所有任务的遍历链表中删除，删除后这个任务将不再属于系统中所有任务中
 * 的一员，遍历任务时将不会再访问到这个任务。
 *
 *	2. 将 p 从其现在父任务(p_pptr)与所有子任务组成的链表中删除，删除后现在父任务将不再
 * 有这个子任务，现在父任务的其它子任务将不再有这个兄弟任务。
 */
#define REMOVE_LINKS(p) do { unsigned long flags; \
	save_flags(flags) ; cli(); \
	(p)->next_task->prev_task = (p)->prev_task; \
	(p)->prev_task->next_task = (p)->next_task; \
	restore_flags(flags); \
	if ((p)->p_osptr) \
		(p)->p_osptr->p_ysptr = (p)->p_ysptr; \
	if ((p)->p_ysptr) \
		(p)->p_ysptr->p_osptr = (p)->p_osptr; \
	else \
		(p)->p_pptr->p_cptr = (p)->p_osptr; \
	} while (0)

/*
 *	SET_LINKS: 设置任务的链接关系，将任务 p 链接到两个链表中。
 *
 *	1. 将 p 插入到系统中所有任务的遍历链表中，其中 init_task 是这个链表的头结点，插入
 * 时采用头插法插入到 init_task 的后面。插入后 p 将正式成为系统中所有任务中的一员。
 *
 *	2. 将 p 作为其现在父任务(p_pptr)的最新子任务插入到现在父任务与其它子任务组成的链表
 * 中。插入后 p 将正式成为其现在父任务的所有子任务中的一员。
 */
#define SET_LINKS(p) do { unsigned long flags; \
	save_flags(flags); cli(); \
	(p)->next_task = &init_task; \
	(p)->prev_task = init_task.prev_task; \
	init_task.prev_task->next_task = (p); \
	init_task.prev_task = (p); \
	restore_flags(flags); \
	(p)->p_ysptr = NULL; \
	if (((p)->p_osptr = (p)->p_pptr->p_cptr) != NULL) \
		(p)->p_osptr->p_ysptr = p; \
	(p)->p_pptr->p_cptr = p; \
	} while (0)

/*
 *	for_each_task: 从 init_task 开始遍历系统中除 init_task 以外的所有任务。
 */
#define for_each_task(p) \
	for (p = &init_task ; (p = p->next_task) != &init_task ; )

/*
 * This is the ldt that every process will get unless we need
 * something other than this.
 */
extern struct desc_struct default_ldt;

/* This special macro can be used to load a debugging register */

#define loaddebug(register) \
		__asm__("movl %0,%%edx\n\t" \
			"movl %%edx,%%db" #register "\n\t" \
			: /* no output */ \
			:"m" (current->debugreg[register]) \
			:"dx");

#endif
