/*
 *  linux/kernel/fork.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 *  'fork.c' contains the help-routines for the 'fork' system call
 * (see also system_call.s).
 * Fork is rather simple, once you get the hang of it, but the memory
 * management can be a bitch. See 'mm/mm.c': 'copy_page_tables()'
 */

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/segment.h>
#include <linux/ptrace.h>
#include <linux/malloc.h>
#include <linux/ldt.h>

#include <asm/segment.h>
#include <asm/system.h>

asmlinkage void ret_from_sys_call(void) __asm__("ret_from_sys_call");

/* These should maybe be in <linux/tasks.h> */

#define MAX_TASKS_PER_USER (NR_TASKS/2)
#define MIN_TASKS_LEFT_FOR_ROOT 4

extern int shm_fork(struct task_struct *, struct task_struct *);

/*
 *	last_pid: 进程号，初始值为 0，但进程号从 1 开始，进程号的有效范围为 1 - 32767，循环使用。
 */
long last_pid=0;

/*
 *	find_empty_process: 这个函数有两个功能，一是为新进程取得不重复的进程号 last_pid，二是为
 * 新进程寻找一个任务号，并返回找到的任务号。
 */
static int find_empty_process(void)
{
	int free_task;
	int i, tasks_free;
	int this_user_tasks;

repeat:
	if ((++last_pid) & 0xffff8000)
		last_pid=1;
			/*
			 *	用 ++last_pid 新分配一个进程号，进程号的有效范围为 1 - 32767。
			 */
	this_user_tasks = 0;
	tasks_free = 0;
	free_task = -EAGAIN;

		/*
		 *	扫描整个 task 数组，查看 task 数组中是否有空闲的元素，并检测新分配出的
		 * 进程号是否可用。
		 */
	i = NR_TASKS;
	while (--i > 0) {
		if (!task[i]) {
			free_task = i;
			tasks_free++;
			continue;
		}
				/*
				 *	task 数组中的元素空闲，每次分配出去的任务号总是空闲任务号中最小
				 * 的那个任务号。
				 */
		if (task[i]->uid == current->uid)
			this_user_tasks++;
				/*
				 *	task[i] 所指示的任务与当前正在运行的任务属于同一个用户
				 */
		if (task[i]->pid == last_pid || task[i]->pgrp == last_pid ||
		    task[i]->session == last_pid)
			goto repeat;
				/*
				 *	进程号已被某一个任务占用，则需重新申请进程号并重新检测进程号是否可用。
				 */
	}
	if (tasks_free <= MIN_TASKS_LEFT_FOR_ROOT ||
	    this_user_tasks > MAX_TASKS_PER_USER)
		if (current->uid)
			return -EAGAIN;
				/*
				 *	系统中空闲的任务号已经很少了，或者与当前正在运行的任务属于同一个用户
				 * 的任务已经很多了。在这种情况下，不允许再为当前用户再创建任务了。
				 */
	return free_task;
			/*
			 *	返回空闲的任务号，进程号不需要返回，由 last_pid 给出。如果已经没有空闲的任务号
			 * 或不允许再创建任务了，则返回 -EAGAIN。
			 */
}

static struct file * copy_fd(struct file * old_file)
{
	struct file * new_file = get_empty_filp();
	int error;

	if (new_file) {
		memcpy(new_file,old_file,sizeof(struct file));
		new_file->f_count = 1;
		if (new_file->f_inode)
			new_file->f_inode->i_count++;
		if (new_file->f_op && new_file->f_op->open) {
			error = new_file->f_op->open(new_file->f_inode,new_file);
			if (error) {
				iput(new_file->f_inode);
				new_file->f_count = 0;
				new_file = NULL;
			}
		}
	}
	return new_file;
}

int dup_mmap(struct task_struct * tsk)
{
	struct vm_area_struct * mpnt, **p, *tmp;

	tsk->mmap = NULL;
	tsk->stk_vma = NULL;
	p = &tsk->mmap;
	for (mpnt = current->mmap ; mpnt ; mpnt = mpnt->vm_next) {
		tmp = (struct vm_area_struct *) kmalloc(sizeof(struct vm_area_struct), GFP_KERNEL);
		if (!tmp)
			return -ENOMEM;
		*tmp = *mpnt;
		tmp->vm_task = tsk;
		tmp->vm_next = NULL;
		if (tmp->vm_inode)
			tmp->vm_inode->i_count++;
		*p = tmp;
		p = &tmp->vm_next;
		if (current->stk_vma == mpnt)
			tsk->stk_vma = tmp;
	}
	return 0;
}

/*
 *	IS_CLONE: 判断用户空间触发的系统调用是 fork 还是 clone，这两种情况对线性地址空间的
 * 处理是不一样的。
 *
 *	copy_vm: 根据 clone_flags 的状态，copy 或 clone 线性地址空间。线性地址空间的最终表现
 * 形式是物理地址空间，而线性地址空间与物理地址空间之间的唯一连接就是页表，线性地址空间通过
 * 页表中的映射关系转换为一一对应的物理地址空间。
 *
 *	因此，复制线性地址空间实际上就是复制页表及物理地址空间。
 */
#define IS_CLONE (regs.orig_eax == __NR_clone)
#define copy_vm(p) ((clone_flags & COPYVM)?copy_page_tables(p):clone_page_tables(p))

/*
 *  Ok, this is the main fork-routine. It copies the system process
 * information (task[nr]) and sets up the necessary registers. It
 * also copies the data segment in its entirety.
 */
/*
 *	sys_fork: 系统调用 fork 对应的系统调用处理函数，创建子任务(子进程)，任务和进程
 * 的概念是通用的。
 *
 *	系统调用 clone 也将会执行这个处理函数(sys.h 中有 #define sys_clone sys_fork)，
 * 故 sys_fork 中需要兼容 clone 的处理流程，clone 用于创建子任务(子进程或子线程)。
 *
 *	入参: struct pt_regs，进入系统调用时所有保存下来的寄存器。
 *
 *	返回值: 执行成功时返回子进程的进程号，执行失败时返回 -EAGAIN。
 */
asmlinkage int sys_fork(struct pt_regs regs)
{
	struct pt_regs * childregs;
	struct task_struct *p;
	int i,nr;
	struct file *f;
	unsigned long clone_flags = COPYVM | SIGCHLD;
			/*
			 *	默认的克隆标志，用于 fork 系统调用。如果是 clone 系统调用，则这个标志会在
			 * 后面根据 clone 调用传入的参数重新设置。
			 */

	if(!(p = (struct task_struct*)__get_free_page(GFP_KERNEL)))
		goto bad_fork;
			/*
			 *	获取一页空闲内存页面用于存放子任务的 task_struct 结构，子任务的 task_struct
			 * 结构从内存页面的起始处开始存放。
			 */
	nr = find_empty_process();
	if (nr < 0)
		goto bad_fork_free;
			/*
			 *	获取任务号，nr < 0 表示系统中已经没有空闲的任务号，或者不允许再创建新任务了。
			 */
	task[nr] = p;
	*p = *current;
			/*
			 *	1. task[nr] 指向子任务的 task_struct 结构。
			 *
			 *	2. 将父任务的 task_struct 结构复制给子任务，后续将会对复制后的 task_struct
			 * 结构中的内容做一些修改，作为子任务的任务结构，子任务的 task_struct 结构中没有修改
			 * 的部分将和父任务保持一致。
			 */
	p->did_exec = 0;
			/*  */
	p->kernel_stack_page = 0;
			/*  */
	p->state = TASK_UNINTERRUPTIBLE;
			/*
			 *	子任务的状态置为不可中断睡眠状态，防止子任务在还未初始化完之前被调度执行。
			 */
	p->flags &= ~(PF_PTRACED|PF_TRACESYS);
			/*  */
	p->pid = last_pid;
			/*
			 *	设置子任务对应的进程号(线程号)，注意与任务号的区别。
			 */
	p->swappable = 1;
			/*  */
	p->p_pptr = p->p_opptr = current;
	p->p_cptr = NULL;
	SET_LINKS(p);
			/*
			 *	1. 子任务刚创建时，其原始父任务和现在父任务都是 current，且它暂时没有自己的
			 * 子任务。
			 *
			 *	2. 将刚创建的子任务链接到两个链表中: 一是系统中所有任务的遍历链表中。二是其
			 * 父任务与父任务的其它子任务组成的链表中。
			 */
	p->signal = 0;
			/*
			 *	子任务不继承父任务已经收到的信号。
			 */
	p->it_real_value = p->it_virt_value = p->it_prof_value = 0;
	p->it_real_incr = p->it_virt_incr = p->it_prof_incr = 0;
			/*  */
	p->leader = 0;		/* process leadership doesn't inherit */
			/*
			 *	进程的领导权是不能继承的，但进程组、会话都会继承，即子进程刚创建时与父进程
			 * 有相同的进程组及会话。
			 */
	p->utime = p->stime = 0;
	p->cutime = p->cstime = 0;
			/*
			 *	任务运行的时间相关的统计清 0。
			 */
	p->min_flt = p->maj_flt = 0;
	p->cmin_flt = p->cmaj_flt = 0;
			/*  */
	p->start_time = jiffies;
			/*
			 *	设置子任务开始存在的时间为系统当前的滴答数。
			 */
/*
 * set up new TSS and kernel stack
 */
	if (!(p->kernel_stack_page = __get_free_page(GFP_KERNEL)))
		goto bad_fork_cleanup;
			/*
			 *	获取一页空闲内存页面用于子任务的内核态栈。
			 */
	p->tss.es = KERNEL_DS;
	p->tss.cs = KERNEL_CS;
	p->tss.ss = KERNEL_DS;
	p->tss.ds = KERNEL_DS;
	p->tss.fs = USER_DS;
	p->tss.gs = KERNEL_DS;
	p->tss.ss0 = KERNEL_DS;
	p->tss.esp0 = p->kernel_stack_page + PAGE_SIZE;
			/*
			 *	子任务的段选择符: 这些段选择符将在子任务第一次被调度运行时加载到段选择符
			 * 寄存器中，作为子任务的初始现场。
			 *
			 *	子任务刚开始运行时的位置在信号处理的地方，信号处理属于内核空间，因此:
			 * CS = KERNEL_CS 用于访问子任务的内核代码段，ES = DS = GS = KERNEL_DS 用于访问子任务
			 * 的内核数据段，FS = USER_DS 用于访问子任务的用户数据段。SS = KERNEL_DS 表示子任务
			 * 刚开始运行时使用的栈位于内核数据段中，是子任务的内核态栈。
			 *
			 *	SS0:ESP0 指示子任务的内核态栈的初始位置，在内核态栈所在内存页面的尾部，
			 * 向下生长，SS0 和 ESP0 的值将会在任务从用户态陷入内核态时被处理器自动加载到
			 * SS:ESP 中。
			 */
	p->tss.tr = _TSS(nr);
			/*
			 *	保存子任务的 TSS 段选择符的值，这个值将在任务切换时用到。
			 */
	childregs = ((struct pt_regs *) (p->kernel_stack_page + PAGE_SIZE)) - 1;
	p->tss.esp = (unsigned long) childregs;
	p->tss.eip = (unsigned long) ret_from_sys_call;
	*childregs = regs;
			/*
			 *	esp 和 eip 的值将会在子任务第一次运行时加载到 ESP 和 EIP 寄存器中，用于指示
			 * 子任务第一次运行时的栈指针和代码位置。
			 *
			 *	eip = ret_from_sys_call: 子任务第一次运行时将从 ret_from_sys_call 处，也就是
			 * 信号处理的地方开始执行。
			 *
			 *	为了子任务可以从 ret_from_sys_call 处正常运行，并能正常退出内核态返回到用户态，
			 * 需要将父任务的内核态栈中的寄存器的信息复制到子任务的内核态栈中，并让 esp 指向当前
			 * 栈顶，进而构造出子任务第一次执行时的现场。
			 */
	childregs->eax = 0;
			/*
			 *	子任务内核态栈中 EAX 的位置的值置 0，这个位置保存系统调用的返回值，表示 fork
			 * 或 clone 返回时子任务的返回值为 0。
			 */
	p->tss.back_link = 0;
			/*
			 *	back_link: Linux 内核不使用这个功能。
			 */
	p->tss.eflags = regs.eflags & 0xffffcfff;	/* iopl is always 0 for a new process */
			/*
			 *	子任务继承父任务的标志寄存器的状态，但是不继承父任务的 IOPL(I/O 特权级)，对
			 * 刚创建的子任务，其 I/O 特权级总是 0。
			 */

	/*
	 *	if (IS_CLONE): 如果是 clone 系统调用:
	 *
	 *	clone 系统调用一共需要传递 3 个参数: eax 寄存器用于传递系统调用号 __NR_clone，
	 * ebx 寄存器用于传递子任务的用户态栈指针，ecx 寄存器用于传递 clone 系统调用的标志。
	 *
	 *	1. 传递 clone 系统调用标志的原因: clone 与 fork 两个系统调用共用同一个系统调用
	 * 处理函数 sys_fork，因此 sys_fork 中需要兼容 clone 的分支，而 clone 与 fork 对线性
	 * 地址空间的处理方式有所不同，而 sys_fork 中默认使用的 clone_flag 是为 fork 系统调用
	 * 准备的，所以需要在 clone 系统调用中传入这种标志。
	 *
	 *	2. 传递子任务用户态栈指针的原因: 通过 clone 这种方式创建出来的子任务称之为子
	 * 线程，子任务将和父任务共用同一个线性地址空间，共用同一套页表，进而共用同一套物理
	 * 内存空间。在这种情况下，子任务开始运行并从内核态返回到用户态时，需要使用子任务自己
	 * 的用户态栈。如果不传入子任务的用户态栈指针，那么子任务将会和父任务使用同一个用户态
	 * 栈指针，这样子任务和父任务将操作同一个用户态栈，这一定会出问题。
	 *	线性地址空间中的栈指针相同，物理地址空间中的栈指针也一定相同。
	 *
	 *	clone 也可以创建进程，这时这个参数传 0 即可。
	 *
	 *	3. fork 不需要传入用户态栈指针的原因: 通过 fork 这种方式创建出来的子任务称之为
	 * 子进程，子任务将完整的复制父任务的线性地址空间，这样子任务和父任务就会有各自独立的
	 * 线性地址空间，因此就会有独立的物理内存空间。故子任务返回到用户态时，虽然栈指针的位置
	 * 和父任务相同，但那也仅仅是在不同线性地址空间中的相同地址而已，而物理地址空间中的地址
	 * 一定不相同，所以子任务和父任务使用的是不同的用户态栈。
	 */
	if (IS_CLONE) {
		if (regs.ebx)
			childregs->esp = regs.ebx;
		clone_flags = regs.ecx;
		if (childregs->esp == regs.esp)
			clone_flags |= COPYVM;
	}
			/*
			 *	对 clone 系统调用，有两种情况:
			 *
			 *	1. 如果传入的用户态栈指针为 0 地址，则表示子任务需要复制父任务的线性地址空间，
			 * 这种情况下对线性地址空间的处理就和 fork 一致，实质上就是创建子进程，这种方式创建出
			 * 的子进程与用 fork 创建出的子进程的差别将由传入的 clone_flags 来决定。
			 *
			 *	2. 如果传入了有效的用户态栈指针，则表示子任务与父任务共用同一个线性地址空间，
			 * 这种情况实质上就是创建子线程。这时需要更新子任务返回用户态时的栈指针，将子任务内核
			 * 态栈中的 OLDESP 位置的值替换为 clone 传入的栈指针即可。
			 */

	p->exit_signal = clone_flags & CSIGNAL;
			/*
			 *	设置子任务退出时的信号。这里有三种情况: 如果是用 fork 创建子进程，则子进程的
			 * 退出信号为 SIGCHLD。如果是用 clone 创建子进程，则子进程的退出信号由用户传入。如果
			 * 是用 clone 创建子线程，则子线程的退出信号由用户传入。
			 */
	p->tss.ldt = _LDT(nr);
	if (p->ldt) {
		p->ldt = (struct desc_struct*) vmalloc(LDT_ENTRIES*LDT_ENTRY_SIZE);
		if (p->ldt != NULL)
			memcpy(p->ldt, current->ldt, LDT_ENTRIES*LDT_ENTRY_SIZE);
	}
			/*
			 *	1. 设置子任务的 LDT 段的段选择符。
			 *
			 *	2. 如果父任务有自己的 LDT 段，则子任务需要完整的复制一份父任务的 LDT 段。如果
			 * 没有，则父任务和子任务都将共用系统默认的 LDT 段 default_ldt，就无需再复制了。
			 */
	p->tss.bitmap = offsetof(struct tss_struct,io_bitmap);
	for (i = 0; i < IO_BITMAP_SIZE+1 ; i++) /* IO bitmap is actually SIZE+1 */
		p->tss.io_bitmap[i] = ~0;
			/*
			 *	1. 设置子任务的 TSS 段中的 BIT_MAP 字段的值，该值表示从 TSS 段开始处到 I/O
			 * 许可位图处的 16 位偏移值，实际上就是 TSS 段中的 IO_BITMAP 字段在 tss_struct 结构
			 * 体中的偏移。
			 *
			 *	2. 将子任务的 TSS 段中的 IO_BITMAP 字段的比特位全部置 1，表示所有的 I/O 端口
			 * 子任务暂时都不能访问。
			 */
	if (last_task_used_math == current)
		__asm__("clts ; fnsave %0 ; frstor %0":"=m" (p->tss.i387));
			/*
			 *	如果最近使用数学协处理器的任务是父任务，则父任务的数学协处理器的信息有可能
			 * 还未更新到父任务的 i387 结构中，这时子任务复制的父任务的 i387 结构中的信息有可能
			 * 不是最新的。故此处需要将父任务的数学协处理器的当前最新信息复制给子任务的 i387
			 * 结构，父任务的 i387 结构的信息将在其它地方更新。
			 */
	p->semun = NULL; p->shm = NULL;
			/*  */
	if (copy_vm(p) || shm_fork(current, p))
		goto bad_fork_cleanup;
			/*
			 *	1. 给子任务复制父任务的线性地址空间，线性地址空间的最终表现形式就是物理地址
			 * 空间，这里将会给子任务克隆或复制父任务的页表，物理内存页面将采用共享或写时复制的
			 * 方式。
			 *
			 *	2. TODO:
			 */
	if (clone_flags & COPYFD) {
		for (i=0; i<NR_OPEN;i++)
			if ((f = p->filp[i]) != NULL)
				p->filp[i] = copy_fd(f);
	} else {
		for (i=0; i<NR_OPEN;i++)
			if ((f = p->filp[i]) != NULL)
				f->f_count++;
	}
			/*  */
	if (current->pwd)
		current->pwd->i_count++;
	if (current->root)
		current->root->i_count++;
	if (current->executable)
		current->executable->i_count++;
			/*  */
	dup_mmap(p);
			/*  */
	set_tss_desc(gdt+(nr<<1)+FIRST_TSS_ENTRY,&(p->tss));
	if (p->ldt)
		set_ldt_desc(gdt+(nr<<1)+FIRST_LDT_ENTRY,p->ldt, 512);
	else
		set_ldt_desc(gdt+(nr<<1)+FIRST_LDT_ENTRY,&default_ldt, 1);
			/*
			 *	1. 在 GDT 表中为子任务设置其 TSS 段和 LDT 段的段描述符，该描述符将描述子任务的
			 * TSS 段和 LDT 段的信息(TSS 段和 LDT 段所在物理内存基地址、段大小等)，由子任务的 TSS
			 * 段选择符和 LDT 段选择符来选择对应的描述符。
			 *
			 *	2. 操作系统在 GDT 表中为每一个任务都预留了 LDT 段描述符，但任务有可能会没有 LDT
			 * 段存在。故如果任务有自己的 LDT 段存在，则用自己的 LDT 段的信息来设置描述符，如果任务
			 * 没有自己的 LDT 段存在，则用系统默认的、大家公用的 LDT 段 default_ldt 的信息来设置描
			 * 述符。
			 */

	p->counter = current->counter >> 1;
	p->state = TASK_RUNNING;	/* do this last, just in case */
			/*
			 *	1. 设置子任务刚开始运行时的时间片，为父任务当前时间片的一半。在调度程序中，
			 * counter 的值越大，任务越先被调度到，这里这样设置，是为了让父任务在子任务之前运行。
			 * 但是父任务一定会在子任务之前吗?
			 *
			 *	2. 设置子任务的状态，设置之后子任务将参与系统调度并运行。
			 */
	return p->pid;
			/*
			 *	父任务将返回子任务对应的进程号(线程号)。
			 */
bad_fork_cleanup:
	task[nr] = NULL;
	REMOVE_LINKS(p);
	free_page(p->kernel_stack_page);
bad_fork_free:
	free_page((long) p);
bad_fork:
	return -EAGAIN;
}
