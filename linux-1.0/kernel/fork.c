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
			 *	2. 将父任务的 task_struct 结构复制给子任务，后续将会对复制后的 task_struct
			 * 结构中的内容做一些修改，作为子任务的任务结构。
			 */
	p->did_exec = 0;
	p->kernel_stack_page = 0;
	p->state = TASK_UNINTERRUPTIBLE;
			/*
			 *	子任务的状态置为不可中断睡眠状态，防止子任务在还未初始化完之前被调度执行。
			 */
	p->flags &= ~(PF_PTRACED|PF_TRACESYS);
	p->pid = last_pid;
			/*
			 *	设置子进程(任务)的进程号，注意与任务号的区别。
			 */
	p->swappable = 1;
	p->p_pptr = p->p_opptr = current;
	p->p_cptr = NULL;
			/*
			 *	子任务刚创建时，其原始父任务和现在父任务都是 current，且它暂时没有自己的子任务。
			 */
	SET_LINKS(p);
	p->signal = 0;
			/*
			 *	子任务不继承父任务收到的信号。
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
			 *	设置子任务开始运行的时间为系统当前的滴答数。
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
			 * 返回时子任务的返回值为 0。
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
	if (IS_CLONE) {
		if (regs.ebx)
			childregs->esp = regs.ebx;
		clone_flags = regs.ecx;
		if (childregs->esp == regs.esp)
			clone_flags |= COPYVM;
	}
	p->exit_signal = clone_flags & CSIGNAL;
	p->tss.ldt = _LDT(nr);
	if (p->ldt) {
		p->ldt = (struct desc_struct*) vmalloc(LDT_ENTRIES*LDT_ENTRY_SIZE);
		if (p->ldt != NULL)
			memcpy(p->ldt, current->ldt, LDT_ENTRIES*LDT_ENTRY_SIZE);
	}
	p->tss.bitmap = offsetof(struct tss_struct,io_bitmap);
	for (i = 0; i < IO_BITMAP_SIZE+1 ; i++) /* IO bitmap is actually SIZE+1 */
		p->tss.io_bitmap[i] = ~0;
	if (last_task_used_math == current)
		__asm__("clts ; fnsave %0 ; frstor %0":"=m" (p->tss.i387));
	p->semun = NULL; p->shm = NULL;
	if (copy_vm(p) || shm_fork(current, p))
		goto bad_fork_cleanup;
	if (clone_flags & COPYFD) {
		for (i=0; i<NR_OPEN;i++)
			if ((f = p->filp[i]) != NULL)
				p->filp[i] = copy_fd(f);
	} else {
		for (i=0; i<NR_OPEN;i++)
			if ((f = p->filp[i]) != NULL)
				f->f_count++;
	}
	if (current->pwd)
		current->pwd->i_count++;
	if (current->root)
		current->root->i_count++;
	if (current->executable)
		current->executable->i_count++;
	dup_mmap(p);
	set_tss_desc(gdt+(nr<<1)+FIRST_TSS_ENTRY,&(p->tss));
	if (p->ldt)
		set_ldt_desc(gdt+(nr<<1)+FIRST_LDT_ENTRY,p->ldt, 512);
	else
		set_ldt_desc(gdt+(nr<<1)+FIRST_LDT_ENTRY,&default_ldt, 1);

	p->counter = current->counter >> 1;
	p->state = TASK_RUNNING;	/* do this last, just in case */
	return p->pid;
bad_fork_cleanup:
	task[nr] = NULL;
	REMOVE_LINKS(p);
	free_page(p->kernel_stack_page);
bad_fork_free:
	free_page((long) p);
bad_fork:
	return -EAGAIN;
}
