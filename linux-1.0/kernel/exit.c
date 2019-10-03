/*
 *  linux/kernel/exit.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#define DEBUG_PROC_TREE

#include <linux/wait.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/resource.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/malloc.h>

#include <asm/segment.h>
extern void shm_exit (void);
extern void sem_exit (void);

int getrusage(struct task_struct *, int, struct rusage *);

/*
 *	generate: 为任务 p 生成信号 sig。信号一旦生成，则表示信号发送成功。
 */
static int generate(unsigned long sig, struct task_struct * p)
{
	unsigned long mask = 1 << (sig-1);		/* 信号对应的信号位图 */
	struct sigaction * sa = sig + p->sigaction - 1;	/* 信号对应的 sigaction 结构 */

	/* always generate signals for traced processes ??? */
	if (p->flags & PF_PTRACED) {
		p->signal |= mask;
		return 1;
	}
			/*
			 *	如果任务 p 是被跟踪的任务，则不管什么信号，都发送给它。
			 */
	/* don't bother with ignored signals (but SIGCHLD is special) */
	if (sa->sa_handler == SIG_IGN && sig != SIGCHLD)
		return 0;
			/*
			 *	如果任务 p 对信号 sig 的处理是忽略，那么就没有向任务 p 发送 sig 信号的必要了。
			 * 但是 SIGCHLD 信号比较特殊，具体在 check_pending 中有说明。
			 */
	/* some signals are ignored by default.. (but SIGCONT already did its deed) */
	if ((sa->sa_handler == SIG_DFL) &&
	    (sig == SIGCONT || sig == SIGCHLD || sig == SIGWINCH))
		return 0;
			/*
			 *	这 3 个信号的默认处理是忽略，就没必要再发送了。
			 */
	p->signal |= mask;
			/* 向任务 p 写入信号 sig，信号发送成功 */
	return 1;
}

/*
 *	send_sig: 当前任务 current 向任务 p 发送信号 sig，权限为 priv。
 *
 *	priv: 是否强制发送信号。priv == 1 表示强制发送信号，不需要考虑任务的用户属性或级别。
 * priv == 0 表示不强制发送信号，发送前需要判断当前任务是否有向任务 p 发送信号的权利。
 */
int send_sig(unsigned long sig,struct task_struct * p,int priv)
{
	if (!p || sig > 32)
		return -EINVAL;
			/* 参数无效 */
	if (!priv && ((sig != SIGCONT) || (current->session != p->session)) &&
	    (current->euid != p->euid) && (current->uid != p->uid) && !suser())
		return -EPERM;
			/*
			 *	1. 不强制发送信号。
			 *	2. 要发送的信号不是 SIGCONT 或 当前任务与任务 p 不在同一个会话中。
			 *	3. 当前任务与任务 p 现在不属于同一个用户。
			 *	4. 当前任务与任务 p 不是同一个用户创建的。
			 *	5. 当前任务所属用户不是超级用户。
			 *
			 *	以上条件均成立，则说明当前任务 current 无权向任务 p 发送信号。
			 */
	if (!sig)
		return 0;
			/* 信号值从 1 开始 */

	/*
	 *	if:	SIGKILL --- 杀死任务。
	 *		SIGCONT --- 让处于停止状态的任务恢复运行。
	 */
	if ((sig == SIGKILL) || (sig == SIGCONT)) {
		if (p->state == TASK_STOPPED)
			p->state = TASK_RUNNING;
				/*
				 *	系统只能处理当前正在运行的任务的信号，因此对于处于停止状态的任务，需要
				 * 将其置为就绪态并使其参与调度进而重新运行。也就是说即便要杀死任务，也要让它
				 * 先运行起来，然后再自杀。
				 *
				 *	处于可中断睡眠状态的任务会在调度程序中唤醒。处于不可中断睡眠状态的任务
				 * 不能被信号唤醒，只能被 wake_up 显示唤醒。
				 */
		p->exit_code = 0;
		p->signal &= ~( (1<<(SIGSTOP-1)) | (1<<(SIGTSTP-1)) |
				(1<<(SIGTTIN-1)) | (1<<(SIGTTOU-1)) );
				/*
				 *	1. 任务已经不在退出运行的状态了，故需要复位任务的退出码。
				 *
				 *	2. 去除任务已经收到的但还未处理的会导致任务进入停止状态的信号。因为
				 * 处理这些信号时会让任务重新进入停止状态，与要发送的信号冲突。
				 */
	}

	/* Depends on order SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU */
	if ((sig >= SIGSTOP) && (sig <= SIGTTOU)) 
		p->signal &= ~(1<<(SIGCONT-1));
			/*
			 *	如果要发送的信号是这 4 个信号中的其中一个，则说明要让接收信号的任务 p 停止
			 * 运行。因此需要将任务 p 已经收到但还未处理的可以让任务继续运行的信号 SIGCONT 去除。
			 */
	/* Actually generate the signal */
	generate(sig,p);
			/* 生成信号，真正发送信号 */
	return 0;
}

void notify_parent(struct task_struct * tsk)
{
	if (tsk->p_pptr == task[1])
		tsk->exit_signal = SIGCHLD;
	send_sig(tsk->exit_signal, tsk->p_pptr, 1);
	wake_up_interruptible(&tsk->p_pptr->wait_chldexit);
}

void release(struct task_struct * p)
{
	int i;

	if (!p)
		return;
	if (p == current) {
		printk("task releasing itself\n");
		return;
	}
	for (i=1 ; i<NR_TASKS ; i++)
		if (task[i] == p) {
			task[i] = NULL;
			REMOVE_LINKS(p);
			free_page(p->kernel_stack_page);
			free_page((long) p);
			return;
		}
	panic("trying to release non-existent task");
}

#ifdef DEBUG_PROC_TREE
/*
 * Check to see if a task_struct pointer is present in the task[] array
 * Return 0 if found, and 1 if not found.
 */
int bad_task_ptr(struct task_struct *p)
{
	int 	i;

	if (!p)
		return 0;
	for (i=0 ; i<NR_TASKS ; i++)
		if (task[i] == p)
			return 0;
	return 1;
}
	
/*
 * This routine scans the pid tree and make sure the rep invarient still
 * holds.  Used for debugging only, since it's very slow....
 *
 * It looks a lot scarier than it really is.... we're doing nothing more
 * than verifying the doubly-linked list found in p_ysptr and p_osptr, 
 * and checking it corresponds with the process tree defined by p_cptr and 
 * p_pptr;
 */
void audit_ptree(void)
{
	int	i;

	for (i=1 ; i<NR_TASKS ; i++) {
		if (!task[i])
			continue;
		if (bad_task_ptr(task[i]->p_pptr))
			printk("Warning, pid %d's parent link is bad\n",
				task[i]->pid);
		if (bad_task_ptr(task[i]->p_cptr))
			printk("Warning, pid %d's child link is bad\n",
				task[i]->pid);
		if (bad_task_ptr(task[i]->p_ysptr))
			printk("Warning, pid %d's ys link is bad\n",
				task[i]->pid);
		if (bad_task_ptr(task[i]->p_osptr))
			printk("Warning, pid %d's os link is bad\n",
				task[i]->pid);
		if (task[i]->p_pptr == task[i])
			printk("Warning, pid %d parent link points to self\n",
				task[i]->pid);
		if (task[i]->p_cptr == task[i])
			printk("Warning, pid %d child link points to self\n",
				task[i]->pid);
		if (task[i]->p_ysptr == task[i])
			printk("Warning, pid %d ys link points to self\n",
				task[i]->pid);
		if (task[i]->p_osptr == task[i])
			printk("Warning, pid %d os link points to self\n",
				task[i]->pid);
		if (task[i]->p_osptr) {
			if (task[i]->p_pptr != task[i]->p_osptr->p_pptr)
				printk(
			"Warning, pid %d older sibling %d parent is %d\n",
				task[i]->pid, task[i]->p_osptr->pid,
				task[i]->p_osptr->p_pptr->pid);
			if (task[i]->p_osptr->p_ysptr != task[i])
				printk(
		"Warning, pid %d older sibling %d has mismatched ys link\n",
				task[i]->pid, task[i]->p_osptr->pid);
		}
		if (task[i]->p_ysptr) {
			if (task[i]->p_pptr != task[i]->p_ysptr->p_pptr)
				printk(
			"Warning, pid %d younger sibling %d parent is %d\n",
				task[i]->pid, task[i]->p_osptr->pid,
				task[i]->p_osptr->p_pptr->pid);
			if (task[i]->p_ysptr->p_osptr != task[i])
				printk(
		"Warning, pid %d younger sibling %d has mismatched os link\n",
				task[i]->pid, task[i]->p_ysptr->pid);
		}
		if (task[i]->p_cptr) {
			if (task[i]->p_cptr->p_pptr != task[i])
				printk(
			"Warning, pid %d youngest child %d has mismatched parent link\n",
				task[i]->pid, task[i]->p_cptr->pid);
			if (task[i]->p_cptr->p_ysptr)
				printk(
			"Warning, pid %d youngest child %d has non-NULL ys link\n",
				task[i]->pid, task[i]->p_cptr->pid);
		}
	}
}
#endif /* DEBUG_PROC_TREE */

/*
 * This checks not only the pgrp, but falls back on the pid if no
 * satisfactory prgp is found. I dunno - gdb doesn't work correctly
 * without this...
 */
int session_of_pgrp(int pgrp)
{
	struct task_struct *p;
	int fallback;

	fallback = -1;
	for_each_task(p) {
 		if (p->session <= 0)
 			continue;
		if (p->pgrp == pgrp)
			return p->session;
		if (p->pid == pgrp)
			fallback = p->session;
	}
	return fallback;
}

/*
 * kill_pg() sends a signal to a process group: this is what the tty
 * control characters do (^C, ^Z etc)
 */
/*
 *	kill_pg: 向组号为 pgrp 的进程组中的所有进程发送信号 sig，权限为 priv。
 */
int kill_pg(int pgrp, int sig, int priv)
{
	struct task_struct *p;
	int err,retval = -ESRCH;
	int found = 0;

	if (sig<0 || sig>32 || pgrp<=0)
		return -EINVAL;

	/*
	 *	遍历系统中除 init_task 以外的所有任务来查找组 pgrp 中的所有进程。
	 */
	for_each_task(p) {
		if (p->pgrp == pgrp) {
			if ((err = send_sig(sig,p,priv)) != 0)
				retval = err;
			else
				found++;
		}
				/*
				 *	进程的组号与给定的组号 pgrp 相同，则向进程发送信号 sig。
				 */
	}
	return(found ? 0 : retval);
			/*
			 *	1. 如果组中没有进程，则返回 0。
			 *
			 *	2. 如果组中有进程，但所有进程的信号均发送失败，则返回发送失败的错误码。
			 *
			 *	3. 如果组中有进程，且至少有一个进程的信号发送成功，则返回最终信号发送成功的
			 * 进程的个数。
			 */
}

/*
 * kill_sl() sends a signal to the session leader: this is used
 * to send SIGHUP to the controlling process of a terminal when
 * the connection is lost.
 */
/*
 *	kill_sl: 向会话号为 sess 的会话中的首领进程发送信号 sig，权限为 priv。
 */
int kill_sl(int sess, int sig, int priv)
{
	struct task_struct *p;
	int err,retval = -ESRCH;
	int found = 0;

	if (sig<0 || sig>32 || sess<=0)
		return -EINVAL;
	/* 遍历系统中除 init_task 以外的所有任务来查找会话号为 sess 的会话中的首领进程 */
	for_each_task(p) {
		if (p->session == sess && p->leader) {
			if ((err = send_sig(sig,p,priv)) != 0)
				retval = err;
			else
				found++;
		}
	}
	return(found ? 0 : retval);
}

/*
 *	kill_proc: 向进程号为 pid 的进程发送信号 sig，权限为 priv。
 */
int kill_proc(int pid, int sig, int priv)
{
 	struct task_struct *p;

	if (sig<0 || sig>32)
		return -EINVAL;
	/* 遍历系统中除 init_task 以外的所有任务来查找进程号为 pid 的进程 */
	for_each_task(p) {
		if (p && p->pid == pid)
			return send_sig(sig,p,priv);
	}
	return(-ESRCH);
}

/*
 * POSIX specifies that kill(-1,sig) is unspecified, but what we have
 * is probably wrong.  Should make it like BSD or SYSV.
 */
/*
 *	sys_kill: 系统调用 kill 对应的系统调用处理函数。用于向任何进程或进程组发送
 * 任何信号，而并非只是杀死进程。
 *
 *	参数 pid 是进程号，sig 是要发送的信号，根据 pid 的不同，有以下几种情况:
 *
 *	1. pid > 0: 则信号 sig 将被发送给进程号是 pid 的进程。
 *
 *	2. pid == 0: 则信号 sig 将被发送给当前进程所属的进程组中的所有进程。
 *
 *	3. pid == -1: 则信号 sig 将被发送给系统中除 0 号进程和 1 号进程及当前进程以外的所有进程。
 *
 *	4. pid < -1: 则信号 sig 将被发送给进程组 -pid 中的所有进程。
 */
asmlinkage int sys_kill(int pid,int sig)
{
	int err, retval = 0, count = 0;

	if (!pid)
		return(kill_pg(current->pgrp,sig,0));
	if (pid == -1) {
		struct task_struct * p;
		for_each_task(p) {
			/* for_each_task 过滤掉 0 号进程，这里过滤掉 1 号进程和当前进程 */
			if (p->pid > 1 && p != current) {
				++count;
				if ((err = send_sig(sig,p,0)) != -EPERM)
					retval = err;
			}
		}
		return(count ? retval : -ESRCH);
	}
	if (pid < 0) 
		return(kill_pg(-pid,sig,0));	/* pid < -1 */
	/* Normal kill */
	return(kill_proc(pid,sig,0));		/* pid > 0 */
}

/*
 * Determine if a process group is "orphaned", according to the POSIX
 * definition in 2.2.2.52.  Orphaned process groups are not to be affected
 * by terminal-generated stop signals.  Newly orphaned process groups are 
 * to receive a SIGHUP and a SIGCONT.
 * 
 * "I ask you, have you ever known what it is to be an orphan?"
 */
int is_orphaned_pgrp(int pgrp)
{
	struct task_struct *p;

	for_each_task(p) {
		if ((p->pgrp != pgrp) || 
		    (p->state == TASK_ZOMBIE) ||
		    (p->p_pptr->pid == 1))
			continue;
		if ((p->p_pptr->pgrp != pgrp) &&
		    (p->p_pptr->session == p->session))
			return 0;
	}
	return(1);	/* (sighing) "Often!" */
}

static int has_stopped_jobs(int pgrp)
{
	struct task_struct * p;

	for_each_task(p) {
		if (p->pgrp != pgrp)
			continue;
		if (p->state == TASK_STOPPED)
			return(1);
	}
	return(0);
}

static void forget_original_parent(struct task_struct * father)
{
	struct task_struct * p;

	for_each_task(p) {
		if (p->p_opptr == father)
			if (task[1])
				p->p_opptr = task[1];
			else
				p->p_opptr = task[0];
	}
}

NORET_TYPE void do_exit(long code)
{
	struct task_struct *p;
	int i;

fake_volatile:
	if (current->semun)
		sem_exit();
	if (current->shm)
		shm_exit();
	free_page_tables(current);
	for (i=0 ; i<NR_OPEN ; i++)
		if (current->filp[i])
			sys_close(i);
	forget_original_parent(current);
	iput(current->pwd);
	current->pwd = NULL;
	iput(current->root);
	current->root = NULL;
	iput(current->executable);
	current->executable = NULL;
	/* Release all of the old mmap stuff. */
	
	{
		struct vm_area_struct * mpnt, *mpnt1;
		mpnt = current->mmap;
		current->mmap = NULL;
		while (mpnt) {
			mpnt1 = mpnt->vm_next;
			if (mpnt->vm_ops && mpnt->vm_ops->close)
				mpnt->vm_ops->close(mpnt);
			kfree(mpnt);
			mpnt = mpnt1;
		}
	}

	if (current->ldt) {
		vfree(current->ldt);
		current->ldt = NULL;
		for (i=1 ; i<NR_TASKS ; i++) {
			if (task[i] == current) {
				set_ldt_desc(gdt+(i<<1)+FIRST_LDT_ENTRY, &default_ldt, 1);
				load_ldt(i);
			}
		}
	}

	current->state = TASK_ZOMBIE;
	current->exit_code = code;
	current->rss = 0;
	/* 
	 * Check to see if any process groups have become orphaned
	 * as a result of our exiting, and if they have any stopped
	 * jobs, send them a SIGUP and then a SIGCONT.  (POSIX 3.2.2.2)
	 *
	 * Case i: Our father is in a different pgrp than we are
	 * and we were the only connection outside, so our pgrp
	 * is about to become orphaned.
 	 */
	if ((current->p_pptr->pgrp != current->pgrp) &&
	    (current->p_pptr->session == current->session) &&
	    is_orphaned_pgrp(current->pgrp) &&
	    has_stopped_jobs(current->pgrp)) {
		kill_pg(current->pgrp,SIGHUP,1);
		kill_pg(current->pgrp,SIGCONT,1);
	}
	/* Let father know we died */
	notify_parent(current);
	
	/*
	 * This loop does two things:
	 * 
  	 * A.  Make init inherit all the child processes
	 * B.  Check to see if any process groups have become orphaned
	 *	as a result of our exiting, and if they have any stopped
	 *	jobs, send them a SIGHUP and then a SIGCONT.  (POSIX 3.2.2.2)
	 */
	while ((p = current->p_cptr) != NULL) {
		current->p_cptr = p->p_osptr;
		p->p_ysptr = NULL;
		p->flags &= ~(PF_PTRACED|PF_TRACESYS);
		if (task[1] && task[1] != current)
			p->p_pptr = task[1];
		else
			p->p_pptr = task[0];
		p->p_osptr = p->p_pptr->p_cptr;
		p->p_osptr->p_ysptr = p;
		p->p_pptr->p_cptr = p;
		if (p->state == TASK_ZOMBIE)
			notify_parent(p);
		/*
		 * process group orphan check
		 * Case ii: Our child is in a different pgrp 
		 * than we are, and it was the only connection
		 * outside, so the child pgrp is now orphaned.
		 */
		if ((p->pgrp != current->pgrp) &&
		    (p->session == current->session) &&
		    is_orphaned_pgrp(p->pgrp) &&
		    has_stopped_jobs(p->pgrp)) {
			kill_pg(p->pgrp,SIGHUP,1);
			kill_pg(p->pgrp,SIGCONT,1);
		}
	}
	if (current->leader)
		disassociate_ctty(1);
	if (last_task_used_math == current)
		last_task_used_math = NULL;
#ifdef DEBUG_PROC_TREE
	audit_ptree();
#endif
	schedule();
/*
 * In order to get rid of the "volatile function does return" message
 * I did this little loop that confuses gcc to think do_exit really
 * is volatile. In fact it's schedule() that is volatile in some
 * circumstances: when current->state = ZOMBIE, schedule() never
 * returns.
 *
 * In fact the natural way to do all this is to have the label and the
 * goto right after each other, but I put the fake_volatile label at
 * the start of the function just in case something /really/ bad
 * happens, and the schedule returns. This way we can try again. I'm
 * not paranoid: it's just that everybody is out to get me.
 */
	goto fake_volatile;
}

asmlinkage int sys_exit(int error_code)
{
	do_exit((error_code&0xff)<<8);
}

/*
 *	sys_wait4: 系统调用 wait4 对应的系统调用处理函数，用于等待指定的子任务退出(终止)，
 * 当指定的子任务退出时将对其占有的资源进行回收，最终使其彻底消失。
 *
 *	1. 一个任务彻底消失会有两个阶段: 第一个阶段是任务自己退出(终止)阶段，在这个阶段里
 * 将由任务自己来释放它所占有的大部分资源，只保留一小部分资源，进而终止执行，变成僵尸态，
 * 然后等待其父任务来回收。第二阶段是父任务回收阶段，在这个阶段里将由父任务来释放它保留的
 * 那一小部分资源，任务所占有的所有资源释放完毕之后，任务将彻底消失。
 *
 *	2. 因此，wait4 系统调用的功能是: 首先等待指定的子任务退出，也就是等待子任务彻底
 * 消失的第一阶段结束，子任务的状态变成僵尸态。然后当指定的子任务退出后执行子任务彻底消失
 * 的第二阶段，回收该子任务，使其彻底消失。
 *
 *	3. 等待子任务退出会有三种情况:
 *	一是 sys_wait4 执行时指定的子任务已经退出了，也就是状态已经变成了 TASK_ZOMBIE，
 * 这时该系统调用期望的状态已经出现，所以会直接回收子任务并退出系统调用。
 *	二是 sys_wait4 执行时指定的子任务还未退出，这时就需要将当前任务挂起来等待，直到
 * 指定的子任务退出或收到中断本系统调用的信号为止。
 *	三是指定的子任务压根就不存在，这时系统调用会直接退出并返回 -ECHILD。
 *
 *	4. 用户指定的 options 和子任务的 TASK_STOPPED 状态会影响 sys_wait4 的执行流程。
 *
 *	5. wait4 系统调用每次只能等待一个子任务退出，如果要等待多个子任务退出，就需要多次
 * 触发 wait4 系统调用。当然，退出的子任务是当前任务 current 的子任务。
 *
 *
 *	入参:	pid --- 子任务对应的进程号。
 *		stat_addr --- 指向当前任务的用户态空间的指针，这个用户态空间用于向用户返回
 *			子任务的退出码。
 *		options --- 等待子任务退出时的选项。
 *		ru --- 指向当前任务的用户态空间的指针，这个用户态空间用于向用户返回子任务的
 *			资源使用信息。
 *
 *	根据参数 pid 的不同，有以下几种情况:
 *
 *	1. pid > 0: 表示当前任务正在等待进程号等于 pid 的子任务退出。
 *
 *	2. pid == 0: 表示当前任务正在等待进程组号等于当前任务进程组号的任何一个子任务退出，
 * 也就是等待与当前任务 current 同组的任何一个子任务退出。
 *
 *	3. pid == -1: 表示当前任务正在等待任何一个子任务退出。
 *
 *	4. pid < -1: 表示当前任务正在等待进程组号等于 -pid 的任何一个子任务退出。
 */
asmlinkage int sys_wait4(pid_t pid,unsigned long * stat_addr, int options, struct rusage * ru)
{
	int flag, retval;
	struct wait_queue wait = { current, NULL };
	struct task_struct *p;

	if (stat_addr) {
		flag = verify_area(VERIFY_WRITE, stat_addr, 4);
		if (flag)
			return flag;
	}
			/*
			 *	验证 stat_addr 指向的用于保存子任务退出状态的用户态空间是否可写。
			 */
	add_wait_queue(&current->wait_chldexit,&wait);
repeat:
	/*
	 *	for: 从当前任务的最年轻的子任务开始扫描当前任务的子任务链表，直到找到指定
	 * 的子任务或扫描完所有的子任务为止。
	 */
	flag=0;
 	for (p = current->p_cptr ; p ; p = p->p_osptr) {
		if (pid>0) {
			if (p->pid != pid)
				continue;
					/* pid > 0: 寻找进程号等于 pid 的子任务 */
		} else if (!pid) {
			if (p->pgrp != current->pgrp)
				continue;
					/* pid == 0: 寻找与父任务位于同一个进程组的任意一个子任务 */
		} else if (pid != -1) {
			if (p->pgrp != -pid)
				continue;
					/* pid < -1: 寻找与 -pid 同组的任意一个子任务 */
		}
					/*
					 *	pid == -1: 任意一个子任务
					 */

		/* wait for cloned processes iff the __WCLONE flag is set */
		if ((p->exit_signal != SIGCHLD) ^ ((options & __WCLONE) != 0))
			continue;
					/*
					 *	对找到的满足条件的一个子任务:
					 *
					 *	1. 如果用户设置了 __WCLONE 标志，且找到的子任务的退出信号为
					 * SIGCHLD，则放弃当前子任务，继续寻找下一个满足条件的子任务。
					 *
					 *	用户设置 __WCLONE 表示只等待通过 clone 方式创建的子任务退出，
					 * 也就是只等待子线程退出，而子线程退出时是不会用 SIGCHLD 信号来通知
					 * 其父任务的。
					 *
					 *	2. 如果用户未设置 __WCLONE 标志，且找到的子任务的退出信号不是
					 * SIGCHLD，则放弃当前子任务，继续寻找下一个满足条件的子任务。
					 *
					 *	用户未设置 __WCLONE 表示只等待通过 fork 方式创建的子任务退出，
					 * 也就是只等待子进程退出，而子进程退出时需要用 SIGCHLD 信号来通知其
					 * 父任务。
					 */

		/*
		 *	flag = 1: 找到了一个满足条件的子任务。
		 */
		flag = 1;
		switch (p->state) {
			/* 选到的子任务处于停止状态 */
			case TASK_STOPPED:
				if (!p->exit_code)
					continue;
				if (!(options & WUNTRACED) && !(p->flags & PF_PTRACED))
					continue;
						/*
						 *	1. 如果子任务的退出码已经被处理了，则继续寻找下一个
						 * 满足条件的子任务，否则就需要判断本系统调用处理函数是否
						 * 需要马上返回。
						 *
						 *	2. 如果用户没有设置 WUNTRACED 标志且子任务的系统调用
						 * 未被跟踪，则表示本系统调用处理函数无需立即返回，因此继续
						 * 寻找其它满足条件的子任务。
						 *
						 *	3. 如果用户设置了 WUNTRACED 标志，则表示当满足条件的
						 * 子任务处于停止状态时，本系统调用处理函数需要马上返回，这时
						 * 代码将继续向下执行并最终退出系统调用处理函数。
						 *	当然，子任务的系统调用被跟踪时也需要马上返回。
						 */
				if (stat_addr)
					put_fs_long((p->exit_code << 8) | 0x7f,
						stat_addr);
				p->exit_code = 0;
				if (ru != NULL)
					getrusage(p, RUSAGE_BOTH, ru);
				retval = p->pid;
				goto end_wait4;
						/*
						 *	1. 将子任务的退出码写入到 stat_addr 指向的用户空间中，
						 * 高字节保存退出码，低字节保存状态信息 0x7F。0x7F 表示子任务
						 * 处于停止状态。
						 *
						 *	2. 子任务的退出码已被处理(返回给了用户)，则需要将退出码
						 * 清除。任务的退出码就是为了告诉别人我为什么退出，现在别人已经
						 * 知道了我为什么退出，那我也就没有必要再保存退出原因了。
						 *
						 *	这里会存在一种情况，当后续再执行本系统调用时，如果该子
						 * 任务的状态没有改变，一直是 TASK_STOPPED，这时就会在最开始的
						 * 退出码判断的地方跳过该子任务。
						 *
						 *	3. 将子任务的资源使用信息写入到 ru 指向的用户空间中。
						 *
						 *	4. 返回子任务对应的进程号。
						 */

			/* 选到的子任务处于僵尸状态，这也是本系统调用期望的状态 */
			case TASK_ZOMBIE:
				current->cutime += p->utime + p->cutime;
				current->cstime += p->stime + p->cstime;
				current->cmin_flt += p->min_flt + p->cmin_flt;
				current->cmaj_flt += p->maj_flt + p->cmaj_flt;
						/*
						 *	1. 子任务在用户态和内核态的运行时间分别累加到父任务中，
						 * 这里的时间还包括子任务的所有子任务的时间。
						 *
						 *	2.
						 */
				if (ru != NULL)
					getrusage(p, RUSAGE_BOTH, ru);
				flag = p->pid;
				if (stat_addr)
					put_fs_long(p->exit_code, stat_addr);
						/*
						 *	1. 将子任务的资源使用信息写入到 ru 指向的用户空间中。
						 *
						 *	2. 暂时保存子任务对应的进程号，用于后面返回该进程号。
						 *
						 *	3. 将子任务的退出码写入到 stat_addr 指向的用户空间中。
						 */
				if (p->p_opptr != p->p_pptr) {
					REMOVE_LINKS(p);
					p->p_pptr = p->p_opptr;
					SET_LINKS(p);
					notify_parent(p);
				} else
					release(p);
#ifdef DEBUG_PROC_TREE
				audit_ptree();
#endif
				retval = flag;
				goto end_wait4;
						/*
						 *	1. 如果子任务的原始父任务与现在父任务(current)不是同
						 * 一个任务: 则先将该子任务从现在父任务与子任务组成的链表中
						 * 删除，然后设置该子任务的现在父任务为原始父任务，再将该子
						 * 任务重新插入到现在父任务(原始父任务)的子任务链表中，最后
						 * 通知该子任务的现在父任务(原始父任务)，由它来回收该子任务。
						 *
						 *	也就是说: 处于 TASK_ZOMBIE 状态的子任务的最终回收应该
						 * 由其原始父任务(创建者)来完成，现在父任务无权回收该子任务。
						 *
						 *	2. 如果子任务的原始父任务和现在父任务是同一个任务，则
						 * 由现在父任务直接回收子任务占有的还没有释放的所有资源，回收
						 * 之后该子任务将彻底消失。
						 *
						 *	3. 最终返回子任务对应的进程号。
						 */
			default:
				continue;
						/*
						 *	满足条件的子任务的状态不符合要求，则继续寻找下一个满足
						 * 条件的子任务。
						 */
		}
	}

	/*
	 *	if: 满足条件的子任务未退出，则需要等待其退出。
	 */
	if (flag) {
		retval = 0;
		if (options & WNOHANG)
			goto end_wait4;
		current->state=TASK_INTERRUPTIBLE;
		schedule();
				/*
				 *	1. WNOHANG 标志要求指定的子任务没有退出(终止)时需立即返回，此时的
				 * 返回值是 0。
				 *
				 *	2. 如果用户没有设置 WNOHANG 标志，则需要将当前任务挂起来等待，直到
				 * 有满足条件的子任务退出，或者当前任务收到了中断本系统调用的信号为止。
				 */
		current->signal &= ~(1<<(SIGCHLD-1));
		retval = -ERESTARTSYS;
		if (current->signal & ~current->blocked)
			goto end_wait4;
		goto repeat;
				/*
				 *	当前任务被再次调度执行，需要检测它被唤醒的原因:
				 *
				 *	1. 如果收到了 SIGCHLD 以外的其它未阻塞的信号，则需要中断本次系统调用，
				 * 转而去处理收到的信号，这时该系统调用的返回值为 -ERESTARTSYS，表示需要重启
				 * 该系统调用，但该系统调用是否能够重启成功还要看信号的 SA_RESTART 标志。
				 *
				 *	2. 否则说明可能是指定的子任务或又有新的子任务退出了，因此需要从头开始
				 * 重新走子任务的检测及处理流程。
				 */
	}

	retval = -ECHILD;
			/*
			 *	没有符合要求的子任务存在，则系统调用直接退出并返回 -ECHILD。
			 */
end_wait4:
	remove_wait_queue(&current->wait_chldexit,&wait);
	return retval;
}

/*
 * sys_waitpid() remains for compatibility. waitpid() should be
 * implemented by calling sys_wait4() from libc.a.
 */
/*
 *	sys_waitpid: 系统调用 waitpid 对应的系统调用处理函数，用于等待指定的子任务退出(终止)
 * 并回收退出的子任务，waitpid 系统调用不获取指定的子任务的资源使用情况。
 */
asmlinkage int sys_waitpid(pid_t pid,unsigned long * stat_addr, int options)
{
	return sys_wait4(pid, stat_addr, options, NULL);
}
