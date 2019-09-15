/*
 *  linux/kernel/signal.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/wait.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>

#include <asm/segment.h>

/*
 *	_S(nr): 获取信号 nr 对应的信号位图。
 */
#define _S(nr) (1<<((nr)-1))

/*
 *	_BLOCKABLE: 表示可被阻塞的信号，除了 SIGKILL 和 SIGSTOP 以外的所有信号
 * 都可以被阻塞。
 */
#define _BLOCKABLE (~(_S(SIGKILL) | _S(SIGSTOP)))

extern int core_dump(long signr,struct pt_regs * regs);

asmlinkage int do_signal(unsigned long oldmask, struct pt_regs * regs);

struct sigcontext_struct {
	unsigned short gs, __gsh;
	unsigned short fs, __fsh;
	unsigned short es, __esh;
	unsigned short ds, __dsh;
	unsigned long edi;
	unsigned long esi;
	unsigned long ebp;
	unsigned long esp;
	unsigned long ebx;
	unsigned long edx;
	unsigned long ecx;
	unsigned long eax;
	unsigned long trapno;
	unsigned long err;
	unsigned long eip;
	unsigned short cs, __csh;
	unsigned long eflags;
	unsigned long esp_at_signal;
	unsigned short ss, __ssh;
	unsigned long i387;
	unsigned long oldmask;
	unsigned long cr2;
};

/*
 *	sys_sigprocmask: 系统调用 sigprocmask 对应的系统调用处理函数，用于更改当前任务的
 * 阻塞信号集，同时返回当前任务的原阻塞信号集。
 *
 *	入参:	how --- 如何更改的标志，增加、删除、重新设置。
 *		set --- 用于更改当前任务的阻塞信号集，该指针指向的空间位于用户态空间中。
 *		oset --- 用于保存当前任务的原阻塞信号集，该指针指向的空间位于用户态空间中。
 */
asmlinkage int sys_sigprocmask(int how, sigset_t *set, sigset_t *oset)
{
	sigset_t new_set, old_set = current->blocked;
	int error;

	/*
	 *	if: set 可以传 NULL，传 NULL 表示不更改当前任务的阻塞信号集，比如用户只是
	 * 想获取一下当前任务的阻塞信号集而已。
	 */
	if (set) {
		error = verify_area(VERIFY_READ, set, sizeof(sigset_t));
		if (error)
			return error;
		new_set = get_fs_long((unsigned long *) set) & _BLOCKABLE;
				/*
				 *	1. 验证 set 指向的存放阻塞信号集的用户态空间是否可读。
				 *
				 *	2. 将要更改的阻塞信号集从 set 指向的用户空间中读取到 new_set 表示的
				 * 内核空间中，且 SIGKILL 和 SIGSTOP 不能被阻塞。
				 */
		switch (how) {
		case SIG_BLOCK:
			current->blocked |= new_set;
			break;
				/* 在当前任务的原阻塞信号集上新增指定的阻塞信号集 */
		case SIG_UNBLOCK:
			current->blocked &= ~new_set;
			break;
				/* 从当前任务的原阻塞信号集中删除指定的阻塞信号集 */
		case SIG_SETMASK:
			current->blocked = new_set;
			break;
				/* 重设置当前任务的阻塞信号集 */
		default:
			return -EINVAL;
		}
	}

	/*
	 *	if: oset 可以传 NULL，传 NULL 表示用户不想获取当前任务的原阻塞信号集。
	 */
	if (oset) {
		error = verify_area(VERIFY_WRITE, oset, sizeof(sigset_t));
		if (error)
			return error;
		put_fs_long(old_set, (unsigned long *) oset);
	}
			/*
			 *	1. 验证 oset 指向的用于保存当前任务的原阻塞信号集的用户态空间是否可写。
			 *
			 *	2. 将当前任务的原阻塞信号集从 old_set 表示的内核空间中写入到 oset 指向的
			 * 用户空间中。
			 */
	return 0;
}

/*
 *	sys_sgetmask: 系统调用 sgetmask 对应的系统调用处理函数，用于获取当前任务的
 * 信号阻塞码。
 */
asmlinkage int sys_sgetmask(void)
{
	return current->blocked;
}

/*
 *	sys_ssetmask: 系统调用 ssetmask 对应的系统调用处理函数，用于给当前任务设置
 * 新的信号阻塞码，SIGKILL 和 SIGSTOP 不能被阻塞。
 *
 *	入参:	newmask --- 新的信号阻塞码。
 *	返回:	当前任务的原信号阻塞码。
 */
asmlinkage int sys_ssetmask(int newmask)
{
	int old=current->blocked;

	current->blocked = newmask & _BLOCKABLE;
	return old;
}

/*
 *	sys_sigpending: 系统调用 sigpending 对应的系统调用处理函数，用于获取当前任务已经
 * 收到的但被屏蔽的信号，这些信号处于未处理的状态。
 *
 *	入参:	set --- 指向用于保存信号的用户态空间的指针。
 */
asmlinkage int sys_sigpending(sigset_t *set)
{
	int error;
	/* fill in "set" with signals pending but blocked. */
	error = verify_area(VERIFY_WRITE, set, 4);
			/*
			 *	验证 set 指向的用于保存信号的用户态空间是否可写。
			 */
	if (!error)
		put_fs_long(current->blocked & current->signal, (unsigned long *)set);
			/*
			 *	将当前任务已经收到的但被屏蔽的信号写入到 set 指向的用户空间中。
			 */
	return error;
}

/*
 * atomically swap in the new signal mask, and wait for a signal.
 */
asmlinkage int sys_sigsuspend(int restart, unsigned long oldmask, unsigned long set)
{
	unsigned long mask;
	struct pt_regs * regs = (struct pt_regs *) &restart;

	mask = current->blocked;
	current->blocked = set & _BLOCKABLE;
	regs->eax = -EINTR;
	while (1) {
		current->state = TASK_INTERRUPTIBLE;
		schedule();
		if (do_signal(mask,regs))
			return -EINTR;
	}
}

/*
 * POSIX 3.3.1.3:
 *  "Setting a signal action to SIG_IGN for a signal that is pending
 *   shall cause the pending signal to be discarded, whether or not
 *   it is blocked" (but SIGCHLD is unspecified: linux leaves it alone).
 *
 *  "Setting a signal action to SIG_DFL for a signal that is pending
 *   and whose default action is to ignore the signal (for example,
 *   SIGCHLD), shall cause the pending signal to be discarded, whether
 *   or not it is blocked"
 *
 * Note the silly behaviour of SIGCHLD: SIG_IGN means that the signal
 * isn't actually ignored, but does automatic child reaping, while
 * SIG_DFL is explicitly said by POSIX to force the signal to be ignored..
 */
/*
 *	对于已经挂起的信号(信号已产生，但还未处理)，将信号的操作设置为 SIG_IGN 将导致已
 * 挂起的信号被丢弃，无论它是否被阻塞(但 SIGCHLD 信号未指定，Linux 将对其做单独处理)。
 *
 *	对于已经挂起且默认操作是 Ignore (比如 SIGCHLD)的信号，将信号的操作设置为 SIG_DFL
 * 将导致已挂起的信号被丢弃，无论它是否被阻塞。
 *
 *	注意 SIGCHLD 信号的荒唐行为: SIG_IGN 意味着信号实际上没有被忽略，而是进行子任务的
 * 自动回收，而 SIG_DFL 则被 POSIX 明确的说成是强制的忽略信号。
 */

/*
 *	check_pending: 检测并处理信号的挂起状态，在重新设置信号的属性结构以后必须检测并
 * 处理信号的挂起状态。
 */
static void check_pending(int signum)
{
	struct sigaction *p;

	p = signum - 1 + current->sigaction;
	if (p->sa_handler == SIG_IGN) {
		if (signum == SIGCHLD)
			return;
		current->signal &= ~_S(signum);
		return;
	}
			/*
			 *	如果信号 signum 的处理函数被重新设置成了 SIG_IGN，则需要将任务已经收到但还未
			 * 处理的 signum 信号丢弃。
			 *
			 *	特例: SIGCHLD 信号不能被丢弃。
			 */
	if (p->sa_handler == SIG_DFL) {
		if (signum != SIGCONT && signum != SIGCHLD && signum != SIGWINCH)
			return;
		current->signal &= ~_S(signum);
		return;
	}	
			/*
			 *	如果信号 signum 的处理函数被重新设置成了 SIG_DFL，则需要将任务已经收到但还未
			 * 处理的 signum 信号丢弃。
			 *
			 *	特例: SIGCONT、SIGCHLD、SIGWINCH 信号不能被丢弃。
			 */
}

/*
 *	sys_signal: 系统调用 signal 对应的系统调用处理函数，用于捕获一个信号，也就是为指定
 * 的信号安装新的信号句柄(设置新的信号处理函数)。新句柄可以是用户自定义的函数，也可以是
 * SIG_DFL 或 SIG_IGN。
 *
 *	signal 函数不可靠，在某些特殊时刻可能会造成信号丢失，原因是: sys_signal 中会强制
 * 设置 SA_ONESHOT 标志，这会让系统在执行用户自定义的信号处理函数之前先将信号的句柄设置为
 * 默认句柄。同时会设置 SA_NOMASK 标志，这会允许在执行信号处理函数的过程中再次收到该信号。
 *
 *	因此，当信号产生并执行信号的处理函数时，在重新设置信号的处理句柄之前，该信号又再
 * 一次产生，但是此时系统已经把该信号的处理句柄设置成了默认的句柄，在这种情况下就有可能会
 * 造成再次产生的这个信号丢失。
 *
 *	信号丢失只是有可能，并不是一定会丢失，信号丢失的时序如下:
 *	1. 信号产生，系统准备执行用户自定义的信号处理函数，并在此之前将该信号的句柄设置为
 * 默认句柄。
 *	2. 执行用户自定义的处理函数，但还没有为该信号重新设置新的句柄，此时该信号又再一次
 * 产生。
 *	3. 因为某些特殊时序的作用(比如产生了中断等)，任务在没有为该信号重新设置句柄之前再一
 * 次进入内核态，并在退出内核态之前处理第二次收到的该信号。
 *	4. 这时由于之前已经将该信号的句柄设置成了默认值，那么第二次收到的信号就不会执行用户
 * 自定义的信号处理函数，进而造成信号丢失。
 *
 *
 *	入参:	signum --- 指定的信号。
 *		handler --- 新句柄。
 *
 *	返回:	该信号的原句柄。
 */
asmlinkage int sys_signal(int signum, unsigned long handler)
{
	struct sigaction tmp;

	if (signum<1 || signum>32 || signum==SIGKILL || signum==SIGSTOP)
		return -EINVAL;
	if (handler >= TASK_SIZE)
		return -EFAULT;
			/*
			 *	1. 系统最大支持 32 个信号，信号值为 1 - 32。SIGKILL 和 SIGSTOP 这两个信号不
			 * 允许被用户捕获。
			 *
			 *	2. 用户自定义的信号处理函数必须位于任务的用户态空间中。
			 */
	tmp.sa_handler = (void (*)(int)) handler;
	tmp.sa_mask = 0;
	tmp.sa_flags = SA_ONESHOT | SA_NOMASK;
	tmp.sa_restorer = NULL;
	handler = (long) current->sigaction[signum-1].sa_handler;
	current->sigaction[signum-1] = tmp;
			/*
			 *	1. 填充信号对应的 sigaction 结构。sa_mask == 0 表示该信号的处理函数执行期间不
			 * 阻塞其它任何信号。sa_flags = SA_ONESHOT | SA_NOMASK 表示用户自定义的信号处理函数
			 * 执行一次之后就恢复为默认的信号处理函数，并且允许在执行信号处理函数的过程中再次收到
			 * 该信号。
			 *
			 *	2. 保存信号的原句柄。
			 *
			 *	3. 重新设置信号的 sigaction 结构。
			 */
	check_pending(signum);
			/*
			 *	重新设置信号的 sigaction 结构后需检测并处理信号的挂起状态
			 */
	return handler;
			/* signal 系统调用返回信号的原句柄 */
}

/*
 *	sys_sigaction: 系统调用 sigaction 对应的系统调用处理函数，用于捕获一个信号，也就是
 * 为指定的信号安装新的属性结构。
 *
 *	sigaction 与 signal 不同，signal 只能安装信号的句柄，不能更改信号的标志。sigaction
 * 将由用户来设置信号的整个属性结构。
 *
 *	从可靠性来讲，sigaction 一般是可靠的，除非用户设置了 SA_ONESHOT 标志，这时 sigaction
 * 就和 signal 一样，变得不可靠了。
 *
 *
 *	入参:	signum --- 指定的信号。
 *		action --- 指向新属性结构的指针，真正的新属性结构存放在用户空间中。
 *		oldaction --- 用户给出的用于保存原属性结构的指针，该指针指向的空间位于用户空间中。
 *
 *	返回:	成功返回 0，失败返回对应的错误码。
 */
asmlinkage int sys_sigaction(int signum, const struct sigaction * action,
	struct sigaction * oldaction)
{
	struct sigaction new_sa, *p;

	if (signum<1 || signum>32 || signum==SIGKILL || signum==SIGSTOP)
		return -EINVAL;
	p = signum - 1 + current->sigaction;
			/*
			 *	1. 系统最大支持 32 个信号，信号值为 1 - 32。SIGKILL 和 SIGSTOP 这两个信号不
			 * 允许被用户捕获。
			 *
			 *	2. p 指向指定信号对应的 sigaction 结构。
			 */

	/*
	 *	if: 指向新属性结构的指针有效。这个指针可以传 NULL，传 NULL 表示不为信号
	 * 安装新的属性结构。比如用户只是想获取一下信号的属性结构而已。
	 */
	if (action) {
		int err = verify_area(VERIFY_READ, action, sizeof(*action));
		if (err)
			return err;
		memcpy_fromfs(&new_sa, action, sizeof(struct sigaction));
				/*
				 *	1. 验证 action 指向的存放新属性结构的用户态空间是否可读。
				 *
				 *	2. 将信号的新属性结构从 action 指向的用户空间中复制到 new_sa 表示的
				 * 内核空间中。
				 */
		if (new_sa.sa_flags & SA_NOMASK)
			new_sa.sa_mask = 0;
		else {
			new_sa.sa_mask |= _S(signum);
			new_sa.sa_mask &= _BLOCKABLE;
		}
				/*
				 *	1. 如果用户设置了 SA_NOMASK 标志，则说明用户允许在执行信号处理函数的
				 * 过程中再次收到信号(该信号和其它信号都允许)，则将 sa_mask 清 0，表示在执行
				 * 信号处理函数的过程中不阻塞任何信号。
				 *
				 *	2. 如果用户没有设置 SA_NOMASK 标志，则说明用户不想在执行信号处理函数
				 * 的过程中再次收到该信号(其它信号是允许的)，则需要在 sa_mask 中加入该信号，
				 * 表示在执行信号处理函数的过程中阻塞该信号。如果用户在 sa_mask 中还设置了其它
				 * 信号，则同时会阻塞这些信号。
				 */
		if (TASK_SIZE <= (unsigned long) new_sa.sa_handler)
			return -EFAULT;
				/*
				 *	用户自定义的信号处理函数必须位于任务的用户态空间中。
				 */
	}

	/*
	 *	if: 保存原属性结构的指针有效。这个指针可以传 NULL，传 NULL 表示用户不想
	 * 获取信号的原属性结构。
	 */
	if (oldaction) {
		int err = verify_area(VERIFY_WRITE, oldaction, sizeof(*oldaction));
		if (err)
			return err;
		memcpy_tofs(oldaction, p, sizeof(struct sigaction));
				/*
				 *	1. 验证 oldaction 指向的用于保存原属性结构的用户态空间是否可写。
				 *
				 *	2. 将信号的原属性结构从 p 指向的内核空间中复制到 oldaction 指向的
				 * 用户空间中。
				 */
	}

	if (action) {
		*p = new_sa;
		check_pending(signum);
	}
			/*
			 *	1. 为指定信号重新设置新的属性结构。
			 *
			 *	2. 重新设置信号的 sigaction 结构后需检测并处理信号的挂起状态
			 */
	return 0;
}

asmlinkage int sys_waitpid(pid_t pid,unsigned long * stat_addr, int options);

/*
 * This sets regs->esp even though we don't actually use sigstacks yet..
 */
asmlinkage int sys_sigreturn(unsigned long __unused)
{
#define COPY(x) regs->x = context.x
#define COPY_SEG(x) \
if ((context.x & 0xfffc) && (context.x & 3) != 3) goto badframe; COPY(x);
#define COPY_SEG_STRICT(x) \
if (!(context.x & 0xfffc) || (context.x & 3) != 3) goto badframe; COPY(x);
	struct sigcontext_struct context;
	struct pt_regs * regs;

	regs = (struct pt_regs *) &__unused;
	if (verify_area(VERIFY_READ, (void *) regs->esp, sizeof(context)))
		goto badframe;
	memcpy_fromfs(&context,(void *) regs->esp, sizeof(context));
	current->blocked = context.oldmask & _BLOCKABLE;
	COPY_SEG(ds);
	COPY_SEG(es);
	COPY_SEG(fs);
	COPY_SEG(gs);
	COPY_SEG_STRICT(ss);
	COPY_SEG_STRICT(cs);
	COPY(eip);
	COPY(ecx); COPY(edx);
	COPY(ebx);
	COPY(esp); COPY(ebp);
	COPY(edi); COPY(esi);
	regs->eflags &= ~0xCD5;
	regs->eflags |= context.eflags & 0xCD5;
	regs->orig_eax = -1;		/* disable syscall checks */
	return context.eax;
badframe:
	do_exit(SIGSEGV);
}

/*
 * Set up a signal frame... Make the stack look the way iBCS2 expects
 * it to look.
 */
static void setup_frame(struct sigaction * sa, unsigned long ** fp, unsigned long eip,
	struct pt_regs * regs, int signr, unsigned long oldmask)
{
	unsigned long * frame;

#define __CODE ((unsigned long)(frame+24))
#define CODE(x) ((unsigned long *) ((x)+__CODE))
	frame = *fp;
	if (regs->ss != USER_DS)
		frame = (unsigned long *) sa->sa_restorer;
	frame -= 32;
	if (verify_area(VERIFY_WRITE,frame,32*4))
		do_exit(SIGSEGV);
/* set up the "normal" stack seen by the signal handler (iBCS2) */
	put_fs_long(__CODE,frame);
	put_fs_long(signr, frame+1);
	put_fs_long(regs->gs, frame+2);
	put_fs_long(regs->fs, frame+3);
	put_fs_long(regs->es, frame+4);
	put_fs_long(regs->ds, frame+5);
	put_fs_long(regs->edi, frame+6);
	put_fs_long(regs->esi, frame+7);
	put_fs_long(regs->ebp, frame+8);
	put_fs_long((long)*fp, frame+9);
	put_fs_long(regs->ebx, frame+10);
	put_fs_long(regs->edx, frame+11);
	put_fs_long(regs->ecx, frame+12);
	put_fs_long(regs->eax, frame+13);
	put_fs_long(current->tss.trap_no, frame+14);
	put_fs_long(current->tss.error_code, frame+15);
	put_fs_long(eip, frame+16);
	put_fs_long(regs->cs, frame+17);
	put_fs_long(regs->eflags, frame+18);
	put_fs_long(regs->esp, frame+19);
	put_fs_long(regs->ss, frame+20);
	put_fs_long(0,frame+21);		/* 387 state pointer - not implemented*/
/* non-iBCS2 extensions.. */
	put_fs_long(oldmask, frame+22);
	put_fs_long(current->tss.cr2, frame+23);
/* set up the return code... */
	put_fs_long(0x0000b858, CODE(0));	/* popl %eax ; movl $,%eax */
	put_fs_long(0x80cd0000, CODE(4));	/* int $0x80 */
	put_fs_long(__NR_sigreturn, CODE(2));
	*fp = frame;
#undef __CODE
#undef CODE
}

/*
 * Note that 'init' is a special process: it doesn't get signals it doesn't
 * want to handle. Thus you cannot kill init even with a SIGKILL even by
 * mistake.
 *
 * Note that we go through the signals twice: once to check the signals that
 * the kernel can handle, and then we build all the user-level signal handling
 * stack-frames in one go after that.
 */
asmlinkage int do_signal(unsigned long oldmask, struct pt_regs * regs)
{
	unsigned long mask = ~current->blocked;
	unsigned long handler_signal = 0;
	unsigned long *frame = NULL;
	unsigned long eip = 0;
	unsigned long signr;
	struct sigaction * sa;

	while ((signr = current->signal & mask)) {
		__asm__("bsf %2,%1\n\t"
			"btrl %1,%0"
			:"=m" (current->signal),"=r" (signr)
			:"1" (signr));
		sa = current->sigaction + signr;
		signr++;
		if ((current->flags & PF_PTRACED) && signr != SIGKILL) {
			current->exit_code = signr;
			current->state = TASK_STOPPED;
			notify_parent(current);
			schedule();
			if (!(signr = current->exit_code))
				continue;
			current->exit_code = 0;
			if (signr == SIGSTOP)
				continue;
			if (_S(signr) & current->blocked) {
				current->signal |= _S(signr);
				continue;
			}
			sa = current->sigaction + signr - 1;
		}
		if (sa->sa_handler == SIG_IGN) {
			if (signr != SIGCHLD)
				continue;
			/* check for SIGCHLD: it's special */
			while (sys_waitpid(-1,NULL,WNOHANG) > 0)
				/* nothing */;
			continue;
		}
		if (sa->sa_handler == SIG_DFL) {
			if (current->pid == 1)
				continue;
			switch (signr) {
			case SIGCONT: case SIGCHLD: case SIGWINCH:
				continue;

			case SIGSTOP: case SIGTSTP: case SIGTTIN: case SIGTTOU:
				if (current->flags & PF_PTRACED)
					continue;
				current->state = TASK_STOPPED;
				current->exit_code = signr;
				if (!(current->p_pptr->sigaction[SIGCHLD-1].sa_flags & 
						SA_NOCLDSTOP))
					notify_parent(current);
				schedule();
				continue;

			case SIGQUIT: case SIGILL: case SIGTRAP:
			case SIGIOT: case SIGFPE: case SIGSEGV:
				if (core_dump(signr,regs))
					signr |= 0x80;
				/* fall through */
			default:
				current->signal |= _S(signr & 0x7f);
				do_exit(signr);
			}
		}
		/*
		 * OK, we're invoking a handler
		 */
		if (regs->orig_eax >= 0) {
			if (regs->eax == -ERESTARTNOHAND ||
			   (regs->eax == -ERESTARTSYS && !(sa->sa_flags & SA_RESTART)))
				regs->eax = -EINTR;
		}
		handler_signal |= 1 << (signr-1);
		mask &= ~sa->sa_mask;
	}
	if (regs->orig_eax >= 0 &&
	    (regs->eax == -ERESTARTNOHAND ||
	     regs->eax == -ERESTARTSYS ||
	     regs->eax == -ERESTARTNOINTR)) {
		regs->eax = regs->orig_eax;
		regs->eip -= 2;
	}
	if (!handler_signal)		/* no handler will be called - return 0 */
		return 0;
	eip = regs->eip;
	frame = (unsigned long *) regs->esp;
	signr = 1;
	sa = current->sigaction;
	for (mask = 1 ; mask ; sa++,signr++,mask += mask) {
		if (mask > handler_signal)
			break;
		if (!(mask & handler_signal))
			continue;
		setup_frame(sa,&frame,eip,regs,signr,oldmask);
		eip = (unsigned long) sa->sa_handler;
		if (sa->sa_flags & SA_ONESHOT)
			sa->sa_handler = NULL;
/* force a supervisor-mode page-in of the signal handler to reduce races */
		__asm__("testb $0,%%fs:%0": :"m" (*(char *) eip));
		regs->cs = USER_CS; regs->ss = USER_DS;
		regs->ds = USER_DS; regs->es = USER_DS;
		regs->gs = USER_DS; regs->fs = USER_DS;
		current->blocked |= sa->sa_mask;
		oldmask |= sa->sa_mask;
	}
	regs->esp = (unsigned long) frame;
	regs->eip = eip;		/* "return" to the first handler */
	current->tss.trap_no = current->tss.error_code = 0;
	return 1;
}
