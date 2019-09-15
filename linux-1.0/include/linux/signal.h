#ifndef _LINUX_SIGNAL_H
#define _LINUX_SIGNAL_H

/*
 *	sigset_t: 定义信号集类型，也就是一些信号的集合。
 */
typedef unsigned int sigset_t;		/* 32 bits */

/*
 *	NSIG: 内核支持的信号种类，共 32 种。
 */
#define _NSIG             32
#define NSIG		_NSIG

/*
 *	below: 定义信号，信号值为 1 - 32，信号在信号位图中的偏移为 0 - 31。
 *
 *	捕获信号: 表示用户通过系统提供的系统调用接口设置信号的处理函数，使得当信号产生时
 * 执行用户自定义的信号处理函数。
 *	阻塞信号: 表示任务可以正常收到信号，但是不处理信号。
 *	忽略信号: 表示任务可以正常收到信号，系统也会处理任务的信号，只是系统处理的方式是
 * 什么也不做。
 *
 *	信号的默认操作有以下 5 种情况:
 *	Abort --- 任务被终止。
 *	Dump --- 任务被终止并产生 core dump 文件。
 *	Ignore --- 忽略，什么也不做。
 *	Continue --- 恢复任务继续执行。
 *	Stop --- 停止任务的运行。
 */
#define SIGHUP		 1
				/*
				 *	SIGHUP --- hang up，用于挂断控制终端或进程，默认操作是 Abort。
				 */
#define SIGINT		 2
				/*
				 *	SIGINT --- interrupt，来自键盘的中断，通常驱动程序会将其与 Ctrl + C
				 * 绑定，默认操作是 Abort。
				 */
#define SIGQUIT		 3
				/*
				 *	SIGQUIT --- quit，来自键盘的退出中断，通常驱动程序会将其与 Ctrl + \
				 * 绑定，默认操作是 Dump。
				 */
#define SIGILL		 4
				/*
				 *	SIGILL --- illegal instruction，表示程序出错或执行了一条非法指令，
				 * 默认操作是 Dump。
				 */
#define SIGTRAP		 5
				/*
				 *	SIGTRAP --- trap，用于调试，跟踪断点，默认操作是 Dump。
				 */
#define SIGABRT		 6
#define SIGIOT		 6
				/*
				 *	SIGABRT --- abort，表示异常结束。
				 *	SIGIOT --- IO trap，同 SIGABRT，这两个是同一个信号。默认操作是 Dump。
				 */
#define SIGUNUSED	 7
				/*
				 *	SIGUNUSED --- unused，没有使用
				 */
#define SIGFPE		 8
				/*
				 *	SIGFPE --- floating point exception，表示浮点异常。默认操作是 Dump。
				 */
#define SIGKILL		 9
				/*
				 *	SIGKILL --- kill，强制终止进程，该信号不能被捕获，也不能被忽略，程序
				 * 将没有任何机会做清理工作，默认操作是 Abort。
				 */
#define SIGUSR1		10
				/*
				 *	SIGUSR1 --- user defined signal 1，用户信号 1，默认操作是 Abort。
				 */
#define SIGSEGV		11
				/*
				 *	SIGSEGV --- segmentation violation，无效内存引用，默认操作是 Dump。
				 */
#define SIGUSR2		12
				/*
				 *	SIGUSR2 --- user defined signal 2，用户信号 2，默认操作是 Abort。
				 */
#define SIGPIPE		13
				/*
				 *	SIGPIPE --- pipe，管道写出错，无读者，默认操作是 Abort。
				 */
#define SIGALRM		14
				/*
				 *	SIGALRM --- alarm，实时定时器报警，用户通过 alarm 系统调用所设置的
				 * 延时时间到期，或通过 setitimer 系统调用设置的真实间隔定时器到期，默认操作
				 * 是 Abort。
				 */
#define SIGTERM		15
				/*
				 *	SIGTERM --- terminate，进程终止，用于和善的要求一个程序终止，它是
				 * kill 的默认信号。与 SIGKILL 不同，该信号可以被捕获，这样就能在退出运行前
				 * 做清理工作。默认操作是 Abort。
				 */
#define SIGSTKFLT	16
				/*
				 *	SIGSTKFLT --- stack fault on coprocessor，协处理器堆栈错误，默认操作
				 * 是 Abort。
				 */
#define SIGCHLD		17
				/*
				 *	SIGCHLD --- child，由子进程发出，表示子进程已停止或被终止，默认操作
				 * 是 Ignore。
				 */
#define SIGCONT		18
				/*
				 *	SIGCONT --- continue，恢复处于停止状态的进程继续执行，默认操作是
				 * Continue。
				 */
#define SIGSTOP		19
				/*
				 *	SIGSTOP --- stop，停止进程的执行，该信号不能被捕获，也不能被忽略，
				 * 默认操作是 Stop。
				 */
#define SIGTSTP		20
				/*
				 *	SIGTSTP --- terminal stop，tty 发出停止进程，可忽略，默认操作是 Stop。
				 */
#define SIGTTIN		21
				/*
				 *	SIGTTIN --- tty input on background，后台进程试图从一个不再被控制的
				 * 终端上读取数据，默认操作是 Stop。
				 */
#define SIGTTOU		22
				/*
				 *	SIGTTOU --- tty output on background，后台进程试图向一个不再被控制的
				 * 终端上输出数据，默认操作是 Stop。
				 */

/*
 * Most of these aren't used yet (and perhaps never will),
 * so they are commented out.
 */


#define SIGIO		23
#define SIGPOLL		SIGIO
				/*
				 *	SIGIO --- io，用于异步 IO 模式，当有 IO 可用时产生该信号通知进程，
				 * 默认操作是 Abort。
				 *	SIGPOLL --- 当指定的时间发生在可选择的设备上时，产生该信号，默认
				 * 操作是 Abort。
				 */
#define SIGURG		SIGIO
				/*
				 *	SIGURG --- 当网络连接接收到带外数据时会产生该信号，默认操作是 Ignore。
				 */
#define SIGXCPU		24
				/*
				 *	SIGXCPU --- 进程超过了 cpu 的时间限制，默认操作是 Dump。
				 */
#define SIGXFSZ		25
				/*
				 *	SIGXFSZ --- 进程超过了文件大小限制，默认操作是 Dump。
				 */


#define SIGVTALRM	26
#define SIGPROF		27
				/*
				 *	SIGVTALRM --- 通过 setitimer 系统调用设置的虚拟间隔定时器到期，默认
				 * 操作是 Abort。
				 *
				 *	SIGPROF --- 通过 setitimer 系统调用设置的 PROF 间隔定时器到期，默认
				 * 操作是 Abort。
				 */

#define SIGWINCH	28
				/*
				 *	SIGWINCH --- 窗口尺寸改变，默认操作是 Ignore。
				 */

/*
#define SIGLOST		29
*/
#define SIGPWR		30
				/*
				 *	SIGPWR --- 电源异常，默认操作是 Abort。
				 */

/* Arggh. Bad user source code wants this.. */
#define SIGBUS		SIGUNUSED
				/*
				 *	SIGBUS --- 总线异常，默认操作是 Dump。
				 */

/*
 * sa_flags values: SA_STACK is not currently supported, but will allow the
 * usage of signal stacks by using the (now obsolete) sa_restorer field in
 * the sigaction structure as a stack pointer. This is now possible due to
 * the changes in signal handling. LBT 010493.
 * SA_INTERRUPT is a no-op, but left due to historical reasons. Use the
 * SA_RESTART flag to get restarting signals (which were the default long ago)
 */
/*
 *	以下是 struct sigaction 中 sa_flags 的值:
 *
 *	SA_NOCLDSTOP --- 当子任务处于停止状态时，父任务就不对收到的 SIGCHLD 信号做处理。
 * 实际上，当子任务处于停止状态并向父任务发送 SIGCHLD 信号之前，会先检测父任务的 SIGCHLD
 * 信号对应 sigaction 结构中的 sa_flags，如果父任务设置了 SA_NOCLDSTOP，则子任务就不再向
 * 父任务发送 SIGCHLD 信号。
 *
 *	SA_STACK --- 执行信号处理函数时使用独立的栈(信号栈)，系统当前暂时不支持该标志，
 * 但是信号栈可以通过 struct sigaction 结构中的 sa_restorer 字段来设置。
 *
 *	SA_RESTART --- 设置该标志表示当系统调用被信号中断后，将重启被中断的系统调用，所以
 * 默认情况下，操作系统是不会重启被中断的系统调用的。
 *
 *	SA_INTERRUPT --- 这是由于历史原因遗留下来的一个标志，原来设置该标志表示当系统调用
 * 被信号中断后，不再重新启动被中断的系统调用。现在该标志已被 SA_RESTART 代替。
 *
 *	SA_NOMASK --- 不阻塞任何信号，允许在执行信号处理程序的过程中再收到信号(所有信号都
 * 被允许)。不设置该标志并不表示阻塞所有信号，而是只阻塞 sigaction 结构对应的那个信号。
 *
 *	SA_ONESHOT --- 该标志表示用户自定义的信号处理函数执行过一次之后就恢复为默认的信号
 * 处理函数 SIG_DFL。如果用户想让自定义的信号处理函数长期有效，就不要设置该标志。
 */
#define SA_NOCLDSTOP	1
#define SA_STACK	0x08000000
#define SA_RESTART	0x10000000
#define SA_INTERRUPT	0x20000000
#define SA_NOMASK	0x40000000
#define SA_ONESHOT	0x80000000

/*
 *	以下宏定义在 sys_sigprocmask 中使用，这是系统调用 sigprocmask 对应的系统调用处理
 * 函数。sigprocmask 用于改变当前任务的阻塞信号集，同时返回当前任务的原阻塞信号集。
 *
 *	SIG_BLOCK --- 在阻塞信号集中加上指定信号集。
 *
 *	SIG_UNBLOCK --- 从阻塞信号集中删除指定信号集。
 *
 *	SIG_SETMASK --- 重新设置阻塞信号集。
 */
#define SIG_BLOCK          0	/* for blocking signals */
#define SIG_UNBLOCK        1	/* for unblocking signals */
#define SIG_SETMASK        2	/* for setting the signal mask */

/* Type of a signal handler.  */
typedef void (*__sighandler_t)(int);

/*
 *	以下宏用于定义信号的处理函数:
 *
 *	SIG_DFL --- 默认的信号处理程序，如果信号的处理函数 sa_handler == SIG_DFL，则系统
 * 将执行该信号的默认操作，比如信号 SIGINT 的默认操作是终止程序。
 *
 *	SIG_IGN --- 忽略信号的处理程序，如果信号的处理函数 sa_handler == SIG_IGN，则系统
 * 将忽略该信号，不做任何处理。
 *
 *	SIG_ERR --- 信号处理返回错误，如果信号的处理函数 sa_handler == SIG_ERR，则系统将
 * 返回错误，错误码由 errno 给出。
 */
#define SIG_DFL	((__sighandler_t)0)	/* default signal handling */
#define SIG_IGN	((__sighandler_t)1)	/* ignore signal */
#define SIG_ERR	((__sighandler_t)-1)	/* error return from signal */

/*
 *	struct sigaction: 信号的属性结构。每个信号都有一个这样的属性结构，用于描述信号的
 * 属性信息。
 *
 *	sa_handler --- 信号对应的处理函数。
 *
 *	sa_mask --- 哪些位置 1，则信号处理程序执行时将阻塞对这些信号的处理。
 *
 *	sa_flags --- 信号对应的一些标志，这些标志会改变信号的处理过程。
 *
 *	sa_restorer --- 这个属性表示的含义已经改变。原来用于表示信号的恢复函数，信号的恢复
 * 函数由库函数提供，用户不需要关心，用于在用户自定义的信号处理函数执行结束时恢复任务的原始
 * 现场。
 *	现在系统使用了新的恢复原始现场的方案，且不再需要库函数提供恢复函数，所以这个属性就
 * 不再用于设置信号的恢复函数。
 *	目前这个属性的用处是: 用户可以通过该字段来设置信号处理过程中使用的栈(信号栈)，这里
 * 将存储信号栈指针。
 */
struct sigaction {
	__sighandler_t sa_handler;
	sigset_t sa_mask;
	int sa_flags;
	void (*sa_restorer)(void);
};

#endif
