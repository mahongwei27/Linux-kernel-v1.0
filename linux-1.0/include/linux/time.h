#ifndef _LINUX_TIME_H
#define _LINUX_TIME_H

/*
 *	struct timeval: 系统当前时间结构体，表示从 1970 年 1 月 1 日 0 时起到现在
 * 所经过的秒数和微秒数。
 */
struct timeval {
	long	tv_sec;		/* seconds */
	long	tv_usec;	/* microseconds */
};

struct timezone {
	int	tz_minuteswest;	/* minutes west of Greenwich */
	int	tz_dsttime;	/* type of dst correction */
};

#define NFDBITS			__NFDBITS

#define FD_SETSIZE		__FD_SETSIZE
#define FD_SET(fd,fdsetp)	__FD_SET(fd,fdsetp)
#define FD_CLR(fd,fdsetp)	__FD_CLR(fd,fdsetp)
#define FD_ISSET(fd,fdsetp)	__FD_ISSET(fd,fdsetp)
#define FD_ZERO(fdsetp)		__FD_ZERO(fdsetp)

/*
 * Names of the interval timers, and structure
 * defining a timer setting.
 */
/*
 *	这三个宏定义了与任务相关的三种间隔定时器的类型，每种类型的间隔定时器都有两个变量
 * incr 和 value，其中 incr 是间隔计数器的初始值，value 是间隔计数器的当前值。它们的单位
 * 都是时钟滴答(tick)，这些变量的定义都在任务的 task_struct 结构中，即每个任务都支持这三
 * 种类型的间隔定时器。
 *
 *	间隔定时器就是当定时器启动后，间隔计数器的当前值 value 将不断减小，当 value 减到
 * 0 时，该定时器到期。
 *
 *	1. ITIMER_REAL: 真实间隔定时器。真实间隔定时器启动后，不管任务是否运行，每个 tick
 * 都将其计数器的当前值 value 减 1，当 value 减到 0 时，内核将向任务发送 SIGALRM 信号。
 *
 *	2. ITIMER_VIRTUAL: 虚拟间隔定时器，也称为任务的用户态间隔定时器。虚拟间隔定时器
 * 启动后，只有当任务在用户态下运行时，每个 tick 才将其计数器的当前值 value 减 1，当 value
 * 减到 0 时，内核向任务发送 SIGVTALRM 信号，并将 value 的值重置为计数器的初始值 incr。
 *
 *	3. ITIMER_PROF: PROF 间隔定时器。PROF 间隔定时器启动后，只要该任务处于运行中，不管
 * 是在内核态还是在用户态下运行，每个 tick 都将计数器的当前值 value 减 1，当 value 减到 0 时，
 * 内核向任务发送 SIGPROF 信号，并将 value 的值重置为计数器的初始值 incr。
 */
#define	ITIMER_REAL	0
#define	ITIMER_VIRTUAL	1
#define	ITIMER_PROF	2

/*
 *	struct itimerval: 这个结构体用于用户设置任务的间隔定时器。
 */
struct	itimerval {
	struct	timeval it_interval;	/* timer interval */
	struct	timeval it_value;	/* current value */
};

#endif
