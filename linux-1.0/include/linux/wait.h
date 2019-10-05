#ifndef _LINUX_WAIT_H
#define _LINUX_WAIT_H

/*
 *	wait4 系统调用会用到的标志:
 *
 *	WNOHANG: 表示如果指定的子任务没有退出，也就是没有处于 TASK_ZOMBIE 状态
 * 时，系统调用处理函数需马上返回，不需要将当前任务挂起来等待。
 *
 *	WUNTRACED: 表示如果指定的子任务已经处于 TASK_STOPPED 状态，则系统调用
 * 处理函数需马上返回。
 *
 *	__WCLONE: 表示只等待通过 clone 的方式创建的子任务，也就是等待子线程退出。
 * 由于线程在线性地址空间上的特殊性，子线程退出时将会使用 SIGCHLD 以外的信号来
 * 通知其父任务，即子线程退出时不会向父任务发送 SIGCHLD 信号。
 */
#define WNOHANG		0x00000001
#define WUNTRACED	0x00000002

#define __WCLONE	0x80000000

/*
 *	wait_queue: 这个结构体表示的不是一个等待队列，而是等待队列中的一个元素。
 * 等待队列是由若干个这样的元素(struct wait_queue)组成的一个单循环链表。
 *
 *	系统中的等待队列将由一个指向 struct wait_queue 的指针来表示，比如 task_struct
 * 结构中的 struct wait_queue *wait_chldexit 就表示等待子任务退出的等待队列。这个指针
 * 将永远指向最早进入等待队列中的那个元素，具体参见 add_wait_queue。
 *
 *	其中:	task --- 等待队列中该元素对应的任务。
 *		next --- 等待队列中指向下一个元素的指针。
 */
struct wait_queue {
	struct task_struct * task;
	struct wait_queue * next;
};

struct semaphore {
	int count;
	struct wait_queue * wait;
};

#define MUTEX ((struct semaphore) { 1, NULL })

struct select_table_entry {
	struct wait_queue wait;
	struct wait_queue ** wait_address;
};

typedef struct select_table_struct {
	int nr;
	struct select_table_entry * entry;
} select_table;

#define __MAX_SELECT_TABLE_ENTRIES (4096 / sizeof (struct select_table_entry))

#endif
