#ifndef _LINUX_UNISTD_H
#define _LINUX_UNISTD_H

/*
 * This file contains the system call numbers and the syscallX
 * macros
 */
/*
 *	系统调用号，用作系统调用函数表 sys_call_table[] 中的索引值。
 */
#define __NR_setup		  0	/* used only by init, to get system going */
#define __NR_exit		  1
#define __NR_fork		  2
#define __NR_read		  3
#define __NR_write		  4
#define __NR_open		  5
#define __NR_close		  6
#define __NR_waitpid		  7
#define __NR_creat		  8
#define __NR_link		  9
#define __NR_unlink		 10
#define __NR_execve		 11
#define __NR_chdir		 12
#define __NR_time		 13
#define __NR_mknod		 14
#define __NR_chmod		 15
#define __NR_chown		 16
#define __NR_break		 17
#define __NR_oldstat		 18
#define __NR_lseek		 19
#define __NR_getpid		 20
#define __NR_mount		 21
#define __NR_umount		 22
#define __NR_setuid		 23
#define __NR_getuid		 24
#define __NR_stime		 25
#define __NR_ptrace		 26
#define __NR_alarm		 27
#define __NR_oldfstat		 28
#define __NR_pause		 29
#define __NR_utime		 30
#define __NR_stty		 31
#define __NR_gtty		 32
#define __NR_access		 33
#define __NR_nice		 34
#define __NR_ftime		 35
#define __NR_sync		 36
#define __NR_kill		 37
#define __NR_rename		 38
#define __NR_mkdir		 39
#define __NR_rmdir		 40
#define __NR_dup		 41
#define __NR_pipe		 42
#define __NR_times		 43
#define __NR_prof		 44
#define __NR_brk		 45
#define __NR_setgid		 46
#define __NR_getgid		 47
#define __NR_signal		 48
#define __NR_geteuid		 49
#define __NR_getegid		 50
#define __NR_acct		 51
#define __NR_phys		 52
#define __NR_lock		 53
#define __NR_ioctl		 54
#define __NR_fcntl		 55
#define __NR_mpx		 56
#define __NR_setpgid		 57
#define __NR_ulimit		 58
#define __NR_oldolduname	 59
#define __NR_umask		 60
#define __NR_chroot		 61
#define __NR_ustat		 62
#define __NR_dup2		 63
#define __NR_getppid		 64
#define __NR_getpgrp		 65
#define __NR_setsid		 66
#define __NR_sigaction		 67
#define __NR_sgetmask		 68
#define __NR_ssetmask		 69
#define __NR_setreuid		 70
#define __NR_setregid		 71
#define __NR_sigsuspend		 72
#define __NR_sigpending		 73
#define __NR_sethostname	 74
#define __NR_setrlimit		 75
#define __NR_getrlimit		 76
#define __NR_getrusage		 77
#define __NR_gettimeofday	 78
#define __NR_settimeofday	 79
#define __NR_getgroups		 80
#define __NR_setgroups		 81
#define __NR_select		 82
#define __NR_symlink		 83
#define __NR_oldlstat		 84
#define __NR_readlink		 85
#define __NR_uselib		 86
#define __NR_swapon		 87
#define __NR_reboot		 88
#define __NR_readdir		 89
#define __NR_mmap		 90
#define __NR_munmap		 91
#define __NR_truncate		 92
#define __NR_ftruncate		 93
#define __NR_fchmod		 94
#define __NR_fchown		 95
#define __NR_getpriority	 96
#define __NR_setpriority	 97
#define __NR_profil		 98
#define __NR_statfs		 99
#define __NR_fstatfs		100
#define __NR_ioperm		101
#define __NR_socketcall		102
#define __NR_syslog		103
#define __NR_setitimer		104
#define __NR_getitimer		105
#define __NR_stat		106
#define __NR_lstat		107
#define __NR_fstat		108
#define __NR_olduname		109
#define __NR_iopl		110
#define __NR_vhangup		111
#define __NR_idle		112
#define __NR_vm86		113
#define __NR_wait4		114
#define __NR_swapoff		115
#define __NR_sysinfo		116
#define __NR_ipc		117
#define __NR_fsync		118
#define __NR_sigreturn		119
#define __NR_clone		120
#define __NR_setdomainname	121
#define __NR_uname		122
#define __NR_modify_ldt		123
#define __NR_adjtimex		124
#define __NR_mprotect		125
#define __NR_sigprocmask	126
#define __NR_create_module	127
#define __NR_init_module	128
#define __NR_delete_module	129
#define __NR_get_kernel_syms	130
#define __NR_quotactl		131
#define __NR_getpgid		132
#define __NR_fchdir		133
#define __NR_bdflush		134

extern int errno;

/* XXX - _foo needs to be __foo, while __NR_bar could be _NR_bar. */

/*
 *	定义系统调用嵌入式汇编宏函数。
 *
 *	1. ##是连字符，用于将前后两个字符串连接在一起变成一个字符串，__NR_##name 在预处理阶段的宏定义
 * 替换时先转换为 __NR_name，其中 name 是系统调用名，__NR_name 再被对应的宏定义替换，变成系统调用号。
 *	例如 fork 系统调用 ===> __NR_##fork ===> __NR_fork ===> 2，表示 fork 的系统调用号是 2。
 *
 *	2. "int $0x80" 指令触发系统调用，随即处理器执行系统调用异常(中断)，当前的流程被暂停在 "int $0x80"
 * 指令的后一条语句 [ if (__res >= 0) ] 处，系统调用返回后从此处继续向下执行。
 *
 *	3. 系统调用指令 "int $0x80" 使得处理器的特权级由 3 切换为 0，使用的栈由特权级 3 对应的栈切换为
 * 特权级 0 对应的栈。
 *	即对于当前进程来讲，进程由用户态陷入内核态，处理器使用的栈由进程的用户态栈变更为进程的内核态栈。
 *
 *	4. 不管哪种类型的系统调用，传给系统调用的第一个参数都是系统调用号 __NR_##name，通过 eax 寄存器
 * 传递这个系统调用号，后续处理器将根据系统调用号执行对应的系统调用处理函数。
 *	系统调用只有一个返回值，通过 eax 寄存器返回这个值，eax >= 0 表示系统调用执行成功，eax < 0 表示
 * 系统调用执行失败，这个返回值最终会被放入变量 __res 中。
 *
 *	5. 若系统调用执行失败，则对应的错误号会被保存在 errno [ errno = -__res ] 中，系统调用嵌入式汇编
 * 宏函数将会返回 -1，进程若想得知具体的错误原因，需要通过 errno 确定。
 *	若系统调用执行成功，宏函数直接将系统调用的返回值返回。
 *
 *	6. 0x80 号中断对应的中断处理函数为 system_call，其实现位于 sys_call.S 中的 _system_call 处。
 */


/*
 *	_syscall0: 不带参数的系统调用宏函数 type name(void)。
 */
#define _syscall0(type,name) \
type name(void) \
{ \
	long __res; \
	__asm__ volatile ("int $0x80" \		/* 触发执行系统调用 system_call，当前流程被中断打断 */
			: "=a" (__res) \
			: "0" (__NR_##name)); \
					/*
					 *	output: 系统调用只有一个返回值，会被放入 eax 寄存器中，
					 * 最终代码返回时 eax 中的值会被放入变量 __res 中。
					 *
					 *	input: 传给系统调用的第一个参数是系统调用号 __NR_##name，
					 * 该值将被放入 eax 寄存器中传递。
					 */
	if (__res >= 0) \
		return (type) __res; \		/* 系统调用执行成功 */
	errno = -__res; \
	return -1; \				/* 系统调用执行失败 */
}

/*
 *	_syscall1: 带一个参数的系统调用宏函数 type name(atype a)。
 */
#define _syscall1(type,name,atype,a) \
type name(atype a) \
{ \
	long __res; \
	__asm__ volatile ("int $0x80" \
			: "=a" (__res) \
			: "0" (__NR_##name),"b" ((long)(a))); \
					/*
					 *	input: 宏函数的参数 a 将通过 ebx 寄存器传递。
					 */
	if (__res >= 0) \
		return (type) __res; \
	errno = -__res; \
	return -1; \
}

/*
 *	_syscall1: 带两个参数的系统调用宏函数 type name(atype a, btype b)。
 */
#define _syscall2(type,name,atype,a,btype,b) \
type name(atype a,btype b) \
{ \
	long __res; \
	__asm__ volatile ("int $0x80" \
			: "=a" (__res) \
			: "0" (__NR_##name),"b" ((long)(a)),"c" ((long)(b))); \
					/*
					 *	input: 宏函数的参数 a、b 将依次通过 ebx、ecx 寄存器传递。
					 */
	if (__res >= 0) \
		return (type) __res; \
	errno = -__res; \
	return -1; \
}

/*
 *	_syscall1: 带三个参数的系统调用宏函数 type name(atype a, btype b, ctype c)。
 */
#define _syscall3(type,name,atype,a,btype,b,ctype,c) \
type name(atype a,btype b,ctype c) \
{ \
	long __res; \
	__asm__ volatile ("int $0x80" \
			: "=a" (__res) \
			: "0" (__NR_##name),"b" ((long)(a)),"c" ((long)(b)),"d" ((long)(c))); \
					/*
					 *	input: 宏函数的参数 a、b、c 将依次通过 ebx、ecx、edx
					 * 寄存器传递。
					 */
	if (__res>=0) \
		return (type) __res; \
	errno=-__res; \
	return -1; \
}

/*
 *	_syscall1: 带四个参数的系统调用宏函数 type name(atype a, btype b, ctype c, dtype d)。
 */
#define _syscall4(type,name,atype,a,btype,b,ctype,c,dtype,d) \
type name (atype a, btype b, ctype c, dtype d) \
{ \
	long __res; \
	__asm__ volatile ("int $0x80" \
			: "=a" (__res) \
			: "0" (__NR_##name),"b" ((long)(a)),"c" ((long)(b)), \
			  "d" ((long)(c)),"S" ((long)(d))); \
					/*
					 *	input: 宏函数的参数 a、b、c、d、将依次通过
					 * ebx、ecx、edx、esi 寄存器传递。
					 */
	if (__res>=0) \
		return (type) __res; \
	errno=-__res; \
	return -1; \
}

/*
 *	_syscall1: 带五个参数的系统调用宏函数 type name(atype a, btype b, ctype c, dtype d, etype e)。
 */
#define _syscall5(type,name,atype,a,btype,b,ctype,c,dtype,d,etype,e) \
type name (atype a,btype b,ctype c,dtype d,etype e) \
{ \
	long __res; \
	__asm__ volatile ("int $0x80" \
			: "=a" (__res) \
			: "0" (__NR_##name),"b" ((long)(a)),"c" ((long)(b)), \
			  "d" ((long)(c)),"S" ((long)(d)),"D" ((long)(e))); \
					/*
					 *	input: 宏函数的参数 a、b、c、d、e 将依次通过
					 * ebx、ecx、edx、esi、edi 寄存器传递。
					 */
	if (__res>=0) \
		return (type) __res; \
	errno=-__res; \
	return -1; \
}

#endif /* _LINUX_UNISTD_H */
