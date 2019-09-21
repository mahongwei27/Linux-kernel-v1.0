#ifndef _ASM_SEGMENT_H
#define _ASM_SEGMENT_H

/*
 *	在 sys_call.S 文件的 SAVE_ALL 中，当任务通过系统调用从用户态陷入到内核态时，
 * 内核程序会设置段寄存器 DS = ES = KERNEL_DS 用于访问内核数据段，FS = USER_DS 用于
 * 访问用户数据段。
 *
 *	因此，在执行内核代码时，若要访问任务的用户态空间中的数据，就需要使用特殊的
 * 方式。即在内核态下，需要通过 FS 段寄存器与用户态空间进行数据交互。
 */

/*
 *	get_fs_byte:
 *	get_user_byte: 从当前任务的用户态空间中的 addr 地址处读取一个字节的内容。
 */
static inline unsigned char get_user_byte(const char * addr)
{
	register unsigned char _v;

	__asm__ ("movb %%fs:%1,%0":"=q" (_v):"m" (*addr));	/* _v = fs:[addr] 地址处的一个字节值 */
	return _v;
}

#define get_fs_byte(addr) get_user_byte((char *)(addr))

/*
 *	get_fs_word:
 *	get_user_word: 从当前任务的用户态空间中的 addr 地址处读取一个字(2 字节)的内容。
 */
static inline unsigned short get_user_word(const short *addr)
{
	unsigned short _v;

	__asm__ ("movw %%fs:%1,%0":"=r" (_v):"m" (*addr));	/* _v = fs:[addr] 地址处的一个字值 */
	return _v;
}

#define get_fs_word(addr) get_user_word((short *)(addr))

/*
 *	get_fs_long:
 *	get_user_long: 从当前任务的用户态空间中的 addr 地址处读取一个长字(4 字节)的内容。
 */
static inline unsigned long get_user_long(const int *addr)
{
	unsigned long _v;

	__asm__ ("movl %%fs:%1,%0":"=r" (_v):"m" (*addr)); \	/* _v = fs:[addr] 地址处的一个长字值 */
	return _v;
}

#define get_fs_long(addr) get_user_long((int *)(addr))

/*
 *	put_fs_byte:
 *	put_user_byte: 向当前任务的用户态空间中的 addr 地址处写入一个字节值 val。
 */
static inline void put_user_byte(char val,char *addr)
{
__asm__ ("movb %0,%%fs:%1": /* no outputs */ :"iq" (val),"m" (*addr));	/* fs:[addr] = val(byte) */
}

#define put_fs_byte(x,addr) put_user_byte((x),(char *)(addr))

/*
 *	put_fs_word:
 *	put_user_word: 向当前任务的用户态空间中的 addr 地址处写入一个字值(2 字节) val。
 */
static inline void put_user_word(short val,short * addr)
{
__asm__ ("movw %0,%%fs:%1": /* no outputs */ :"ir" (val),"m" (*addr));	/* fs:[addr] = val(word) */
}

#define put_fs_word(x,addr) put_user_word((x),(short *)(addr))

/*
 *	put_fs_long:
 *	put_user_long: 向当前任务的用户态空间中的 addr 地址处写入一个长字值(4 字节) val。
 */
static inline void put_user_long(unsigned long val,int * addr)
{
__asm__ ("movl %0,%%fs:%1": /* no outputs */ :"ir" (val),"m" (*addr));	/* fs:[addr] = val(long) */
}

#define put_fs_long(x,addr) put_user_long((x),(int *)(addr))

static inline void __generic_memcpy_tofs(void * to, const void * from, unsigned long n)
{
__asm__("cld\n\t"
			/* cld: 清方向位，使地址自增。std: 置方向位，使地址自减 */
	"push %%es\n\t"
			/* movsb movsw movsl 指令要用到 es，故将原 es 保存 */
	"push %%fs\n\t"
	"pop %%es\n\t"
			/* es = fs，es 将用于选择用户数据段 */
	"testb $1,%%cl\n\t"
	"je 1f\n\t"
	"movsb\n"
			/*
			 *	测试 ecx 中的 n 的 bit0 位是否等于 0，如果等于 0，则向前跳转到标号 1 处。
			 *
			 *	如果等于 1，则说明 n 是一个奇数，则先从 ds:esi(from) 处复制一个字节到 es:edi(to)
			 * 处，并使 ecx(n) -= 1，同时 esi 和 edi 指针自增一个字节指向下一次要复制的位置。复制后
			 * ecx 中的 n 就变成了一个偶数。
			 */
	"1:\ttestb $2,%%cl\n\t"
	"je 2f\n\t"
	"movsw\n"
			/*
			 *	测试 ecx 中的 n 的 bit1 位是否等于 0，如果等于 0，则向前跳转到标号 2 处。
			 *
			 *	如果等于 1，则说明 n 在 2 的边界对齐，则先从 ds:esi(from) 处复制两个字节到
			 * es:edi(to) 处，并使 ecx 中的 n 减 1，同时 from 和 to 指针自增两个字节指向下一次要
			 * 复制的位置。复制后剩余的还未复制的字节数就是 4 个倍数了，后面就可以每次复制 4 个
			 * 字节了。
			 *	本次复制的 ecx -= 1 表示减少一个字，实际上减 1 之后 ecx 又会变成一个奇数，
			 * 但是下面紧接着会将 ecx 整除 4，所以这里的奇数不会对后面的结果产生影响。
			 *
			 *	前面这两个测试的主要作用是: 将不足 4 字节的数据先用 movsb 和 movsw 复制过去，
			 * 后面剩下的数据就可以循环用 movsl 每次复制 4 字节了。
			 */
	"2:\tshrl $2,%%ecx\n\t"
	"rep ; movsl\n\t"
			/*
			 *	ecx(n) >>= 2，这时 ecx 中的 n 就表示每次复制 4 个字节时总共需要复制的次数了。
			 *
			 *	repeat, ds:esi ===> es:edi, esi += 4, edi += 4, ecx -= 1. until ecx == 0.
			 *
			 *	循环复制，每次将 ds:esi(from) 指向的内核空间中的数据复制 4 字节到 es:edi(to)
			 * 指向的用户空间中，每次复制后 esi(from) 和 edi(to) 都自增 4 个字节指向下一次要复制
			 * 的位置，并将 ecx(n) 减 1。直到 ecx(n) == 0 时，也就是所有的数据都复制完以后，循环
			 * 结束。
			 */
	"pop %%es"
			/* 恢复原 es */
	: /* no outputs */
	:"c" (n),"D" ((long) to),"S" ((long) from)	/* ecx = n, edi = to, esi = from */
	:"cx","di","si");
}

static inline void __constant_memcpy_tofs(void * to, const void * from, unsigned long n)
{
	/* 4 个字节以内的复制方式，这种复制方式的指令数少，执行速度更快 */
	switch (n) {
		case 0:
			return;
		case 1:
			put_user_byte(*(const char *) from, (char *) to);
			return;
		case 2:
			put_user_word(*(const short *) from, (short *) to);
			return;
		case 3:
			put_user_word(*(const short *) from, (short *) to);
			put_user_byte(*(2+(const char *) from), 2+(char *) to);
			return;
		case 4:
			put_user_long(*(const int *) from, (int *) to);
			return;
	}
#define COMMON(x) \
__asm__("cld\n\t" \
	"push %%es\n\t" \
	"push %%fs\n\t" \
	"pop %%es\n\t" \
	"rep ; movsl\n\t" \
	x \
	"pop %%es" \
	: /* no outputs */ \
	:"c" (n/4),"D" ((long) to),"S" ((long) from) \	/* ecx = n/4, edi = to, esi = from */
	:"cx","di","si")

	/*
	 *	超过 4 个字节时，循环复制，每次复制 4 个字节，复制次数为 n/4，最后不足 4
	 * 个字节的部分用 movsb 和 movsw 的组合来复制。
	 */
	switch (n % 4) {
		case 0:
			COMMON("");
			return;
		case 1:
			COMMON("movsb\n\t");
			return;
		case 2:
			COMMON("movsw\n\t");
			return;
		case 3:
			COMMON("movsw\n\tmovsb\n\t");
			return;
	}
#undef COMMON
}

static inline void __generic_memcpy_fromfs(void * to, const void * from, unsigned long n)
{
__asm__("cld\n\t"
	"testb $1,%%cl\n\t"
	"je 1f\n\t"
	"fs ; movsb\n"
	"1:\ttestb $2,%%cl\n\t"
	"je 2f\n\t"
	"fs ; movsw\n"
	"2:\tshrl $2,%%ecx\n\t"
	"rep ; fs ; movsl"
	: /* no outputs */
	:"c" (n),"D" ((long) to),"S" ((long) from)
	:"cx","di","si","memory");
}

static inline void __constant_memcpy_fromfs(void * to, const void * from, unsigned long n)
{
	switch (n) {
		case 0:
			return;
		case 1:
			*(char *)to = get_user_byte((const char *) from);
			return;
		case 2:
			*(short *)to = get_user_word((const short *) from);
			return;
		case 3:
			*(short *) to = get_user_word((const short *) from);
			*(char *) to = get_user_byte(2+(const char *) from);
			return;
		case 4:
			*(int *) to = get_user_long((const int *) from);
			return;
	}
#define COMMON(x) \
__asm__("cld\n\t" \
	"rep ; fs ; movsl\n\t" \
	x \
	: /* no outputs */ \
	:"c" (n/4),"D" ((long) to),"S" ((long) from) \
	:"cx","di","si","memory")

	switch (n % 4) {
		case 0:
			COMMON("");
			return;
		case 1:
			COMMON("fs ; movsb");
			return;
		case 2:
			COMMON("fs ; movsw");
			return;
		case 3:
			COMMON("fs ; movsw\n\tfs ; movsb");
			return;
	}
#undef COMMON
}

/*
 *	memcpy_fromfs: 从 from 指向的用户空间中复制 n 个字节到 to 指向的内核空间中。
 */
#define memcpy_fromfs(to, from, n) \
(__builtin_constant_p(n) ? \
 __constant_memcpy_fromfs((to),(from),(n)) : \
 __generic_memcpy_fromfs((to),(from),(n)))

/*
 *	memcpy_tofs: 从 from 指向的内核空间中复制 n 个字节到 to 指向的用户空间中。
 */
#define memcpy_tofs(to, from, n) \
(__builtin_constant_p(n) ? \
 __constant_memcpy_tofs((to),(from),(n)) : \
 __generic_memcpy_tofs((to),(from),(n)))

/*
 * Someone who knows GNU asm better than I should double check the followig.
 * It seems to work, but I don't know if I'm doing something subtly wrong.
 * --- TYT, 11/24/91
 * [ nothing wrong here, Linus: I just changed the ax to be any reg ]
 */

/*
 *	get_fs: 获取当前的 FS 段寄存器的值，FS 中存放的是某一个段的段选择符。
 */
static inline unsigned long get_fs(void)
{
	unsigned long _v;
	__asm__("mov %%fs,%w0":"=r" (_v):"0" (0));
	return _v;
}

/*
 *	get_ds: 获取当前的 DS 段寄存器的值，DS 中存放的是某一个段的段选择符。
 */
static inline unsigned long get_ds(void)
{
	unsigned long _v;
	__asm__("mov %%ds,%w0":"=r" (_v):"0" (0));
	return _v;
}

/*
 *	set_fs: 设置 FS 段寄存器的值。
 */
static inline void set_fs(unsigned long val)
{
	__asm__ __volatile__("mov %w0,%%fs": /* no output */ :"r" (val));
}

#endif /* _ASM_SEGMENT_H */
