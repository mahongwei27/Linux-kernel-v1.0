/* interrupt.h */
#ifndef _LINUX_INTERRUPT_H
#define _LINUX_INTERRUPT_H

/*
 *	中断下半部(bottom half)结构，每一个中断下半部都有一个 bh_struct 结构，
 * routine 是下半部的执行入口，data 是下半部参数。
 */
struct bh_struct {
	void (*routine)(void *);
	void *data;
};

extern unsigned long bh_active;
extern unsigned long bh_mask;
extern struct bh_struct bh_base[32];

/* Who gets which entry in bh_base.  Things which will occur most often
   should come first. */
enum {
	TIMER_BH = 0,
	CONSOLE_BH,
	SERIAL_BH,
	TTY_BH,
	INET_BH,
	KEYBOARD_BH
};

extern inline void mark_bh(int nr)
{
	__asm__ __volatile__("orl %1,%0":"=m" (bh_active):"ir" (1<<nr));
}

extern inline void disable_bh(int nr)
{
	__asm__ __volatile__("andl %1,%0":"=m" (bh_mask):"ir" (~(1<<nr)));
}

extern inline void enable_bh(int nr)
{
	__asm__ __volatile__("orl %1,%0":"=m" (bh_mask):"ir" (1<<nr));
}

#endif
