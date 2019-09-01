#ifndef _LINUX_STDDEF_H
#define _LINUX_STDDEF_H

#ifndef _SIZE_T
#define _SIZE_T
typedef unsigned int size_t;
#endif

#undef NULL
#define NULL ((void *)0)

/*
 *	offsetof: 计算 MEMBER 在 TYPE 中的偏移值，通常用来计算结构体成员
 * 在结构体中的偏移值。
 */
#undef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#endif
