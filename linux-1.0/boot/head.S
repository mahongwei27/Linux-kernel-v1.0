/*
 *  linux/boot/head.S
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 *  head.S contains the 32-bit startup code.
 */

/*
 * 	head.S 程序位于 system 模块最开始的位置，setup 中已经将 system 模块搬移
 * 到了 0x01000 开始的位置。
 * 	在重新设置 IDTR 和 GDTR 之前，IDT 和 GDT 都使用 setup 中的配置。
 */

.text
.globl _idt,_gdt,
.globl _swapper_pg_dir,_pg0
.globl _empty_bad_page
.globl _empty_bad_page_table
.globl _empty_zero_page
.globl _tmp_floppy_area,_floppy_track_buffer

#include <linux/tasks.h>
#include <linux/segment.h>

#define CL_MAGIC_ADDR	0x90020
#define CL_MAGIC	0xA33F
#define CL_BASE_ADDR	0x90000
#define CL_OFFSET	0x90022

/*
 * swapper_pg_dir is the main page directory, address 0x00001000 (or at
 * address 0x00101000 for a compressed boot).
 */
startup_32:			/* head.S 程序开始执行的地方 */
	cld
	movl $(KERNEL_DS),%eax
	mov %ax,%ds
	mov %ax,%es
	mov %ax,%fs
	mov %ax,%gs
	lss _stack_start,%esp
				/*
				 * 	以上代码: 设置数据段寄存器及栈的位置。
				 * 	1. DS = ES = FS = GS = 内核数据段选择符 0x18，用于选择 GDT 表中的
				 * 内核数据段描述符。
				 * 	2. lss 指令用于设置系统栈指针: [ SS:ESP = user_stack 数组的尾部 ]
				 */
/*
 * Clear BSS first so that there are no surprises...
 */
	xorl %eax,%eax
	movl $__edata,%edi
	movl $__end,%ecx
	subl %edi,%ecx
	cld
	rep
	stosb
				/*
				 * 	以上代码: 将 BSS 段清0。
				 */
/*
 * start system 32-bit setup. We need to re-do some of the things done
 * in 16-bit mode for the "real" operations.
 */
	call setup_idt
				/*
				 * 	设置 IDT 表，这个 IDT 表是系统最终使用的 IDT 表。此处并未设置 IDTR。
				 */
	xorl %eax,%eax
1:	incl %eax		# check that A20 really IS enabled
	movl %eax,0x000000	# loop forever if it isn't
	cmpl %eax,0x100000
	je 1b
				/*
				 * 	以上代码: 检测 A20 地址线是否开启成功，若未成功开启，则处理器无法
				 * 访问 1MB 以上的内存空间，代码在此处死循环。
				 */
/*
 * Initialize eflags.  Some BIOS's leave bits like NT set.  This would
 * confuse the debugger if this code is traced.
 * XXX - best to initialize before switching to protected mode.
 */
	pushl $0
	popfl
				/*
				 * 	上面两行代码: 将标志寄存器 EFLAGS 中的标志位全清为 0。pushfl 指令
				 * 用于将 EFLAGS 入栈，popfl 指令用于将栈中的值弹出恢复到 EFLAGS 寄存器中。
				 * 此处使用的栈是本文件代码最开始设置的 stack_start。
				 */
/*
 * Copy bootup parameters out of the way. First 2kB of
 * _empty_zero_page is for boot parameters, second 2kB
 * is for the command line.
 */
	movl $0x90000,%esi
	movl $_empty_zero_page,%edi
	movl $512,%ecx
	cld
	rep
	movsl
	xorl %eax,%eax
	movl $512,%ecx
	rep
	stosl
	cmpw $(CL_MAGIC),CL_MAGIC_ADDR
	jne 1f
	movl $_empty_zero_page+2048,%edi
	movzwl CL_OFFSET,%esi	//movzwl: 做0扩展的2字节复制到4字节。ESI = CL_OFFSET & 0x0000FFFF = 0x00000022。
	addl $(CL_BASE_ADDR),%esi
	movl $2048,%ecx
	rep
	movsb
				/*
				 * 	以上代码: 系统为启动参数和命令行预留了 4kB 的空间，启动参数和命令行
				 * 分别占用前后 2kB。目前 4kB 的空间位于物理内存的 0x5000(20kB) 起始的地址处。
				 *
				 * 	1. 将 0x90000 开始的 2kB 的启动参数复制到 0x5000 - 0x5800 中。实际上，
				 * 目前只有 512 字节的启动参数，后面的 1.5kB 实际上是 setup 中的代码，属于
				 * 无效参数。
				 * 	2. 将命令行占用的 2kB(0x5800 - 0x6000) 空间清 0。
				 *	3. 确定 0x90020 地址处的值是否等于 0xA33F。若不相等则表示没有命令行
				 * 参数，本流程结束。若相等则说明有命令行参数，需要复制命令行参数。
				 * 	4. 从 CL_BASE_ADDR + (CL_OFFSET & 0x0000FFFF) = 0x90022 开始的地址处
				 * 复制 2kB 的命令行参数到 0x5800 开始的空间中。
				 *
				 * 	【以上 !!! 对吗 ???】
				 */
1:
/* check if it is 486 or 386. */
/*
 * XXX - this does a lot of unnecessary setup.  Alignment checks don't
 * apply at our cpl of 0 and the stack ought to be aligned already, and
 * we don't need to preserve eflags.
 */
	movl %esp,%edi		# save stack pointer
	andl $0xfffffffc,%esp	# align stack to avoid AC fault
	movl $3,_x86
	pushfl			# push EFLAGS
	popl %eax		# get EFLAGS
	movl %eax,%ecx		# save original EFLAGS
	xorl $0x40000,%eax	# flip AC bit in EFLAGS
	pushl %eax		# copy to EFLAGS
	popfl			# set EFLAGS
	pushfl			# get new EFLAGS
	popl %eax		# put it in eax
	xorl %ecx,%eax		# change in flags
	andl $0x40000,%eax	# check if AC bit changed
	je is386
	movl $4,_x86
	movl %ecx,%eax
	xorl $0x200000,%eax	# check ID flag
	pushl %eax
	popfl			# if we are on a straight 486DX, SX, or
	pushfl			# 487SX we can't change it
	popl %eax
	xorl %ecx,%eax
	andl $0x200000,%eax
	je is486
isnew:	pushl %ecx		# restore original EFLAGS
	popfl
	movl $1, %eax		# Use the CPUID instruction to 
	.byte 0x0f, 0xa2	# check the processor type
	andl $0xf00, %eax	# Set _x86 with the family
	shrl $8, %eax		# returned.	
	movl %eax, _x86
	movl %edi,%esp		# restore esp
	movl %cr0,%eax		# 486+
	andl $0x80000011,%eax	# Save PG,PE,ET
	orl $0x50022,%eax	# set AM, WP, NE and MP
	jmp 2f
is486:	pushl %ecx		# restore original EFLAGS
	popfl
	movl %edi,%esp		# restore esp
	movl %cr0,%eax		# 486
	andl $0x80000011,%eax	# Save PG,PE,ET
	orl $0x50022,%eax	# set AM, WP, NE and MP
	jmp 2f
is386:	pushl %ecx		# restore original EFLAGS
	popfl
	movl %edi,%esp		# restore esp
	movl %cr0,%eax		# 386
	andl $0x80000011,%eax	# Save PG,PE,ET
	orl $2,%eax		# set MP
				/*
				 * 	以上代码: 检测 CPU 型号，并将型号保存在 schedule.c 文件的 x86 变量中，
				 * x86 变量的取值可能是 3、4、5 等等，分别代表 386、486、586 等。
				 *
				 * 	检测好型号后将该型号下需要设置给 CR0 的值存放到 eax 寄存器中。CR0 - CR3
				 * 是控制寄存器组，其中 CR0 中含有处理器操作模式和状态的系统控制标志，不同 CPU
				 * 型号的 CR0 中的标志是不一样的，因此此处才需要检测 x86 的具体型号。
				 *
				 * 	不管是哪种类型的 CPU，最后放在 eax 中的值，第 0(PE，控制分段) 位和第
				 * 31(PG，控制分页) 位的值都还是原来的值，PE 位已经在 setup 结束的位置设置了，
				 * 分段机制已经开启了，PG 位之前没有被设置过，所以仍然是 0，分页机制暂未开启。
				 */
2:	movl %eax,%cr0
				/*
				 * 	这行代码用 eax 中的值设置 CR0 寄存器。设置后处理器仍工作在只开启了分段
				 * 机制的保护模式下。
				 */
	call check_x87
				/*
				 * 	check_x87: 检测数学协处理器 80287/80387 是否存在并设置相关标志。
				 */
	call setup_paging
				/*
				 * 	setup_paging: 设置页目录表及页表并开启分页机制，从此处理器便工作在
				 * 开启分页机制的保护模式下。以后处理器发出的线性地址都将经过 MMU 的地址转换
				 * 才能访问物理内存地址。
				 */
	lgdt gdt_descr
	lidt idt_descr
				/*
				 * 	分页机制已经开启，初步的页面映射已经完成，该重新加载 GDTR 和 IDTR 了。
				 */
	ljmp $(KERNEL_CS),$1f
				/*
				 * 	通过跳转指令，用内核代码段的选择符重新选择内核代码段的描述符。因为
				 * 描述符中的线性基地址已经改成了 0xC0000000，所以从此之后，处理器发出的内核
				 * 的线性基地址都是基于 0xC0000000 的。在此之前，该线性基地址都是基于 0 的。
				 */
1:	movl $(KERNEL_DS),%eax	# reload all the segment registers
	mov %ax,%ds		# after changing gdt.
	mov %ax,%es
	mov %ax,%fs
	mov %ax,%gs
				/*
				 * 	修改了 GDT，需要重新装载所有的段寄存器。DS = ES = FS = GS = 0x18。
				 */
	lss _stack_start,%esp
				/*
				 * 	重新设置 SS:ESP = user_stack 数组的尾部，栈指针回到栈底部，栈为空。
				 */
	xorl %eax,%eax
	lldt %ax
				/*
				 * 	设置局部描述符表寄存器 LDTR = 0。LDTR 目前处于无效状态。
				 */
	pushl %eax		# These are the parameters to main :-)
	pushl %eax
	pushl %eax
				/*
				 * 	在栈中压入 3 个值，都是 0，这三个值将作为传给函数 start_kernel 的参数，
				 * start_kernel 函数并未用到这三个参数，所以此处直接置 0，三个参数从上到下依次
				 * 表示  envp  argv  argc 。
				 */
	cld			# gcc2 wants the direction flag cleared at all times
	call _start_kernel
				/*
				 *	这是 head.S 结束的位置，跳转到 main.c 文件中的 start_kernel 函数处继续
				 * 执行后续代码。全局中断还处于禁止状态。
				 */
L6:
	jmp L6			# main should never return here, but
				# just in case, we know what happens.

/*
 * We depend on ET to be correct. This checks for 287/387.
 */
check_x87:
	movl $0,_hard_math
	clts
	fninit
	fstsw %ax
	cmpb $0,%al
	je 1f
	movl %cr0,%eax		/* no coprocessor: have to set bits */
	xorl $4,%eax		/* set EM */
	movl %eax,%cr0
	ret
.align 2
1:	movl $1,_hard_math
	.byte 0xDB,0xE4		/* fsetpm for 287, ignored by 387 */
	ret
				/*
				 * 	以上代码: 检测数学协处理器 80287/80387 是否存在，若存在，则设置定义在
				 * sched.c 中的变量 hard_math = 1 表示数学协处理器存在。若不存在则设置 CR0 中
				 * 的 EM = 1，表示处理器没有内部或外部协处理器。
				 */


				/*
				 * 中断描述符表 IDT 中的中断门描述符格式:
				 *
				 * | 31                   16 | 15 | 14 13 | 12      8 | 7 6 5 | 4     0 |
				 * ----------------------------------------------------------------------
				 * | 过程入口点偏移(31 - 16) | P  |  DPL  | 0 1 1 1 0 | 0 0 0 | 0 0 0 0 |
				 * ----------------------------------------------------------------------
				 * |       段选择符          |           过程入口点偏移(15 - 0)         |
				 * ----------------------------------------------------------------------
				 */
/*
 *  setup_idt
 *
 *  sets up a idt with 256 entries pointing to
 *  ignore_int, interrupt gates. It doesn't actually load
 *  idt - that can be done only after paging has been enabled
 *  and the kernel moved to 0xC0000000. Interrupts
 *  are enabled elsewhere, when we can be relatively
 *  sure everything is ok.
 */
setup_idt:
	lea ignore_int,%edx
	movl $(KERNEL_CS << 16),%eax
	movw %dx,%ax		/* selector = 0x0010 = cs */
	movw $0x8E00,%dx	/* interrupt gate - dpl=0, present */

	lea _idt,%edi
	mov $256,%ecx
rp_sidt:
	movl %eax,(%edi)
	movl %edx,4(%edi)
	addl $8,%edi
	dec %ecx
	jne rp_sidt
	ret
				/*
				 * 	以上代码: 设置中断描述符表 IDT，IDT 由 256 个中断描述符表项构成，每个
				 * 表项占 8 个字节，IDT 表共占用 2kB 的内存空间，默认的 256 个表项相同，指向
				 * 同一个中断门 ignore_int，真正的中断门在后面的代码中安装。IDT 表的位置在本
				 * 文件中 _idt 符号所表示的位置处。
				 *
				 * 	设置后的中断描述符表项:
				 * | 31                   16 | 15 | 14 13 | 12      8 | 7 6 5 | 4     0 |
				 * ----------------------------------------------------------------------
				 * |  ignore_int 函数的地址  | 1  |  0 0  | 0 1 1 1 0 | 0 0 0 | 0 0 0 0 |
				 * ----------------------------------------------------------------------
				 * |   0x10 选择内核代码段   |                   0x0000                 |
				 * ----------------------------------------------------------------------
				 *
				 * 	其中: P = 1 表示中断门存在。DPL = 0 表示中断要执行的处理函数位于 0
				 * 特权级的代码中。因此，默认情况下，当中断产生时，将会执行内核代码段中的
				 * ignore_int 函数。在后面安装真正的中断门时只需将 ignore_int 替换成真正的
				 * 中断处理函数即可。安装其它门，比如陷阱门时还需要更改描述符的类型。
				 */
				/*
				 * 	目前只是启用了分段机制，还未启用分页机制，所以目前内核代码的线性地址
				 * 空间与物理地址空间一致。当启用分页机制后，内核会被移动到 4GB 线性地址空间
				 * 的 0xC0000000(3GB) 地址处。因为中断描述表当前的线性地址和启用分页机制之后
				 * 之后的线性地址不一致，所以此处并不设置 IDTR，后续等开启分页并将内核移动到
				 * 0xC0000000 地址后，最终确定了 IDT 的线性地址空间后，才设置 IDTR。
				 */


				/*
				 * 	页目录表中的页目录项和页表中的页表项具有相同的格式:
				 *
				 * | 31                    12 | 11 10 9 | 8 7 | 6 | 5 | 4 3 |  2  |  1  | 0 |
				 * --------------------------------------------------------------------------
				 * |    物理内存页面基地址    |   AVL   | 0 0 | D | A | 0 0 | U/S | R/W | P |
				 * --------------------------------------------------------------------------
				 *
				 *	因物理内存页面基地址是 20 位，所以所有的内存页面都必须在 4kB 的边界对齐。
				 *
				 * 	P: 存在标志，用于表明页目录项指向的页表或页表项指向的真正内存页面是否
				 * 存在。P = 1 表示页面存在。线性地址到物理地址的转换过程中，页面不存在将会
				 * 导致缺页异常。
				 * 	R/W: 读写标志，等于 1 表示页面可被读、写或执行，等于 0 表示页面只读或
				 * 可执行，向一个不可写的页面执行写操作时会产生页写保护异常。
				 *	U/S: 等于 1 表示该页面是用户级页面，等于0 表示该页面是超级用户级页面。
				 *	A: 已访问标志，处理器访问该页面时，该标志会被置 1。
				 *	D: 页面已修改(Dirty)标志，对一个页面执行写操作时会设置该位，处理器并
				 * 不会修改页目录项中的 D 标志。
				 */
				/*
				 * 	开启分页机制之后的地址变换过程:
				 *
				 * 	处理器发出的始终是线性地址，未开启分页时，线性地址与物理地址相同，无需
				 * 转换。开启分页后，线性地址要经过 MMU 的转换才能知道并访问最终的物理地址，MMU
				 * 使用操作系统设置在内存中的页目录表和页表完成线性地址到物理地址之间的转换。
				 *
				 * 	1. 32 位的线性地址被分割为 3 部分，按最高 10bit，中间 10bit，和最低
				 * 12bit 分割，页目录表的物理地址保存在 CR3 中。
				 *
				 * 	2. 最高 10bit 用于选择页目录表 1024 个页目录项中的其中一个页目录项。由
				 * 这个页目录项来获取到页目录项所指向的页表的物理内存基地址。
				 *
				 * 	3. 获取到页表后，用中间 10bit 选择页表 1024 个页表项中的其中一个页表项。
				 * 由这个页表项来获取到页表项所指向的真正物理内存页面的基地址。
				 *
				 * 	4. 获取到物理内存页面之后，用最低 12bit 作为页内偏移，加到物理内存页面
				 * 基地址上形成最终的物理内存地址。
				 *
				 *	以执行完 setup_paging 之后的状态为准，以处理器发出线性地址 0xC03FF408
				 * 为例，描述地址转换的过程:
				 *
				 * 	1. MMU从页目录表基地址寄存器 CR3 中取得页目录表基地址，
				 * CR3 = 0x00001000(swapper_pg_dir)。线性地址被分割为 3 部分，分别是最高 10bit
				 * 为 0x300(0b1100000000)，中间 10bit 为 0x3FF(0b1111111111)，最低 12bit 为 0x408。
				 *
				 * 	2. 最高 10bit 0x300选择页目录表中的第 768 个页目录项，由这个页目录项获取
				 * 该页目录项所指向的页表的物理内存页面基地址为 0x00002000(pg0)。
				 *
				 * 	3. 获取到页表后，用中间 10bit 0x3FF 选择页表中的第 1023 个页表项。由这个
				 * 页表项获取到页表项所指向的真正物理内存页面的基地址 0x003ff000。
				 *
				 * 	4. 物理内存页面基地址 + 线性地址最低 12bit 的页内偏移，得到最终的物理内存
				 * 地址。线性地址 0xC03FF408 ===> 物理地址 0x003FF408。
				 */
/*
 * Setup_paging
 *
 * This routine sets up paging by setting the page bit
 * in cr0. The page tables are set up, identity-mapping
 * the first 4MB.  The rest are initialized later.
 *
 * (ref: added support for up to 32mb, 17Apr92)  -- Rik Faith
 * (ref: update, 25Sept92)  -- croutons@crunchy.uucp 
 * (ref: 92.10.11 - Linus Torvalds. Corrected 16M limit - no upper memory limit)
 */
.align 2
setup_paging:
	movl $1024*2,%ecx		/* 2 pages - swapper_pg_dir+1 page table */
	xorl %eax,%eax
	movl $_swapper_pg_dir,%edi	/* swapper_pg_dir is at 0x1000 */
	cld;rep;stosl
				/*
				 * 	对两页内存空间(swapper_pg_dir 和 pg0，共 8kB)清 0。
				 */
/* Identity-map the kernel in low 4MB memory for ease of transition */
	movl $_pg0+7,_swapper_pg_dir		/* set present bit/user r/w */
/* But the real place is at 0xC0000000 */
	movl $_pg0+7,_swapper_pg_dir+3072	/* set present bit/user r/w */
				/*
				 * 	1. 设置页目录表中的第 0 个页目录项，该页目录项所指向的页表为 pg0，
				 * 该页目录项映射的线性地址空间为 0 - 4MB。
				 *
				 * 	2. 设置页目录表中的第 768 个页目录项，该页目录项指向的页表为 pg0。
				 * 该页目录项映射的线性地址空间为 0xC0000000(3GB) 开始的 4MB 空间。
				 *
				 * 	线性地址空间中的 0 - 4MB 和 0xC0000000 开始的 4MB 所对应的两个
				 * 页目录项的内容都为 0x00002007，都指向同一个页表 pg0，也就意味着这两个
				 * 4MB 的线性地址空间将映射到相同的物理地址空间上。后面会设置 pg0 中的
				 * 页表项，最终将两个 4MB 的线性地址空间映射到物理地址空间的 0 - 4MB 上。
				 *
				 * 	这样做的原因:
				 *
				 * 	1. 设置完页目录表和页表之后会开启分页，分页开启之后处理器发出的
				 * 所有的线性地址都需要经过 MMU 的转换才能访问物理内存。
				 *
				 * 	2. 开启分页时，GDTR 中的值还未重新设置，还是 setup 中设置的那个值，
				 * 因此内核代码段的线性基地址还是 0，处理器发出的线性地址还是基于 0 的线性
				 * 地址。所以需要先建立线性地址 0 开始的一段空间的映射，此处映射 4MB 的
				 * 空间而已，当然也可以映射更多的空间，但没什么用处。
				 *
				 * 	3. 后面会重新加载 GDTR，加载后内核代码段的线性基地址变为 0xC0000000，
				 * 这时候处理器发出的线性地址是基于 0xC0000000 开始的线性地址。所以需要先
				 * 建立线性地址 0xC0000000 开始的一段空间的映射。同样是 4MB。
				 *
				 * 	4. 不管处理器发出的线性地址是基于 0 的还是基于 0xC0000000 的，所访问
				 * 的代码和数据都是一样的，因此需要将他们映射到相同的物理内存空间上。而这些
				 * 代码和数据已经存在于物理内存的 0 - 4MB 的空间上，所以将两个 4MB 的线性地址
				 * 直接映射到此处。
				 *
				 * 	此处只设置两个 4MB 的映射，其余的线性地址空间在后面映射，从这个地方
				 * 开始到后面重新映射其它的线性地址空间，4MB 的空间足够了，此处没有必要映射
				 * 更多的线性地址空间。
				 */
	movl $_pg0+4092,%edi
	movl $0x03ff007,%eax		/*  4Mb - 4096 + 7 (r/w user,p) */
	std
1:	stosl			/* fill the page backwards - more efficient :-) */
	subl $0x1000,%eax
	jge 1b
				/*
				 * 	设置页表 pg0 中的 1024 个页表项: 从最后一个页表项开始往前设置，
				 * 每个页表项中的内容是当前项所映射的物理页面基地址 + 该页面的标志 7。
				 *
				 * 	页表 pg0 映射物理内存的 0 - 4MB，最后一个页表项对应的物理内存页面
				 * 基地址是 0x3ff000，和页面标志组合在一起就是 0x3ff007。第一个页表项对应
				 * 的物理内存页面基地址是 0x000000，和页面标志组合在一起就是 0x000007。
				 */
	cld
	movl $_swapper_pg_dir,%eax
	movl %eax,%cr3			/* cr3 - page directory start */
				/*
				 * 	CR3 是页目录基地址寄存器 PDBR，其中保存页目录表物理内存基地址。
				 * 将 swapper_pg_dir 标号所表示的地址的高 20 位装入 CR3 中，CR3 低 12
				 * 位保留。
				 *
				 * 	加载后 CR3 = 0x00001000。
				 */
	movl %cr0,%eax
	orl $0x80000000,%eax
	movl %eax,%cr0		/* set paging (PG) bit */
	ret			/* this also flushes the prefetch-queue */
				/*
				 * 	设置 CR0 的 PG 位，开启分页机制，与 PE 一样，设置 PG 后需紧跟一条
				 * 跳转指令以刷新已经预取的指令序列，但函数返回指令 ret 同样可以刷新当前
				 * 指令序列，因此不再有跳转指令，由 ret 指令来完成刷新工作。
				 */

/*
 * page 0 is made non-existent, so that kernel NULL pointer references get
 * caught. Thus the swapper page directory has been moved to 0x1000
 *
 * XXX Actually, the swapper page directory is at 0x1000 plus 1 megabyte,
 * with the introduction of the compressed boot code.  Theoretically,
 * the original design of overlaying the startup code with the swapper
 * page directory is still possible --- it would reduce the size of the kernel
 * by 2-3k.  This would be a good thing to do at some point.....
 */
/*
 * 	从上面的注释可知:
 *
 * 	1. 页 0 不存在，也就是物理内存 0 开始的 4kB 空间未使用，主要是为了捕获内核
 * 空指针引用，因此 setup 在搬移 system 的时候，并未将 system 搬移到 0 地址处，而是
 * 搬移到了 0x1000 开始的地方。
 *
 * 	2. 页交换目录被放置在 0x1000 处，这个位置也是 head 代码开始的位置，所以在
 * 设置页目录表的时候会覆盖掉这部分代码。因为初始化时只设置了页目录表的第 0 项和第
 * 768 项，所以对 head 的代码执行并不会产生什么影响。
 *
 * 	3. 如果引入了压缩引导代码技术，交换页目录表将会放置在 0x00101000 处。
 */
.org 0x1000
_swapper_pg_dir:
				/*
				 * 	swapper_pg_dir: 物理内存地址 0x1000，是页目录表，一个页目录表有 1024 个
				 * 页目录项，每个页目录项可映射 4MB 的线性地址空间，故一个页目录表可映射 4GB 的
				 * 线性地址空间。初始化时只映射线性地址空间的 0 - 4MB 和 0xC0000000 开始的 4MB。
				 *
				 * 	初始化后，页目录表中的内容:
				 *
				 * 	编号	页目录项内容	指向的页表地址	  页目录项指向的页表所在页面的属性
				 *	 0	0x00002007	0x00002000 (pg0)	7 (用户 | 可读写 | 存在)
				 *	 1	0x00000000				0 (不存在)
				 *	 2	0x00000000				0 (不存在)
				 *	 .	.		.
				 *	768	0x00002007	0x00002000 (pg0)	7 (用户 | 可读写 | 存在)
				 *	 .	.		.
				 *	1023	0x00000000				0 (不存在)
				 */

/*
 * The page tables are initialized to only 4MB here - the final page
 * tables are set up later depending on memory size.
 */
.org 0x2000
_pg0:
				/*
				 * 	pg0: 物理内存地址 0x2000，是页目录表的第一个页表，用于将线性地址空间
				 * 的 0 - 4MB 和 0xC0000000(3GB) 开始的 4MB 映射到物理地址空间的 0 - 4MB。
				 *
				 * 	初始化后，页表中的内容:
				 *
				 * 	编号	页表项内容	指向的物理内存地址	被映射的物理内存页面的属性
				 * 	 0	0x00000007	0x00000000 (0)		7 (用户 | 可读写 | 存在)
				 * 	 1	0x00001007	0x00001000 (4kB)	7
				 *	 2	0x00002007	0x00002000 (8kB)	7
				 * 	 .	    .			.		.
				 * 	 .	    .			.		.
				 * 	 .	    .			.		.
				 *	1023	0x003ff007	0x003ff000 (4MB - 4kB)	7
				 */

.org 0x3000
_empty_bad_page:
				/*
				 * 	_empty_bad_page: 4kB，暂未知。
				 */

.org 0x4000
_empty_bad_page_table:
				/*
				 * 	_empty_bad_page_table: 4kB，暂未知。
				 */

.org 0x5000
_empty_zero_page:
				/*
				 * 	_empty_zero_page: 存放启动参数和命令行参数，分别占前后 2kB 空间，外部
				 * 通过符号 empty_zero_page 访问这块空间。
				 */

.org 0x6000
/*
 * tmp_floppy_area is used by the floppy-driver when DMA cannot
 * reach to a buffer-block. It needs to be aligned, so that it isn't
 * on a 64kB border.
 */
_tmp_floppy_area:
	.fill 1024,1,0
				/*
				 * 	0x6000 开始的 1kB 内存预留给软盘驱动程序使用。外部通过符号
				 * tmp_floppy_area 来访问这块空间。
				 */
/*
 * floppy_track_buffer is used to buffer one track of floppy data: it
 * has to be separate from the tmp_floppy area, as otherwise a single-
 * sector read/write can mess it up. It can contain one full track of
 * data (18*2*512 bytes).
 */
_floppy_track_buffer:
	.fill 512*2*18,1,0
				/*
				 * 	紧接着 tmp_floppy_area 之后的 18kB 内存预留给软驱程序使用，用于
				 * 存储一个完整磁道的数据。外部通过符号 floppy_track_buffer 来访问这块空间。
				 */

/* This is the default interrupt "handler" :-) */
int_msg:
	.asciz "Unknown interrupt\n"
.align 2
ignore_int:
	cld
	pushl %eax
	pushl %ecx
	pushl %edx
	push %ds
	push %es
	push %fs
	movl $(KERNEL_DS),%eax
	mov %ax,%ds
	mov %ax,%es
	mov %ax,%fs
	pushl $int_msg
	call _printk
	popl %eax
	pop %fs
	pop %es
	pop %ds
	popl %edx
	popl %ecx
	popl %eax
	iret
				/*
				 * 	ignore_int: 系统默认的中断处理函数，只输出 "Unknown interrupt\n"
				 * 之后就退出，其它什么也不做。
				 */

/*
 * The interrupt descriptor table has room for 256 idt's
 */
.align 4
.word 0
idt_descr:
	.word 256*8-1		# idt contains 256 entries
	.long 0xc0000000+_idt
				/*
				 * 	idt_descr: 此处的 6 个字节将被 lidt 指令加载到中断描述符表寄存器
				 * IDTR 中，前两个字节表示 IDT 表的长度，后四个字节表示 IDT 表在线性地址
				 * 空间中的线性基地址，位于 0xC0000000(3GB) 开始的内核空间中。
				 */

.align 4
_idt:
	.fill 256,8,0		# idt is uninitialized
				/*
				 * 	_idt: 中断描述符表的位置，共占用 2kB 的内存空间。
				 */

.align 4
.word 0
gdt_descr:
	.word (8+2*NR_TASKS)*8-1
	.long 0xc0000000+_gdt
				/*
				 * 	gdt_descr: 此处的 6 个字节将被 lgdt 指令加载到全局描述符表寄存器
				 * GDTR 中，前两个字节表示 GDT 表的长度，后四个字节表示 GDT 表在线性地址
				 * 空间中的线性基地址，位于 0xC0000000(3GB) 开始的内核空间中。
				 */

/*
 * This gdt setup gives the kernel a 1GB address space at virtual
 * address 0xC0000000 - space enough for expansion, I hope.
 */
.align 4
_gdt:
	.quad 0x0000000000000000	/* NULL descriptor */
	.quad 0x0000000000000000	/* not used */
	.quad 0xc0c39a000000ffff	/* 0x10 kernel 1GB code at 0xC0000000 */
	.quad 0xc0c392000000ffff	/* 0x18 kernel 1GB data at 0xC0000000 */
	.quad 0x00cbfa000000ffff	/* 0x23 user   3GB code at 0x00000000 */
	.quad 0x00cbf2000000ffff	/* 0x2b user   3GB data at 0x00000000 */
	.quad 0x0000000000000000	/* not used */
	.quad 0x0000000000000000	/* not used */
	.fill 2*NR_TASKS,8,0		/* space for LDT's and TSS's etc */
				/*
				 * 	_gdt: GDT 表的位置，由段描述符组成，每个段描述符占 8 字节，描述段
				 * 的线性基地址，大小等信息。第 0 和 第 1 个描述符未使用。
				 *
				 * 	第二个描述符是内核代码段的描述符，由段选择符 0x10 选择该描述符，
				 * 描述符的信息指明: 内核代码段的线性基地址为 0xC0000000，段限长为 1GB，
				 * 是一个可执行代码段，该段已存在于内存中，段的特权等级为 0，可读可执行。
				 *
				 * 	第三个描述符是内核数据段的描述符，由段选择符 0x18 选择该描述符，
				 * 描述符的信息指明: 内核数据段的线性基地址为 0xC0000000，段限长为 1GB，
				 * 是一个数据段，该段已存在于内存中，段的特权等级为 0，可读写。
				 *
				 * 	第三个描述符是用户代码段的描述符，由段选择符 0x23 选择该描述符，
				 * 描述符的信息指明: 用户数据段的线性基地址为 0x00000000，段限长为 3GB，
				 * 是一个可执行代码段，该段已存在于内存中，段的特权等级为 3，可读可执行。
				 *
				 * 	第四个描述符是用户数据段的描述符，由段选择符 0x2B 选择该描述符，
				 * 描述符的信息指明: 用户数据段的线性基地址为 0x00000000，段限长为 3GB，
				 * 是一个数据段，该段已存在于内存中，段的特权等级为 3，可读写。
				 *
				 * 	第六和七两个描述符也未使用。
				 *
				 * 	从第八个描述符开始，将是任务相关的描述符，用于描述任务的 LDT 段和
				 * TSS 段，每个任务占用两个描述符，目前这些描述符都是 0。
				 */

				/*
				 *	x86 处理器有 4 个特权等级，Linux 内核只使用 0 和 3 两个特权等级。
				 * 分别表示内核态和用户态，0 是最高特权等级，3 是最低特权等级。
				 *
				 *	段的特权等级表示处理器要访问这个段所需要的最低特权等级。故只有当
				 * 处理器处于 0 特权级时才能访问内核代码段和内核数据段，处理器要访问用户
				 * 代码段和用户数据段，只需要处理器的特权等级 >= 3 即可。
				 *
				 *	因此，当处理器执行内核代码时，处理器特权等级为 0，处理器同时也可以
				 * 访问用户空间中的代码和数据。当处理器执行用户代码时，处理器特权等级为 3，
				 * 这时处理器只能访问用户空间中的代码和数据，不能访问内核空间中的代码及数据。
				 */

				/*
				 *	一个任务，有内核态和用户态之分，内核态表明处理器正在执行内核空间中的
				 * 代码，用户态表明处理器正在执行用户空间中的代码。从操作系统的角度看，内核
				 * 空间被所有任务共享，因为系统只有一个内核代码段和一个内核数据段，而可以有
				 * 很多个用户代码段和用户数据段。从用户任务的角度看，内核空间被任务独占，因为
				 * 每个任务都可以访问内核空间。
				 *
				 *	一个任务的内核态和用户态的区别:
				 *	【内核态】: 处理器特权特权为 0，使用任务对应的内核态栈，可访问内核段
				 * 及用户段。
				 *	【用户态】: 处理器特权等级为 3，使用任务对应的用户态栈，只能访问用户
				 * 段，不能访问内核段。
				 *	【中  断】: 处理器特权等级为 0，使用任务对应的内核态栈，可访问内核段
				 * 及用户段。中断处理函数位于内核段中。因此任务被中断的情况，可以看做是任务
				 * 处于内核态。
				 *
				 *	每个任务在内核态都有独立的内核态的栈，这个栈的位置在创建任务时就已经
				 * 产生了，栈在任务进入内核态时使用，在任务退出内核态时清空，下一次进入内核态
				 * 时从头开始使用。因为有独立的内核态栈的存在，所以可以保证所有任务访问同一套
				 * 内核空间而互不影响。
				 */
