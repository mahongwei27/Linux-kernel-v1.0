/*
 *	Start here !!!
 */

/*
 * 	PC上电启动后，CPU自动进入实地址模式，并从地址 0xFFFF0 处开始执行代码，
 * 这里的代码通常是 BIOS 程序，BIOS 执行时会在物理 0 地址处初始化中断向量，这个
 * 中断向量是 BIOS 使用的中断向量，同时也是 bootsect.S 程序使用的中断向量。
 * 	BIOS 执行的最后，会将启动设备的第一个扇区，也就是引导扇区中的 512B 读入
 * 内存绝对地址 0x7C00(31KB) 处，并跳转到这个地址处执行。
 */

/*
 *	启动设备: 存放的是 build 程序制作出来的系统镜像，系统镜像中位于第一个
 * 扇区的是 bootsect，随后四个扇区是 setup，紧接 setup 的是 system 模块。关于
 * 根文件系统，有两种做法，一种做法是根文件系统紧接在 system 模块之后，这种
 * 情况下，启动设备的组成是: 【bootsect + setup + system + 根文件系统】。
 * 另一种做法是根文件系统使用一个单独的设备，这种情况下，组成是:
 * 启动设备 --- 【bootsect + setup + system】
 * 根文件系统设备 --- 【根文件系统】
 *
 *	bootsect 主要用于从软盘启动系统，即启动设备为软盘时会用到 bootsect，
 * 若要从硬盘设备启动系统，则 bootsect 程序就不会被执行了，会由 GRUB 等引导
 * 程序引导系统启动，bootsect 所完成的任务会由这些程序来完成。
 */

/*
 * 	本文件中的代码就是引导扇区中的代码，BIOS 最后会将本文件中的 512B 的代码
 * 读入到内存的 0x7C00 处，并跳转到本文件的 _main 标号所示的地址处执行。
 */

!
! SYS_SIZE is the number of clicks (16 bytes) to be loaded.
! 0x7F00 is 0x7F000 bytes = 508kB, more than enough for current
! versions of linux which compress the kernel
!
#include <linux/config.h>
SYSSIZE = DEF_SYSSIZE
!
!	bootsect.s		Copyright (C) 1991, 1992 Linus Torvalds
!	modified by Drew Eckhardt
!	modified by Bruce Evans (bde)
!
! bootsect.s is loaded at 0x7c00 by the bios-startup routines, and moves
! itself out of the way to address 0x90000, and jumps there.
!
! bde - should not jump blindly, there may be systems with only 512K low
! memory.  Use int 0x12 to get the top of memory, etc.
!
! It then loads 'setup' directly after itself (0x90200), and the system
! at 0x10000, using BIOS interrupts. 
!
! NOTE! currently system is at most (8*65536-4096) bytes long. This should 
! be no problem, even in the future. I want to keep it simple. This 508 kB
! kernel size should be enough, especially as this doesn't contain the
! buffer cache as in minix (and especially now that the kernel is 
! compressed :-)
!
! The loader has been made as simple as possible, and continuos
! read errors will result in a unbreakable loop. Reboot by hand. It
! loads pretty fast by getting whole tracks at a time whenever possible.

.text

SETUPSECS = 4				! nr of setup-sectors
BOOTSEG   = 0x07C0			! original address of boot-sector
INITSEG   = DEF_INITSEG			! we move boot here - out of the way
SETUPSEG  = DEF_SETUPSEG		! setup starts here
SYSSEG    = DEF_SYSSEG			! system loaded at 0x10000 (65536).

! ROOT_DEV & SWAP_DEV are now written by "build".
ROOT_DEV = 0
SWAP_DEV = 0
#ifndef SVGA_MODE
#define SVGA_MODE ASK_VGA
#endif
#ifndef RAMDISK
#define RAMDISK 0
#endif 
#ifndef CONFIG_ROOT_RDONLY
#define CONFIG_ROOT_RDONLY 0
#endif

! ld86 requires an entry symbol. This may as well be the usual one.
.globl	_main
_main:								/* 本文件中的代码开始执行的位置 */
#if 0 /* hook for debugger, harmless unless BIOS is fussy (old HP) */
	int	3
#endif
	mov	ax,#BOOTSEG
	mov	ds,ax
	mov	ax,#INITSEG
	mov	es,ax
	mov	cx,#256
	sub	si,si
	sub	di,di
	cld
	rep
	movsw
	jmpi	go,INITSEG
				/*
				 * 	以上代码完成的功能是: 将自己从内存的 0x7C00(31KB) 处复制到内存的
				 * 0x90000(576KB) 处，并跳转到 [0x90000 + go] 的位置处执行。
				 */
				/*
				 * 	以下从 go 标号开始的代码将从 0x90000 开始的地址中执行，原来 0x7C00
				 * 处的代码已经无用了。
				 */
go:	mov	ax,cs		
	mov	dx,#0x4000-12	! 0x4000 is arbitrary value >= length of
				! bootsect + length of setup + room for stack
				! 12 is disk parm size

! bde - changed 0xff00 to 0x4000 to use debugger at 0x6400 up (bde).  We
! wouldn't have to worry about this if we checked the top of memory.  Also
! my BIOS can be configured to put the wini drive tables in high memory
! instead of in the vector table.  The old stack might have clobbered the
! drive table.

	mov	ds,ax
	mov	es,ax
	mov	ss,ax		! put stack at INITSEG:0x4000-12.
	mov	sp,dx
				/*
				 * 	上面两行代码用于设置 SS:SP，也就是栈的位置，位于【0x94000 - 12】
				 * 地址处，12字节用于存放软驱参数表。
				 * 	最终设置好的栈的位置 SS:SP = 0x93FF4 = 约592kB处，(0x94000 = 592kB)
				 * 在未重新设置栈之前，后面执行的代码都将使用这个栈。
				 * 	代码结束的位置在576.5kB处，栈开始的位置在约592kB处，栈的大小约为
				 * 15.5KB不到。
				 */
/*
 *	Many BIOS's default disk parameter tables will not 
 *	recognize multi-sector reads beyond the maximum sector number
 *	specified in the default diskette parameter tables - this may
 *	mean 7 sectors in some cases.
 *
 *	Since single sector reads are slow and out of the question,
 *	we must take care of this by creating new parameter tables
 *	(for the first disk) in RAM.  We will set the maximum sector
 *	count to 18 - the most we will encounter on an HD 1.44.  
 *
 *	High doesn't hurt.  Low does.
 *
 *	Segments are as follows: ds=es=ss=cs - INITSEG,
 *		fs = 0, gs = parameter table segment
 */

	push	#0
	pop	fs
	mov	bx,#0x78		! fs:bx is parameter table address
	seg fs
	lgs	si,(bx)			! gs:si is source

	mov	di,dx			! es:di is destination
	mov	cx,#6			! copy 12 bytes
	cld

	rep
	seg gs
	movsw

	mov	di,dx
	movb	4(di),*18		! patch sector count

	seg fs
	mov	(bx),di
	seg fs
	mov	2(bx),es

	mov	ax,cs
	mov	fs,ax
	mov	gs,ax
	
	xor	ah,ah			! reset FDC 
	xor	dl,dl
	int 	0x13	
				/*
				 * 	BIOS设置的 0x1E 号中断的中断向量值是软驱参数表地址，该向量值位于
				 * 0x1E * 4 = 0x78地址处，上面这部分代码，主要完成以下工作:
				 * 	1. 从内存 0x00078 地址处复制12字节的原软驱参数表到 0x93FF4 地址处。
				 *	2. 修改 0x93FF4 地址处的软驱参数表中的每磁道最大扇区数为 18。
				 *	3. 让 0x1E 向量指向 0x93FF4，也就是指向新软驱参数表。
				 * 	4. 通过中断 int 0x13 复位软盘控制器，使其采用新参数，后续对软盘的
				 * 操作都将使用新参数。
				 *
				 * 	一句话，就是为了更改软盘控制器参数中的每磁道最大扇区数。因为0地址处
				 * 的中断向量表在后面很快就会被覆盖，而软驱参数需要在程序运行过程中一直使用
				 * 到，所以需要给它重新找一个位置保存起来。
				 */

! load the setup-sectors directly after the bootblock.
! Note that 'es' is already set up.

load_setup:
	xor	dx, dx			! drive 0, head 0
	mov	cx,#0x0002		! sector 2, track 0
	mov	bx,#0x0200		! address = 512, in INITSEG
	mov	ax,#0x0200+SETUPSECS	! service 2, nr of sectors
					! (assume all on head 0, track 0)
	int	0x13			! read it
	jnc	ok_load_setup		! ok - continue

	push	ax			! dump error code
	call	print_nl
	mov	bp, sp
	call	print_hex
	pop	ax	
	
	xor	dl, dl			! reset FDC
	xor	ah, ah
	int	0x13
	jmp	load_setup
				/*
				 * 	load_setup: 加载 setup.S 中的程序，setup.S 中的程序最后会被放置到软盘
				 * 第二个扇区开始的4个扇区中，共占用 2kB 的空间。当然，第一个扇区存放的是
				 * bootsect.S 程序，已经位于 0x90000 地址处，且正在执行。
				 *	这段代码将4个扇区 2kB 的 setup.S 程序从软盘加载到内存的 0x90200 地址处。
				 * 也就是内存中连着 bootsect.S 的后面存放。
				 * 	将 setup.S 放到 bootsect.S 之后，栈的大小就剩大约 13.5kB 不到了。
				 *
				 * 	加载的过程中如果出错，会显示错误信息并复位软盘控制器并重新加载，直到
				 * 加载成功为止。
				 */

ok_load_setup:

! Get disk drive parameters, specifically nr of sectors/track

#if 0

! bde - the Phoenix BIOS manual says function 0x08 only works for fixed
! disks.  It doesn't work for one of my BIOS's (1987 Award).  It was
! fatal not to check the error code.

	xor	dl,dl
	mov	ah,#0x08		! AH=8 is get drive parameters
	int	0x13
	xor	ch,ch
#else

! It seems that there is no BIOS call to get the number of sectors.  Guess
! 18 sectors if sector 18 can be read, 15 if sector 15 can be read.
! Otherwise guess 9.

	xor	dx, dx			! drive 0, head 0
	mov	cx,#0x0012		! sector 18, track 0
	mov	bx,#0x0200+SETUPSECS*0x200  ! address after setup (es = cs)
	mov	ax,#0x0201		! service 2, 1 sector
	int	0x13
	jnc	got_sectors
	mov	cl,#0x0f		! sector 15
	mov	ax,#0x0201		! service 2, 1 sector
	int	0x13
	jnc	got_sectors
	mov	cl,#0x09

#endif

got_sectors:
	seg cs
	mov	sectors,cx
	mov	ax,#INITSEG
	mov	es,ax
				/*
				 * 	以上代码: 取软盘驱动器的参数，实际上是取每磁道扇区数，然后将取到的
				 * 每磁道扇区数保存在 sectors 处，sectors 定义在本文件接近尾部的位置，sectors
				 * 中的值会在下面确定系统根设备时使用到。
				 *
				 * 	每磁道扇区数有18、15、9三种取值，通过尝试相应编号的扇区是否可读来
				 * 确定每磁道扇区数到底是多少。
				 *
				 * 	此处取到的是 bootsect 所在的软盘设备的每磁道扇区数。也就是系统镜像
				 * 所在设备的每磁道扇区数，换句话说，也就是启动设备的每磁道扇区数。
				 */

! Print some inane message

	mov	ah,#0x03		! read cursor pos
	xor	bh,bh
	int	0x10
	
	mov	cx,#9
	mov	bx,#0x0007		! page 0, attribute 7 (normal)
	mov	bp,#msg1
	mov	ax,#0x1301		! write string, move cursor
	int	0x10
				/*
				 * 	以上8行代码: 在屏幕上显示 Loading
				 */

! ok, we've written the message, now
! we want to load the system (at 0x10000)

	mov	ax,#SYSSEG
	mov	es,ax		! segment of 0x010000
	call	read_it
	call	kill_motor
	call	print_nl
				/*
				 * 	除了 bootsect.S 和 setup.S 以外的所有程序，统称为 system 模块，包括
				 * head.S  main.c  ......
				 *
				 * 	system 模块最后会被放在软盘第6个扇区开始的位置处，也就是 setup.S
				 * 的后面，最大大小为 508kB。
				 *
				 * 	上面5行代码: 通过调用 reat_it 将 system 模块加载到 0x10000 地址处，也就是
				 * 64kB 处，bootsect 位于576kB处，即便system以最大大小508kB加载，加载后离
				 * bootsect 还有 576 - 508 - 64 = 4kB 的距离。
				 *
				 * 	此处只是加载 system 模块到内存中，当 setup 执行时会将 system 从 0x10000
				 * 地址处搬移到内存 0 地址处，进而覆盖掉 BIOS 设置在 0 地址处的中断向量表，
				 * 此处不直接加载到 0 地址处是因为 BIOS 设置在 0 地址处的中断向量表还有用。
				 */

! After that we check which root-device to use. If the device is
! defined (!= 0), nothing is done and the given device is used.
! Otherwise, either /dev/PS0 (2,28) or /dev/at0 (2,8), depending
! on the number of sectors that the BIOS reports currently.

	seg cs
	mov	ax,root_dev
	or	ax,ax
	jne	root_defined
	seg cs
	mov	bx,sectors
	mov	ax,#0x0208		! /dev/ps0 - 1.2Mb
	cmp	bx,#15
	je	root_defined
	mov	ax,#0x021c		! /dev/PS0 - 1.44Mb
	cmp	bx,#18
	je	root_defined
	mov	ax,#0x0200		! /dev/fd0 - autodetect
root_defined:
	seg cs
	mov	root_dev,ax
				/*
				 * 	以上代码: 确定系统的根设备，并将最终确定好的根设备号重新写回到
				 * root_dev 处，root_dev 被定义在本文件尾部的位置处。
				 *
				 * 	build 程序用于创建系统镜像文件 Image，创建过程中，build 会根据
				 * 我们在 Makefile 中指定的根设备号填充 root_dev，如果我们没有指定或者
				 * 指定了非法的根设备，则 root_dev 处会被填入0，而0是一个无效的设备号，
				 * 因此需要在此处对 root_dev 做检测。
				 *
				 * 	如果 root_dev 不为0，则说明 build 已经在 root_dev 处填入了一个合法
				 * 的根设备号，则此处直接将这个设备号重新写回 root_dev 处，相当于什么也
				 * 没做。
				 * 	如果 root_dev = 0，则此处强制重新设置 root_dev，使根文件系统所在
				 * 设备为当前系统镜像所在的设备，也就是启动设备，这时启动设备的布局就是:
				 * 【bootsect + setup + system + 根文件系统】。
				 * 	当前设备的每磁道扇区数已经在前面获取到了，此处再根据具体的扇区数
				 * 来确定启动设备的设备号即可。
				 */

! after that (everyting loaded), we jump to
! the setup-routine loaded directly after
! the bootblock:

	jmpi	0,SETUPSEG
				/*
				 * 	这是 bootsect 程序结束的位置，跳转到 0x90200 处执行 setup.S 程序。
				 *
				 * 至此:
				 *	1. bootsect 将自己从 0x7C00 处搬移到了 0x90000 处，并执行完毕。
				 *	2. 启动过程中所使用的栈已经设置完成，位于 0x93FF4 处向下生长。
				 *	3. 软盘驱动器参数表已被放到了新位置，并更改了相关信息，也已使用
				 * 新的参数了。
				 *	4. 4个扇区的 setup 已被加载到了 0x90200 处。
				 *	5. system 模块已经被加载到了 0x10000 处。
				 *	6. 系统需要的根文件系统的设备号也已最终确定。
				 *
				 * 	下一步，跳转到位于 0x90200 处的 setup 中去执行，setup 会将位于
				 * 0x10000 处的 system 模块搬移到 0 地址处，setup 执行完后，跳转到 system
				 * 模块的 head.S 中去执行。
				 */

! This routine loads the system at address 0x10000, making sure
! no 64kB boundaries are crossed. We try to load it as fast as
! possible, loading whole tracks whenever we can.
!
! in:	es - starting address segment (normally 0x1000)
!
sread:	.word 1+SETUPSECS	! sectors read of current track
head:	.word 0			! current head
track:	.word 0			! current track

read_it:	/* 将 system 模块加载到 0x10000 地址处 */
	mov ax,es
	test ax,#0x0fff
die:	jne die			! es must be at 64kB boundary
	xor bx,bx		! bx is starting address within segment
rp_read:
	mov ax,es
	sub ax,#SYSSEG
	cmp ax,syssize		! have we loaded all yet?
	jbe ok1_read
	ret
ok1_read:
	seg cs
	mov ax,sectors
	sub ax,sread
	mov cx,ax
	shl cx,#9
	add cx,bx
	jnc ok2_read
	je ok2_read
	xor ax,ax
	sub ax,bx
	shr ax,#9
ok2_read:
	call read_track
	mov cx,ax
	add ax,sread
	seg cs
	cmp ax,sectors
	jne ok3_read
	mov ax,#1
	sub ax,head
	jne ok4_read
	inc track
ok4_read:
	mov head,ax
	xor ax,ax
ok3_read:
	mov sread,ax
	shl cx,#9
	add bx,cx
	jnc rp_read
	mov ax,es
	add ah,#0x10
	mov es,ax
	xor bx,bx
	jmp rp_read

read_track:
	pusha
	pusha	
	mov	ax, #0xe2e 	! loading... message 2e = .
	mov	bx, #7
 	int	0x10
	popa		

	mov	dx,track
	mov	cx,sread
	inc	cx
	mov	ch,dl
	mov	dx,head
	mov	dh,dl
	and	dx,#0x0100
	mov	ah,#2
	
	push	dx				! save for error dump
	push	cx
	push	bx
	push	ax

	int	0x13
	jc	bad_rt
	add	sp, #8
	popa
	ret

bad_rt:	push	ax				! save error code
	call	print_all			! ah = error, al = read
	
	
	xor ah,ah
	xor dl,dl
	int 0x13
	

	add	sp, #10
	popa	
	jmp read_track

/*
 *	print_all is for debugging purposes.  
 *	It will print out all of the registers.  The assumption is that this is
 *	called from a routine, with a stack frame like
 *	dx 
 *	cx
 *	bx
 *	ax
 *	error
 *	ret <- sp
 *
*/
 
print_all:
	mov	cx, #5		! error code + 4 registers
	mov	bp, sp	

print_loop:
	push	cx		! save count left
	call	print_nl	! nl for readability

	cmp	cl, 5
	jae	no_reg		! see if register name is needed
	
	mov	ax, #0xe05 + 'A - 1
	sub	al, cl
	int	0x10

	mov	al, #'X
	int	0x10

	mov	al, #':
	int	0x10

no_reg:
	add	bp, #2		! next register
	call	print_hex	! print it
	pop	cx
	loop	print_loop
	ret

print_nl:
	mov	ax, #0xe0d	! CR
	int	0x10
	mov	al, #0xa	! LF
	int 	0x10
	ret

/*
 *	print_hex is for debugging purposes, and prints the word
 *	pointed to by ss:bp in hexadecmial.
*/

print_hex:
	mov	cx, #4		! 4 hex digits
	mov	dx, (bp)	! load word into dx
print_digit:
	rol	dx, #4		! rotate so that lowest 4 bits are used
	mov	ah, #0xe	
	mov	al, dl		! mask off so we have only next nibble
	and	al, #0xf
	add	al, #'0		! convert to 0-based digit
	cmp	al, #'9		! check for overflow
	jbe	good_digit
	add	al, #'A - '0 - 10

good_digit:
	int	0x10
	loop	print_digit
	ret


/*
 * This procedure turns off the floppy drive motor, so
 * that we enter the kernel in a known state, and
 * don't have to worry about it later.
 */
kill_motor:		/* 关闭软盘驱动器的马达震动 */
	push dx
	mov dx,#0x3f2
	xor al, al
	outb
	pop dx
	ret

sectors:
	.word 0		/* 存放系统镜像所在设备(启动设备，软盘)的每磁道扇区数 */

msg1:
	.byte 13,10
	.ascii "Loading"

				/*
				 * 下面是 bootsect 所在扇区的 512B 中的最后 14 字节
				 */
.org 498
root_flags:
	.word CONFIG_ROOT_RDONLY	/* 根文件系统是否是只读的，默认为0，用户在 Makefile 中自定义即可 */
syssize:
	.word SYSSIZE		/* system 模块的大小，build 在制作 Image 镜像时会根据实际大小来填充 */
swap_dev:
	.word SWAP_DEV		/* 系统所使用的交换设备的设备号，build 未填充该设备号【???】 */
ram_size:
	.word RAMDISK		/* ram disk 的大小，默认为0，用户在 Makefile 中自定义即可 */
vid_mode:
	.word SVGA_MODE
root_dev:
	.word ROOT_DEV		/* 系统所使用的根文件系统设备的设备号，build 在制作镜像时填充 */
boot_flag:
	.word 0xAA55		/* 启动扇区标识符，由 build 在制作镜像时填充 */
