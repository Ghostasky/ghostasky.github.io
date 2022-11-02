---
title: Chunk Extend and Overlapping
date: 2021-03-22
tags: PWN
categories: Technology
---
[TOC]

# Chunk Extend and Overlapping



## 介绍

chunk extend 是堆漏洞的一种常见利用手法，通过extend可以实现chunk overlapping（块重叠）的效果。这种利用的方法需要以下的条件：

-   程序中存在堆的漏洞
-   漏洞可以控制chunk header中的数据

## 原理

这种利用的技术能够产生在于ptmalloc在对堆chunk进行操作时使用的各种宏。

在ptmalloc中，获取chunk块大小的宏：

```c
/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask(p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p) ((p)->mchunk_size)
```

一种是直接获取，不忽略掩码部分，另外一种是忽略掩码部分。



在 ptmalloc 中，获取下一 chunk 块地址的宏：

```c
/* Ptr to next physical malloc_chunk. */ 
#define next_chunk(p) ((mchunkptr)(((char *) (p)) + chunksize(p)))
```



在 ptmalloc 中，获取前一个 chunk 信息的宏：

```c
/* Size of the chunk below P.  Only valid if prev_inuse (P).  */
#define prev_size(p) ((p)->mchunk_prev_size)

/* Ptr to previous physical malloc_chunk.  Only valid if prev_inuse (P).  */
#define prev_chunk(p) ((mchunkptr)(((char *) (p)) - prev_size(p)))
```

在 ptmalloc 中，判断当前 chunk 是否是 use 状态的宏：

```c
#define inuse(p)
    ((((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size) & PREV_INUSE)
```

chunk extend 就是通过控制 size 、prev_size 、prev_inuse域来实现跨越块操作从而导致 overlapping 的。

## 基本示例

### 示例1：对inuse的fastbin进行extend

示例代码：

```c
#include<stdio.h>
#include<stdlib.h>
int main()
{
    void *p, *q;
    p = malloc(0x10);//分配第一个0x10的chunk
    malloc(0x10);//分配第二个0x10的chunk
    *(long long *)((long long)p - 0x8) = 0x41;// 修改第一个块的size域
    free(p);
    q = malloc(0x30);// 实现extend，控制了第二个块的内容
    return 0;
}
```

这里编译的时候使用了`-g`参数，可以在gdb调试的时候在任意行下断点。方法：b + 行号

```
pwndbg> n
8	    malloc(0x10);//分配第二个0x10的chunk
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────────────────────────────────
 RAX  0x602010 ◂— 0x0
 RBX  0x0
 RCX  0x7ffff7dd1b20 (main_arena) ◂— 0x100000000
 RDX  0x602010 ◂— 0x0
 RDI  0x7ffff7dd1b20 (main_arena) ◂— 0x100000000
 RSI  0x602020 ◂— 0x0
 R8   0x602000 ◂— 0x0
 R9   0xd
 R10  0x7ffff7dd1b78 (main_arena+88) —▸ 0x602020 ◂— 0x0
 R11  0x0
 R12  0x400470 (_start) ◂— xor    ebp, ebp
 R13  0x7fffffffdf90 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffffffdeb0 —▸ 0x4005c0 (__libc_csu_init) ◂— push   r15
 RSP  0x7fffffffdea0 —▸ 0x602010 ◂— 0x0
 RIP  0x40057c (main+22) ◂— mov    edi, 0x10
──────────────────────────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────────────────────────────
   0x40056e <main+8>     mov    edi, 0x10
   0x400573 <main+13>    call   malloc@plt <0x400450>
 
   0x400578 <main+18>    mov    qword ptr [rbp - 0x10], rax
 ► 0x40057c <main+22>    mov    edi, 0x10
   0x400581 <main+27>    call   malloc@plt <0x400450>
 
   0x400586 <main+32>    mov    rax, qword ptr [rbp - 0x10]
   0x40058a <main+36>    sub    rax, 8
   0x40058e <main+40>    mov    qword ptr [rax], 0x41
   0x400595 <main+47>    mov    rax, qword ptr [rbp - 0x10]
   0x400599 <main+51>    mov    rdi, rax
   0x40059c <main+54>    call   free@plt <0x400430>
───────────────────────────────────────────────────────────────────────[ SOURCE (CODE) ]───────────────────────────────────────────────────────────────────────
In file: /home/gwt/Desktop/1.c
    3 #include<stdlib.h>
    4 int main()
    5 {
    6     void *p, *q;
    7     p = malloc(0x10);//分配第一个0x10的chunk
 ►  8     malloc(0x10);//分配第二个0x10的chunk
    9     *(long long *)((long long)p - 0x8) = 0x41;// 修改第一个块的size域
   10     free(p);
   11     q = malloc(0x30);// 实现extend，控制了第二个块的内容
   12     return 0;
   13 }
───────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────
00:0000│ rsp  0x7fffffffdea0 —▸ 0x602010 ◂— 0x0
01:0008│      0x7fffffffdea8 ◂— 0x0
02:0010│ rbp  0x7fffffffdeb0 —▸ 0x4005c0 (__libc_csu_init) ◂— push   r15
03:0018│      0x7fffffffdeb8 —▸ 0x7ffff7a2d830 (__libc_start_main+240) ◂— mov    edi, eax
04:0020│      0x7fffffffdec0 ◂— 0x0
05:0028│      0x7fffffffdec8 —▸ 0x7fffffffdf98 —▸ 0x7fffffffe30e ◂— 0x77672f656d6f682f ('/home/gw')
06:0030│      0x7fffffffded0 ◂— 0x100000000
07:0038│      0x7fffffffded8 —▸ 0x400566 (main) ◂— push   rbp
─────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────
 ► f 0           40057c main+22
   f 1     7ffff7a2d830 __libc_start_main+240
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
          0x400000           0x401000 r-xp     1000 0      /home/gwt/Desktop/a.out
          0x600000           0x601000 r--p     1000 0      /home/gwt/Desktop/a.out
          0x601000           0x602000 rw-p     1000 1000   /home/gwt/Desktop/a.out
          0x602000           0x623000 rw-p    21000 0      [heap]
    0x7ffff7a0d000     0x7ffff7bcd000 r-xp   1c0000 0      /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ffff7bcd000     0x7ffff7dcd000 ---p   200000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ffff7dcd000     0x7ffff7dd1000 r--p     4000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ffff7dd1000     0x7ffff7dd3000 rw-p     2000 1c4000 /lib/x86_64-linux-gnu/libc-2.23.so
    0x7ffff7dd3000     0x7ffff7dd7000 rw-p     4000 0      
    0x7ffff7dd7000     0x7ffff7dfd000 r-xp    26000 0      /lib/x86_64-linux-gnu/ld-2.23.so
    0x7ffff7fdc000     0x7ffff7fdf000 rw-p     3000 0      
    0x7ffff7ff7000     0x7ffff7ffa000 r--p     3000 0      [vvar]
    0x7ffff7ffa000     0x7ffff7ffc000 r-xp     2000 0      [vdso]
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000 25000  /lib/x86_64-linux-gnu/ld-2.23.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000 26000  /lib/x86_64-linux-gnu/ld-2.23.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000 0      
    0x7ffffffde000     0x7ffffffff000 rw-p    21000 0      [stack]
0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]
```

```
pwndbg> info locals 
p = 0x602010
q = 0x0
pwndbg> x/10gx 0x602020
0x602020:	0x0000000000000000	0x0000000000000021 <=chunk1
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000020fc1 <=top chunk
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
```

info local可以查看指针指向的地址，即user_data的起始地址

继续执行

```
pwndbg> x/32gx 0x602000
0x602000:	0x0000000000000000	0x0000000000000021 <=chunk1
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000021 <=chunk2
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000020fc1 <=top chunk
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000000000
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000000000
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x0000000000000000	0x0000000000000000
0x6020e0:	0x0000000000000000	0x0000000000000000
0x6020f0:	0x0000000000000000	0x0000000000000000
pwndbg> heap
0x602000 FASTBIN {
  prev_size = 0, 
  size = 33, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x21
}
0x602020 FASTBIN {
  prev_size = 0, 
  size = 33, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x20fc1
}
0x602040 PREV_INUSE {
  prev_size = 0, 
  size = 135105, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

size = 33 = 0x21 = 0x8(prev_size) + 0x8(size) + 0x1(内容) + 0x1(标志位)

继续执行：`*(long long *)((long long)p - 0x8) = 0x41`后

```
pwndbg> x/32gx 0x602000
0x602000:	0x0000000000000000	0x0000000000000041
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000021
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000020fc1
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000000000
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000000000
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x0000000000000000	0x0000000000000000
0x6020e0:	0x0000000000000000	0x0000000000000000
0x6020f0:	0x0000000000000000	0x0000000000000000
```

可以看到chunk1的size 已经变为了0x41，也就是说chunk1的现在大小包含了原来的chunk1和chunk2的大小。

继续执行：free后

```
pwndbg> x/32gx 0x602000
0x602000:	0x0000000000000000	0x0000000000000041
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000021
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000020fc1
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000000000
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000000000
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x0000000000000000	0x0000000000000000
0x6020e0:	0x0000000000000000	0x0000000000000000
0x6020f0:	0x0000000000000000	0x0000000000000000
pwndbg> bin
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x602000 ◂— 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
pwndbg> info locals 
p = 0x602010
q = 0x0
```

这里虽然free了chunk1，但是内容并没有清空。

之后将chunk1（也就是合并之后的）放进了fastbin中。

继续执行：malloc

```
pwndbg> x/32gx 0x602000
0x602000:	0x0000000000000000	0x0000000000000041
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000021
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000020fc1
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000000000
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000000000
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x0000000000000000	0x0000000000000000
0x6020e0:	0x0000000000000000	0x0000000000000000
0x6020f0:	0x0000000000000000	0x0000000000000000
pwndbg> info bin
Undefined info command: "bin".  Try "help info".
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
pwndbg> info locals 
p = 0x602010
q = 0x602010
```

malloc后的空间给了q，这样就可以通过新分配的chunk来对chunk2中的内容进行操作了，将这种状态称为overlapping chunk。

### 示例2：对inuse的smallbin进行extend

示例代码：

```c
#include<stdio.h>
#include<stdlib.h>
int main()
{
    void *p, *q;
    p = malloc(0x80);//分配第一个 0x80 的chunk1
    malloc(0x10); //分配第二个 0x10 的chunk2
    malloc(0x10); //防止与top chunk合并
    *(long *)((long)p-0x8) = 0xb1;
    free(p);
    q = malloc(0xa0);
}
```

```
pwndbg> r
Starting program: /home/gwt/Desktop/a.out 

Breakpoint 1, main () at 1.c:9
9	    *(long *)((long)p-0x8) = 0xb1;
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────────────────────────────────
 RAX  0x6020c0 ◂— 0x0
 RBX  0x0
 RCX  0x7ffff7dd1b20 (main_arena) ◂— 0x100000000
 RDX  0x6020c0 ◂— 0x0
 RDI  0x0
 RSI  0x6020d0 ◂— 0x0
 R8   0x602000 ◂— 0x0
 R9   0xd
 R10  0x7ffff7dd1b78 (main_arena+88) —▸ 0x6020d0 ◂— 0x0
 R11  0x0
 R12  0x400470 (_start) ◂— xor    ebp, ebp
 R13  0x7fffffffdf90 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffffffdeb0 —▸ 0x4005c0 (__libc_csu_init) ◂— push   r15
 RSP  0x7fffffffdea0 —▸ 0x602010 ◂— 0x0
 RIP  0x400590 (main+42) ◂— mov    rax, qword ptr [rbp - 0x10]
──────────────────────────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────────────────────────────
 ► 0x400590 <main+42>    mov    rax, qword ptr [rbp - 0x10]
   0x400594 <main+46>    sub    rax, 8
   0x400598 <main+50>    mov    qword ptr [rax], 0xb1
   0x40059f <main+57>    mov    rax, qword ptr [rbp - 0x10]
   0x4005a3 <main+61>    mov    rdi, rax
   0x4005a6 <main+64>    call   free@plt <0x400430>
 
   0x4005ab <main+69>    mov    edi, 0xa0
   0x4005b0 <main+74>    call   malloc@plt <0x400450>
 
   0x4005b5 <main+79>    mov    qword ptr [rbp - 8], rax
   0x4005b9 <main+83>    mov    eax, 0
   0x4005be <main+88>    leave  
───────────────────────────────────────────────────────────────────────[ SOURCE (CODE) ]───────────────────────────────────────────────────────────────────────
In file: /home/gwt/Desktop/1.c
    4 {
    5     void *p, *q;
    6     p = malloc(0x80);//分配第一个 0x80 的chunk1
    7     malloc(0x10); //分配第二个 0x10 的chunk2
    8     malloc(0x10); //防止与top chunk合并
 ►  9     *(long *)((long)p-0x8) = 0xb1;
   10     free(p);
   11     q = malloc(0xa0);
   12 }
───────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────
00:0000│ rsp  0x7fffffffdea0 —▸ 0x602010 ◂— 0x0
01:0008│      0x7fffffffdea8 ◂— 0x0
02:0010│ rbp  0x7fffffffdeb0 —▸ 0x4005c0 (__libc_csu_init) ◂— push   r15
03:0018│      0x7fffffffdeb8 —▸ 0x7ffff7a2d830 (__libc_start_main+240) ◂— mov    edi, eax
04:0020│      0x7fffffffdec0 ◂— 0x0
05:0028│      0x7fffffffdec8 —▸ 0x7fffffffdf98 —▸ 0x7fffffffe30e ◂— 0x77672f656d6f682f ('/home/gw')
06:0030│      0x7fffffffded0 ◂— 0x100000000
07:0038│      0x7fffffffded8 —▸ 0x400566 (main) ◂— push   rbp
─────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────
 ► f 0           400590 main+42
   f 1     7ffff7a2d830 __libc_start_main+240
Breakpoint /home/gwt/Desktop/1.c:9
pwndbg> x/50gx 0x602000 
0x602000:	0x0000000000000000	0x0000000000000091 <=chunk1
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000 <=chunk1_end
0x602090:	0x0000000000000000	0x0000000000000021 <=chunk2
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000000021 <=chunk3
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x0000000000000000	0x0000000000020f31 <=top_chunk
0x6020e0:	0x0000000000000000	0x0000000000000000
0x6020f0:	0x0000000000000000	0x0000000000000000
0x602100:	0x0000000000000000	0x0000000000000000
0x602110:	0x0000000000000000	0x0000000000000000
0x602120:	0x0000000000000000	0x0000000000000000
0x602130:	0x0000000000000000	0x0000000000000000
0x602140:	0x0000000000000000	0x0000000000000000
0x602150:	0x0000000000000000	0x0000000000000000
0x602160:	0x0000000000000000	0x0000000000000000
0x602170:	0x0000000000000000	0x0000000000000000
0x602180:	0x0000000000000000	0x0000000000000000
```

继续执行后和上一个示例一样，chunk1的大小变为了原来的chunk1+chunk2。

执行free：

```
pwndbg> x/50gx 0x602000 
0x602000:	0x0000000000000000	0x00000000000000b1
0x602010:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000000021
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x00000000000000b0	0x0000000000000020
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x0000000000000000	0x0000000000020f31
0x6020e0:	0x0000000000000000	0x0000000000000000
0x6020f0:	0x0000000000000000	0x0000000000000000
0x602100:	0x0000000000000000	0x0000000000000000
0x602110:	0x0000000000000000	0x0000000000000000
0x602120:	0x0000000000000000	0x0000000000000000
0x602130:	0x0000000000000000	0x0000000000000000
0x602140:	0x0000000000000000	0x0000000000000000
0x602150:	0x0000000000000000	0x0000000000000000
0x602160:	0x0000000000000000	0x0000000000000000
0x602170:	0x0000000000000000	0x0000000000000000
0x602180:	0x0000000000000000	0x0000000000000000
pwndbg> bin
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x602000 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x602000
smallbins
empty
largebins
empty
```

可以看到chunk3 的size变为了0x20。free后的chunk1进入了unsortedbin，有两种情况下进入unsortedbin：

-   当一个较大的chunk被分割为两部分后，如果剩下的部分大于minsize，就会放入unsortedbin中。
-   释放一个不属于fastbin的chunk，并且这个chunk不和top chunk紧邻时，这个chunk就会授信啊被放到unsortedbin中。

这个例子就是上面的第二种情况，不属于fastbin，且不和top chunk紧邻。同样，之后的malloc后也可以达到对chunk2进行操作的目的。



### 示例3：对 free 的 smallbin 进行 extend

示例代码：

```c
#include<stdio.h>
#include<stdlib.h>
int main()
{
    void *p, *q;
    p = malloc(0x80);//分配第一个0x80的chunk1
    malloc(0x10);//分配第二个0x10的chunk2
    free(p);//首先进行释放，使得chunk1进入unsorted bin
    *(long *)((long)p - 0x8) = 0xb1;
    q = malloc(0xa0);
}
```

执行free后：

```
pwndbg> bin
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x602000 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x602000
smallbins
empty
largebins
empty
pwndbg> x/40gx  0x602000
0x602000:	0x0000000000000000	0x0000000000000091
0x602010:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000090	0x0000000000000020
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000020f51
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x0000000000000000	0x0000000000000000
0x6020e0:	0x0000000000000000	0x0000000000000000
0x6020f0:	0x0000000000000000	0x0000000000000000
0x602100:	0x0000000000000000	0x0000000000000000
0x602110:	0x0000000000000000	0x0000000000000000
0x602120:	0x0000000000000000	0x0000000000000000
0x602130:	0x0000000000000000	0x0000000000000000
```

接下来执行：`*(long *)((long)p - 0x8) = 0xb1;`

```
pwndbg> x/40gx  0x602000
0x602000:	0x0000000000000000	0x00000000000000b1
0x602010:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000090	0x0000000000000020
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000020f51
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x0000000000000000	0x0000000000000000
0x6020e0:	0x0000000000000000	0x0000000000000000
0x6020f0:	0x0000000000000000	0x0000000000000000
0x602100:	0x0000000000000000	0x0000000000000000
0x602110:	0x0000000000000000	0x0000000000000000
0x602120:	0x0000000000000000	0x0000000000000000
0x602130:	0x0000000000000000	0x0000000000000000
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x602000 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x602000
smallbins
empty
largebins
empty
```

继续malloc：

```
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
pwndbg> info locals 
p = 0x602010
q = 0x602010
```

依然可以达到对chunk2进行控制。

### 示例4：通过extend后向overlapping

示例代码：

```c
#include<stdio.h>
int main()
{
    void *p, *q;
    p = malloc(0x10);//分配第1个 0x10 的chunk1
    malloc(0x10); //分配第2个 0x10 的chunk2
    malloc(0x10); //分配第3个 0x10 的chunk3
    malloc(0x10); //分配第4个 0x10 的chunk4    
    *(long *)((long)p - 0x8) = 0x61;
    free(p);
    q = malloc(0x50);
}
```

free：

```
pwndbg> bin
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x602000 ◂— 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
```

在 malloc(0x50) 后，其中 0x10 的 fastbin 块依然可以正常的分配和释放，此时已经构成 overlapping，通过对 overlapping 的进行操作可以实现 fastbin attack

### 示例5：通过 extend 前向 overlapping

这里展示通过修改 pre_inuse 域和 pre_size 域实现合并前面的块。

示例代码：

```c
#include<stdlib.h>
#include<stdio.h>
int main(void)
{
    void *p, *q, *r, *t;
    p = malloc(128);//smallbin1
    q = malloc(0x10);//fastbin1
    r = malloc(0x10);//fastbin2
    t = malloc(128);//smallbin2
    malloc(0x10);//防止与top合并
    free(p);
    *(int *)((long long)t - 0x8) = 0x90;//修改prev_inuse域
    *(int *)((long long)t - 0x10) = 0xd0;//修改prev_size域
    free(t);//unlink进行前向extend
    malloc(0x150);//占位块
}
```

前面的几个malloc后：

```
pwndbg> x/80gx 0x602000
0x602000:	0x0000000000000000	0x0000000000000091 <=chunk1
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000 <=chunk1_end
0x602090:	0x0000000000000000	0x0000000000000021 <=chunk2
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000000021 <=chunk3
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x0000000000000000	0x0000000000000091 <=chunk4
0x6020e0:	0x0000000000000000	0x0000000000000000
0x6020f0:	0x0000000000000000	0x0000000000000000
0x602100:	0x0000000000000000	0x0000000000000000
0x602110:	0x0000000000000000	0x0000000000000000
0x602120:	0x0000000000000000	0x0000000000000000
0x602130:	0x0000000000000000	0x0000000000000000
0x602140:	0x0000000000000000	0x0000000000000000
0x602150:	0x0000000000000000	0x0000000000000000 <=chunk4_end
0x602160:	0x0000000000000000	0x0000000000000021
0x602170:	0x0000000000000000	0x0000000000000000
0x602180:	0x0000000000000000	0x0000000000020e81
0x602190:	0x0000000000000000	0x0000000000000000
0x6021a0:	0x0000000000000000	0x0000000000000000
0x6021b0:	0x0000000000000000	0x0000000000000000
0x6021c0:	0x0000000000000000	0x0000000000000000
0x6021d0:	0x0000000000000000	0x0000000000000000
0x6021e0:	0x0000000000000000	0x0000000000000000
0x6021f0:	0x0000000000000000	0x0000000000000000
0x602200:	0x0000000000000000	0x0000000000000000
0x602210:	0x0000000000000000	0x0000000000000000
0x602220:	0x0000000000000000	0x0000000000000000
0x602230:	0x0000000000000000	0x0000000000000000
0x602240:	0x0000000000000000	0x0000000000000000
0x602250:	0x0000000000000000	0x0000000000000000
0x602260:	0x0000000000000000	0x0000000000000000
0x602270:	0x0000000000000000	0x0000000000000000
```

修改prev_inuse域和prev_size后：

```
pwndbg> x/60gx 0x602000
0x602000:	0x0000000000000000	0x0000000000000091
0x602010:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000090	0x0000000000000020
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000000021
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x00000000000000d0	0x0000000000000090
0x6020e0:	0x0000000000000000	0x0000000000000000
0x6020f0:	0x0000000000000000	0x0000000000000000
0x602100:	0x0000000000000000	0x0000000000000000
0x602110:	0x0000000000000000	0x0000000000000000
0x602120:	0x0000000000000000	0x0000000000000000
0x602130:	0x0000000000000000	0x0000000000000000
0x602140:	0x0000000000000000	0x0000000000000000
0x602150:	0x0000000000000000	0x0000000000000000
0x602160:	0x0000000000000000	0x0000000000000021
0x602170:	0x0000000000000000	0x0000000000000000
0x602180:	0x0000000000000000	0x0000000000020e81
0x602190:	0x0000000000000000	0x0000000000000000
0x6021a0:	0x0000000000000000	0x0000000000000000
0x6021b0:	0x0000000000000000	0x0000000000000000
0x6021c0:	0x0000000000000000	0x0000000000000000
0x6021d0:	0x0000000000000000	0x0000000000000000
```

注意0x602097和0x6020d7。此时chunk1为之前malloc的4个大小之和。

通过修改prev_size域和prev_inuse域可以跨越多个chunk进行合并。
