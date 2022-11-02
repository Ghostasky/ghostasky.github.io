---
title: 在64位的glibc上payload调用system导致crash的问题
date: 2021-04-08
tags: PWN
categories: Technology
---
[TOC]



# 在64位的glibc上payload调用system导致crash的问题



在一些64位的pwn题中，调用system后会导致程序crash掉

首先小讲下原因：

```
.text:000000000040F93C                 mov     [rsp+198h+var_190], rax
.text:000000000040F941                 movhps  xmm0, [rsp+198h+var_190]
.text:000000000040F946                 movaps  [rsp+198h+var_158], xmm0
.text:000000000040F94B                 call    sigaction
```

是`movaps  [rsp+198h+var_158], xmm0`指令要求`rsp+198h+var_158`的值是对其16byte(0x10)，否则的话会直接出发中断从而导致crash。

>   Movaps：
>   `movaps XMM,XMM/m128 movaps XMM/128,XMM`
>   把源存储器内容值送入目的寄存器,当有m128时,必须对齐内存16字节,也就是内存地址低4位为0.

## 演示

示例程序

```c
#include<stdio.h>
#include<stdlib.h>
int main()
{
	system("/bin/sh");
	return 0;
}
```

断在：`movaps  [rsp+198h+var_158], xmm0`

```
pwndbg> 
131	in ../sysdeps/posix/system.c
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────
 RAX  0x7ffff7b95e17 ◂— sub    eax, 0x622f0063 /* '-c' */
 RBX  0x0
 RCX  0x7ffff7b95e1f ◂— jae    0x7ffff7b95e89 /* 'sh' */
 RDX  0x0
 RDI  0x2
 RSI  0x7ffff7dcf6a0 (intr) ◂— 0x0
 R8   0x7ffff7dcf600 (quit) ◂— 0x0
 R9   0x7ffff7dced80 (initial) ◂— 0x0
 R10  0x8
 R11  0x346
 R12  0x5555555546f4 ◂— 0x68732f6e69622f /* '/bin/sh' */
 R13  0x7fffffffe080 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffffffde60 ◂— 0x0
 RSP  0x7fffffffde00 ◂— 0x7fff00000002
*RIP  0x7ffff7a3140b (do_system+1099) ◂— call   0x7ffff7a21230
───────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────
   0x7ffff7a313ed <do_system+1069>    mov    qword ptr [rsp + 0x58], 0
   0x7ffff7a313f6 <do_system+1078>    movq   xmm0, qword ptr [rsp + 8]
   0x7ffff7a313fc <do_system+1084>    mov    qword ptr [rsp + 8], rax
   0x7ffff7a31401 <do_system+1089>    movhps xmm0, qword ptr [rsp + 8]
   0x7ffff7a31406 <do_system+1094>    movaps xmmword ptr [rsp + 0x40], xmm0
 ► 0x7ffff7a3140b <do_system+1099>    call   sigaction <sigaction>
        sig: 0x2
        act: 0x7ffff7dcf6a0 (intr) ◂— 0x0
        oact: 0x0
 
   0x7ffff7a31410 <do_system+1104>    lea    rsi, [rip + 0x39e1e9] <0x7ffff7dcf600>
   0x7ffff7a31417 <do_system+1111>    xor    edx, edx
   0x7ffff7a31419 <do_system+1113>    mov    edi, 3
   0x7ffff7a3141e <do_system+1118>    call   sigaction <sigaction>
 
   0x7ffff7a31423 <do_system+1123>    xor    edx, edx
───────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ rsp  0x7fffffffde00 ◂— 0x7fff00000002
01:0008│      0x7fffffffde08 —▸ 0x7ffff7b95e17 ◂— sub    eax, 0x622f0063 /* '-c' */
02:0010│      0x7fffffffde10 —▸ 0x7fffffffdf10 ◂— 0x0
03:0018│      0x7fffffffde18 ◂— 0x3
04:0020│      0x7fffffffde20 —▸ 0x7ffff7a31470 (cancel_handler) ◂— push   rbx
05:0028│      0x7fffffffde28 —▸ 0x7fffffffde1c ◂— 0xf7a3147000000000
06:0030│      0x7fffffffde30 —▸ 0x7ffff7ffe738 —▸ 0x7ffff7ffe710 —▸ 0x7ffff7ffb000 ◂— jg     0x7ffff7ffb047
07:0038│      0x7fffffffde38 ◂— 0x0
─────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────
 ► f 0     7ffff7a3140b do_system+1099
   f 1     55555555465a main+16
   f 2     7ffff7a03bf7 __libc_start_main+231
────────────────────────────────────────────────────────────────────────────────────────────────────────────────

```

然后查看$rsp+0x40:

```
pwndbg> p/x $rsp+0x40
$2 = 0x7fffffffde40
```

可以看到是对齐的，也就是内存地址的低位为0。

下面对$rsp+1：`set $rsp=$rsp+1`

```
pwndbg> set $rsp=$rsp+1
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────
 RAX  0x7ffff7b95e17 ◂— sub    eax, 0x622f0063 /* '-c' */
 RBX  0x0
 RCX  0x7ffff7b95e1f ◂— jae    0x7ffff7b95e89 /* 'sh' */
 RDX  0x0
 RDI  0x2
 RSI  0x7ffff7dcf6a0 (intr) ◂— 0x0
 R8   0x7ffff7dcf600 (quit) ◂— 0x0
 R9   0x7ffff7dced80 (initial) ◂— 0x0
 R10  0x8
 R11  0x346
 R12  0x5555555546f4 ◂— 0x68732f6e69622f /* '/bin/sh' */
 R13  0x7fffffffe080 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffffffde60 ◂— 0x0
*RSP  0x7fffffffde01 ◂— 0x1700007fff000000
*RIP  0x7ffff7a3140b (do_system+1099) ◂— call   0x7ffff7a21230
───────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────
   0x7ffff7a313ed <do_system+1069>    mov    qword ptr [rsp + 0x58], 0
   0x7ffff7a313f6 <do_system+1078>    movq   xmm0, qword ptr [rsp + 8]
   0x7ffff7a313fc <do_system+1084>    mov    qword ptr [rsp + 8], rax
   0x7ffff7a31401 <do_system+1089>    movhps xmm0, qword ptr [rsp + 8]
   0x7ffff7a31406 <do_system+1094>    movaps xmmword ptr [rsp + 0x40], xmm0
 ► 0x7ffff7a3140b <do_system+1099>    call   sigaction <sigaction>
        sig: 0x2
        act: 0x7ffff7dcf6a0 (intr) ◂— 0x0
        oact: 0x0
 
   0x7ffff7a31410 <do_system+1104>    lea    rsi, [rip + 0x39e1e9] <0x7ffff7dcf600>
   0x7ffff7a31417 <do_system+1111>    xor    edx, edx
   0x7ffff7a31419 <do_system+1113>    mov    edi, 3
   0x7ffff7a3141e <do_system+1118>    call   sigaction <sigaction>
 
   0x7ffff7a31423 <do_system+1123>    xor    edx, edx
───────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ rsp  0x7fffffffde01 ◂— 0x1700007fff000000
01:0008│      0x7fffffffde09 ◂— 0x1000007ffff7b95e
02:0010│      0x7fffffffde11 ◂— 0x300007fffffffdf
03:0018│      0x7fffffffde19 ◂— 0x7000000000000000
04:0020│      0x7fffffffde21 ◂— 0x1c00007ffff7a314
05:0028│      0x7fffffffde29 ◂— 0x3800007fffffffde
06:0030│      0x7fffffffde31 ◂— 0x7ffff7ffe7
07:0038│      0x7fffffffde39 ◂— 0x1f00000000000000
─────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────
 ► f 0     7ffff7a3140b do_system+1099
   f 1 7000005555555546
   f 2 f700005555555546
   f 3       7ffff7a03b
   f 4 8800000020000000
   f 5       7fffffffe0
   f 6 4a00000001000000
   f 7       5555555546
────────────────────────────────────────────────────────────────────────────────────────────────────────────────

```

然后查看$rsp+0x40的位置：

```
pwndbg> p/x $rsp+0x40
$3 = 0x7fffffffde41
```

已经未对齐了，继续执行。

```
pwndbg> c
Continuing.

Thread 2.1 "a.out" received signal SIGSEGV, Segmentation fault.
0x000000000040f946 in do_system ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────
 RAX  0x492be5 ◂— sub    eax, 0x622f0063 /* '-c' */
 RBX  0x0
 RCX  0x492bed ◂— jae    0x492c57 /* 'sh' */
 RDX  0x0
 RDI  0x2
 RSI  0x6bbdc0 (intr) ◂— 0x0
 R8   0x6bbd20 (quit) ◂— 0x0
 R9   0x6bb8e0 (initial) ◂— 0x0
 R10  0x8
 R11  0x346
 R12  0x492444 ◂— 0x68732f6e69622f /* '/bin/sh' */
 R13  0x0
 R14  0x6b9018 (_GLOBAL_OFFSET_TABLE_+24) —▸ 0x440670 (__strcpy_ssse3) ◂— mov    rcx, rsi
 R15  0x0
 RBP  0x7fffffffde20 ◂— 0x0
 RSP  0x7fffffffddc1 ◂— 0xe500007fffffffe3
 RIP  0x40f946 (do_system+1062) ◂— movaps xmmword ptr [rsp + 0x40], xmm0
───────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────
   0x40f928 <do_system+1032>    mov    qword ptr [rsp + 8], rcx
   0x40f92d <do_system+1037>    mov    qword ptr [rsp + 0x58], 0
   0x40f936 <do_system+1046>    movq   xmm0, qword ptr [rsp + 8]
   0x40f93c <do_system+1052>    mov    qword ptr [rsp + 8], rax
   0x40f941 <do_system+1057>    movhps xmm0, qword ptr [rsp + 8]
 ► 0x40f946 <do_system+1062>    movaps xmmword ptr [rsp + 0x40], xmm0
   0x40f94b <do_system+1067>    call   sigaction <sigaction>
 
   0x40f950 <do_system+1072>    lea    rsi, [rip + 0x2ac3c9] <0x6bbd20>
   0x40f957 <do_system+1079>    xor    edx, edx
   0x40f959 <do_system+1081>    mov    edi, 3
   0x40f95e <do_system+1086>    call   sigaction <sigaction>
───────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ rsp  0x7fffffffddc1 ◂— 0xe500007fffffffe3
01:0008│      0x7fffffffddc9 ◂— 0xb0000000000492b /* '+I' */
02:0010│      0x7fffffffddd1 ◂— 0x700000015004a4f /* 'OJ' */
03:0018│      0x7fffffffddd9 ◂— 0x4000000000000000
04:0020│      0x7fffffffdde1 ◂— 0xdc000000000040f4
05:0028│      0x7fffffffdde9 ◂— 0x6800007fffffffdd
06:0030│      0x7fffffffddf1 ◂— 0x7000000000006be2
07:0038│      0x7fffffffddf9 ◂— 0x500000000000001
─────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────
 ► f 0           40f946 do_system+1062
   f 1 700000000000400b
   f 2  900000000004018
   f 3             4011
   f 4                0
────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

已经crash掉。

## 解决办法

1.改变payload的长度

​	直接更改payload的长度，在栈溢出的时候栈的地址会不同，将栈地址+1，不行的话，继续增加，最多16次就一定会遇到栈对齐的长度。

2.栈转移

​	当有些payload有长度限制时，可以使用栈转移，之后如果栈的地址还是不同的话，继续+1，对齐。

3.execve

​	调用system的话可能会crash掉，那么可以使用execve函数，只不过这个函数的参数比system的参数多，在之前的ret2syscall 中也有讲到，之前讲的是32位，那64位的话就是参数构造不一样而已：rdi,rsi,rdx。

```c
int execve(const char * filename,char * const argv[ ],char * const envp[ ]);
```





