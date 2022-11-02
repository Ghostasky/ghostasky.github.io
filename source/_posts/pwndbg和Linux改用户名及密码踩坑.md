---
title: 'pwndbg和Linux改用户名及密码踩坑'
date: 2021-03-23 00:10:56
tags: [PWN,Linux]
categories: Technology
---
[TOC]



## 关于pwndbg

安装：

```
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
sudo ./setup.sh
```

gdb后如果是peda或者其他的插件，可以改下配置文件.gdbinit，在home中，或者root目录下，加上这么一句，其他注释掉。

```
source /home/yourname/pwndbg/gdbinit.py
```

## 关于Ubuntu修改用户名和密码

### 修改root密码

```
sudo passwd root
```

### 修改用户名密码

```
passwd xxx  //xxx表示用户名
```

### 修改用户名

```
sudo gedit /etc/passwd
```

打开该文件后找到当前用户名的一行(单用户一般是文件最后一行)，将旧用户名改为新的用户名，但不要动/home/旧用户名的名字，否则重启后可能会无法从图形界面登录系统。

```
oldUser:x:1000:1000:A User ,,,:/home/oldUser:/bin/bash
```

比如上面的是我需要修改的行，那么我只将开头的旧用户名oldUser修改为新的用户名，比如newUser就可以了。(A User是用户名全称，也可以修改.)

修改后：

```
newUser:x:1000:1000:newUser ,,,:/home/oldUser:/bin/bash
```

修改保存后，切换到root。

```
gedit /etc/shadow
```

找到你的旧用户名并将其修改为新用户名，修改后保存

```
gedit /etc/sudoers
```

在`root ALL=(ALL:ALL) ALL`后添加一行`newUser ALL=(ALL:ALL) ALL`(旧用户的类似内容也可以删除了)，其中newUser是新的用户名。

修改保存后重启系统

### 修改用户目录名

```
sudo gedit /etc/passwd
```

还是在我们之前修改的那一行，只不过这一次是将/home/旧用户名修改为/home/新用户名。

然后再执行以下指令

```
sudo mv /home/oldUser /home/newUser
```

重启，完了。