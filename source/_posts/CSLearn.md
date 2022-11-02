

[toc]





# 1.目录结构

```
agscript 拓展应用的脚本
c2lint 用于检查profile的错误异常
teamserver 服务端程序
cobaltstrike，cobaltstrike.jar客户端程序(java跨平台)
license.pdf 许可证文件
logs 目录记录与目标主机的相关信息 
update，update.jar用于更新CS 
third-party 第三方工具
```

# 2.安装运行

。。。这个就不说了，在服务器上搞了半天，，也不知道为啥，，好像是java环境的问题，最后还是好了。。

# 3.译

## Cobalt Strike

```
New Connection  	 # 新建连接，支持连接多个服务器端
Preferences  		 # 设置Cobal Strike界面、控制台、以及输出报告样式、TeamServer连接记录
Visualization  		 # 主要展示输出结果的视图
VPN Interfaces 		  # 设置VPN接口
Listenrs  			 # 创建监听器
Script Manager  	 # 脚本管理，可以通过AggressorScripts脚本来加强自身，能够扩展菜单栏，Beacon命令行，提权脚本等
Close   			# 退出连接
```

## view

```
Applications   # 显示受害主机的应用信息
Credentials   # 显示所有以获取的受害主机的凭证，如hashdump、Mimikatz
Downloads   # 查看已下载文件
Event Log   # 主机上线记录以及团队协作聊天记录
Keystrokes   # 查看键盘记录结果
Proxy Pivots   # 查看代理模块
Screenshots   # 查看所有屏幕截图
Script Console   # 加载第三方脚本以增强功能 
Targets   # 显示所有受害主机
Web Log    # 所有Web服务的日志
```

## Attack

### Packages

```
HTML Application   # 生成(executable/VBA/powershell)这三种原理实现的恶意HTA木马文件
MS Office Macro   # 生成office宏病毒文件
Payload Generator   # 生成各种语言版本的payload
USB/CD AutoPlay   # 生成利用自动播放运行的木马文件
Windows Dropper   # 捆绑器能够对任意的正常文件进行捆绑(免杀效果差)
Windows Executable   # 生成可执行exe木马
Windows Executable(Stageless)   # 生成无状态的可执行exe木马
```

### Web Drive-by

```
Manage   # 对开启的web服务进行管理
Clone Site   # 克隆网站，可以记录受害者提交的数据
Host File   # 提供文件下载，可以选择Mime类型
Scripted Web Delivery   # 为payload提供web服务以便下载和执行，类似于Metasploit的web_delivery 
Signed Applet Attack   # 使用java自签名的程序进行钓鱼攻击(该方法已过时)
Smart Applet Attack   # 自动检测java版本并进行攻击，针对Java 1.6.0_45以下以及Java 1.7.0_21以下版本(该方法已过时)
System Profiler   # 用来获取系统信息，如系统版本，Flash版本，浏览器版本等
Spear Phish   # 鱼叉钓鱼邮件
```

![在这里插入图片描述](CSLearn/201910241554298.png)

```
1.新建连接
2.断开当前连接
3.监听器
4.改变视图为Pivot Graph(视图列表)
5.改变视图为Session Table(会话列表)
6.改变视图为Target Table(目标列表)
7.显示所有以获取的受害主机的凭证
8.查看已下载文件
9.查看键盘记录结果
10.查看屏幕截图
11.生成无状态的可执行exe木马
12.使用java自签名的程序进行钓鱼攻击
13.生成office宏病毒文件
14.为payload提供web服务以便下载和执行
15.提供文件下载，可以选择Mime类型
16.管理Cobalt Strike上运行的web服务
17.帮助
18.关于
```

# 4.基本流程

## 创建监听器

cobalt strike=>listeners=>add，里面有9个Listener

```
indows/beacon_dns/reverse_dns_txtwindows/beacon_dns/reverse_http
windows/beacon_http/reverse_http
windows/beacon_https/reverse_https
windows/beacon_smb/bind_pipe
windows/foreign/reverse_dns_txt
windows/foreign/reverse_http
windows/foreign/reverse_https
windows/foreign/reverse_tcp
```

