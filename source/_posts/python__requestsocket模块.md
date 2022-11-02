---
title: Python__request，socket模块
date: 2020-11-23 20:18:54
tags: Python
categories: Technology
---
[TOC]

------

# 一、requests库基本使用

请求方式：

​	get，post，head，put，delete，options。

**kwargs访问控制参数：

- params：字典或字节序列，作为参数加到URL中
- data：字典、字节序列或文件对象，作为request的内容
- json：json格式的数据，作为request的内容
- headers：字典，http定制头
- cookies：字典或cookiejar
- files：字典类型，传输文件
- timeout：设定超时时间，秒为单位、
- proxies：字典类型，设定访问代理服务器，可以增加登陆认证
- allow_redirects：true/false，默认true，重定向开关
- stream：true/false，默认true，获取内容立即下载开关
- verify：true/false，默认true，认证SSL证书开关
- cert：本地SSL证书
- auth：元组，支持http认证功能



使用requests方法后，会返回一个response对象。

response对象的属性：

> r.status_code：http请求的返回状态
>
> r.text：http响应内容的字符串形式
>
> r.encoding：从http header中猜测的响应内容编码方式
>
> r.apparent_encodign：从内容中分析出的响应内容编码格式
>
> r.content：http响应内容的二进制形式

requests库的异常：

> requests.ConnectionError：网络连接错误异常，如DNS查询失败、拒绝连接等
>
> requests.HTTPErroe：http错误异常
>
> requests.URLRequired：URL缺失异常
>
> requests.TooManyRedirects：超过最大重定向次数，产生重定向异常
>
> requests.ConnectTimeout：连接远程服务器超时异常
>
> requests.Timeyout请求URL是，产生超时异常
>
> requests.raise_for_status()：如果不是200，产生requests.HTTPError

## 1.request.get(url,params=*,**kwargs)

其中后两个参数可选

```python
import requests
response = requests.get('http://xxxx.xx')

response = requests.get('http://xxxx.xx/?a=xxx&b=sss')

data = {'a'='xxx','b'='sss'}
response = requests.get('http://xxxx.xx',params=data)

payload = {'key1': 'value1', 'key2': 'value2'}
headers = {'content-type': 'application/json'}
response = requests.get("http://xxx.xx", params=payload, headers=headers)

#response的一些属性：

r = requests.get("https://www.baidu.com")
print r.status_code
#print r.text
print r.encoding
print r.apparent_encoding
#print r.content
#print r.json()
print r.reason
print r.headers
print r.cookies
print r.raw
```

## 2.requests.post(url,data=None,json=None,\**kwargs)

```
import requests
data={'a'='xxx','b'='sss'}
response = requests.post('http://xxx.xx',data=data)

url = 'http://httpbin.org/post'
files = {'file': open('test.txt', 'rb')}
r = requests.post(url, files=files)
print r.text
```
## 3.request.head(url,**kwargs)
## 4.requests.put(url,data=None,**kwargs)
## 5.request.patch(url,data=None,**kwargs)

## 6.request.delete(url,**kwargs)

以上都大同小异，就不写了。。。

# 二、socket库

- sk.socket.socket(socket.AF_INET,socket.SOCK_STREAM,0)

  参数一：

  ​	默认为socket.AF_INET(IPv4)，还有socket.AF_INET6(IPv6),socket.AF_UNIX，其中最后一个只能用于单一的UNIX系统进程间通信

  参数二：类型

  ​	socket.SOCK_STREAM  //流式socket，tcp（默认）

  ​	socket.SOCK_DREAM  //数据报式socket，udp

  参数三：协议

  ​	（默认）与特定的地址家族相关的协议,如果是 0 ，则系统就会根据地址格式和套接类别,自动选择一个合适的协议(非必填)

  ```
  #创建socket：
      #TCP socket
      sk = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
      # UDP socke
      sk = socket.socket(socket.AF_INET,socket.SOCK_DREAM)
  ```

## 1.socket常用函数介绍

  	因为TCP发送数据时已经建立好链接，所以不需要指定地，UDP是面向无链接的，每次发送需要指定。

- ### 服务器端函数：

  | 函数名             | 描述                                                         |
  | ------------------ | ------------------------------------------------------------ |
  | sk.bind(address)   | 将套接字绑定到地址，address是元组(host,port)                 |
  | sk.listen(backlog) | 开始监听TCP传入链接，backlog指定在拒绝连接前，操作系统可以连接的最大连接数，最少为1 |
  | sk.accept()        | 接收TCP连接并返回(conn,address)，其中conn是新的套接字对象    |

- ### 客户端函数：

  | 函数名                 | 描述                                                         |
  | ---------------------- | ------------------------------------------------------------ |
  | sk.connect(address)    | 连接到address处的套接字，address是元组(host,port)，如果连接出错，返回socket.error |
  | sk.connect_ex(address) | 功能与上相同，但成功返回0，失败返回erron的值                 |

- ### 公共函数：

  | 函数                             | 描述                                                         |
  | -------------------------------- | ------------------------------------------------------------ |
  | sk.recv(bufsize[,flag])          | 接收TCP套接字的数据，数据已字符串形式返回，bufsize指定接收最大数据量，flag提供有关消息的其他信息，可省略 |
  | sk.send(string[,flag])           | 发送TCP数据，返回值是要发送的字节数量                        |
  | sk.sendall(string[,flag])        | 发送完整TCP数据，在返回之前尝试发送所有数据，成功返回none，失败跑出异常 |
  | sk.recvfro(bufsize[,flag])       | 接收UDP套接字数据，返回值是(data,address)。data是包含接收数据的字符串，address是发送数据的套接字地址 |
  | sk.sendto(string[,flag],address) | 发送UDP数据，address是元组(host,port)，返回值是发送的字节数  |
  | sk.close()                       | 关闭套接字                                                   |
  | sk.getpeername()                 | 返回套接字的远程地址，返回值是(host,port)                    |
  | sk.getsockname()                 | 返回套接字自己的地址                                         |



## 2.举例：

```python
#服务器端
import socket
host = '192.168.1.123'
port = 4444
sk = socket.socket(socket.AF_INET,socket_STREAM)
sk.bind((host,port))
sk.listen(5)
print 'Conn...'
while True:
    print 'conn ok'
    conn,addr = accept()
    print 'conne form ',addr
    while True:
        data = sk.soket.recv(1024)
        print data
        print 'server received your msg'
sk.close()

#客户端
import socket
host = '192.168.1.123'
port = 4444
sk = socket.socket(socket.AF_INET,socket,STREAM)
sk.connet((host,port))
while True:
    msg = input('input msg:')
    sk.send(msg)
    data = sk.recv(1024)
    print data
sk.close()
```

查看socket状态： `netstart -an`

> request和socket大致介绍就这样了，不是很全，但基本用法都在这了