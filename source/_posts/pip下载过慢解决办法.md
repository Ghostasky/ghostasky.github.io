---
title: 'pip下载过慢解决办法'
date: 2021-01-23 21:31:55
tags: Python
categories: Technology
---




```
pip install packet
```

以上命令安装时过慢，可以加入：

```
-i https://pypi.tuna.tsinghua.edu.cn/simple
```

设置国内源为默认源：

首先看pip版本

```
pip -V
```

如果版本在10.0.0以上需要如下：

```
python -m pip install --upgrade pip
pip install pip -U
pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
```

搞定。