---
title: JSON相关
date: 2021-02-27 17:57:36
tags: Python
categories: Technology
---




## 1. JSON的两种结构

两种结构分别为：对象，数组。

### 对象结构

这种结构以大括号开始和结束，中间有多个以逗号分隔的键值对构成，键值对由冒号分隔。

```json
{
	key:value,
	key2:value2,
	key3:value3,
	...
}
```

其中的键为字符串，而值可以是字符串，数值，true，false，null，对象或数组。

### 数组结构

数组结构如下：

```json
[
    {
        "键名1":值1,
        "键名2":值2
    },
    {
        "键名3":值3,
        "键名4":值4
    },
    ……
]
```

## 2. python中JSON模块

四个方法：

dumps，dump，loads，load

- dump的功能就是把**Python对象**encode为**json对象**，一个编码过程。 注意json模块提供了json.dumps和json.dump方法，区别是**dump直接到文件**，而**dumps到一个字符串**，这里的s可以理解为string。

```python
#dumps方法
import json
data = [{ 'a':'A', 'b':(2, 4), 'c':3.0 }]
print('DATA:', repr(data), type(data)) 

data_string = json.dumps(data)
print('JSON:', data_string, type(data_string))
```

- dump方法不仅可以将python对象编码为string，还可写入文件。但是不能把Python对象直接写入文件。

```python
#dump方法
import json
data = [ { 'a':'A', 'b':(2, 4), 'c':3.0 } ]
 
with open('output.json','w') as fp:
    json.dump(data,fp)
```

- loads方法可以将JSON对象decode为python可以识别是对象，这是基于string的，如果是文件，可以用json.load方法。

