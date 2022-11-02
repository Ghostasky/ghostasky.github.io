---
title: Python__RE模块与正则表达式
date: 2020-11-21 00:24:49
tags: Python
categories: Technology
---
[TOC]

------

# 一Python模块之RE模块

一些可选值：

- re.I（全拼：ignorecase）：忽略大小写
- re.M（全拼：multiline）：多行模式，改变^和$的行为
- re.S（全拼：datall）：点任意匹配模式，改变.的行为
- re.L（全拼locale）：是预定字符串类\w \W \b \B \s \S取决于当前区域设定
- re.U（全拼：UNICODE）: 使预定字符类 \w \W \b \B \s \S \d \D 取决于unicode定义的字符属性
- re.X（全拼：VERBOSE）: 详细模式。这个模式下正则表达式可以是多行，忽略空白字符，并可以加入注释。

方法：

1.group([group1, …]):
获得一个或多个分组截获的字符串；指定多个参数时将以元组形式返回。group1可以使用编号也可以使用别名；编号0代表整个匹配的子串；不填写参数时，返回group(0)；没有截获字符串的组返回None；截获了多次的组返回最后一次截获的子串。
2.groups([default]):
以元组形式返回全部分组截获的字符串。相当于调用group(1,2,…last)。default表示没有截获字符串的组以这个值替代，默认为None。
3.groupdict([default]):
返回以有别名的组的别名为键、以该组截获的子串为值的字典，没有别名的组不包含在内。default含义同上。
4.start([group]):
返回指定的组截获的子串在string中的起始索引（子串第一个字符的索引）。group默认值为0。
5.end([group]):
返回指定的组截获的子串在string中的结束索引（子串最后一个字符的索引+1）。group默认值为0。
6.span([group]):
返回(start(group), end(group))。
7.expand(template):
将匹配到的分组代入template中然后返回。template中可以使用\id或\g、\g引用分组，但不能使用编号0。\id与\g是等价的；但\10将被认为是第10个分组，如果你想表达\1之后是字符’0’，只能使用\g0。



pattern可以理解为一个匹配模式，利用re.compile方法就可以。例如:

`pattern = re.compile(r'hello')`

在参数中传入原生字符串对象，通过compile方法生成一个pattern对象。

## 1.re.match(pattern,string,[flags])

这个方法会从string字符串的开头开始，尝试匹配pattern，一直向后匹配，如遇到无法匹配的字符串，返回None，如果匹配未结束已经到达string尾，也会返回None。另个结果表示匹配失败，否则成功，同时匹配终止。

```python
import re
pattern = re.compile(r'hello')#r的意思是"原生字符串"

result_1 = re.match(pattern,'hello')
result_2 = re.match(pattern,'helloo, ASDF')
result_3 = re.match(pattern,'helo asdf')
result_4 = re.match(pattern,'hello adf')
if result_1:
    print result_1.group()
else:
    print "result_1 匹配失败"
    
if result_2:
    print result_2.group()
else:
    print "result_2 匹配失败"
    
if result_3:
    print result_3.group()
else:
    print "result_3 匹配失败"
if result_4:
    print result_4.group()
else:
    print "result_4 匹配失败"
```

结果是只有3未匹配...

## 2.re.search(pattern,string,[flags])

与match类似，match是从头开始检测，search会扫描整个string

```Python
import re
pattern = re.compile(r'hello')#r的意思是"原生字符串"

result_1 = re.match(pattern,'hello')
result_2 = re.match(pattern,'helloo, ASDF')
result_3 = re.match(pattern,'helo asdf')
result_4 = re.match(pattern,'hello adf')
if result_1:
    print result_1.group()
else:
    print "result_1 匹配失败"
    
if result_2:
    print result_2.group()
else:
    print "result_2 匹配失败"
    
if result_3:
    print result_3.group()
else:
    print "result_3 匹配失败"
if result_4:
    print result_4.group()
else:
    print "result_4 匹配失败"
```

# 3.re.split(pattern,string,[flags])

按照能够匹配的子串将少天日工分割后返回列表。

maxsplit用于指定最大分割次数，不指定将全部分割

```python
import re
pattern = re.compile(r'\d+')
print re.split(pattern,'one1two2three3')
```

## 4.re.findall(pattern,string,[flags])

搜索string，以列表的形式返回全部匹配的子串

```python
import re
pattern = re.compile(r'\d+')
print re.findall(pattern,'one1two2three3')
```

## 5.re.finditer(pattern,string,[flags])

搜索string，返回一个顺序访问没一个匹配结果（match对象）的迭代器

```python
import re
pattern = re.compile(r'\d+')
for i in re.finditer(pattern,'one1two2three3four4'):
    print i.group()
```

## 6.re.sub(pattern,repl,string ,[count])

使用repl替换string中没一个匹配的子串返回替换后的字符串

## 7.re.subn(pattern,repl,string,[count])

返回 (sub(repl, string[, count]), 替换次数)

# 二、正则表达式

正则表达式由以下几个部分组成：

- 原子（普通字符，如a~z）
- 有特殊功能的字符（称为元字符，例如*+？等）
- 模式修正符

`/<a.*?(?:|\\t|\\r|\\n)?href=[\'"]?(.+?)[\'"]?(?:(?:|\\t|\\r|\\n)+.*?)?>(.+?)<\/a.*?>/sim`

拆分后如下：

- 定界符使用的是两个斜线'/'
- 原子用到了<、a、href、=、'、"、等普通字符和\t,\r,\n等转义字符
- 元字符使用了[]()|.*?+d等具有特殊含义的字符

## 1.定界符

不仅仅局限于斜杠/，除了字母、数字、反斜线以外的字符都可以，如#!{}|等

## 2.原子

原子是正则表达式最基本的组成单位，这里将其划分为5类进行介绍：

1. 普通字符作为原子

   ```
   如a~z,0~9,A~Z等
   /5/  ---用于匹配是否有5
   /php/  ---用于匹配是否有php
   ```

2. 一些特殊字符和元字符作为原子

   ```
   使用特殊字符必须转义，如：
   /\./    --用于匹配是否由于.出现
   /\<br \/>/---用于匹配是否有<br />出现
   ```

3. 一些非打印字符作为原子

   非打印字符，如空格，回车，制表符等。

   | 原子字符 | 含义描述                                                     |
   | -------- | ------------------------------------------------------------ |
   | \cx      | 匹配一个由x指明的控制字符，例如，\cM匹配一个Ctrl+M或回车符。x的值必须为a~z或者A~Z之一。否则，将c视为一个原义的d字符 |
   | \f       | 匹配一个换页符                                               |
   | \n       | 匹配一个换行符                                               |
   | \r       | 匹配一个回车符                                               |
   | \t       | 匹配一个制表符                                               |
   | \v       | 匹配一个垂直制表符                                           |


4. 使用“通用字符类型”作为原子

   前面介绍 的不管是打印字符还是非打印字符，都是一个原子只能匹配一个字符。有时需要匹配所有字母或者所有数字，这是就要用“通用字符类型”

   | 原子字符 | 含义描述                               |
   | -------- | -------------------------------------- |
   | \d       | 匹配任意一个十进制数字，等价于[0~9]    |
   | \D       | 匹配任意一个非十进制数字，等价于[ ^ 0~9 ] |
   | \s       | 匹配任意一个空白字符 |
   | \S       | 匹配出空白字符以外的任何一个字符 |
   | \w       | 匹配任意一个数字、字母、或下划线 |
   | \W       | 匹配除数字、字母、或下划线以外的任何一个字符 |

   

5. 自定义原子表[]作为原子

   直接上例子：

   ```
   /[apj]sp/   ---可以匹配asp jsp或psp三种，从原子表中仅选一种作为原子
   /[^apj]sp   ---可以匹配除asp jsp 和PSP之外的字符串，如xsp，zsp等
   /0[xX][0-9a-fA-F]  ---可以匹配一个简单的十六进制数
   ```

# 3.元字符

| 元字符 | 含义描述                                                     |
| ------ | ------------------------------------------------------------ |
| *      | 匹配0次1次或多次其前的原子                                   |
| +      | 匹配1次或多次其前的原子                                      |
| ?      | 匹配0次或1次其前的原子                                       |
| \|     | 匹配两个或多个分支选择                                       |
| .      | 匹配除了换行符之外的任意一个字符                             |
| {n}    | 表示其前面的原子恰好出现n次                                  |
| {n,}   | 表示其前面的原子出现不少于n次                                |
| {n,m}  | 其前面的原子出现次数介于n和m之间                             |
| ^或\A  | 匹配输入字符串的开始位置                                     |
| $或\Z  | 匹配输入字符串的结束为止                                     |
| \b     | 匹配单词的边界                                               |
| \B     | 匹配除单词边界以外的部分                                     |
| []     | 匹配方括号中指定的任意一个原子                               |
| [^]    | 匹配除方括号中指定的任意一个原子                             |
| ()     | 匹配器整体为一个原子，即模式单元可以理解为多个原子组成的大原子 |

栗子如下：

```
/a\s*b/        --可以匹配在a和b之间没用空白，一个空白或多个空白的情况
/a\d+b/		----可以匹配在a和b之间1个数字或多个数字的情况
/a\W?b/		----可以匹配在a和b之间有一个货没有特殊字符的情况
/ax{4}b/		----可以匹配在a和b之间必须有4个x，如axxxxb
/ax{2,}b/      ----ab之间至少两个x
/ax{2,4}b/		--ab之间的x的个数在2,4之间

/^this/   --匹配此字符串是否是以this开始的
/this$/
/\bis\b/ ---匹配此字符串中是否含有is
/\Bis\b/  ----查找字符串is时，左边不能有边界，右边必须有边界，如this
/a.b/  
/Linux|Apache|mysql/
/(very)*good/ ---可以匹配good,very good,very very good ....等
/(Windows)(Linus)\\2OS/  ---使用\2再次引用第二个缓冲区中的字符串Linux
/(?:windows)(linux)\\1OS/ ---使用?:忽略了第一个表达式的存储，所以\1引用的就是Linux
```

## 模式匹配的优先级：

| 元字符                    | 描述             |
| ------------------------- | ---------------- |
| \                         | 转义符号         |
| ()、(?: )、(?=)、[]        | 模式单元和原子表 |
| *、+、?、{n}、{n,}、{n,m} | 重复匹配         |
| ^、$、\b、\B、\A、\Z      | 边界限制         |
| \|                        | 模式选择         |

### 模式修正符

模式修正符是在正则表达式定界符之外使用

| 模式修正符 | 功能描述                                                     |
| ---------- | ------------------------------------------------------------ |
| i          | 在和模式进行匹配是不区分大小写                               |
| m          | 将字符串视为多行。默认的正则开始^和结束$竟目标字符串作为单一的一行字符（甚至其中包含有换行符也是如此）。如果在修正符中加上m，那么开始和结束将会指字符串的每一行，每一行的开头是^，结束是$ |
| s          | 如果设定了次修正符，则模式中的圆点字符.匹配所有字符，包括换行符。即将字符串视为单行，换行符作为普通字符看待 |
| x          | 模式中的空白忽略不计，除非它已经被转义                       |
| e          | 只用在preg_replace()函数中，在替换字符串中对逆向引用做正常的替换，将其作为PHP代码求值，并用其结果来替换所搜索的字符串 |
| U          | 本修正符反转了匹配数量的值使其不是默认的重复，而变成在后面跟上?才变得重复 |
| D          | 模式中的美元字符仅匹配字符串的结尾。没有此选项是，如果最后一个字符是换行符，则美元符号也会匹配此字符之前的内容。如果设定了m修正符，则忽略此选项。 |

