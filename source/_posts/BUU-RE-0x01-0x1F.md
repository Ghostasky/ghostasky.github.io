---
title: BUU_RE刷题
date: 2021-11-07
tags: RE
categories: Technology
---

之前写过一部分re的题解，最近又有点想搞re了，重来吧。(从01开始计)

# 0x01.简单注册器

![image-20211021234037840](BUU-RE-0x01-0x1F/image-20211021234037840.png)

简单的替换和翻转字符串

```python
x = "dd2940c04462b4dd7c450528835cca15"
x = list(x)
x[2] = chr((ord(x[2]) + ord(x[3])) - 50)
x[4] = chr((ord(x[2]) + ord(x[5])) - 48)
x[30] = chr((ord(x[31]) + ord(x[9])) - 48)
x[14] = chr((ord(x[27]) + ord(x[28])) - 97)
x = x[::-1]
x = ''.join(x)
print(x)
```

# 0x02.Java逆向解密

代码逻辑很清晰

```java
package defpackage;

import java.util.ArrayList;
import java.util.Scanner;

/* renamed from: Reverse  reason: default package */
public class Reverse {
    public static void main(String[] args) {
        Scanner s = new Scanner(System.in);
        System.out.println("Please input the flag ：");
        String str = s.next();
        System.out.println("Your input is ：");
        System.out.println(str);
        Encrypt(str.toCharArray());
    }

    public static void Encrypt(char[] arr) {
        int[] KEY;
        ArrayList<Integer> Resultlist = new ArrayList<>();
        for (char c : arr) {
            Resultlist.add(Integer.valueOf((c + '@') ^ 32));
        }
        ArrayList<Integer> KEYList = new ArrayList<>();
        for (int i : new int[]{180, 136, 137, 147, 191, 137, 147, 191, 148, 136, 133, 191, 134, 140, 129, 135, 191, 65}) {
            KEYList.add(Integer.valueOf(i));
        }
        System.out.println("Result:");
        if (Resultlist.equals(KEYList)) {
            System.out.println("Congratulations！");
        } else {
            System.err.println("Error！");
        }
    }
}
```



exp：

```python
flag = [180, 136, 137, 147, 191, 137, 147, 191,
        148, 136, 133, 191, 134, 140, 129, 135, 191, 65]
for i in range(len(flag)):
    flag[i] = chr((flag[i] - ord('@')) ^ 0x20)
flag = ''.join(flag)
print(flag)
```

# 0x03.findit

就是个凯撒

```java
package com.example.findit;

import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends ActionBarActivity {
    /* access modifiers changed from: protected */
    @Override // android.support.v7.app.ActionBarActivity, android.support.v4.app.FragmentActivity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        final EditText edit = (EditText) findViewById(R.id.widget2);
        final TextView text = (TextView) findViewById(R.id.widget1);
        final char[] a = {'T', 'h', 'i', 's', 'I', 's', 'T', 'h', 'e', 'F', 'l', 'a', 'g', 'H', 'o', 'm', 'e'};
        final char[] b = {'p', 'v', 'k', 'q', '{', 'm', '1', '6', '4', '6', '7', '5', '2', '6', '2', '0', '3', '3', 'l', '4', 'm', '4', '9', 'l', 'n', 'p', '7', 'p', '9', 'm', 'n', 'k', '2', '8', 'k', '7', '5', '}'};
        ((Button) findViewById(R.id.widget3)).setOnClickListener(new View.OnClickListener() {
            /* class com.example.findit.MainActivity.AnonymousClass1 */

            public void onClick(View v) {
                char[] x = new char[17];
                char[] y = new char[38];
                for (int i = 0; i < 17; i++) {
                    if ((a[i] < 'I' && a[i] >= 'A') || (a[i] < 'i' && a[i] >= 'a')) {
                        x[i] = (char) (a[i] + 18);
                    } else if ((a[i] < 'A' || a[i] > 'Z') && (a[i] < 'a' || a[i] > 'z')) {
                        x[i] = a[i];
                    } else {
                        x[i] = (char) (a[i] - '\b');
                    }
                }
                if (String.valueOf(x).equals(edit.getText().toString())) {
                    for (int i2 = 0; i2 < 38; i2++) {
                        if ((b[i2] < 'A' || b[i2] > 'Z') && (b[i2] < 'a' || b[i2] > 'z')) {
                            y[i2] = b[i2];
                        } else {
                            y[i2] = (char) (b[i2] + 16);
                            if ((y[i2] > 'Z' && y[i2] < 'a') || y[i2] >= 'z') {
                                y[i2] = (char) (y[i2] - 26);
                            }
                        }
                    }
                    text.setText(String.valueOf(y));
                    return;
                }
                text.setText("答案错了肿么办。。。不给你又不好意思。。。哎呀好纠结啊~~~");
            }
        });
    }

    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
```

exp：

```python
a = ['p', 'v', 'k', 'q', '{', 'm', '1', '6', '4', '6', '7', '5', '2', '6', '2', '0', '3', '3', 'l',
     '4', 'm', '4', '9', 'l', 'n', 'p', '7', 'p', '9', 'm', 'n', 'k', '2', '8', 'k', '7', '5', '}']
mod = 'abcdefghijklmnopqrstuvwxyz'
aa = ''
for i in range(1, 27):
    for s in a:
        if s.isalpha():
            n = mod.find(s)
            s = mod[n-i]
        print(s, end='')
    print()
```



# 0x04.[GWCTF 2019]pyre



```python
#!/usr/bin/env python
# visit https://tool.lu/pyc/ for more information
print 'Welcome to Re World!'
print 'Your input1 is your flag~'
l = len(input1)
for i in range(l):
    num = ((input1[i] + i) % 128 + 128) % 128
    code += num

for i in range(l - 1):
    code[i] = code[i] ^ code[i + 1]

print code
code = [
    '\x1f',
    '\x12',
    '\x1d',
    '(',
    '0',
    '4',
    '\x01',
    '\x06',
    '\x14',
    '4',
    ',',
    '\x1b',
    'U',
    '?',
    'o',
    '6',
    '*',
    ':',
    '\x01',
    'D',
    ';',
    '%',
    '\x13']

```

exp：

```python
code = [
    '\x1f',
    '\x12',
    '\x1d',
    '(',
    '0',
    '4',
    '\x01',
    '\x06',
    '\x14',
    '4',
    ',',
    '\x1b',
    'U',
    '?',
    'o',
    '6',
    '*',
    ':',
    '\x01',
    'D',
    ';',
    '%',
    '\x13']

n = len(code)
print(n)
for i in range(n-2, -1, -1):
    code[i] = chr(ord(code[i]) ^ ord(code[i+1])
for i in range(n):
    print(chr((ord(code[i])-i) % 128), end="")
```

代码功底还是太烂了。



# 0x05.[ACTF新生赛2020]easyre

peid查完是upx壳，脱壳：

![image-20211024154813690](BUU-RE-0x01-0x1F/image-20211024154813690.png)

清晰了很多：

![image-20211024162234474](BUU-RE-0x01-0x1F/image-20211024162234474.png)

![image-20211024155033211](BUU-RE-0x01-0x1F/image-20211024155033211.png)

就是

```python
# !\"'
str = '''~}|{zyxwvutsrqponmlkjihgfedcba`_^]\\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876543210/.-,+*)('&%$# !\"'''
v4 = '''*F'\"N,\"(I?+@'''
flag = ''
# v4 = list(v4)
for i in v4:
    flag += chr(str.find(i)+1)
print(flag)
```

# 0x06.rsa

第一次做RSA的题，就先看了一遍RSA的流程。

这个题给了两个文件：flag.enc，pub.key

>   公钥N = p*q,(为pub.key),e
>
>   e是随机选择的数，d是e关于phi(N)的模反元素：ed≡1(mod phi(N))
>
>   私钥：N,d

copy到公钥解析的网站进行解析：http://tool.chacuo.net//cryptrsakeyparse

| key长度： | 256                                                              |
| --------- | ---------------------------------------------------------------- |
| 模数(N)： | C0332C5C64AE47182F6C1C876D42336910545A58F7EEFEFC0BCAAF5AF341CCDD |
| 指数(e)： | 65537 (0x10001)                                                  |

所以：e =  65537

N = C0332C5C64AE47182F6C1C876D42336910545A58F7EEFEFC0BCAAF5AF341CCDD(要转成10进制)

再通过网站分解N得到pq：http://www.factordb.com/index.php?query=

得到：

p = 285960468890451637935629440372639283459
q = 304008741604601924494328155975272418463

再接下来就是写exp了：

```python
import rsa
import gmpy2
e = 65537
n = 86934482296048119190666062003494800588905656017203025617216654058378322103517
p = 285960468890451637935629440372639283459
q = 304008741604601924494328155975272418463

phin = (p-1)*(q-1)
d = gmpy2.invert(e, phin)
key = rsa.PrivateKey(n, e, int(d), p, q)

with open("D:\\Desktop\\output\\flag.enc", "rb+") as f:
    f = f.read()
    print(rsa.decrypt(f, key))

```





# 0x07.[ACTF新生赛2020]rome

简化了下代码：

```c
int func()
{
  int result; // eax
  char v1[16]; // [esp+14h] [ebp-44h]
  char input_str[22]; // [esp+24h] [ebp-34h] BYREF
  char local_str[29]; // [esp+3Bh] [ebp-1Dh] BYREF

  strcpy(local_str, "Qsw3sj_lz4_Ujw@l");
  printf("Please input:");
  scanf("%s", input_str);
  result = input_str[0];
  if ( input_str[0] == 'A' )
  {
    result = input_str[1];
    if ( input_str[1] == 'C' )
    {
      result = input_str[2];
      if ( input_str[2] == 'T' )
      {
        result = input_str[3];
        if ( input_str[3] == 'F' )
        {
          result = input_str[4];
          if ( input_str[4] == '{' )
          {
            result = input_str[21];
            if ( input_str[21] == '}' )
            {
              *v1 = *&input_str[5];
              *&v1[4] = *&input_str[9];
              *&v1[8] = *&input_str[13];
              *&v1[12] = *&input_str[17];
              *&local_str[17] = 0;
              while ( *&local_str[17] <= 15 )
              {
                if ( v1[*&local_str[17]] > 64 && v1[*&local_str[17]] <= 90 )// 大写
                  v1[*&local_str[17]] = (v1[*&local_str[17]] - 51) % 26 + 65;
                if ( v1[*&local_str[17]] > 96 && v1[*&local_str[17]] <= 122 )// 小写
                  v1[*&local_str[17]] = (v1[*&local_str[17]] - 79) % 26 + 97;
                ++*&local_str[17];
              }
              *&local_str[17] = 0;
              while ( *&local_str[17] <= 15 )
              {
                result = local_str[*&local_str[17]];
                if ( v1[*&local_str[17]] != result )
                  return result;
                ++*&local_str[17];
              }
              result = printf("You are correct!");
            }
          }
        }
      }
    }
  }
  return result;
}
```



```python
local = "Qsw3sj_lz4_Ujw@l"
a = 0
flag = ''
for k in range(16):
    for i in range(33, 128):
        a = i
        if i > 64:
            if i <= 90:
                a = (i-51) % 26 + 65
        if i > 96:
            if i <= 122:
                a = (i-0x4f) % 26 + 97
        if chr(a) == local[k]:
            flag += chr(i)
print(flag)
```

# 0x08.[2019红帽杯]easyRE

讲真我还是太拉了，这题把wp看了半天，代码也看了半天。。。先看题吧：

刚进去代码完全看不懂，然后应该是要输入些什么东西，

![image-20211025193922062](BUU-RE-0x01-0x1F/image-20211025193922062.png)

这里是将输入的东西异或后与本地的字符串比较，解一下：

```python
local_str = [73, 111, 100, 108, 62, 81, 110, 98, 40, 111, 99, 121, 127, 121, 46, 105, 127, 100, 96, 51, 119, 125,
             119, 101, 107, 57, 123, 105, 121, 61, 126, 121, 76, 64, 69, 67]

for i in range(len(local_str)):
    for j in range(128):
        if j ^ i == local_str[i]:
            print(chr(j), end='')
#output: Info:The first four chars are `flag`
```

之后是又一次的输入：

![image-20211025195507127](BUU-RE-0x01-0x1F/image-20211025195507127.png)

会base64进行10次后和本地的另一个字符串比较，解密10次后发现这是个假的hint........

接下来的一点是我怎么都没想到的，，在字符串的下面有个常量，在另一个函数有调用：

![image-20211025200621618](BUU-RE-0x01-0x1F/image-20211025200621618.png)

x查看交叉引用，关键代码：

![image-20211026141034428](BUU-RE-0x01-0x1F/image-20211026141034428.png)

输入的第一位和第四位和本地的字符串异或之后要分别为f和g，猜测前4位为flag，后面的是循环异或

shift+e提取数据，exp：

```python
str = [
    0x40, 0x35, 0x20, 0x56, 0x5D, 0x18, 0x22, 0x45, 0x17, 0x2F,
    0x24, 0x6E, 0x62, 0x3C, 0x27, 0x54, 0x48, 0x6C, 0x24, 0x6E,
    0x72, 0x3C, 0x32, 0x45, 0x5B
]
flag = 'flag'
qq = []
for i in range(len(flag)):
    qq.append(chr(ord(flag[i]) ^ str[i]))
print(qq)
for i in range(len(str)):
    a = chr(str[i] ^ ord(qq[i % 4]))
    print(a, end='')
```

# 0x09.[FlareOn4]login

关键的部分就只有12行的那部分：

```html
<!DOCTYPE Html />
<html>
    <head>
        <title>FLARE On 2017</title>
    </head>
    <body>
        <input type="text" name="flag" id="flag" value="Enter the flag" />
        <input type="button" id="prompt" value="Click to check the flag" />
        <script type="text/javascript">
            document.getElementById("prompt").onclick = function () {
                var flag = document.getElementById("flag").value;
                var rotFlag = flag.replace(/[a-zA-Z]/g, function(c){return String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);});
                if ("PyvragFvqrYbtvafNerRnfl@syner-ba.pbz" == rotFlag) {
                    alert("Correct flag!");
                } else {
                    alert("Incorrect flag, rot again");
                }
            }
        </script>
    </body>
</html>
```

其实就是rot13，在if前面把rotflag给输出一下就OK。

# 0x0A.[GUET-CTF2019]re

>   考点是z3约束器相关：
>
>   https://arabelatso.github.io/2018/06/14/Z3%20API%20in%20Python/

exeinfope查壳之后发现是upx壳，脱掉之后：

```c
__int64 __fastcall mian(__int64 a1, int a2, int a3, int a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // er8
  int v9; // er9
  __int64 result; // rax
  char v11[32]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v12; // [rsp+28h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  *&v11[8] = 0LL;
  *&v11[16] = 0LL;
  *&v11[24] = 0LL;
  printf("input your flag:", a2, a3, a4, a5, a6);
  scanf("%s", v11, v6, v7, v8, v9, 0);
  if ( check(v11) )
    puts("Correct!");
  else
    puts("Wrong!");
  result = 0LL;
  if ( __readfsqword(0x28u) != v12 )
    sub_443550();
  return result;
}
```

最关键的就是check那个了：

```c
_BOOL8 __fastcall check(char *a1)
{
  if ( 1629056 * *a1 != 166163712 )
    return 0LL;
  if ( 6771600 * a1[1] != 731332800 )
    return 0LL;
  if ( 3682944 * a1[2] != 357245568 )
    return 0LL;
  if ( 10431000 * a1[3] != 1074393000 )
    return 0LL;
  if ( 3977328 * a1[4] != 489211344 )
    return 0LL;
  if ( 5138336 * a1[5] != 518971936 )
    return 0LL;
  if ( 7532250 * a1[7] != 406741500 )
    return 0LL;
  if ( 5551632 * a1[8] != 294236496 )
    return 0LL;
  if ( 3409728 * a1[9] != 177305856 )
    return 0LL;
  if ( 13013670 * a1[10] != 650683500 )
    return 0LL;
  if ( 6088797 * a1[11] != 298351053 )
    return 0LL;
  if ( 7884663 * a1[12] != 386348487 )
    return 0LL;
  if ( 8944053 * a1[13] != 438258597 )
    return 0LL;
  if ( 5198490 * a1[14] != 249527520 )
    return 0LL;
  if ( 4544518 * a1[15] != 445362764 )
    return 0LL;
  if ( 3645600 * a1[17] != 174988800 )
    return 0LL;
  if ( 10115280 * a1[16] != 981182160 )
    return 0LL;
  if ( 9667504 * a1[18] != 493042704 )
    return 0LL;
  if ( 5364450 * a1[19] != 257493600 )
    return 0LL;
  if ( 13464540 * a1[20] != 767478780 )
    return 0LL;
  if ( 5488432 * a1[21] != 312840624 )
    return 0LL;
  if ( 14479500 * a1[22] != 1404511500 )
    return 0LL;
  if ( 6451830 * a1[23] != 316139670 )
    return 0LL;
  if ( 6252576 * a1[24] != 619005024 )
    return 0LL;
  if ( 7763364 * a1[25] != 372641472 )
    return 0LL;
  if ( 7327320 * a1[26] != 373693320 )
    return 0LL;
  if ( 8741520 * a1[27] != 498266640 )
    return 0LL;
  if ( 8871876 * a1[28] != 452465676 )
    return 0LL;
  if ( 4086720 * a1[29] != 208422720 )
    return 0LL;
  if ( 9374400 * a1[30] == 515592000 )
    return 5759124 * a1[31] == 719890500;
  return 0LL;
}
```

可以手动一个一个解，也可z3：


```python
from z3 import *
s = Solver()
a1 = [0]*32
for i in range(32):
    a1[i] = Int('a1['+str(i)+']')

s.add(1629056 * a1[0] == 166163712)
s.add(6771600 * a1[1] == 731332800)
s.add(3682944 * a1[2] == 357245568)
s.add(10431000 * a1[3] == 1074393000)
s.add(3977328 * a1[4] == 489211344)
s.add(5138336 * a1[5] == 518971936)
s.add(7532250 * a1[7] == 406741500)
s.add(5551632 * a1[8] == 294236496)
s.add(3409728 * a1[9] == 177305856)
s.add(13013670 * a1[10] == 650683500)
s.add(6088797 * a1[11] == 298351053)
s.add(7884663 * a1[12] == 386348487)
s.add(8944053 * a1[13] == 438258597)
s.add(5198490 * a1[14] == 249527520)
s.add(4544518 * a1[15] == 445362764)
s.add(3645600 * a1[17] == 174988800)
s.add(10115280 * a1[16] == 981182160)
s.add(9667504 * a1[18] == 493042704)
s.add(5364450 * a1[19] == 257493600)
s.add(13464540 * a1[20] == 767478780)
s.add(5488432 * a1[21] == 312840624)
s.add(14479500 * a1[22] == 1404511500)
s.add(6451830 * a1[23] == 316139670)
s.add(6252576 * a1[24] == 619005024)
s.add(7763364 * a1[25] == 372641472)
s.add(7327320 * a1[26] == 373693320)
s.add(8741520 * a1[27] == 498266640)
s.add(8871876 * a1[28] == 452465676)
s.add(4086720 * a1[29] == 208422720)
s.add(9374400 * a1[30] == 515592000)
s.add(5759124 * a1[31] == 719890500)
s.check()
print(s.model())
```

输出：

```pyhton
[a1[31] = 125,
 a1[30] = 55,
 a1[29] = 51,
 a1[28] = 51,
 a1[27] = 57,
 a1[26] = 51,
 a1[25] = 48,
 a1[24] = 99,
 a1[23] = 49,
 a1[22] = 97,
 a1[21] = 57,
 a1[20] = 57,
 a1[19] = 48,
 a1[18] = 51,
 a1[16] = 97,
 a1[17] = 48,
 a1[15] = 98,
 a1[14] = 48,
 a1[13] = 49,
 a1[12] = 49,
 a1[11] = 49,
 a1[10] = 50,
 a1[9] = 52,
 a1[8] = 53,
 a1[7] = 54,
 a1[5] = 101,
 a1[4] = 123,
 a1[3] = 103,
 a1[2] = 97,
 a1[1] = 108,
 a1[0] = 102]
```

```python
a1 = [0]*32
a1[31] = 125
a1[30] = 55
a1[29] = 51
a1[28] = 51
a1[27] = 57
a1[26] = 51
a1[25] = 48
a1[24] = 99
a1[23] = 49
a1[22] = 97
a1[21] = 57
a1[20] = 57
a1[19] = 48
a1[18] = 51
a1[16] = 97
a1[17] = 48
a1[15] = 98
a1[14] = 48
a1[13] = 49
a1[12] = 49
a1[11] = 49
a1[10] = 50
a1[9] = 52
a1[8] = 53
a1[7] = 54
a1[5] = 101
a1[4] = 123
a1[3] = 103
a1[2] = 97
a1[1] = 108
a1[0] = 102

for i in range(32):
    if i == 6:
        print('1', end='')
    else:
        print(chr(a1[i]), end='')

```

这里因为6没有，所以只能一个一个试，恰巧第一个就可。

# 0x0B.[SUCTF2019]SignIn



```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char v4[16]; // [rsp+0h] [rbp-4A0h] BYREF
  char v5[16]; // [rsp+10h] [rbp-490h] BYREF
  char v6[16]; // [rsp+20h] [rbp-480h] BYREF
  char v7[16]; // [rsp+30h] [rbp-470h] BYREF
  char input[112]; // [rsp+40h] [rbp-460h] BYREF
  char v9[1000]; // [rsp+B0h] [rbp-3F0h] BYREF
  unsigned __int64 v10; // [rsp+498h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  puts("[sign in]");
  printf("[input your flag]: ");
  __isoc99_scanf("%99s", input);
  sub_96A(input, v9);
  __gmpz_init_set_str(v7, "ad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35", 16LL);
  __gmpz_init_set_str(v6, v9, 16LL);
  __gmpz_init_set_str(v4, "103461035900816914121390101299049044413950405173712170434161686539878160984549", 10LL);
  __gmpz_init_set_str(v5, "65537", 10LL);
  __gmpz_powm(v6, v6, v5, v4);
  if ( __gmpz_cmp(v6, v7) )
    puts("GG!");
  else
    puts("TTTTTTTTTTql!");
  return 0LL;
}
```

其中的`sub_96A`就是转16进制，然后是`__gmpz_init_set_str`，这个是 GNU 高精度算法库。贴个官网:https://gmplib.org/manual/

`__gmpz_powm`：

```c
void mpz_powm (mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t mod) [Function]
Set rop to base^exp mod mod.
```

就是计算base的exp次方，然后对mod取模，存到rop。

这里再看下RSA的加解密情况：

>   c  = (m ^ e) mod n
>
>   其中c为密文，m为明文，e为公钥

>   m = (c ^ d) mod n
>
>   d是e关于phi(N)的模反元素

于是乎：

```pyhton
C = ad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35
m = input
e = 65537
N = 103461035900816914121390101299049044413950405173712170434161686539878160984549
```

可以通过在线网站分解pq或者使用yafu也可：

>   p = 282164587459512124844245113950593348271
>
>   q = 366669102002966856876605669837014229419

再之后就是计算私钥d，根据密文，私钥，N计算明文

exp：

```python
import gmpy2
import binascii
C = 0xad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35
e = 65537
N = 103461035900816914121390101299049044413950405173712170434161686539878160984549
p = 282164587459512124844245113950593348271
q = 366669102002966856876605669837014229419
d = gmpy2.invert(e, (q-1)*(p-1))
m = gmpy2.powmod(C, d, N)
# print(m)
print(binascii.unhexlify(hex(m)[2:]).decode(encoding='utf-8'))
```

# 0x0C.Youngter-drive

查壳发现是upx，有一个输入，然后是两个线程

先看下第一个线程：

```c
void __stdcall StartAddress_0(int a1)
{
  while ( 1 )
  {
    WaitForSingleObject(hObject, 0xFFFFFFFF);
    if ( dword_418008 > -1 )
    {
      sub_41112C(&input, dword_418008);
      --dword_418008;
      Sleep(0x64u);
    }
    ReleaseMutex(hObject);
  }
}
//sub_41112C函数(套了一层)：
char *__cdecl sub_411940(char *input, int a2)
{
  char *result; // eax
  char v3; // [esp+D3h] [ebp-5h]

  v3 = input[a2];
  if ( (v3 < 97 || v3 > 122) && (v3 < 65 || v3 > 90) )
    exit(0);
  if ( v3 < 97 || v3 > 122 )
  {
    result = off_418000[0];
    input[a2] = off_418000[0][input[a2] - 38];
  }
  else
  {
    result = off_418000[0];
    input[a2] = off_418000[0][input[a2] - 96];
  }
  return result;
}
```

如果是小写，当前字符的ascii减96之后到off_418000查；如果是大写，减38

第二个线程：

```c
void __stdcall sub_411B10(int a1)
{
  while ( 1 )
  {
    WaitForSingleObject(hObject, 0xFFFFFFFF);
    if ( dword_418008 > -1 )
    {
      Sleep(0x64u);
      --dword_418008;
    }
    ReleaseMutex(hObject);
  }
}
```

各一个字符加密，好家伙幸亏之前看过Windows程序设计，要不然还真可能看不懂.

再之后的有个与本地字符串的比较：

```c
int sub_411880()
{
  int i; // [esp+D0h] [ebp-8h]

  for ( i = 0; i < 29; ++i )
  {
    if ( input[i] != off_418004[i] )
      exit(0);
  }
  return printf("\nflag{%s}\n\n", Destination);
}
```

只比较了29位，但是一共有30位，尝试到E正好可以：exp

```python
off_418000 = 'QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm'
off_418004 = 'TOiZiZtOrYaToUwPnToBsOaOapsyS'
str = ''
a = ''
for i in range(len(off_418004)):
    if i % 2 == 0:
        print(off_418004[i], end='')
        continue
    if off_418004[i].isupper():
        a = chr(off_418000.find(off_418004[i])+96)
    else:
        a = chr(off_418000.find(off_418004[i])+38)
    print(a, end='')
    # i += 1
#ThisisthreadofwindowshahaIsES
#y
```

# 0x0D.[WUSTCTF2020]level1

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+4h] [rbp-2Ch]
  FILE *stream; // [rsp+8h] [rbp-28h]
  char ptr[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  stream = fopen("flag", "r");
  fread(ptr, 1uLL, 0x14uLL, stream);
  fclose(stream);
  for ( i = 1; i <= 19; ++i )
  {
    if ( (i & 1) != 0 )
      printf("%ld\n", (ptr[i] << i));
    else
      printf("%ld\n", (i * ptr[i]));
  }
  return 0;
}
```

就是将output的文件逆一遍，注意上面是从1开始的

```python
a = [198,
     232,
     816,
     200,
     1536,
     300,
     6144,
     984,
     51200,
     570,
     92160,
     1200,
     565248,
     756,
     1474560,
     800,
     6291456,
     1782,
     65536000]
for i in range(len(a)):
    if (i+1) & 1 == 0:
        print(chr(a[i]//(i+1)), end='')
    else:
        print(chr(a[i] >> (i+1)), end='')
```

# 0x0E.[ACTF新生赛2020]usualCrypt

ida识别的很多东西都有问题，改了很多

main：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // esi
  int result; // eax
  char v5[12]; // [esp+8h] [ebp-74h] BYREF
  __int16 v6; // [esp+14h] [ebp-68h]
  char v7; // [esp+16h] [ebp-66h]
  char input[100]; // [esp+18h] [ebp-64h] BYREF

  puts(aGiveMeYourFlag);
  scanf("%s", input);
  *v5 = 0;
  *&v5[4] = 0;
  *&v5[8] = 0;
  v6 = 0;
  v7 = 0;
  sub_401080(input, strlen(input), v5);
  v3 = 0;
  while ( v5[v3] == aZmxhz3tignxlxj[v3] )
  {
    if ( ++v3 > strlen(v5) )
      goto LABEL_6;
  }
  puts(aError);
LABEL_6:
  if ( v3 - 1 == strlen(aZmxhz3tignxlxj) )
      //zMXHz3TIgnxLxJhFAdtZn2fFk3lYCrtPC2l9
    result = puts(aAreYouHappyYes);
  else
    result = puts(aAreYouHappyNo);
  return result;
}
```

其中的sub_401080:

```c
int __cdecl sub_401080(char *a1, int a2, int *a3)
{
  int v3; // edi
  int v4; // esi
  int v5; // edx
  char *v6; // eax
  int v7; // ecx
  int v8; // esi
  int v9; // esi
  int v10; // esi
  int v11; // esi
  char *v12; // ecx
  int v13; // esi
  int v15; // [esp+18h] [ebp+8h]

  v3 = 0;
  v4 = 0;
  sub_401000();
  v5 = a2 % 3;
  v6 = a1;
  v7 = a2 - a2 % 3;
  v15 = a2 % 3;
  if ( v7 > 0 )
  {
    do
    {
      LOBYTE(v5) = a1[v3];
      v3 += 3;
      v8 = v4 + 1;
      *(a3 + v8 - 1) = aAbcdefghijklmn[(v5 >> 2) & 0x3F];
      *(a3 + v8++) = aAbcdefghijklmn[16 * (a1[v3 - 3] & 3) + ((a1[v3 - 2] >> 4) & 0xF)];
      *(a3 + v8++) = aAbcdefghijklmn[4 * (a1[v3 - 2] & 0xF) + ((a1[v3 - 1] >> 6) & 3)];
      v5 = a1[v3 - 1] & 0x3F;
      v4 = v8 + 1;
      *(a3 + v4 - 1) = aAbcdefghijklmn[v5];
    }
    while ( v3 < v7 );
    v5 = v15;
  }
  if ( v5 == 1 )
  {
    LOBYTE(v7) = a1[v3];
    v9 = v4 + 1;
    *(a3 + v9 - 1) = aAbcdefghijklmn[(v7 >> 2) & 0x3F];
    v10 = v9 + 1;
    *(a3 + v10 - 1) = aAbcdefghijklmn[16 * (a1[v3] & 3)];
    *(a3 + v10) = 61;
LABEL_8:
    v13 = v10 + 1;
    *(a3 + v13) = 61;
    v4 = v13 + 1;
    goto LABEL_9;
  }
  if ( v5 == 2 )
  {
    v11 = v4 + 1;
    *(a3 + v11 - 1) = aAbcdefghijklmn[(a1[v3] >> 2) & 0x3F];
    v12 = &a1[v3 + 1];
    LOBYTE(v6) = *v12;
    v10 = v11 + 1;
    *(a3 + v10 - 1) = aAbcdefghijklmn[16 * (a1[v3] & 3) + ((v6 >> 4) & 0xF)];
    *(a3 + v10) = aAbcdefghijklmn[4 * (*v12 & 0xF)];
    goto LABEL_8;
  }
LABEL_9:
  *(a3 + v4) = 0;
  return sub_401030(a3);
}
```

```c
int sub_401000()
{
  int result; // eax
  char v1; // cl

  for ( result = 6; result < 15; ++result )
  {
    v1 = aAbcdefghijklmn[result + 10];
    aAbcdefghijklmn[result + 10] = aAbcdefghijklmn[result];
    aAbcdefghijklmn[result] = v1;
  }
  return result;
}
```

```c
int *__cdecl sub_401030(char *input)
{
  __int64 v1; // rax
  char v2; // al

  v1 = 0i64;
  if ( strlen(input) )
  {
    do
    {
      v2 = input[HIDWORD(v1)];
      if ( v2 < 97 || v2 > 122 )
      {
        if ( v2 < 65 || v2 > 90 )
          goto LABEL_9;
        LOBYTE(v1) = v2 + 32;
      }
      else
      {
        LOBYTE(v1) = v2 - 32;
      }
      input[HIDWORD(v1)] = v1;
LABEL_9:
      LODWORD(v1) = 0;
      ++HIDWORD(v1);
    }
    while ( HIDWORD(v1) < strlen(input) );
  }
  return v1;
}
```

sub_401080主要是三部分：

-   sub_401000：换base64表
-   base64
-   大小写转换的操作

也就是说，我们拿本地的str先大小写转换，换表，在decode就OK

```python
import base64
str = 'zMXHz3TIgnxLxJhFAdtZn2fFk3lYCrtPC2l9'.swapcase()
base = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
A2Z = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
base = list(base)
for i in range(6, 15):
    a = base[i]
    base[i] = base[i+10]
    base[i+10] = a

base = ''.join(base)
flag = ''
for i in range(len(str)):
    flag += A2Z[base.find(str[i])]
    print(A2Z[base.find(str[i])], end='')
b = base64.b64decode(flag)
print(b)
```

# 0x0F.[MRCTF2020]Transform

无壳：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char input[104]; // [rsp+20h] [rbp-70h] BYREF
  int j; // [rsp+88h] [rbp-8h]
  int i; // [rsp+8Ch] [rbp-4h]

  sub_402230();
  printf("Give me your code:\n");
  scanf("%s", input);
  if ( strlen(input) != 33 )
  {
    printf("Wrong!\n");
    system("pause");
    exit(0);
  }
  for ( i = 0; i <= 32; ++i )
  {
    aHknvfymgQbpaJ[i] = input[asc_40F040[i]];
    aHknvfymgQbpaJ[i] ^= LOBYTE(asc_40F040[i]);
  }
  for ( j = 0; j <= 32; ++j )
  {
    if ( local_str[j] != aHknvfymgQbpaJ[j] )
    {
      printf("Wrong!\n");
      system("pause");
      exit(0);
    }
  }
  printf("Right!Good Job!\n");
  printf("Here is your flag: %s\n", input);
  system("pause");
  return 0;
}
```

长度是33，之后和本地的一个表异或，再等于另一个字符串

```python
table = [9,10,15, 23,7,
         24,12, 6, 1,
         16,3,17, 32, 29, 11,30,
         27, 22,
         4,13, 19, 20,
         21,
         2,
         25,
         5,
         31,
         8,
         18,
         26,
         28,
         14, 0]

local_str = [
    0x67, 0x79, 0x7B, 0x7F, 0x75, 0x2B, 0x3C, 0x52, 0x53, 0x79,
    0x57, 0x5E, 0x5D, 0x42, 0x7B, 0x2D, 0x2A, 0x66, 0x42, 0x7E,
    0x4C, 0x57, 0x79, 0x41, 0x6B, 0x7E, 0x65, 0x3C, 0x5C, 0x45,
    0x6F, 0x62, 0x4D]
flag = [0]*33
print(len(table))
for i in range(len(local_str)):
    local_str[i] ^= table[i]

for i in range(33):
    flag[table[i]] = local_str[i]
for i in flag:
    print(chr(i), end='')
```

# 0x10.相册

根据提示说是和邮箱有关，jadx打开搜mail，有个`sendMailByJavaMail`，且第一个参数的含义大概为sendto的邮箱地址，查找交叉引用。

![image-20211029182421975](BUU-RE-0x01-0x1F/image-20211029182421975.png)

发现有个mailserver的东西，大概率就是了，反查定义，：

![image-20211029182507735](BUU-RE-0x01-0x1F/image-20211029182507735.png)

base64解码了一下。

Java中NativeMethod一般用于调用外部文件，ida打开libcore.so，查看导出(export)，

![image-20211029182804375](BUU-RE-0x01-0x1F/image-20211029182804375.png)

![image-20211029183044566](BUU-RE-0x01-0x1F/image-20211029183044566.png)

base64解一下就好了

# 0x11.[WUSTCTF2020]level2

就脱个upx就OK

# 0x12.[HDCTF2019]Maze

这个题学到知识点了。

忘了有没有壳了，有也是upx，脱了就行

ida查看是这样：

![image-20211029232619651](BUU-RE-0x01-0x1F/image-20211029232619651.png)

main下面有一堆数据，f5不了；而且上面有个jnz的指令，相当于没跳转，而call的也是个乱的地址。这段代码加了花指令，ida分析错了。

首先将jnz给nop掉，可以直接ida也可od：

![image-20211029232903932](BUU-RE-0x01-0x1F/image-20211029232903932.png)

之后是call，当然不能全nop，后面可能会有代码，按d转为字节数据：

![image-20211029233029066](BUU-RE-0x01-0x1F/image-20211029233029066.png)

然后一步步测试改为nop，之后会发现ida自动就把后面给显示为了代码，但是还是不能f5：

![image-20211029233330994](BUU-RE-0x01-0x1F/image-20211029233330994.png)

这是因为这块还不是函数，之后将红色的text选中按p，将这块弄为函数，之后就可f5了，简单的迷宫题：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [esp+10h] [ebp-14h]
  char flag[16]; // [esp+14h] [ebp-10h] BYREF

  printf("Go through the maze to get the flag!\n");
  scanf("%14s", flag);
  for ( i = 0; i <= 13; ++i )
  {
    switch ( flag[i] )
    {
      case 'a':
        --*asc_408078;
        break;
      case 'd':
        ++*asc_408078;
        break;
      case 's':
        --dword_40807C;
        break;
      case 'w':
        ++dword_40807C;
        break;
      default:
        continue;
    }
  }
    //初始分别为7和0
  if ( *asc_408078 == 5 && dword_40807C == -4 )
  {
    printf("Congratulations!\n");
    printf("Here is the flag:flag{%s}\n", flag);
  }
  else
  {
    printf("Try again...\n");
  }
  return 0;
}
```

迷宫如下:

```
*******+**
******* **
****    **
**   *****
** **F****
**    ****
**********
//ssaaasaassdddw
```

# 0X13.[GWCTF 2019]xxor（未完）



```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int i; // [rsp+8h] [rbp-68h]
  int j; // [rsp+Ch] [rbp-64h]
  __int64 v6[6]; // [rsp+10h] [rbp-60h] BYREF
  __int64 v7[6]; // [rsp+40h] [rbp-30h] BYREF

  v7[5] = __readfsqword(0x28u);
  puts("Let us play a game?");
  puts("you have six chances to input");
  puts("Come on!");
  v6[0] = 0LL;
  v6[1] = 0LL;
  v6[2] = 0LL;
  v6[3] = 0LL;
  v6[4] = 0LL;
  for ( i = 0; i <= 5; ++i )
  {
    printf("%s", "input: ");
    a2 = (v6 + 4 * i);
    __isoc99_scanf("%d", a2);
  }
  v7[0] = 0LL;
  v7[1] = 0LL;
  v7[2] = 0LL;
  v7[3] = 0LL;
  v7[4] = 0LL;
  for ( j = 0; j <= 2; ++j )
  {
    dword_601078 = v6[j];
    dword_60107C = HIDWORD(v6[j]);
    a2 = &unk_601060;
    sub_400686(&dword_601078, &unk_601060);
    LODWORD(v7[j]) = dword_601078;
    HIDWORD(v7[j]) = dword_60107C;
  }
  if ( sub_400770(v7, a2) != 1 )
  {
    puts("NO NO NO~ ");
    exit(0);
  }
  puts("Congratulation!\n");
  puts("You seccess half\n");
  puts("Do not forget to change input to hex and combine~\n");
  puts("ByeBye");
  return 0LL;
}
```

首先是输入，然后进行了一个变换，再进行了一次判断。

先看判断：

```c
__int64 __fastcall sub_400770(_DWORD *a1)
{
  __int64 result; // rax

  if ( a1[2] - a1[3] == 2225223423LL
    && a1[3] + a1[4] == 4201428739LL
    && a1[2] - a1[4] == 1121399208LL
    && *a1 == -548868226
    && a1[5] == -2064448480
    && a1[1] == 550153460 )
  {
    puts("good!");
    result = 1LL;
  }
  else
  {
    puts("Wrong!");
    result = 0LL;
  }
  return result;
}
```

使用z3简单算下：

```python
from z3 import *
s = Solver()
a1 = [0]*6
for i in range(6):
    a1[i] = Int('a1['+str(i)+']')
s.add(a1[2] - a1[3] == 0x84A236FF)
s.add(a1[3] + a1[4] == 0xFA6CB703)
s.add(a1[2] - a1[4] == 1121399208)
s.add(a1[0] == -548868226)
s.add(a1[5] == -2064448480)
s.add(a1[1] == 550153460)
s.check()
print(s.model())
```

得到：

```txt
a1[2] = 3774025685,
 a1[1] = 550153460,
 a1[5] = -2064448480,
 a1[0] = -548868226,
 a1[3] = 1548802262,
 a1[4] = 2652626477
```

之后往前看是：

```c
__int64 __fastcall sub_400686(unsigned int *temp, int *table)
{
  __int64 result; // rax
  unsigned int v3; // [rsp+1Ch] [rbp-24h]
  unsigned int v4; // [rsp+20h] [rbp-20h]
  int v5; // [rsp+24h] [rbp-1Ch]
  unsigned int i; // [rsp+28h] [rbp-18h]

  v3 = *temp;
  v4 = temp[1];
  v5 = 0;
  for ( i = 0; i <= 0x3F; ++i )
  {
    v5 += 0x458BCD42;
    v3 += (v4 + v5 + 11) ^ ((v4 << 6) + *table) ^ ((v4 >> 9) + table[1]) ^ 0x20;
    v4 += (v3 + v5 + 20) ^ ((v3 << 6) + table[2]) ^ ((v3 >> 9) + table[3]) ^ 0x10;
  }
  *temp = v3;
  result = v4;
  temp[1] = v4;
  return result;
}
```

我看网上都是c写的，想试试py，但是还要看其他的内容，先鸽了

# 0x14.[MRCTF2020]Xor

简单的一个异或：

```python
local = [0x4D, 0x53, 0x41, 0x57, 0x42, 0x7E, 0x46, 0x58, 0x5A, 0x3A,
         0x4A, 0x3A, 0x60, 0x74, 0x51, 0x4A, 0x22, 0x4E, 0x40, 0x20,
         0x62, 0x70, 0x64, 0x64, 0x7D, 0x38, 0x67]
for i in range(len(local)):
    print(chr(i ^ local[i]), end='')
```

# 0x15.[FlareOn4]IgniteMe

无壳，打开

```c
void __noreturn start()
{
  DWORD NumberOfBytesWritten; // [esp+0h] [ebp-4h] BYREF

  NumberOfBytesWritten = 0;
  hFile = GetStdHandle(0xFFFFFFF6);
  dword_403074 = GetStdHandle(0xFFFFFFF5);
  WriteFile(dword_403074, aG1v3M3T3hFl4g, 0x13u, &NumberOfBytesWritten, 0);
  sub_4010F0();
  if ( sub_401050() )
    WriteFile(dword_403074, aG00dJ0b, 0xAu, &NumberOfBytesWritten, 0);
  else
    WriteFile(dword_403074, aN0tT00H0tRWe7r, 0x24u, &NumberOfBytesWritten, 0);
  ExitProcess(0);
}
```

其中的sub_4010F0就是去了\r和\n，下面是sub_401050：

```c
int sub_401050()
{
  int len; // [esp+0h] [ebp-Ch]
  int i; // [esp+4h] [ebp-8h]
  unsigned int j; // [esp+4h] [ebp-8h]
  char v4; // [esp+Bh] [ebp-1h]

  len = sub_401020(byte_403078);
  v4 = sub_401000();
  for ( i = len - 1; i >= 0; --i )
  {
    byte_403180[i] = v4 ^ byte_403078[i];
    v4 = byte_403078[i];
  }
  for ( j = 0; j < 0x27; ++j )
  {
    if ( byte_403180[j] != local_str[j] )
      return 0;
  }
  return 1;
}
```

又是个异或，且v4第一开始是4，调出来的，exp：

```python
local_str = [0x0D, 0x26, 0x49, 0x45, 0x2A, 0x17, 0x78, 0x44, 0x2B, 0x6C,
             0x5D, 0x5E, 0x45, 0x12, 0x2F, 0x17, 0x2B, 0x44, 0x6F, 0x6E,
             0x56, 0x09, 0x5F, 0x45, 0x47, 0x73, 0x26, 0x0A, 0x0D, 0x13,
             0x17, 0x48, 0x42, 0x01, 0x40, 0x4D, 0x0C, 0x02, 0x69]
local_str.reverse()
v4 = 4
flag = ''
for i in range(len(local_str)):
    flag += chr(local_str[i] ^ v4)
    v4 = local_str[i] ^ v4
print(flag[::-1])
```

# 0x16.[MRCTF2020]hello_world_go

说实话没看懂在搞啥，就看到memequal和cmpstring两个函数就拿到flag了。

# 0x17.[WUSTCTF2020]level3

是一个变表的base64，虽然能看到变表的函数，但是不知道在哪里调用的。。。

```c
import base64
import string
str0 = "d2G0ZjLwHjS7DmOzZAY0X2lzX3CoZV9zdNOydO9vZl9yZXZlcnGlfD=="
string2 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
string1 = list(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
for i in range(10):
    string1[i], string1[19-i] = string1[19-i], string1[i]

string1 = ''.join(string1)
print(base64.b64decode(str0.translate(str.maketrans(string1, string2))))
```

# 0x18.[WUSTCTF2020]Cr0ssfun

check里面啥都有

# 0x19.[FlareOn6]Overlong

ida不太会改，就od了，首先他是因为push了1c的长度，而需要显示的长度远大于0x1c，所以将它改大一些就OK，这里直接在stack上改的：

![image-20211031173412785](BUU-RE-0x01-0x1F/image-20211031173412785.png)

![image-20211031173430925](BUU-RE-0x01-0x1F/image-20211031173430925.png)

# 0x1A.[BJDCTF2020]BJD hamburger competition

>   **识别Unity游戏**
>
>   Android平台的apk包可以直接解压，看是否有./assets/bin/Data/Managed目录，也可以查看lib文件夹下面包含的一些so，如果有libmono,libunity等模块，基本可以确定是unity游戏了。
>
>   Android平台中C#编写的主逻辑模块代码静态编辑之后存储于Assembly-CSharp.dll文件中。因为unity的跨平台，Android平台是unity编译的游戏，那么其对应的IOS平台上也是unity编译出来的。如果希望直接从IOS上面去看是否是unity游戏，可以提取游戏中的主模块查看是否有unity之类的函数即可。
>
>   转自：https://www.52pojie.cn/thread-495115-1-1.html

第一次做unity的题，unity是C++写的，所以这里使用dnspy直接看源码，在BJD hamburger competition_Data\Managed文件夹中找到Assembly-CSharp.dll（进去文件后第一个就是），这个dll文件是程序的源码，用来存放C++工程。

Assembly-CSharp.dll这个文件很重要。

之后在buttonspawnfruit看到：

![image-20211031175420892](BUU-RE-0x01-0x1F/image-20211031175420892.png)

解密之后md5，要注意的是md5返回的是前20位：

![image-20211031175939675](BUU-RE-0x01-0x1F/image-20211031175939675.png)

# 0x1B.[ACTF新生赛2020]Oruga

重点在sub_78A

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  __int64 result; // rax
  int i; // [rsp+0h] [rbp-40h]
  char s1[6]; // [rsp+4h] [rbp-3Ch] BYREF
  char s2[6]; // [rsp+Ah] [rbp-36h] BYREF
  char input[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  memset(input, 0, 0x19uLL);
  printf("Tell me the flag:");
  scanf("%s", input);
  strcpy(s2, "actf{");
  for ( i = 0; i <= 4; ++i )
    s1[i] = input[i];
  s1[5] = 0;
  if ( !strcmp(s1, s2) )
  {
    if ( sub_78A(input) )
      printf("That's True Flag!");
    else
      printf("don't stop trying...");
    result = 0LL;
  }
  else
  {
    printf("Format false!");
    result = 0LL;
  }
  return result;
}
```

sub_78A:

```c
_BOOL8 __fastcall sub_78A(char *input)
{
  int now; // [rsp+Ch] [rbp-Ch]
  int v3; // [rsp+10h] [rbp-8h]
  int v4; // [rsp+14h] [rbp-4h]

  now = 0;
  v3 = 5;
  v4 = 0;
  while ( map[now] != 33 )
  {
    now -= v4;
    if ( input[v3] != 'W' || v4 == 0xFFFFFFF0 )
    {
      if ( input[v3] != 'E' || v4 == 1 )
      {
        if ( input[v3] != 'M' || v4 == 0x10 )
        {
          if ( input[v3] != 'J' || v4 == 0xFFFFFFFF )
            return 0LL;
          v4 = 0xFFFFFFFF;
        }
        else
        {
          v4 = 0x10;
        }
      }
      else
      {
        v4 = 1;
      }
    }
    else
    {
      v4 = 0xFFFFFFF0;
    }
    ++v3;
    while ( !map[now] )
    {
      if ( v4 == -1 && (now & 0xF) == 0 )       // 在最左边
        return 0LL;
      if ( v4 == 1 && now % 16 == 15 )          // 在最右边
        return 0LL;
      if ( v4 == 0x10 && (now - 240) <= 15 )    // 在最后一行
        return 0LL;
      if ( v4 == 0xFFFFFFF0 && (now + 15) <= 30 )// 在第一行
        return 0LL;
      now += v4;                                // 每次可以一直走
    }
  }
  return input[v3] == '}';
}
```

每次只要没撞到墙都可以一直走

```c
unsigned char map[] =
{
    0,   0,   0,   0,  35,   0,   0,   0,   0,   0, 
    0,   0,  35,  35,  35,  35,   0,   0,   0,  35, 
   35,   0,   0,   0,  79,  79,   0,   0,   0,   0, 
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0, 
   79,  79,   0,  80,  80,   0,   0,   0,   0,   0, 
    0,  76,   0,  79,  79,   0,  79,  79,   0,  80, 
   80,   0,   0,   0,   0,   0,   0,  76,   0,  79, 
   79,   0,  79,  79,   0,  80,   0,   0,   0,   0, 
    0,   0,  76,  76,   0,  79,  79,   0,   0,   0, 
    0,  80,   0,   0,   0,   0,   0,   0,   0,   0, 
    0,  79,  79,   0,   0,   0,   0,  80,   0,   0, 
    0,   0,  35,   0,   0,   0,   0,   0,   0,   0, 
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0, 
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0, 
   35,   0,   0,   0,   0,   0,   0,   0,   0,   0, 
   77,  77,  77,   0,   0,   0,  35,   0,   0,   0, 
    0,   0,   0,   0,   0,   0,   0,  77,  77,  77, 
    0,   0,   0,   0,  69,  69,   0,   0,   0,  48, 
    0,  77,   0,  77,   0,  77,   0,   0,   0,   0, 
   69,   0,   0,   0,   0,   0,   0,   0,   0,   0, 
    0,   0,   0,   0,   0,   0,  69,  69,  84,  84, 
   84,  73,   0,  77,   0,  77,   0,  77,   0,   0, 
    0,   0,  69,   0,   0,  84,   0,  73,   0,  77, 
    0,  77,   0,  77,   0,   0,   0,   0,  69,   0, 
    0,  84,   0,  73,   0,  77,   0,  77,   0,  77, 
   33,   0,   0,   0,  69,  69
};
//MEWEMEWJMEWJM
```

# 0x1C.[FlareOn3]Challenge1

无壳，

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char Buffer[128]; // [esp+0h] [ebp-94h] BYREF
  char *Str1; // [esp+80h] [ebp-14h]
  char *Str2; // [esp+84h] [ebp-10h]
  HANDLE v7; // [esp+88h] [ebp-Ch]
  HANDLE hFile; // [esp+8Ch] [ebp-8h]
  DWORD NumberOfBytesWritten; // [esp+90h] [ebp-4h] BYREF

  hFile = GetStdHandle(0xFFFFFFF5);
  v7 = GetStdHandle(0xFFFFFFF6);
  Str2 = "x2dtJEOmyjacxDemx2eczT5cVS9fVUGvWTuZWjuexjRqy24rV29q";
  WriteFile(hFile, "Enter password:\r\n", 0x12u, &NumberOfBytesWritten, 0);
  ReadFile(v7, Buffer, 0x80u, &NumberOfBytesWritten, 0);
  Str1 = sub_401260(Buffer, NumberOfBytesWritten - 2);
  if ( !strcmp(Str1, Str2) )
    WriteFile(hFile, "Correct!\r\n", 0xBu, &NumberOfBytesWritten, 0);
  else
    WriteFile(hFile, "Wrong password\r\n", 0x11u, &NumberOfBytesWritten, 0);
  return 0;
}

_BYTE *__cdecl sub_401260(char *input, DWORD size)
{
  int v3; // [esp+Ch] [ebp-24h]
  int v4; // [esp+10h] [ebp-20h]
  int v5; // [esp+14h] [ebp-1Ch]
  int i; // [esp+1Ch] [ebp-14h]
  unsigned int v7; // [esp+20h] [ebp-10h]
  _BYTE *v8; // [esp+24h] [ebp-Ch]
  int v9; // [esp+28h] [ebp-8h]
  int v10; // [esp+28h] [ebp-8h]
  DWORD v11; // [esp+2Ch] [ebp-4h]

  v8 = malloc(4 * ((size + 2) / 3) + 1);
  if ( !v8 )
    return 0;
  v11 = 0;
  v9 = 0;
  while ( v11 < size )
  {
    v5 = input[v11];
    if ( ++v11 >= size )
      v4 = 0;
    else
      v4 = input[v11++];
    if ( v11 >= size )
      v3 = 0;
    else
      v3 = input[v11++];
    v7 = v3 + (v5 << 16) + (v4 << 8);
    v8[v9] = aZyxabcdefghijk[(v7 >> 18) & 0x3F];
    v10 = v9 + 1;
    v8[v10] = aZyxabcdefghijk[(v7 >> 12) & 0x3F];
    v8[++v10] = aZyxabcdefghijk[(v7 >> 6) & 0x3F];
    v8[++v10] = aZyxabcdefghijk[v3 & 0x3F];
    v9 = v10 + 1;
  }
  for ( i = 0; i < *&aZyxabcdefghijk[4 * (size % 3) + 64]; ++i )
    v8[4 * ((size + 2) / 3) - i - 1] = '=';
  v8[4 * ((size + 2) / 3)] = 0;
  return v8;
}
```

变表的base64：

```python
import base64
str1 = 'x2dtJEOmyjacxDemx2eczT5cVS9fVUGvWTuZWjuexjRqy24rV29q'
base = 'ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw0123456789+/'
table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
a = base64.b64decode(str1.translate(str.maketrans(base, table)))
print(a)
```

# 0x1D.[Zer0pts2020]easy strcmp

又学到了个小东西，在main之前会先执行init，最后会fini也就是说：

在执行：

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  if ( a1 > 1 )
  {
    if ( !strcmp(a2[1], "zer0pts{********CENSORED********}") )
      puts("Correct!");
    else
      puts("Wrong!");
  }
  else
  {
    printf("Usage: %s <FLAG>\n", *a2);
  }
  return 0LL;
}
```

之前，先执行了init：

```c
void __fastcall init(unsigned int a1, __int64 a2, __int64 a3)
{
  signed __int64 v4; // rbp
  __int64 i; // rbx

  v4 = &off_200DF0 - &funcs_889;
  init_proc();
  if ( v4 )
  {
    for ( i = 0LL; i != v4; ++i )
      ((void (__fastcall *)(_QWORD, __int64, __int64))*(&funcs_889 + i))(a1, a2, a3);
  }
}
```

而这里面是执行了两个之间的所有函数：

![image-20211031232427647](BUU-RE-0x01-0x1F/image-20211031232427647.png)

其中重要的就是795的那个函数了

```c
int (**sub_795())(const char *s1, const char *s2)
{
  int (**result)(const char *, const char *); // rax

  result = &strcmp;
  qword_201090 = (__int64)&strcmp;
  off_201028 = sub_6EA;
  return result;
}
```

吧strcmp的函数换为了sub_6EA，：

```c
__int64 __fastcall sub_6EA(__int64 a1, __int64 a2)
{
  int i; // [rsp+18h] [rbp-8h]
  int v4; // [rsp+18h] [rbp-8h]
  int j; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; *(_BYTE *)(i + a1); ++i )
    ;
  v4 = (i >> 3) + 1;
  for ( j = 0; j < v4; ++j )
    *(_QWORD *)(8 * j + a1) -= qword_201060[j];
  return qword_201090(a1, a2);
}
```

网上的exp，怎么说呢，中间那块算的还是有问题

```python
import binascii
enc = "********CENSORED********"
m = [0x410A4335494A0942, 0x0B0EF2F50BE619F0, 0x4F0A3A064A35282B]
flag = b''
for i in range(3):
    p = enc[i*8:(i+1)*8]
    a = binascii.b2a_hex(p.encode('ascii')[::-1])
    b = binascii.a2b_hex(hex(int(a, 16) + m[i])[2:])[::-1]
    print(a, b, hex(m[i]))
    flag += b
print(flag)
```

# 0x1E.[UTCTF2020]basic-re

字符串flag

# 0x1F.[ACTF新生赛2020]Universe_final_answer

z3的题：

```c
bool __fastcall sub_860(char *a1)
{
  int v1; // ecx
  int v2; // esi
  int v3; // edx
  int v4; // er9
  int v5; // er11
  int v6; // ebp
  int v7; // ebx
  int v8; // er8
  int v9; // er10
  bool result; // al
  int v11; // [rsp+0h] [rbp-38h]

  v1 = a1[1];
  v2 = *a1;
  v3 = a1[2];
  v4 = a1[3];
  v5 = a1[4];
  v6 = a1[6];
  v7 = a1[5];
  v8 = a1[7];
  v9 = a1[8];
  result = 0;
  if ( -85 * v9 + 58 * v8 + 97 * v6 + v7 + -45 * v5 + 84 * v4 + 95 * v2 - 20 * v1 + 12 * v3 == 12613 )
  {
    v11 = a1[9];
    if ( 30 * v11 + -70 * v9 + -122 * v6 + -81 * v7 + -66 * v5 + -115 * v4 + -41 * v3 + -86 * v1 - 15 * v2 - 30 * v8 == -54400
      && -103 * v11 + 120 * v8 + 108 * v7 + 48 * v4 + -89 * v3 + 78 * v1 - 41 * v2 + 31 * v5 - (v6 << 6) - 120 * v9 == -10283
      && 71 * v6 + (v7 << 7) + 99 * v5 + -111 * v3 + 85 * v1 + 79 * v2 - 30 * v4 - 119 * v8 + 48 * v9 - 16 * v11 == 22855
      && 5 * v11 + 23 * v9 + 122 * v8 + -19 * v6 + 99 * v7 + -117 * v5 + -69 * v3 + 22 * v1 - 98 * v2 + 10 * v4 == -2944
      && -54 * v11 + -23 * v8 + -82 * v3 + -85 * v2 + 124 * v1 - 11 * v4 - 8 * v5 - 60 * v7 + 95 * v6 + 100 * v9 == -2222
      && -83 * v11 + -111 * v7 + -57 * v2 + 41 * v1 + 73 * v3 - 18 * v4 + 26 * v5 + 16 * v6 + 77 * v8 - 63 * v9 == -13258
      && 81 * v11 + -48 * v9 + 66 * v8 + -104 * v6 + -121 * v7 + 95 * v5 + 85 * v4 + 60 * v3 + -85 * v2 + 80 * v1 == -1559
      && 101 * v11 + -85 * v9 + 7 * v6 + 117 * v7 + -83 * v5 + -101 * v4 + 90 * v3 + -28 * v1 + 18 * v2 - v8 == 6308 )
    {
      result = 99 * v11 + -28 * v9 + 5 * v8 + 93 * v6 + -18 * v7 + -127 * v5 + 6 * v4 + -9 * v3 + -93 * v1 + 58 * v2 == -1697;
    }
  }
  return result;
}
```

需要注意的是它的v1和v2，v6和v7要换顺序，拿到输入的东西放入程序就能拿到第二段flag

```python
from z3 import *
v1, v2, v3, v4, v5, v6, v7, v8, v9, v11 = BitVecs(
    'v1 v2 v3 v4 v5 v6 v7 v8 v9 v11', 16)
s = Solver()
s.add(v1 < 128)
s.add(v2 < 128)
s.add(v3 < 128)
s.add(v4 < 128)
s.add(v5 < 128)
s.add(v6 < 128)
s.add(v7 < 128)
s.add(v8 < 128)
s.add(v9 < 128)
s.add(v11 < 128)
s.add(-85 * v9 + 58 * v8 + 97 * v6 + v7 + -45 * v5 +
      84 * v4 + 95 * v2 - 20 * v1 + 12 * v3 == 12613)
s.add(30 * v11 + -70 * v9 + -122 * v6 + -81 * v7 + -66 * v5 + -
      115 * v4 + -41 * v3 + -86 * v1 - 15 * v2 - 30 * v8 == -54400)
s.add(-103 * v11 + 120 * v8 + 108 * v7 + 48 * v4 + -89 * v3 +
      78 * v1 - 41 * v2 + 31 * v5 - (v6 << 6) - 120 * v9 == -10283)
s.add(71 * v6 + (v7 << 7) + 99 * v5 + -111 * v3 + 85 * v1 +
      79 * v2 - 30 * v4 - 119 * v8 + 48 * v9 - 16 * v11 == 22855)
s.add(5 * v11 + 23 * v9 + 122 * v8 + -19 * v6 + 99 * v7 + -
      117 * v5 + -69 * v3 + 22 * v1 - 98 * v2 + 10 * v4 == -2944)
s.add(-54 * v11 + -23 * v8 + -82 * v3 + -85 * v2 + 124 * v1 -
      11 * v4 - 8 * v5 - 60 * v7 + 95 * v6 + 100 * v9 == -2222)
s.add(-83 * v11 + -111 * v7 + -57 * v2 + 41 * v1 + 73 * v3 -
      18 * v4 + 26 * v5 + 16 * v6 + 77 * v8 - 63 * v9 == -13258)
s.add(81 * v11 + -48 * v9 + 66 * v8 + -104 * v6 + -121 * v7 +
      95 * v5 + 85 * v4 + 60 * v3 + -85 * v2 + 80 * v1 == -1559)
s.add(101 * v11 + -85 * v9 + 7 * v6 + 117 * v7 + -83 * v5 + -
      101 * v4 + 90 * v3 + -28 * v1 + 18 * v2 - v8 == 6308)
s.add(99 * v11 + -28 * v9 + 5 * v8 + 93 * v6 + -18 * v7 + -
      127 * v5 + 6 * v4 + -9 * v3 + -93 * v1 + 58 * v2 == -1697)

if s.check() == sat:
    print(s.model())
v8 = 55
v1 = 48
v6 = 95
v4 = 82
v2 = 70
v3 = 117
v11 = 64
v5 = 84
v7 = 121
v9 = 119
print(chr(v2)+chr(v1)+chr(v3)+chr(v4)+chr(v5) +
      chr(v7)+chr(v6)+chr(v8)+chr(v9)+chr(v11))
```

# 0x20.[WUSTCTF2020]level4(二叉树)

64位elf的逆向，先运行下：

```sh
yutao@ubuntu:~/Desktop$ ./attachment 
Practice my Data Structure code.....
Typing....Struct.....char....*left....*right............emmmmm...OK!
Traversal!
Traversal type 1:2f0t02T{hcsiI_SwA__r7Ee}
Traversal type 2:20f0Th{2tsIS_icArE}e7__w
Traversal type 3:    //type3(&x[22]);   No way!
```

ida:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  puts("Practice my Data Structure code.....");
  puts("Typing....Struct.....char....*left....*right............emmmmm...OK!");
  init();
  puts("Traversal!");
  printf("Traversal type 1:");
  type1(byte_601290);
  printf("\nTraversal type 2:");
  type2(byte_601290);
  printf("\nTraversal type 3:");
  puts("    //type3(&x[22]);   No way!");
  puts(&byte_400A37);
  return 0;
}

unsigned __int64 init()
{
  int i; // [rsp+Ch] [rbp-34h]
  char v2[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v3; // [rsp+38h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  strcpy(v2, "I{_}Af2700ih_secTS2Et_wr");
  for ( i = 0; i <= 23; ++i )
    x[24 * i] = v2[i];
  qword_601298 = &unk_6011E8;
  qword_6011F0 = &unk_601260;
  qword_601268 = &unk_6010F8;
  qword_601100 = &unk_601110;
  qword_601108 = &unk_601140;
  qword_601270 = &unk_601230;
  qword_601238 = &unk_601158;
  qword_601240 = &unk_601098;
  qword_6010A0 = &unk_601200;
  qword_6010A8 = &unk_601188;
  qword_6011F8 = &unk_601170;
  qword_601178 = &unk_6011B8;
  qword_601180 = &unk_6010B0;
  qword_6010B8 = x;
  qword_6010C0 = &unk_601218;
  qword_6012A0 = &unk_601278;
  qword_601280 = &unk_6010E0;
  qword_601288 = &unk_6011A0;
  qword_6011B0 = &unk_601128;
  qword_601130 = &unk_6012A8;
  qword_601138 = &unk_6011D0;
  qword_6011D8 = &unk_601248;
  qword_6011E0 = &unk_6010C8;
  return __readfsqword(0x28u) ^ v3;
}
```

再看下type1和type2：

```c
void __fastcall type1(char *a1)
{
  if ( a1 )
  {
    type1(*(a1 + 1));
    putchar(*a1);
    type1(*(a1 + 2));
  }
}
void __fastcall type2(char *a1)
{
  if ( a1 )
  {
    type2(*(a1 + 1));
    type2(*(a1 + 2));
    putchar(*a1);
  }
}
```

就是二叉树的遍历（具体文章看这个：https://blog.csdn.net/LX18792732127/article/details/76167482），一共有3种（先序遍历，后序遍历，中序遍历），上面的是中序遍历和后序遍历。差一个先序遍历，使用中序后序求先序：

```python
class TreeNode:
    def __init__(self, x):
        self.val = x
        self.left = None
        self.right = None


class Solution:
    def reConstructBinaryTree(self, post, tin):
        if len(post) == 0:
            return None
        root = TreeNode(post[-1])
        TinIndex = tin.index(post[-1])
        root.left = self.reConstructBinaryTree(
            post[0:TinIndex], tin[0:TinIndex])
        root.right = self.reConstructBinaryTree(
            post[TinIndex:len(post) - 1], tin[TinIndex + 1:])
        return root

    def PreTraversal(self, root):
        if root != None:
            print(root.val, end="")
            self.PreTraversal(root.left)
            self.PreTraversal(root.right)


strm = "2f0t02T{hcsiI_SwA__r7Ee}"
stre = "20f0Th{2tsIS_icArE}e7__w"
post = list(stre)  # 后序
tin = list(strm)  # 中序

S = Solution()
root = S.reConstructBinaryTree(post, tin)
S.PreTraversal(root)
```

# 0x21.[网鼎杯 2020 青龙组]singal（vm逆向）

>   VM逆向参考：https://blog.csdn.net/weixin_43876357/article/details/108570305

看了wp知道这这类题目的名字：VM逆向：

主函数和关键函数：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int a1[117]; // [esp+18h] [ebp-1D4h] BYREF

  __main();
  qmemcpy(a1, &asc_403040, 0x1C8u);
  vm_operad(a1, 'r');
  puts("good,The answer format is:flag {}");
  return 0;
}

void __cdecl vm_operad(int *str_local, int a2)
{
  char input[100]; // [esp+13h] [ebp-E5h] BYREF
  char v3[100]; // [esp+77h] [ebp-81h] BYREF
  char v4; // [esp+DBh] [ebp-1Dh]
  int v5; // [esp+DCh] [ebp-1Ch]
  int v6; // [esp+E0h] [ebp-18h]
  int v7; // [esp+E4h] [ebp-14h]
  int v8; // [esp+E8h] [ebp-10h]
  int v9; // [esp+ECh] [ebp-Ch]

  v9 = 0;
  v8 = 0;
  v7 = 0;
  v6 = 0;
  v5 = 0;
LABEL_2:
  while ( v9 < a2 )
  {
    switch ( str_local[v9] )
    {
      case 1:
        v3[v6] = v4;
        ++v9;
        ++v6;
        ++v8;
        break;
      case 2:
        v4 = str_local[v9 + 1] + input[v8];
        v9 += 2;
        break;
      case 3:
        v4 = input[v8] - LOBYTE(str_local[v9 + 1]);
        v9 += 2;
        break;
      case 4:
        v4 = str_local[v9 + 1] ^ input[v8];
        v9 += 2;
        break;
      case 5:
        v4 = str_local[v9 + 1] * input[v8];
        v9 += 2;
        break;
      case 6:
        ++v9;
        break;
      case 7:
        if ( v3[v7] != str_local[v9 + 1] )
        {
          printf("what a shame...");
          exit(0);
        }
        ++v7;
        v9 += 2;
        break;
      case 8:
        input[v5] = v4;
        ++v9;
        ++v5;
        break;
      case 10:
        read(input);
        ++v9;
        break;
      case 11:
        v4 = input[v8] - 1;
        ++v9;
        break;
      case 12:
        v4 = input[v8] + 1;
        ++v9;
        break;
      default:
        goto LABEL_2;
    }
  }
}
```

仔细看下operad的操作：

case7当不等的时候直接退出，v3由v4得出，v4由输入的input和本地的local_str经过运算得出。

input-->v4--->v3，所以我们要根据local_str算出v3，然后算v4，最后flag。

case10的时候输入的是固定长度15.

输出看下与localstr比较的是那些index，并且记录每次index的值（包括没有比较的index

所以：

```c
#include <stdio.h>
#include <Windows.h>
#include <string.h>
void __cdecl read(char *Str)
{
    printf("string:");
    scanf("%s", Str);
    if (strlen(Str) != 15)
    {
        puts("WRONG!\n");
        exit(0);
    }
}
void __cdecl vm_operad(int *str_local, int a2)
{
    char order[114] = {};
    char input[100]; // [esp+13h] [ebp-E5h] BYREF
    char v3[100];    // [esp+77h] [ebp-81h] BYREF
    char v4;         // [esp+DBh] [ebp-1Dh]
    int v5;          // [esp+DCh] [ebp-1Ch]
    int v6;          // [esp+E0h] [ebp-18h]
    int v7;          // [esp+E4h] [ebp-14h]
    int v8;          // [esp+E8h] [ebp-10h]
    int v9;          // [esp+ECh] [ebp-Ch]

    v9 = 0;
    v8 = 0;
    v7 = 0;
    v6 = 0;
    v5 = 0;
    int s = 0;
LABEL_2:
    while (v9 < a2)
    {
        switch (str_local[v9])
        {
        case 1:
            v3[v6] = v4;
            ++v9;
            ++v6;
            ++v8;
            break;
        case 2:
            v4 = str_local[v9 + 1] + input[v8];
            v9 += 2;
            break;
        case 3:
            v4 = input[v8] - LOBYTE(str_local[v9 + 1]);
            v9 += 2;
            break;
        case 4:
            v4 = str_local[v9 + 1] ^ input[v8];
            v9 += 2;
            break;
        case 5:
            v4 = str_local[v9 + 1] * input[v8];
            v9 += 2;
            break;
        case 6:
            ++v9;
            break;
        case 7:
            v3[v7] = str_local[v9 + 1];
            printf("%#x,", v3[v7]);
            ++v7;
            v9 += 2;
            break;
        case 8:
            input[v5] = v4;
            ++v9;
            ++v5;
            break;
        case 10:
            read(input);
            ++v9;
            break;
        case 11:
            v4 = input[v8] - 1;
            ++v9;
            break;
        case 12:
            v4 = input[v8] + 1;
            ++v9;
            break;
        default:
            goto LABEL_2;
        }
        order[s++] = v9;
    }
    printf("\n顺序:\n");
    for (int ss = 0; ss < strlen(order); ss++)
    {
        printf("%x, ", order[ss]);
    }
}

int main()
{
    unsigned char ida_chars[] =
        {
            0x0A, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x05, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x21, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x20, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x51, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x0C, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x0B, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x20, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00,
            0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x20, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x41, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x0C, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
            0x22, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x3F, 0x00,
            0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
            0x07, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x07, 0x00,
            0x00, 0x00, 0x72, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
            0x33, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x18, 0x00,
            0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xA7, 0xFF, 0xFF, 0xFF,
            0x07, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x07, 0x00,
            0x00, 0x00, 0xF1, 0xFF, 0xFF, 0xFF, 0x07, 0x00, 0x00, 0x00,
            0x28, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x84, 0xFF,
            0xFF, 0xFF, 0x07, 0x00, 0x00, 0x00, 0xC1, 0xFF, 0xFF, 0xFF,
            0x07, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x07, 0x00,
            0x00, 0x00, 0x7A, 0x00, 0x00, 0x00};
    int *str = (int *)ida_chars;
    // for (int i = 0; i < 100; i++)
    // {
    //     printf("%d ", str[i]);
    // }
    vm_operad(str, 114);
    return 0;
}
```

得到：

```
0x22 0x3f 0x34 0x32 0x72 0x33 0x18 0xffffffa7 0x31 0xfffffff1 0x28 0xffffff84 0xffffffc1 0x1e 0x7a 
顺序:
1, 3, 4, 6, 7, 9, 10, 12, 13, 15, 16, 17, 18, 19, 20, 22, 23, 25, 26, 28, 29, 30, 31, 32, 33, 35, 36, 38, 39, 41, 42, 44, 45, 46, 47, 48, 49, 51, 52, 54, 55, 57, 58, 
60, 61, 63, 64, 66, 67, 69, 70, 72, 73, 75, 76, 78, 79, 81, 82, 83, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104, 106, 108, 110, 112, 114,
```

正好比较了15次。

现在知道了执行顺序以及有关flag的关键信息。逆着走一遍就好：

```c
int __cdecl vm_decode(int *opcode,int len_114)
{
  char order[100] = {1, 3, 4, 6, 7, 9, 10, 12, 13, 15, 16, 17, 18, 19, 20, 22, 23, 25, 26, 28, 29, 30, 31, 32, 33, 35, 36, 38, 39, 41, 42, 44, 45, 46, 47, 48, 49, 51, 52, 54, 55, 57, 58, 60, 61, 63, 64, 66, 67, 69, 70, 72, 73, 75, 76, 78, 79, 81, 82, 83, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104, 106, 108, 110, 112, 114};
  unsigned char v4[] = {0x22, 0x3f, 0x34, 0x32, 0x72, 0x33, 0x18, 0xffffffa7, 0x31, 0xfffffff1, 0x28, 0xffffff84, 0xffffffc1, 0x1e, 0x7a};
  unsigned char flag[100] = {}; // [esp+13h] [ebp-E5h]
  int v5; // [esp+DBh] [ebp-1Dh]
  int m; // [esp+DCh] [ebp-1Ch]
  int z; // [esp+E0h] [ebp-18h]
  int x; // [esp+E8h] [ebp-10h]
  int i; // [esp+ECh] [ebp-Ch]
  x = 15;
  z = 15;
  m = 15;
  for(int k=strlen(order) - 1;k>=0;k--)//从后往前
  {
	i = order[k];
    switch ( opcode[i] )
    {
      case 1:
		--x;
		--z;
        v5 = v4[z];
        break;
      case 2:
        flag[x] = v5 - opcode[i + 1];
        break;
      case 3:
        flag[x] = v5 + opcode[i + 1];
        break;
      case 4:
        flag[x] = v5 ^ opcode[i + 1];
        break;
      case 5:
        flag[x] = v5 / opcode[i + 1];
        break;
      case 6:
		break;
      case 8:
        v5 = flag[--m];
        break;
      case 11:
        flag[x] = v5 + 1;
        break;
      case 12:
        flag[x] = v5 - 1;
        break;
    }
  }
  printf("%s",flag);
  return 0;
}
```

太不熟了。。

# 0x22.firmware

binwalk提取

```sh
┌──(kali㉿kali)-[~/Desktop]
└─$ binwalk -e 51475f91-7b90-41dd-81a3-8b82df4f29d0.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             TP-Link firmware header, firmware version: 1.-20432.3, image version: "", product ID: 0x0, product version: 155254791, kernel load address: 0x0, kernel entry point: 0x80002000, kernel offset: 4063744, kernel length: 512, rootfs offset: 772784, rootfs length: 1048576, bootloader offset: 2883584, bootloader length: 0
69424         0x10F30         Certificate in DER format (x509 v3), header length: 4, sequence length: 64
94080         0x16F80         U-Boot version string, "U-Boot 1.1.4 (Aug 26 2013 - 09:07:51)"
94256         0x17030         CRC32 polynomial table, big endian
131584        0x20200         TP-Link firmware header, firmware version: 0.0.3, image version: "", product ID: 0x0, product version: 155254791, kernel load address: 0x0, kernel entry point: 0x80002000, kernel offset: 3932160, kernel length: 512, rootfs offset: 772784, rootfs length: 1048576, bootloader offset: 2883584, bootloader length: 0
132096        0x20400         LZMA compressed data, properties: 0x5D, dictionary size: 33554432 bytes, uncompressed size: 2203728 bytes

WARNING: Extractor.execute failed to run external extractor 'sasquatch -p 1 -le -d 'squashfs-root' '%e'': [Errno 2] No such file or directory: 'sasquatch', 'sasquatch -p 1 -le -d 'squashfs-root' '%e'' might not be installed correctly

WARNING: Extractor.execute failed to run external extractor 'sasquatch -p 1 -be -d 'squashfs-root' '%e'': [Errno 2] No such file or directory: 'sasquatch', 'sasquatch -p 1 -be -d 'squashfs-root' '%e'' might not be installed correctly
1180160       0x120200        Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 2774624 bytes, 519 inodes, blocksize: 131072 bytes, created: 2015-04-13 09:35:04

```

几个文件，其中

>   SquashFS 是一套基于Linux内核使用的压缩只读文件系统

需要用到 **firmware-mod-kit**解压，安装方法：

```sh
sudo apt-get install git build-essential zlib1g-dev liblzma-dev python-magic
git clone https://github.com/mirror/firmware-mod-kit.git
cd firmware-mod-kit/src
./configure && make
```

解压文件系统：

```sh
gwt@ubuntu:~/Desktop/_51475f91-7b90-41dd-81a3-8b82df4f29d0.bin.extracted$ /home/gwt/firmware-mod-kit/unsquashfs_all.sh  120200.squashfs 
/home/gwt/firmware-mod-kit/unsquashfs_all.sh: line 85: ./src/binwalk: No such file or directory
Attempting to extract SquashFS .X file system...


Trying ./src/squashfs-2.1-r2/unsquashfs... 
Trying ./src/squashfs-2.1-r2/unsquashfs-lzma... 
Trying ./src/squashfs-3.0/unsquashfs... 
Trying ./src/squashfs-3.0/unsquashfs-lzma... 
Trying ./src/squashfs-3.0-lzma-damn-small-variant/unsquashfs-lzma... 
Trying ./src/others/squashfs-2.0-nb4/unsquashfs... 
Trying ./src/others/squashfs-3.0-e2100/unsquashfs... 
Trying ./src/others/squashfs-3.0-e2100/unsquashfs-lzma... 
Trying ./src/others/squashfs-3.2-r2/unsquashfs... 
Trying ./src/others/squashfs-3.2-r2-lzma/squashfs3.2-r2/squashfs-tools/unsquashfs... 
Trying ./src/others/squashfs-3.2-r2-hg612-lzma/unsquashfs... 
Trying ./src/others/squashfs-3.2-r2-wnr1000/unsquashfs... 
Trying ./src/others/squashfs-3.2-r2-rtn12/unsquashfs... 
Trying ./src/others/squashfs-3.3/unsquashfs... 
Trying ./src/others/squashfs-3.3-lzma/squashfs3.3/squashfs-tools/unsquashfs... 
Trying ./src/others/squashfs-3.3-grml-lzma/squashfs3.3/squashfs-tools/unsquashfs... 
Trying ./src/others/squashfs-3.4-cisco/unsquashfs... 
Trying ./src/others/squashfs-3.4-nb4/unsquashfs... 
Trying ./src/others/squashfs-3.4-nb4/unsquashfs-lzma... 
Trying ./src/others/squashfs-4.2-official/unsquashfs... Parallel unsquashfs: Using 1 processor

Trying ./src/others/squashfs-4.2/unsquashfs... Parallel unsquashfs: Using 1 processor

Trying ./src/others/squashfs-4.0-lzma/unsquashfs-lzma... Parallel unsquashfs: Using 1 processor
480 inodes (523 blocks) to write

[==================================================================================================-               ] 454/523  86%
created 341 files
created 39 directories
created 70 symlinks
created 0 devices
created 0 fifos
File system sucessfully extracted!
MKFS="./src/others/squashfs-4.0-lzma/mksquashfs-lzma"
```

找到backdoor文件，去upx壳，然后直接找到：`echo.byethost51.com:36667`

# 0x23.[GUET-CTF2019]number_game(未完，记得动调)

先看了下流程：

```c
unsigned __int64 __fastcall main(int a1, char **a2, char **a3)
{
  __int64 v4; // [rsp+8h] [rbp-38h]
  __int64 v5; // [rsp+10h] [rbp-30h] BYREF
  __int16 v6; // [rsp+18h] [rbp-28h]
  __int64 v7; // [rsp+20h] [rbp-20h] BYREF
  __int16 v8; // [rsp+28h] [rbp-18h]
  char v9; // [rsp+2Ah] [rbp-16h]
  unsigned __int64 v10; // [rsp+38h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  v5 = 0LL;
  v6 = 0;
  v7 = 0LL;
  v8 = 0;
  v9 = 0;
  __isoc99_scanf("%s", &v5);
  if ( sub_4006D6(&v5) )
  {
    v4 = sub_400758(&v5, 0LL, 10LL);
    sub_400807(v4, &v7);
    v9 = 0;
    sub_400881(&v7);
    if ( sub_400917() )
    {
      puts("TQL!");
      printf("flag{");
      printf("%s", &v5);
      puts("}");
    }
    else
    {
      puts("your are cxk!!");
    }
  }
  return __readfsqword(0x28u) ^ v10;
}
```

经过了几次变换，重要的是这个：

```c
__int64 sub_400917()
{
  unsigned int v1; // [rsp+0h] [rbp-10h]
  int i; // [rsp+4h] [rbp-Ch]
  int j; // [rsp+8h] [rbp-8h]
  int k; // [rsp+Ch] [rbp-4h]

  v1 = 1;
  for ( i = 0; i <= 4; ++i )
  {
    for ( j = 0; j <= 4; ++j )
    {
      for ( k = j + 1; k <= 4; ++k )
      {
        if ( *(&byte_601060 + 5 * i + j) == *(&byte_601060 + 5 * i + k) )
          v1 = 0;
        if ( *(&byte_601060 + 5 * j + i) == *(&byte_601060 + 5 * k + i) )
          v1 = 0;
      }
    }
  }
  return v1;
}
```

应该是个5*5的东西，发现了：`14#2330#1#0#23##3##042##1`

是和数独差不多的东西

```
14#23
30#1#
0#23#
#3##0
42##1
```

看了好多wp终于看懂了，他上面的判断只是判断了每一行和每一列不能有相同的而已，so：`0 4 2 1 4 2 1 4 3 0` 

输出0123456789动调下（这个等明天调，https://blog.csdn.net/Palmer9/article/details/104613420），（或者可以根据以上的代码看出）

得到：0123456789 —> 7381940526，最后exp：

```python
model = [7, 3, 8, 1, 9, 4, 0, 5, 2, 6]
s = [48, 52, 50, 49, 52, 50, 49, 52, 51, 48]
flag = [0] * 10
for i in range(10):
    flag[model[i]] = chr(s[i])
flag = ''.join(flag)
print(flag)
```

# 0x24.特殊的 BASE64



无壳，变表base64

```python
import base64
import string

str1 = "mTyqm7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI=="

string1 = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0987654321+/"
string2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

print(base64.b64decode(str1.translate(str.maketrans(string1, string2))))
```

