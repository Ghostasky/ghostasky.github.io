---
title: RC4
date: 2022-07-27
tags: Crypto
categories: Technology

---

hw摸鱼，闲的没啥事干，把RC4的加解密原理写一遍吧，明天干别的东西。（hw期间电脑装了dlp，，就不截图了）

RC4，对称加密算法，流加密，秘钥长度可变。RC4 算法广泛应用于 SSL/TLS 协议和 WEP/WPA 协议。

RC4加解密时依次以字节流的方式加解密明文中的每一个字节。

# RC4

RC4中的一些变量：

-   密钥流：与明文长度相等，加密生成的密文也是相同的字节
-   状态向量S：长度为256，S[0]~S[255]，每个单元一字节，
-   临时向量T：长度为256，每个单元为一字节，如果密钥的长度是256字节，就直接把密钥的值赋给T，否则，轮转地将密钥的每个字节赋给T
-   密钥K(Key)：长度为1~256字节(`keyLen`)，密钥的长度与明文长度、密钥流的长度没有必然关系，通常密钥的长度16字节（128比特）。



RC4算法步骤：

1.  初始化S和T
2.  初始排列S（前两部分称为KSA）
3.  产生密钥流（称为PRGA）

## 初始化S和T

![](RC4/rc4_s_t.png)

```python
for i in range(256):
    self.S.append(i)
for i in range(self.keyLen):    
    index = random.randint(0, 63)
    self.Key.append(self.charTable[index])
for i in range(256):
    tmp = self.Key[i % self.keyLen]
    self.T.append(tmp)
```





