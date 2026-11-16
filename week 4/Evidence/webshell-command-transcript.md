# Evidence — Web shell command transcript

All requests to `http://192.168.1.128/uploads/shell.php?cmd=<command>` from `192.168.1.1`, `User-Agent: curl/8.5.0`, `Cookie: PHPSESSID=4f21e6caa9f18e454c2f4f9eead6e277`.
Extracted from `webshell.pcap` (HTTP response bodies, `text/plain; charset=utf-8`). Responses are shown verbatim, with `\n` rendered as line breaks.

| Stream | Frame (req/resp) | Time (rel) | Command |
|---|---|---|---|
| 2 | 54 / 56 | 0.0250 s | `whoami` |
| 3 | 64 / 66 | 0.0354 s | `id` |
| 4 | 74 / 76 | 0.0473 s | `hostname` |
| 5 | 84 / 86 | 0.0564 s | `uname -a` |
| 6 | 94 / 96 | 0.0671 s | `cat /etc/os-release \| head -5` |
| 7 | 104 / 106 | 0.0783 s | `pwd` |
| 8 | 114 / 117 | 0.0849 s | `ls -la /var/www/blackstone/` |
| 9 | 126 / 128 | 0.0960 s | `ls -la /var/www/blackstone/uploads/` |
| 10 | 136 / 138 | 0.1070 s | `cat /etc/passwd \| head -10` |
| 11 | 146 / 148 | 0.1182 s | `ps aux \| head -15` |
| 12 | 156 / 158 | 0.1284 s | `ss -tlnp 2>/dev/null \|\| netstat -tlnp 2>/dev/null` |
| 13 | 166 / 168 | 0.1411 s | `ip -4 addr show` |
| 14 | 176 / 178 | 0.1500 s | `env` |
| 15 | 186 / 188 | 0.1608 s | `sudo -l 2>&1` |
| 16 | 196 / 198 | 0.1721 s | `find / -perm -4000 -type f 2>/dev/null \| head -10` |

---

## 1. `whoami`

```
www-data
```

## 2. `id`

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 3. `hostname`

```
wazuh-server
```

## 4. `uname -a`

```
Linux wazuh-server 7.0.0-42-generic #42-Ubuntu SMP PREEMPT_DYNAMIC Thu Oct 15 08:06:44 UTC 2026 x86_64 GNU/Linux
```

## 5. `cat /etc/os-release | head -5`

```
PRETTY_NAME="Ubuntu 26.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="26.04"
VERSION="26.04.1 LTS (Resolute Raccoon)"
VERSION_CODENAME=resolute
```

## 6. `pwd`

```
/var/www/blackstone/uploads
```

## 7. `ls -la /var/www/blackstone/`

```
total 108
drwxr-xr-x 6 www-data www-data  4096 Nov  8 08:53 .
drwxr-xr-x 4 root     root      4096 Oct 15 10:17 ..
-rw-r--r-- 1 www-data www-data   220 Oct 15 10:17 .bash_logout
-rw-r--r-- 1 www-data www-data  3771 Oct 15 10:17 .bashrc
drwx------ 2 www-data www-data  4096 Oct 15 10:17 .cache
-rw------- 1 www-data www-data    20 Oct 15 10:17 .lesshst
drwx------ 3 www-data www-data  4096 Oct 15 10:17 .local
-rw-r--r-- 1 www-data www-data   807 Oct 15 10:17 .profile
drwx------ 2 www-data www-data  4096 Oct 15 10:17 .ssh
-rw------- 1 www-data www-data   774 Oct 15 10:17 .viminfo
-rw-r--r-- 1 www-data www-data   975 Oct 15 11:28 contact.php
-rw-r--r-- 1 www-data www-data   365 Oct 15 10:56 db.php
-rw-r--r-- 1 www-data www-data   413 Nov  7 09:34 footer.php
-rw-r--r-- 1 www-data www-data  1588 Nov  7 09:35 header.php
-rw-r--r-- 1 www-data www-data  1099 Nov  7 09:36 index.php
-rw-r--r-- 1 www-data www-data  2134 Oct 15 11:24 login.php
-rw-r--r-- 1 www-data www-data  1452 Oct 15 10:56 schema.sql
-rw-r--r-- 1 www-data www-data  2630 Oct 15 11:27 search.php
-rw-r--r-- 1 www-data www-data  7422 Nov  7 09:37 style.css
-rw-r--r-- 1 www-data www-data  3464 Nov  7 09:36 upload.js
-rw-r--r-- 1 www-data www-data 19989 Nov  8 08:51 upload.php
drwxr-x--- 2 www-data www-data  4096 Nov  8 09:29 uploads
```

## 8. `ls -la /var/www/blackstone/uploads/`

```
total 16
drwxr-x--- 2 www-data www-data 4096 Nov  8 09:29 .
drwxr-xr-x 6 www-data www-data 4096 Nov  8 08:53 ..
-rw-r--r-- 1 www-data www-data  223 Nov  8 09:02 exploit.php
-rw-r--r-- 1 www-data www-data  135 Nov  8 09:29 shell.php
```

> `exploit.php` (09:02) predates this capture by 27 minutes → an earlier successful upload.

## 9. `cat /etc/passwd | head -10`

```
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
```

## 10. `ps aux | head -15` (abridged)

```
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
www-data 17721  0.0 ...        ...   ... ?        S    ...
```

## 11. `ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null`

```
State  Recv-Q Send-Q      Local Address:Port      Peer Address:PortProcess
LISTEN 0      4096              0.0.0.0:22         0.0.0.0:*
LISTEN 0      511               0.0.0.0:443        0.0.0.0:*
LISTEN 0      4096           127.0.0.54:53         0.0.0.0:*
LISTEN 0      128               0.0.0.0:1515       0.0.0.0:*
LISTEN 0      128               0.0.0.0:1514       0.0.0.0:*
LISTEN 0      2048              0.0.0.0:55000      0.0.0.0:*
LISTEN 0      4096        127.0.0.53%lo:53         0.0.0.0:*
LISTEN 0      80              127.0.0.1:3306       0.0.0.0:*
LISTEN 0      4096                 [::]:22            [::]:*
LISTEN 0      511                     *:80               *:*
LISTEN 0      4096   [::ffff:127.0.0.1]:9200             *:*
LISTEN 0      4096   [::ffff:127.0.0.1]:9300             *:*
LISTEN 0      2048                 [::]:55000        [::]:*
```

Ports 1514/1515/55000 = Wazuh agent/manager/authd; 9200/9300 = OpenSearch; 3306 = MySQL.

## 12. `ip -4 addr show`

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 127.0.0.1/8 scope host lo
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    altname enp2s1
    altname enx000c2952c78b
    inet 192.168.1.128/24 brd 192.168.1.255 scope global ens33
3: ens36: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    altname enp2s4
    altname enx000c2952c795
    inet 172.16.173.138/24 metric 100 brd 172.16.173.255 scope global dynamic ens36
```

> `ens36` MAC suffix `…c7:95` matches the scanned host in `nmap.pcap`; `ens33` MAC `…c7:8b` matches the web-shell victim.

## 13. `env`

```
USER=root
APACHE_RUN_DIR=/run/apache2
SYSTEMD_EXEC_PID=1920
NOTIFY_SOCKET=/run/systemd/notify
APACHE_PID_FILE=/run/apache2/apache2.pid
JOURNAL_STREAM=10:28493
MEMORY_PRESSURE_WATCH=/sys/fs/cgroup/system.slice/apache2.service/memory.pressure
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
INVOCATION_ID=d27a19bbd630466b9ac3cda6ee2e7170
APACHE_LOCK_DIR=/run/lock/apache2
LANG=C.UTF-8
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
PWD=/var/www/blackstone/uploads
MEMORY_PRESSURE_WRITE=c29tZSAyMDAwMDAgMjAwMDAwMAA=
```

## 14. `sudo -l 2>&1`

```
sudo: Sorry, user www-data may not run sudo on wazuh-server.
```

## 15. `find / -perm -4000 -type f 2>/dev/null | head -10`

```
/snap/core24/1643/usr/bin/chfn
/snap/core24/1643/usr/bin/chsh
/snap/core24/1643/usr/bin/gpasswd
/snap/core24/1643/usr/bin/mount
/snap/core24/1643/usr/bin/newgrp
/snap/core24/1643/usr/bin/passwd
/snap/core24/1643/usr/bin/su
/snap/core24/1643/usr/bin/sudo
/snap/core24/1643/usr/bin/umount
/snap/core24/1643/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```
