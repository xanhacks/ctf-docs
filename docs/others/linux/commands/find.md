---
title: find
description: find - search for files in a directory hierarchy.
---

# find - search for files in a directory hierarchy

Find SUID bit.

```
$ find / -perm /4000 -user root -type f -ls 2>/dev/null
 13501117     56 -rwsr-xr-x   1 root     root        54096 Jul 27  2018 /usr/bin/chfn
 13501166     84 -rwsr-xr-x   1 root     root        84016 Jul 27  2018 /usr/bin/gpasswd
 13501219     64 -rwsr-xr-x   1 root     root        63736 Jul 27  2018 /usr/bin/passwd
 13501209     44 -rwsr-xr-x   1 root     root        44440 Jul 27  2018 /usr/bin/newgrp
 13501120     44 -rwsr-xr-x   1 root     root        44528 Jul 27  2018 /usr/bin/chsh
 13500615     64 -rwsr-xr-x   1 root     root        63568 Jan 10  2019 /bin/su
 13500597     52 -rwsr-xr-x   1 root     root        51280 Jan 10  2019 /bin/mount
 13500622     36 -rwsr-xr-x   1 root     root        34888 Jan 10  2019 /bin/umount
```

Find files creation between two date.

```
$ find / -perm /4000 -user root -type f -newermt '28 jul 2018 00:00:00' ! -newermt '11 jan 2019 00:00:00' -ls 2>/dev/null
 13500615     64 -rwsr-xr-x   1 root     root        63568 Jan 10  2019 /bin/su
 13500597     52 -rwsr-xr-x   1 root     root        51280 Jan 10  2019 /bin/mount
 13500622     36 -rwsr-xr-x   1 root     root        34888 Jan 10  2019 /bin/umount
$ find . -newermt '2022-02-10' 2>/dev/null
```
 
 Find files of a specific user with a name that match a regex.
 
```
$ find / -user www-data -name '*.conf' -type f 2>/dev/null
/var/www/html/ecommerce/database.conf
```
