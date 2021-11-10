---
title: stat
description: stat - display file or file system status.
---

# stat - display file or file system status

```
$ stat /etc/passwd
  File: /etc/passwd
  Size: 965             Blocks: 8          IO Block: 4096   regular file
Device: 2eh/46d Inode: 13631986    Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2021-09-03 07:48:11.000000000 +0000
Modify: 2021-09-03 07:48:11.000000000 +0000
Change: 2021-09-12 19:40:02.730102800 +0000
 Birth: -
```

The system files have the milliseconds of the `Modify` date set to `000000000`. If this is not the case, the user has probably installed the file by hand.