---
title: Linux advanced
description: Linux advanced guide for pentester.
---

# Linux advanced

## /proc/

`/proc/<pid>/` : PID n°\<pid\>.
`/proc/self/` : The link `self` points to the process reading the file system.

| File                          | Content |
| ----------------------------- | ------- |
| `/proc/<pid>/clear_refs`      | Clears page referenced bits shown in smaps output |
| `/proc/<pid>/cmdline`         | Command line arguments |
| `/proc/<pid>/cpu`             | Current and last cpu in which it was executed |
| `/proc/<pid>/cwd`             | Symlink to the current working directory |
| `/proc/<pid>/environ`         | Values of environment variables |
| `/proc/<pid>/exe`             | Link to the executable of this process |
| `/proc/<pid>/fd`              | Directory, which contains all file descriptors |
| `/proc/<pid>/maps`            | Memory maps to executables and library files |
| `/proc/<pid>/mem`             | Memory held by this process |
| `/proc/<pid>/root`            | Link to the root directory of this process |
| `/proc/<pid>/stat`            | Process status |
| `/proc/<pid>/statm`           | Process memory status information |
| `/proc/<pid>/status`          | Process status in human readable form |
| `/proc/<pid>/wchan`           | Present with CONFIG_KALLSYMS=y: it shows the kernel function symbol the task is blocked in - or “0” if not blocked. |
| `/proc/<pid>/pagemap`         | Page table |
| `/proc/<pid>/stack`           | Report full stack trace, enable via CONFIG_STACKTRACE |
| `/proc/<pid>/smaps`           | An extension based on maps, showing the memory consumption of each mapping and flags associated with it |
| `/proc/<pid>/smaps_rollup`    | Accumulated smaps stats for all mappings of the process. This can be derived from smaps, but is faster and more convenient |
| `/proc/<pid>/numa_maps`    | An extension based on maps, showing the memory locality and binding policy as well as mem usage (in pages) of each mapping. |

> Source [kernel.org](https://www.kernel.org/doc/html/latest/filesystems/proc.html).

## Capabilities

- [https://man7.org/linux/man-pages/man7/capabilities.7.html](https://man7.org/linux/man-pages/man7/capabilities.7.html)

Display capabilities :

```bash
$ capsh --print
```

### Example of usage

I want to use python HTTP server on port < 1024 without using `sudo`.

```bash
$ python3 -m http.server 80
Traceback (most recent call last):
  File "/usr/lib/python3.9/runpy.py", line 197, in _run_module_as_main
    return _run_code(code, main_globals, None,
  File "/usr/lib/python3.9/runpy.py", line 87, in _run_code
    exec(code, run_globals)
  File "/usr/lib/python3.9/http/server.py", line 1290, in <module>
    test(
  File "/usr/lib/python3.9/http/server.py", line 1245, in test
    with ServerClass(addr, HandlerClass) as httpd:
  File "/usr/lib/python3.9/socketserver.py", line 452, in __init__
    self.server_bind()
  File "/usr/lib/python3.9/http/server.py", line 1288, in server_bind
    return super().server_bind()
  File "/usr/lib/python3.9/http/server.py", line 138, in server_bind
    socketserver.TCPServer.server_bind(self)
  File "/usr/lib/python3.9/socketserver.py", line 466, in server_bind
    self.socket.bind(self.server_address)
PermissionError: [Errno 13] Permission denied
```

Let's add the capability `CAP_NET_BIND_SERVICE`.

```bash
$ sudo setcap CAP_NET_BIND_SERVICE+eip $(which python3)
Invalid file '/usr/bin/python3' for capability operation
$ ls -al /usr/bin/python3
lrwxrwxrwx 1 root root 9 Aug 31 15:28 /usr/bin/python3 -> python3.9
$ sudo setcap CAP_NET_BIND_SERVICE+eip /usr/bin/python3.9
$ python3.9 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

It's working !

### Famous cap.

- **CAP_NET_ADMIN** : Allows you to perform various network-related operations.
- **CAP_SETUID** / **CAP_SETGID** : Allows you to make arbitrary manipulations of process UIDs / GIDs.

## fstab - File System Table
System configuration file commonly found at `/etc/fstab`. The fstab file typically lists all available disk partitions and other types of file systems and data sources.

This configuration file is read by the `mount` command, which happens automatically at boot time to determine the overall file system structure, and thereafter when a user executes the mount command to modify that structure.

### Example

```bash linenums="0"
# device-spec   mount-point     fs-type      options                                          dump pass
LABEL=/         /               ext4         defaults                                            1 1
/dev/sda6       none            swap         defaults                                            0 0
none            /dev/pts        devpts       gid=5,mode=620                                      0 0
none            /proc           proc         defaults                                            0 0
none            /dev/shm        tmpfs        defaults                                            0 0

# Removable media
/dev/cdrom      /mnt/cdrom      udf,iso9660  noauto,owner,ro                                     0 0

# NTFS Windows 7 partition
/dev/sda1       /mnt/Windows    ntfs-3g      quiet,defaults,locale=en_US.utf8,umask=0,noexec     0 0

# Partition shared by Windows and Linux
/dev/sda7       /mnt/shared     vfat         umask=000                                           0 0

# Mounting tmpfs
tmpfs           /mnt/tmpfschk   tmpfs        size=100m                                           0 0

# Mounting cifs
//cifs_server_name/ashare  /store/pingu    cifs         credentials=/root/smbpass.txt            0 0

# Mounting NFS
nfs_server_name:/store    /store          nfs          rw                                        0 0
```

1. **device-spec** : Device name, label, UUID, ...
2. **mount-point** : Where the contents of the device may be accessed after mounting (for swap partitions or files, this is set to none).
3. **fs-type** : Type of file system.
4. **options** : Options describing various other aspects of the file system, such as whether it is automatically mounted at boot, which users may mount or access it, whether it may be written to or only read from, its size, and so forth (the special option defaults refers to a pre-determined set of options depending on the file system type).
5. **dump** : A number indicating whether and how often the file system should be backed up by the dump program (a zero indicates the file system will never be automatically backed up).
6. **pass** : A number indicating the order in which the fsck program will check the devices for errors at boot time (0 : do not check, 1 :check immediately during boot, 2 : check after boot).

### Options common to all filesystems

- `auto` / `noauto` : With the `auto` option, the device will be mounted automatically at bootup or when the `mount -a` command is issued. `auto` is the default option. With `noauto`, the device can be only mounted explicitly.
- `dev` / `nodev` : Controls behavior of the interpretation of block special devices on the filesystem.
- `exec` / `noexec` : `exec` lets binaries that are on the partition be executed, whereas `noexec` is the opposite.
- `rw` / `ro` : Mount the filesystem in either read write or read only mode.
- `sync` / `async` : How the input and output to the filesystem should be done, synchronously or asynchronously.
- `suid` / `nosuid` : Controls the behavior of the operation of suid, and sgid bits.
- `user` / `users` / `nouser` : `user` permits any user to mount the filesystem. This automatically implies noexec, nosuid, nodev unless explicitly overridden. If `nouser` is specified, only root can mount the filesystem. If `users` is specified, every user in group users will be able to unmount the volume.
- `defaults` : Use default settings. Default settings are defined per file system at the file system level.
- `owner` (Linux-specific) : Permit the owner of device to mount.
- `atime` / `noatime` / `relatime` / `strictatime` (Linux-specific) : The Unix stat structure records when files are last accessed (atime), modified (mtime), and changed (ctime). One result is that atime is written every time a file is read, which has been heavily criticized for causing performance degradation and increased wear. However, atime is used by some applications and desired by some users, and thus is configurable as atime (update on access), noatime (do not update), or (in Linux) relatime (update atime if older than mtime). Through Linux 2.6.29, atime was the default; as of 2.6.30, relatime is the default.

> Source [Wikipedia](https://en.wikipedia.org/wiki/Fstab).

## mtab - Mounted File System Table

System configuration file commonly found at `/etc/mtab` (it can be a symlink to `/proc/mounts` or `/proc/self/mounts`). This file lists all currently mounted filesystems along with their initialization options.

### Example

```bash
/dev/sdb1 / ext3 rw,relatime,errors=remount-ro 0 0
proc /proc proc rw,noexec,nosuid,nodev 0 0
/sys /sys sysfs rw,noexec,nosuid,nodev 0 0
varrun /var/run tmpfs rw,noexec,nosuid,nodev,mode=0755 0 0
varlock /var/lock tmpfs rw,noexec,nosuid,nodev,mode=1777 0 0
udev /dev tmpfs rw,mode=0755 0 0
devshm /dev/shm tmpfs rw 0 0
devpts /dev/pts devpts rw,gid=5,mode=620 0 0
lrm /lib/modules/2.6.24-16-generic/volatile tmpfs rw 0 0
securityfs /sys/kernel/security securityfs rw 0 0
gvfs-fuse-daemon /home/alice/.gvfs fuse.gvfs-fuse-daemon rw,nosuid,nodev,user=alice 0 0
```
 
 > Source [Wikipedia](https://en.wikipedia.org/wiki/Mtab).