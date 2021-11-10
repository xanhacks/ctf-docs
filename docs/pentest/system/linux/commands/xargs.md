---
title: xargs
description: xargs - build and execute command lines from standard input.
---

# xargs - build and execute command lines from standard input

## Threading
- `-n max-args` : Use  at most max-args arguments per command line.
- `-P max-procs` : Run up to max-procs processes at a time.

```bash
$ echo "https://github.com/HeroCTF/HeroCTF_v3\n" \
	"https://github.com/HeroCTF/HeroCTF_v2\n" \
	"https://github.com/HeroCTF/HeroCTF_v1" \
	| xargs -n1 -P3 git clone
Cloning into 'HeroCTF_v3'...
Cloning into 'HeroCTF_v2'...
Cloning into 'HeroCTF_v1'...
remote: Enumerating objects: 1047, done.
remote: Enumerating objects: 3109, done.
remote: Enumerating objects: 835, done.
remote: Counting objects: 100% (381/381), done.
remote: Compressing objects: 100% (347/347), done.
remote: Counting objects: 100% (178/178), done.
[...]
```

- `-a file` : Read items from file instead of standard input.

```bash
$ cat git_urls.lst
https://github.com/HeroCTF/HeroCTF_v3
https://github.com/HeroCTF/HeroCTF_v2
https://github.com/HeroCTF/HeroCTF_v1
$ xargs -a git_urls.lst -P3 -n1 git clone
Cloning into 'HeroCTF_v3'...
Cloning into 'HeroCTF_v2'...
Cloning into 'HeroCTF_v1'...
[...]
```