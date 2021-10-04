---
title: Introduction to x86 assembly
description: Introduction to x86 assembly with nasm.
---

# Introduction to x86 assembly

## exit syscall

This program call the syscall n°1 (value of the register `eax`) which represents the syscall `exit` ([syscalls list](https://syscalls.w3challs.com/?arch=x86)). The register `ebx` holds the argument of the function exit, here the program will do `exit(0xc)`.

code.asm

```asm
section     .text
global      _start
_start:
    mov     ebx, 0xc
    mov     eax, 1
    int     0x80
```

### Assemble and link

```bash
$ nasm -f elf64 code.asm	# assemble the program
$ ld -s -o code code.o		# link the object file nasm produced into an executable
$ ./code
$ echo $?
12
```

If we look at the exit code of the program, we can see it's `12` (`0xc`).