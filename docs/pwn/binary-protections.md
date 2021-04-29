---
title: Binary protections
description: List of binary protections set up by the compiler or our computer.
---

# Binary protections

## Identification

``` shell
$ checksec BOO_2
[*] '/tmp/BOO_2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## RELRO

Relro (Relocation Read only) affects the memory permissions. This is a protection implemented by GCC, allowing to ask the linker to resolve the dynamic library functions at the very beginning of the execution, and thus to be able to remap the GOT section and GOT.plt as read-only.

!!! info
    Partial RELRO is enabled by default in GCC.

!!! warning
    If your program has a vulnerability that makes it possible to write somewhere in the memory, you can overwrite such address by your own (or replace the address of printf by the address of the function system).

## Canary

Stack canaries are random values placed in memory just before the return address.
In order to overwrite the return address and redirect program flow, an attacker would have to overwrite the stack canary as well. And thus the program would be able to detect stack overflow by checking if the canary value is correct.

## NX

The NX bit (no-execute) bit may mark certain areas of memory (like the stack) as non-executable. The processor will then refuse to execute any code residing in these areas of memory. It is used to prevent certain types of malicious software from taking over computers by inserting their code into another program's data storage area and running their own code from within this section (like shellcode), one class of such attacks is known as the buffer overflow attack.

## PIE

PIE (Position Independent Executable) allows a program to be relocated, just like a shared object. At each run of the program, the program can be loaded at different addresses to make it harder for an attacker to guess certain program state.

## ASLR

Address space layout randomization (ASLR) is a computer security technique involved in preventing exploitation of memory corruption vulnerabilities. In order to prevent an attacker from reliably jumping to, for example, a particular exploited function in memory, ASLR randomly arranges the address space positions of key data areas of a process, including the base of the executable and the positions of the stack, heap and libraries.

!!! info
    You can disable ASLR on your computer by using this command :<br>
    <strong>echo 0 | sudo tee /proc/sys/kernel/randomize_va_space</strong>

## FORTIFY_SOURCE

The GNU Compiler Collection has a FORTIFY_SOURCE option that does automatic bounds checking of dangerous functions to prevent simple buffer overflows. The FORTIFY_SOURCE code will do static and dynamic checks on buffer sizes to prevent these buffer overflows.

!!! example
    <strong>gets(buffer)</strong> would be converted to <strong>__gets_chk(buffer, sizeof(buffer))</strong>, then <strong>__gets_chk</strong> would make sure that the input does not exceed <strong>sizeof(buffer)</strong>.

### References

- https://blog.usejournal.com/binary-exploitation-buffer-overflows-a9dc63e8b546
- https://en.wikipedia.org/wiki/Position-independent_code
- https://stackoverflow.com/questions/30498776/position-independent-executables-and-android
- https://en.wikipedia.org/wiki/NX_bit
- https://www.root-me.org/fr/Documentation/Applicatif/Memoire-protection-RELRO
- https://guyinatuxedo.github.io/7.2-mitigation_relro/index.html
- https://en.wikipedia.org/wiki/Address_space_layout_randomization
- https://medium.com/@HockeyInJune/fortify-source-semantics-de54ca4bbe12
- https://cotonne.github.io/binary/2020/07/14/format-string.html
