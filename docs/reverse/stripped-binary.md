---
title: Stripped binary
description: Debugging stripped binary.
---

# Stripped binary

A **stripped binary** is a binary which does not conatin any debugging symbols.

## Debbugging with gdb

```bash
$ file Basic-ELF-x64.bin
Basic-ELF-x64.bin: ELF 64-bit LSB pie executable, x86-64, [...], stripped

$ gdb ./Basic-ELF-x64.bin
GNU gdb (GDB) 11.1
Reading symbols from ./Basic-ELF-x64.bin...
(No debugging symbols found in ./Basic-ELF-x64.bin)

gef➤  info file
Symbols from ".../Basic-ELF-x64.bin".
Local exec file: `.../Basic-ELF-x64.bin', file type elf64-x86-64.
        Entry point: 0x10e0 # <--- ENTRYPOINT
        0x0000000000000318 - 0x0000000000000334 is .interp
        0x0000000000000338 - 0x0000000000000358 is .note.gnu.property
```

Using entrypoint does not always work :

```bash
gef➤  b *0x10e0
Breakpoint 1 at 0x10e0
gef➤  r
Starting program: .../Basic-ELF-x64.bin
Warning:
Cannot insert breakpoint 1.
Cannot access memory at address 0x10e0
gef➤  del 1
```

However, you can look for entrypoint at runtime :

```bash
gef➤  b *0x0
Breakpoint 2 at 0x0
Warning:
Cannot insert breakpoint 2.
Cannot access memory at address 0x0

gef➤  r
Starting program: .../Basic-ELF-x64.bin
Warning:
Cannot insert breakpoint 2.
Cannot access memory at address 0x0

gef➤  disass
Dump of assembler code for function _start:
=> 0x00007ffff7fce090 <+0>:     mov    rdi,rsp
   0x00007ffff7fce093 <+3>:     call   0x7ffff7fcee20 <_dl_start>
End of assembler dump.
gef➤  del 2
gef➤  b *0x00007ffff7fce090
Breakpoint 3 at 0x7ffff7fce090
gef➤  x/10i $rip
=> 0x7ffff7fce090 <_start>:     mov    rdi,rsp
   0x7ffff7fce093 <_start+3>:   call   0x7ffff7fcee20 <_dl_start>
   0x7ffff7fce098 <_dl_start_user>:     mov    r12,rax
   0x7ffff7fce09b <_dl_start_user+3>:   mov    eax,DWORD PTR [rip+0x2dc17]        # 0x7ffff7ffbcb8 <_dl_skip_args>
   0x7ffff7fce0a1 <_dl_start_user+9>:   pop    rdx
   0x7ffff7fce0a2 <_dl_start_user+10>:  lea    rsp,[rsp+rax*8]
   0x7ffff7fce0a6 <_dl_start_user+14>:  sub    edx,eax
   0x7ffff7fce0a8 <_dl_start_user+16>:  push   rdx
   0x7ffff7fce0a9 <_dl_start_user+17>:  mov    rsi,rdx
   0x7ffff7fce0ac <_dl_start_user+20>:  mov    r13,rsp
```

If you know that the `main` function will call `printf`, you can break at `printf` address.

```bash
gef➤  b *printf
gef➤ r
[...]
gef➤ c 
# break inside printf
gef➤ si
# get ouf of printf

# look for instructions before 'printf' call
# until you find the start of main
gef➤  x/100i $rip-0xA0
[...]
   0x5555555551cd:      push   rbp
   0x5555555551ce:      mov    rbp,rsp
   0x5555555551d1:      sub    rsp,0x50
[...]
   0x55555555524b:      call   0x5555555550c0 <printf@plt>
=> 0x555555555250:      mov    rax,QWORD PTR [rbp-0x50]
   0x555555555254:      add    rax,0x8
[...]
gef➤  b *0x5555555551cd # adress of main
```