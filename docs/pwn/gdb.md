---
title: gdb cheatsheet
description: gdb cheatsheet with examples.
---

# gdb cheatsheet

**gdb** (The GNU Debugger) allows you to debug your program, it can be very usefull to check if your exploit is working as expected.

## gdb add-ons

I recommend you to use one of the following gdb plugins, it will simplify your debugging process by adding new functions and readability to **gdb**.

- [gef](https://github.com/hugsy/gef)
- [pwndbg](https://github.com/pwndbg/pwndbg)
- [peda](https://github.com/longld/peda)

## Cheatsheets

### Stdin

```bash
gef➤  r <<< $(python2 -c "print '\xb2\x91\x04\x08'")

or

gef➤  r < payload.txt
```

### Breakpoints

```bash
gef➤  b *main
Breakpoint 1 at 0x1139
gef➤  b *main+2
Breakpoint 2 at 0x113b
gef➤  info b
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x0000000000001139 <main>
2       breakpoint     keep y   0x000000000000113b <main+2>
gef➤  disable 2
gef➤  info b
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x0000000000001139 <main>
2       breakpoint     keep n   0x000000000000113b <main+2>
gef➤  del 1
gef➤  info b
Num     Type           Disp Enb Address            What
2       breakpoint     keep n   0x000000000000113b <main+2>
```

### Navigation

```bash
gef➤ si # Step one instruction.
gef➤ ni # Step one instruction, but if it is a function call, proceed until the function returns.
gef➤ c # or 'continue', run the programm normally until we hit a breakpoint.
```

### Printing

`x[/Nuf] expr` : examine memory.

`N` : count of how many units to display.

`u` : unit size; one of : `b` individual bytes, `h` halfwords (two bytes), `w` words (four bytes), `g` giant words (eight bytes)

`f` : printing format, `s` null terminated string, `i` machine instructions.

```bash
gef➤  x 0x55555555513d
0x55555555513d <main+4>:        0xc0058d48
gef➤  x/3 0x55555555513d
0x55555555513d <main+4>:        0xc0058d48      0x4800000e      0xe4e8c789
gef➤  x/3b 0x55555555513d
0x55555555513d <main+4>:        0x48    0x8d    0x05
```



### Heap

```bash
gef➤  heap
[!] Syntax
heap (chunk|chunks|bins|arenas)
gef➤  heap chunks
Chunk(addr=0x603010, size=0x290, flags=PREV_INUSE)
    [0x0000000000603010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x6032a0, size=0x410, flags=PREV_INUSE)
    [0x00000000006032a0     74 6f 74 6f 0a 0a 00 00 00 00 00 00 00 00 00 00    toto............]
Chunk(addr=0x6036b0, size=0x30, flags=PREV_INUSE)
    [0x00000000006036b0     e0 36 60 00 00 00 00 00 00 00 00 00 00 00 00 00    .6`.............]
Chunk(addr=0x6036e0, size=0x20, flags=PREV_INUSE)
    [0x00000000006036e0     74 6f 74 6f 00 00 00 00 00 00 00 00 00 00 00 00    toto............]
- Chunk(addr=0x603700, size=0x20910, flags=PREV_INUSE)  ←  top chunk
```