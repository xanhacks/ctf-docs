---
title: Hook functions
description: How to hook functions to improve debugging.
---

# Hook functions

## ltrace / strace

- `ltrace` - A library call tracer
- `strace` - Trace system calls and signals

## Using LD_PRELOAD

Hook two functions :

- `ptrace` : Always return 0 (no debugger present).
- `strcmp` : String are always equals.

```c
#include <stdio.h>


long ptrace(int request, unsigned int pid, void *addr, void *data) {
       printf("\n[*] call ptrace(%d, %u, %x, %x);\n", request, pid, addr, data);
       return 0;
}

int strcmp(const char *s1, const char *s2) {
    printf("\n[*] call strcmp(%s, %s);\n", s1, s2);
    return 0;
}
```

Compile and run it :

```
$ gcc preload.c -m32 -shared -fPIC -o preload.so
$ LD_PRELOAD=./preload.so ./binary
[*] call ptrace(0, 0, 1, 0);
Enter a password : toto

[*] call strcmp(toto, Password123);

Authentication successful !
```