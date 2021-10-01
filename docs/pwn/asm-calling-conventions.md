---
title: Assembly Calling Conventions
description: Assembly calling conventions in 64 bits and 32 bits architecture.
---

# Assembly Calling Conventions

## 64 bits

Arguments order : `rdi`, `rsi`, `rdx`, `rcx`, `r8` and `r9`.

!!! info
    If there are more than six parameters, then the program’s stack is used to pass in additional parameters to the function.

## 32 bits

The program’s stack is used to pass all the parameters to the function.

Example with a third arguments function :

```asm
push <third_argument>
push <second_argument>
push <first_argument>
call func
```