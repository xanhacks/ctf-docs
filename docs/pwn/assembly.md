---
title: Introduction to x86 Assembly
description: Calling conventions, stacks, insctructions, ...
---

# Introduction to x86 Assembly
## Instructions

...

## Registers
...

## Stack

```assembly
ebp	; Pointer to the start of the current stack-frame.
esp ; Pointer to the end of the stack
```

## Functions

The function **prologue** is a few lines of code at the beginning of a function, which prepare the stack and registers for use within the function. Similarly, the function **epilogue** appears at the end of the function, and restores the stack and registers to the state they were in before the function was called.

> Source [Wikipedia](https://en.wikipedia.org/wiki/Function_prologue_and_epilogue).

### Prologue

**Goal :**
1. Pushes current base pointer onto the stack, so it can be restored later.
2. Assigns the value of base pointer to the address of stack pointer (which is pointed to the top of the stack) so that the base pointer will point to the top of the stack.
3. Moves the stack pointer further by decreasing or increasing its value, depending on whether the stack grows down or up. On x86, the stack pointer is decreased to make room for the function's local variables.

```assembly
push ebp
mov	ebp, esp
sub	esp, N
```

### Epilogue

**Goal :**
1. Drop the stack pointer to the current base pointer, so room reserved in the prologue for local variables is freed.
2. Pops the base pointer off the stack, so it is restored to its value before the prologue.
3. Returns to the calling function, by popping the previous frame's program counter off the stack and jumping to it.

```assembly
leave
ret
```

`leave` is a shortcut for :
```assembly
mov	esp, ebp
pop	ebp
```

## Calling conventions

### 64 bits

Arguments order : `rdi`, `rsi`, `rdx`, `rcx`, `r8` and `r9`.

!!! info
    If there are more than six parameters, then the program’s stack is used to pass in additional parameters to the function.

### 32 bits

The program’s stack is used to pass all the parameters to the function.

Example with a third arguments function :

```assembly
push <third_argument>
push <second_argument>
push <first_argument>
call func
```

