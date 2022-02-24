---
title: Introduction
description: Introduction to shellcode
---

# Introduction to shellcode

A **shellcode** is just a small piece of code that spawns a shell (ex: `/bin/sh`).

## Usage

In binary exploitation, if you put your shellcode inside an executable memory space, then jump to it. You can spawn a shell on the victim machine.

## Types

- **Local** : Spawn a shell on the local machine.
- **Remote** : Spawn a shell over TCP/UDP (reverse or bind shell).
- **Staged** : 2 parts (dropper + actual shellcode)
- **Egg-hunt** : Place an *egg* (unique value) just before your shellcode. Then, look for this *egg* inside the process's address space to find your shellcode address (Very usefull when you can't determine where your shellcode will be in memory).
- **Omelette** : Similar to _egg-hunt_ shellcode, but looks for multiple blocks (_eggs_) and recombines them into one larger block (the _omelette_) that is subsequently executed.

## Encoding

You can use shellcode encoding for multiple purposes :

- bypass badchars (null-free, alphanumeric, ...)
- AV evasion
- reduce code size
- ...

## References

- [Wikipedia - Shellcode](https://en.wikipedia.org/wiki/Shellcode)
- [AnubisSec - Egghunter Shellcode](https://anubissec.github.io/Egghunter-Shellcode/)

