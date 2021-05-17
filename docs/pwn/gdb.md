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

```shell
gef➤  r <<< $(python2 -c "print '\xb2\x91\x04\x08'")
```
