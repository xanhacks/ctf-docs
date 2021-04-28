---
title: Pwntools cheatsheets
description: Pwntools cheatsheets with examples.
---

# Pwntools cheatsheets

![pwntools logo](https://github.com/Gallopsled/pwntools/blob/stable/docs/source/logo.png?raw=true)

Pwntools is a CTF framework and exploit development library. Written in Python, it is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible.

- [Github](https://github.com/Gallopsled/pwntools)
- [Official docs](https://docs.pwntools.com/en/latest/)

## Context

``` python
context(arch="arm", os="linux", endian="big", log_level="debug")

arch : "aarch64", "arm", "i386", "amd64", "mips64", ... (default: "i386")
bits : "32", "64" (default: "32")
endian : "big", "little" (default: "little")
log_file : File to send all of the logging output into.
log_level : "debug", "info", "warn", "error" (default: "info")
signed : "signed", "unsigned" (default: "unsigned")
terminal : "x-terminal-emulator", "tmux", ...
timeout : Default timeout for tube operations.
```

## Process / Remote

``` python
# Local
p = process("./pwn")

# Remote
r = remote("ftp.example.com", 21)
r = remote("ctf.example.com", 1337)

# SSH
s = ssh(host="ctf.example.com", port=22,
	user="ssh_username", password="ssh_password")
sh = s.process('/challenges/vuln')

# USB
io = serialtube('/dev/ttyUSB0', baudrate=115200)
```

## Receive / Send

``` python
p = process("./pwn")

p.recv(numb = 4096)
p.recvline()
p.recvlines(numlines)
p.recvuntil(delim)

p.send(data)
p.sendline(line)
p.sendlineafter(delim, data)

p.interactive()
```

## Listen

``` python
l = listen(port=1337, bindaddr = "0.0.0.0")
c = l.wait_for_connection()
c.recv()
```

## ELF

``` python
>>> e = ELF('/bin/cat')
>>> print hex(e.address) 
0x400000
>>> print hex(e.symbols['write']) 
0x401680
>>> print hex(e.got['write']) 
0x60b070
>>> print hex(e.plt['write']) 
0x401680
>>> e.address = 0x0
>>> print hex(e.symbols['write']) 
0x1680
```

``` python
>>> e = ELF('/bin/cat')
>>> e.read(e.address+1, 3)
'ELF'
>>> e.asm(e.address, 'ret')
>>> e.save('/tmp/quiet-cat')
>>> disasm(file('/tmp/quiet-cat','rb').read(1))
```

``` python
>>> from pwn import ELF
>>> e = ELF('/bin/bash')
...
>>> for address in e.search(b'/bin/sh\x00'):
...     print(hex(address))
... 
0x31a62
0x31afc
```

## ROP

``` python
>>> from pwn import ELF, ROP
>>> elf = ELF('/bin/bash')
>>> rop = ROP(elf)
[*] Loading gadgets for '/bin/bash'
>>> rop.rbx
Gadget(0x2ccd7, ['pop rbx', 'ret'], ['rbx'], 0x8)

>>> for key in rop.gadgets:
...     print(rop.gadgets[key])
... 
Gadget(0x3e7e5, ['add esp, 0x10', 'pop rbx', 'pop rbp', 'pop r12', 'ret'], ['rbx', 'rbp', 'r12'], 0x20)                                                                          
Gadget(0x2ccd4, ['add esp, 0x10', 'pop rbx', 'ret'], ['rbx'], 0x18)                                                                                                              
Gadget(0x2cfee, ['add esp, 0x110', 'pop rbx', 'ret'], ['rbx'], 0x118)         
[...]
```


## gdb

``` python
p = process('./helloworld')
gdb.attach(p, execute="b *0x4000000")

gdb.attach(('127.0.0.1', 8765)) # attach to remote gdb server

s = ssh(host='rpi', user='pi')
conn = s.process('/tmp/helloworld')
gdb.attach(conn) # start gdb on remote server via ssh
```

## Shellcraft

``` python
asm = shellcraft.sh()       # Generate shellcode.
asm = shellcraft.cat(path) 	# Generate assembly that dumps the file at path.
asm = shellcraft.exit(code) # Generate assembly that exits with code code.
asm = shellcraft.nop()      # Generate assembly for a single-byte no-op.
bin = asm(asm)              # Assembles asm into a binary snippet.
asm = disasm(bin)           # Disassembles bin into assembly.
```

## CLI

``` shell
$ pwn -h
usage: pwn [-h]
           {asm,checksec,constgrep,cyclic,debug,disasm,disablenx,elfdiff,elfpatch,errno,hex,phd,pwnstrip,scramble,shellcraft,template,unhex,update,version}
           ...

Pwntools Command-line Interface

positional arguments:
  {asm,checksec,constgrep,cyclic,debug,disasm,disablenx,elfdiff,elfpatch,errno,hex,phd,pwnstrip,scramble,shellcraft,template,unhex,update,version}
    asm                 Assemble shellcode into bytes
    checksec            Check binary security settings
    constgrep           Looking up constants from header files. Example:
                        constgrep -c freebsd -m ^PROT_ '3 + 4'
    cyclic              Cyclic pattern creator/finder
    debug               Debug a binary in GDB
    disasm              Disassemble bytes into text format
    disablenx           Disable NX for an ELF binary
    elfdiff             Compare two ELF files
    elfpatch            Patch an ELF file
    errno               Prints out error messages
    hex                 Hex-encodes data provided on the command line or stdin
    phd                 Pwnlib HexDump
    pwnstrip            Strip binaries for CTF usage
    scramble            Shellcode encoder
    shellcraft          Microwave shellcode -- Easy, fast and delicious
    template            Generate an exploit template
    unhex               Decodes hex-encoded data provided on the command line
                        or via stdin.
    update              Check for pwntools updates
    version             Pwntools version

optional arguments:
  -h, --help            show this help message and exit
```

``` shell
$ pwn checksec /bin/ls
[*] '/bin/ls'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled

$ pwn elfdiff <file1> <file2>

$ pwn hex "toto"
746f746f

$ pwn asm "add eax, 1"
83c001
$ pwn disasm "83c001"
   0:    83 c0 01                 add    eax,  0x1

$ pwn cyclic 30
aaaabaaacaaadaaaeaaafaaagaaaha
$ pwn cyclic -l "caaa" # Search for pattern offset
8
$ python3 -c "print('aaaabaaacaaadaaaeaaafaaagaaaha'[8:12])"
caaa
```

### References

- [http://blog.eadom.net/uncategorized/pwntools-quick-reference-guide/](http://blog.eadom.net/uncategorized/pwntools-quick-reference-guide/)
- [https://xavierholt.github.io/cheatsheets/pwntools.html](https://xavierholt.github.io/cheatsheets/pwntools.html)
- [https://book.hacktricks.xyz/exploiting/tools/pwntools](https://book.hacktricks.xyz/exploiting/tools/pwntools)
- [https://github.com/Gallopsled/pwntools-tutorial](https://github.com/Gallopsled/pwntools-tutorial)
