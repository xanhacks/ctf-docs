# Pwntools

![pwntools logo](https://github.com/Gallopsled/pwntools/blob/stable/docs/source/logo.png?raw=true)

Pwntools is a CTF framework and exploit development library. Written in Python, it is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible.

- [Github](https://github.com/Gallopsled/pwntools)
- [Official docs](https://docs.pwntools.com/en/latest/)

## Basic

``` python
context(arch="arm", os="linux", endian="big", log_level="debug")
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
```

## Receive / Send

``` python
p = process("./pwn")

p.recv(numb = 4096, timeout = default)
p.recvuntil(delims, drop=False, timeout = default)
p.recvn(numb, timeout = default)
p.recvlines(numlines, keepends = False, timeout = default)
p.recvline(keepends = True, timeout = default)
p.recvregex(regex, exact = False, timeout = default)
p.recvrepeat(timeout = default)  # Receives data until a timeout or EOF is reached.
p.recvall(self, timeout=Timeout.forever)  # Receives data until EOF is reached.
p.send(data)
p.sendline(line)
p.sendlineafter(pattern, data)
p.interactive()
```

## Listen

``` python
l = listen(port=1337, bindaddr = "0.0.0.0")
c = l.wait_for_connection()
c.recv()
```

### References

- [http://blog.eadom.net/uncategorized/pwntools-quick-reference-guide/](http://blog.eadom.net/uncategorized/pwntools-quick-reference-guide/)
