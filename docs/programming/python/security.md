---
title: Security
description: Security warning in Python
---

# Security warning in Python

## python2 input eval

The input() function in Python 2.x evaluates things before returning.

### RCE (Remote Code Execution)

```python
>>> input("What's your name ? ")
What's your name ? __import__("os").system("id")
uid=1000(xanhacks) gid=1000(xanhacks) groups=1000(xanhacks),995(audio),998(wheel)
0
```

### Bypass check

```python
>>> password = "p@ssw0rd"
>>> value = input("What's is the password ? ")
What's is the password ? password
>>> password == value
True
>>> password
'p@ssw0rd'
>>> value
'p@ssw0rd'
```

### Mitigation using raw_input

```python
>>> password = "p@ssw0rd"
>>> value = raw_input("What's is the password ? ")
What's is the password ? password
>>> password == value
False
>>> password
'p@ssw0rd'
>>> value
'password'
```
