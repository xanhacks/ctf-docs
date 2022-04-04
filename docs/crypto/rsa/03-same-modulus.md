---
title: Same modulus - Bezout identity
description: RSA - Attack using same modulus.
---

# Using same modulus (n)

## Introduction

Alice and Bob encrypt the same message `m` (`c1` for Alice and `c2` for Bob).

The attacker intercepts the two encrypted messages `c1` and `c2` and the two public keys of Alice and Bob. Let's try to find the original message.

Alice : `pubKey1(n, e1)` and `privKey1(n, d1)`<br>
Bob : `pubKey2(n, e2)` and `privKey2(n, d2)`

### Prerequisites

- We have `c1` and `c2` which are two encrypted messages from `pubKey1` and `pubKey2`.
- `pubKey1` and `pubKey2` have the same modulus `n` (`n1` = `n2`), however `e1`, `e2`, `d1` and `d2` can differ.
- `c1` and `c2` comes from the same cleartext `m`.

### Maths

Basic RSA :

$$
c_{1} \equiv m^{e_{1}} [n]
$$
$$
c_{2} \equiv m^{e_{2}} [n]
$$

Bezout's identity :

$$
gcd(e_{1}, e_{2}) == 1
$$
$$
e_{1} * u + e_{2} * v = 1
$$

Try to make something to the power of `e1 * u + e2 * v` :

$$
c_{1}^u \equiv (m^{ e_{1} })^u \equiv m^{ {e_{1} } \times u} [n]
$$

$$
c_{2}^v \equiv (m^{ e_{2} })^v \equiv m^{ {e_{2} } \times v} [n]
$$

$$
m^{ {e_{1}} \times u } \times m^{ {e_{2} } \times v } \equiv m^{ {e_{1}} \times u + {e_{2}} \times v} \equiv m^1 \equiv m[n]
$$

Conclusion :

$$
c_{1}^u \times c_{2}^v \equiv m[n]
$$

## Example

### Encryption using same modulus

Source code :

```python
from Crypto.Util.number import bytes_to_long

m = bytes_to_long(b"S3CR3T!!!")
print("Plaintext (hex) =", m)

# Alice (1) and Bob (2)
n = 262680224351198943558562962102931091165978396557063906345939
e_1, e_2 = 65537, 34352

c_1 = pow(m, e_1, n)
c_2 = pow(m, e_2, n)
print("Encrypted (c1) =", c_1)
print("Encrypted (c2) =", c_2)
```

Output :

```
Plaintext (hex) = 1534773644617674989857
Encrypted (c1) = 188774664250657377040945189723460943665792254753522168336372
Encrypted (c2) = 183884636824805796552562064524263351724174474778356736863748
```

### Decryption with

- `pubKey1(n, e1)` and `pubKey2(n, e2)`
- `c1` and `c2`

Source code :

```python
from Crypto.Util.number import long_to_bytes

def bezout(a, b):
    if b == 0:
        return 1, 0
    else:
        q, r = a // b, a % b
        x, y = bezout(b, r)
        return y, x - q * y

u, v = bezout(e_1, e_2)
assert e_1 * u + e_2 * v == 1

cleartext = pow(c_1, u, n) * pow(c_2, v, n) % n
print("Cleartext :", long_to_bytes(cleartext).decode())
```

Output :

```
Cleartext : S3CR3T!!!
```