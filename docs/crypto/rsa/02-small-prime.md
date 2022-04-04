---
title: Small primes
description: RSA - Attack on small prime.
---

# Attack on small primes (p & q)

## Introduction

`d` (private exponent) can be calculated very easily if you know `φ(n)`. To calculate `φ(n)`, you need to find the two prime factors `p` and `q`.

$$
n = p * q
$$
$$
\varphi(n) = \varphi(pq) = (p - 1)(q - 1)
$$
$$
d * e \equiv 1 [\varphi(n))]
$$

If `n` is small (< 256 bits) you can bruteforce `p` and `q`, or you can use a well-known database like [factordb](http://factordb.com/) which contains a lot of factors.

## Example

The victim generates a `pubKey(n, e)` and a `privKey(n, d)`, then encrypt a secret message.

Source code :

```python
from binascii import hexlify

m = int(hexlify(b"s3cr3t"), 16)

p, q = 5484631, 50601277
n = p * q
e = 65537

c = pow(m, e, n)

print("m =", m)
print("n =", n)
print("Encrypted =", c)
```

Output :

```
m = 126664548954996
n = 277529332473787
Encrypted = 189766109539025
```

---

The attacker only have access to the victim's `pubKey(n, e)`. He will try to recover the victim's `privKey(n, d)` by factoring `n` with the help of `factordb`.

Source code :

```python
from Crypto.Util.number import long_to_bytes
from factordb.factordb import FactorDB
# python3 -m pip install pycryptodome factordb-python


f = FactorDB(n)
f.connect()
factors = f.get_factor_from_api()

p, q = int(factors[0][0]), int(factors[1][0])
phi_n = (p - 1) * (q - 1)
d = pow(e, -1, phi_n)
m = pow(c, d, n)

print("p =", p, ", q =", q)
print("phi(n) =", phi_n)
print("d =", d)
print("m =", long_to_bytes(m))
```

Output :

```
p = 5484631 , q = 50601277
phi(n) = 277529276387880
d = 173465855145593
m = b's3cr3t'
```

The attacker successfully recovers the `privKey(n, d)` and the plaintext message.