---
title: Quadratic residue
description: Introduction to Quadratic residue in modular arithmetic.
---

# Quadractic residues

## Introduction

An integer `a` is a quadratic residue modulo `n`, if there exists an integer `x` such that : 

$$
x^2 \equiv a \pmod{n}
$$

## Legendre symbol

The **Legendre symbol** is a multiplicative function that returns (`p` must be an odd prime number):

- **1** : `a` is a quadratic residue and `a ≢ 0 mod p`.
- **-1** : `a` is a quadratic non-residue `mod p`.
- **0** : `a ≡ 0 mod p`

```python
>>> def legendre_symbol(a, p):
...     from Crypto.Util.number import isPrime
...     assert isPrime(p) and p % 2 == 1, "'p' must be a prime odd"
...     res = pow(a, (p - 1) // 2, p)
...     return res - p if res > 1 else res
...

>>> legendre_symbol(a=12, p=145)
1

>>> legendre_symbol(a=2, p=5)
-1
>>> 2 % 5 != 0
True

>>> legendre_symbol(a=5, p=5)
0
>>> 5 % 5 == 0
True
```

## Modular square root

### The modulus is congruent to 3 modulo 4

If :

$$
p \equiv 3 \pmod{4}
$$

So :

$$
x \equiv \pm a^{(p + 1) / 4} \pmod{p}
$$

Example :

$$
x^2 \equiv 4 \pmod{19}
$$

```python
# Check if a solution exists with legendre symbol
>>> legendre_symbol(4, 19) == 1
True

>>> 19 % 4 == 3
True

>>> pow(4, (19 + 1) // 4, 19)
17 # x = 17
>>> 17 ** 2 % 19 == 4
True
>>> (-17) ** 2 % 19 == 4
True
```

### The modulus is congruent to 5 modulo 8

If :

$$
p \equiv 5 \pmod{8}
$$

So :

$$
v = (2a)^{(p - 5) / 8} \pmod{p}
$$
$$
i = 2av^2 \pmod{p}
$$
$$
x \equiv \pm av(i - 1) \pmod{p}
$$

Example :

$$
x^2 \equiv 51 \pmod{85}
$$

```python
from Crypto.Util.number import isPrime


def legendre_symbol(a, p):
    res = pow(a, (p - 1) // 2, p)
    return res - p if res > 1 else res


def square_root_modulo(a, p):
    if isPrime(p) and p % 2 == 1:
        if legendre_symbol(a, p) == -1:
            return None, None

    if p % 4 == 3:
        x = pow(a, (p + 1) // 4, p)
        return -x, x

    if p % 8 == 5:
        v = pow(2 * a, (p - 5) // 8, p)
        i = 2 * a * v ** 2 % p
        x = a * v * (i -1) % p
        return -x, x
    return None, None


a = 51
p = 85
print(f"x^2 = {a} [{p}]") 
print(square_root_modulo(a, p))
```

Output :

```
x^2 = 51 [85]
(-34, 34)
```

### The modulus is a prime number

You can use the Tonelli-Shanks algorithm.

```python
def legendre(a, p):
    return pow(a, (p - 1) // 2, p)
 
def tonelli(n, p):
    assert legendre(n, p) == 1, "not a square (mod p)"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r

a, p = 48807038706356516327835928540, 588522524122640355249739913363 
print(f"x^2 = {a} [{p}]") 
print(tonelli(a, p))
```

Output :

```
x^2 = 48807038706356516327835928540 [588522524122640355249739913363]
2502859248593759290
```