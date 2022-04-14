---
title: Introduction
description: Introduction to modular arithmetic
---

# Introduction

## Congruence

Congruence modulo `n` is a congruence relation, meaning that it is an equivalence relation that is compatible with the operations of addition, subtraction, and multiplication. Congruence modulo `n` is denoted :

$$
a \equiv b [n]
$$

The congruence relation may be rewritten as (k ∈ ℤ):

$$
a = b + k \times n
$$

> More information on [Wikipedia.org](https://en.wikipedia.org/wiki/Modular_arithmetic).

### Practical example

$$
12 \equiv 3 [9]
$$

$$
21 \equiv 3 [9]
$$

$$
-6 \equiv 3 [9]
$$

Because :

$$
12 = 3 + 1 \times 9
$$

$$
21 = 3 + 2 \times 9
$$

$$
-6 = 3 - 1 \times 9
$$

In python, you can use the `%` symbol.

```python
>>> 12 % 9 == 21 % 9 == -6 % 9 == 3
True
```

## Addition and substraction

$$
12 \equiv 3 [9]
$$

You can add or substract any number. Example with `+3` and `-5` :

$$
15 \equiv 6 [9]
$$

$$
7 \equiv -2 [9] 
$$

The last equivalence is equals too (sometimes it's easier to deal with positive numbers):

$$
7 \equiv 7 [9]
$$

## Multiplication

$$
12 \equiv 3 [9]
$$

You can multiply with any number € Z (you cannot make a division, ex: multiply by `1/2`).

**1.** Example with `* 3` :

$$
36 \equiv 9 [9]
$$

Which is equals to :

$$
0 \equiv 0 [9]
$$

$$
36 - 9 * 4 = 9 - 9 * 1
$$

**2.** Example with `* -5` :

$$
-60 \equiv -15 [9]
$$

Which is equals to :

$$
3 \equiv 3 [9]
$$

$$
-60 + 9 * 7 = -15 + 2 * 9
$$

## Divsion (warning)

You can't divise a equivalence relation.

$$
12 \equiv 2 [10]
$$

Divide by `2` :

$$
6 \not\equiv 1 [10]
$$

## Modular inverse

The multiplicative inverse :

$$
x * a \equiv 1 [n]
$$

$$
x * a + n * k = 1
$$

$$
x \equiv a^{-1} [n]
$$

It may be efficiently computed by solving *Bézout's equation* `a * x + n * k = 1` using the Extended Euclidean algorithm (used to compute the GCD - Greatest common divisor).

### Practical example

$$
5 \times x \equiv 1 [34]
$$

$$
5 \times x = 1 + 34 \times k
$$

$$
1 = 5 \times 7 - 34
$$


You can use the modular inverse in Python :

$$
5 \equiv x^{-1} [34]
$$

```python
>>> pow(5, -1, 34)
7
>>> from Crypto.Util.number import inverse
>>> inverse(5, 34)
7
>>> from gmpy2 import invert
>>> invert(5, 34)
mpz(7)
```