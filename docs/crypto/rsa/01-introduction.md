---
title: Introduction to RSA
description: Introduction to RSA.
---

# RSA

**RSA** (**Rivest–Shamir–Adleman**) is a public-key cryptosystem that is widely used for secure data transmission.

The strength of RSA relies on the fact that you need to factor `n` to obtain `d` and there is no known algorithm that can do that efficiently for large numbers.

## Introduction

RSA is an **asymmetric** cipher. The **public key** contains `n` and `e`, `pubKey(n, e)`, and the **private key** contains `n` and `d`, `privKey(n, d)`.

- `p` and `q` are two large random primes that validate the following equation :

$$
n = p * q
$$

-  Euler’s totient function :
$$
\varphi(n)=(p - 1)(q - 1)
$$

- `e` (public key exponent) must verify :

$$
1 < e < \varphi(n)
$$
$$
gcd(e, \varphi(n)) = 1
$$
$$
d * e \equiv 1 [\varphi(n))]
$$
$$
d \equiv invmod(e) [\varphi(n))]
$$

- `m` (plaintext) must verify (otherwise it will be trim by the modulus) :

$$
m < n
$$

!!! info
	Greatest common divisor (**GCD**) of two integers is the largest positive integer that divides each of the integers.

## Encryption (public key)

- `c` : ciphertext (encrypted message, the result of calculation)
- `m` : cleartext (plain message to send)
- `e` : exponent (from public key)
- `n` : product of two large prime numbers (from public key)

$$
c = m^e [n]
$$

## Decryption (private key)

- `c` : ciphertext (encrypted message, the result of calculation)
- `m` : cleartext (plain message to send)
- `n` : product of two large prime numbers (from public key)
- `d` : exponent (from private key)

$$
m \equiv c^d [n]
$$

## References

- https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-1/
- https://en.wikipedia.org/wiki/RSA_(cryptosystem)