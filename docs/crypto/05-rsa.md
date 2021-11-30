---
title: RSA
description: Introduction to RSA.
---

# RSA

**RSA** (**Rivest–Shamir–Adleman**) is a public-key cryptosystem that is widely used for secure data transmission.

The strength of RSA relies on the fact that you need to factor `n` to obtain `d` and there is no known algorithm that can do that efficiently for large numbers.

## Introduction

RSA is an **asymmetric** cipher with a **public key** (n, e) and a **private key** (n, d).

- `p` and `q` two large random primes that validate the following equation :

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

!!! info
	Greatest common divisor (**GCD**) of two integers is the largest positive integer that divides each of the integers.

## Key generation

The keys for the RSA algorithm are generated in the following way:

- Choose two distinct prime numbers `p` and `q`.

For security purposes, the integers `p` and `q` should be chosen at random, and should be similar in magnitude but differ in length by a few digits to make factoring harder. Prime integers can be efficiently found using a primality test. `p` and `q` are kept secret.

- Compute n = pq.

3. Compute λ(n), where λ is Carmichael's totient function. Since n = pq, λ(n) = lcm(λ(p),λ(q)), and since p and q are prime, λ(p) = φ(p) = p − 1 and likewise λ(q) = q − 1. Hence λ(n) = lcm(p − 1, q − 1).
	λ(n) is kept secret.
	The lcm may be calculated through the Euclidean algorithm, since lcm(a,b) = |ab|/gcd(a,b).
4. Choose an integer e such that 1 < e < λ(n) and gcd(e, λ(n)) = 1; that is, e and λ(n) are coprime.
	e having a short bit-length and small Hamming weight results in more efficient encryption  – the most commonly chosen value for e is 216 + 1 = 65,537. The smallest (and fastest) possible value for e is 3, but such a small value for e has been shown to be less secure in some settings.[15]
	e is released as part of the public key.
5. Determine d as d ≡ e−1 (mod λ(n)); that is, d is the modular multiplicative inverse of e modulo λ(n).
	This means: solve for d the equation d⋅e ≡ 1 (mod λ(n)); d can be computed efficiently by using the Extended Euclidean algorithm, since, thanks to e and λ(n) being coprime, said equation is a form of Bézout's identity, where d is one of the coefficients.
	d is kept secret as the private key exponent.

## Encryption (public key)

- `c` : ciphertext (encrypted message, the result of calculation)
- `m` : cleartext (plain message to send)
- `e` : exponent (from public key)
- `n` : product of two large prime numbers (from public key)

$$
c = m^e [n]
$$

## Decryption (private key)

- `d` : exponent (from private key)

$$
m \equiv c^d [n]
$$

## Attacks on RSA

### Small factors

`d` is secret and can be calculated very easily if you know `φ(n)`.
 
 $$
\varphi(pq) = (p - 1)(q - 1)
$$
$$
n = p * q
$$

The security of RSA depends on the two factors `p` and `q`. You can bruteforce this two factors if `n` is small (< 256 bits) or use a well-known [database](http://factordb.com/).

## References

- https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-1/
- https://en.wikipedia.org/wiki/RSA_(cryptosystem)