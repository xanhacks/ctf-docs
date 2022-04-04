---
title: Same modulus - k approximation
description: RSA - Using same modulus.
---

# Same modulus - k approximation

## Introduction

Find the private key of another user, if you have a private and a public key with the same modulus than him.

### Prerequisites

- `pubKey1(n, e1)` and `privKey1(n, d1)`
- `pubKey2(n, e2)`

The goal is to find : `privKey2(n, d2)`

### Maths

$$e * d \equiv 1 [\phi(n)]$$

So, with `𝑘 ∈ ℤ` :

$$
e * d - 1 = k * \phi(n)
$$

If you know `k`, you can calcultate `phi(n)` :

$$
\phi(n) = \frac{(e * d - 1)}{k}
$$

To calculate `k`, you can approximate :

$$
\phi(n) \approx n
$$
$$
(p - 1) * (q - 1) \approx p * q
$$

So :

$$
k = \frac{(e * d - 1)}{\phi(n)}
$$

$$
k \approx \frac{(e * d - 1)}{n}
$$

Now, you can come back and calculate `phi(n)` :

$$
\phi(n) = \frac{(e * d - 1)}{k}
$$

You can verify your calcul by using this formula :

$$
e * d - 1 = k * \phi(n)
$$

If the result is not correct, you need to add 1 to `k` and retry it. It is because of the approximation.

## Example

Source code :

```python
e_1 = 0x10001
e_2 = 491
n = 211231128460542766584141422369
d_1 = 6043278848032645765057870973

tmp_k = (d_1 * e_1 - 1) // n
tmp_phi_n = (d_1 * e_1 - 1) // tmp_k

while tmp_phi_n * tmp_k != (e_1 * d_1) - 1:
    tmp_k += 1
    tmp_phi_n = (d_1 * e_1 - 1) // tmp_k

phi_n = tmp_phi_n
print("phi(n) :", phi_n)
d_2 = pow(e_2, -1, phi_n)
print("d_2 :", d_2)
```

Output :

```
phi(n) : 211231128460541602935785434644
d_2 : 84750574962783494456924094959
```