---
title: Introduction to Diffie-Hellman
description: Introduction to Diffie-Hellman.
---

# Diffie-Hellman

## Introduction

The **Diffie–Hellman** key exchange method allows two parties that have no prior knowledge of each other to jointly **establish a shared secret key over an insecure channel**. This key can then be used to encrypt subsequent communications using a symmetric-key cipher.

## Variables

Public elements :

- `p` : multiplicative group of integers modulo `p`, where `p` is prime.
- `g` : a primitive root modulo `p`
- `A` & `B` : Public calculation

Private elements :

- `a` & `b` : Two random big numbers.
- `s` : Final shared secret.

## Maths

$$
A \equiv g^a [p]
$$
$$
B \equiv g^b [p]
$$
$$
s \equiv A^{b} \equiv B^{a} \equiv g^{a^{b}} \equiv g^{b^{a}} \equiv g^{a+b} [p]
$$
$$
a \equiv \text{discrete_log}(p, B, g)
$$
$$
b \equiv \text{discrete_log}(p, A, g)
$$

## Exchange

`K` is the final secret :

![Exchange protocol](https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fi.pinimg.com%2Foriginals%2Fe2%2F7d%2F87%2Fe27d87413aa03a2cf73f542bdcf02184.png&f=1&nofb=1)