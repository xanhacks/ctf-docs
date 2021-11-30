---
title: Introduction to cryptography
description: Introduction to cryptography.
---

# Cryptography

## Introduction

**Cryptography**, or **cryptology**, is the practice and study of techniques for secure communication in the presence of adversarial behavior. More generally, cryptography is about constructing and analyzing protocols that prevent third parties or the public from reading private messages; various aspects in information security such as data **confidentiality**, data **integrity**, **authentication**, and **non-repudiation** are central to modern cryptography.

- **Confidentiality :** Limits access or places restrictions on certain types of information.
- **Integrity :** Assurance of, data accuracy and consistency over its entire life-cycle.
- **Authentication :** The act of proving an assertion, such as the identity of a computer system user. In contrast with identification, the act of indicating a person or thing's identity, authentication is the process of verifying that identity.
- **Non-repudiation :** Non-repudiation refers to a situation where a statement's author cannot successfully dispute its authorship or the validity of an associated contract.

> Source [Wikipedia](https://en.wikipedia.org/wiki/Cryptography).

## Symmetric cryptography

**Symmetric-key cryptography** refers to encryption methods in which both the **sender and receiver share the same key** (or, less commonly, in which their keys are different, but related in an easily computable way).

Symmetric-key cryptosystems use the **same key for encryption and decryption** of a message, although a message or group of messages can have a different key than others. A significant disadvantage of symmetric ciphers is the **key management necessary to use them securely**.

## Asymetric cryptography

*In a groundbreaking 1976 paper, Whitfield Diffie and Martin Hellman proposed the notion of public-key.*

**Public-key** (also, more generally, called **asymmetric key**) **cryptography** in which two different but mathematically related keys are used — a **public key and a private key**. A public key system is so constructed that calculation of one key (the 'private key') is computationally infeasible from the other (the 'public key'), even though they are necessarily related.

The public key may be freely distributed, while its paired private key must remain secret.

- **Public key** => encryption.
- **Private key** => decryption. 

Public-key algorithms are most often based on the computational complexity of "hard" problems, often from number theory. For example, the hardness of **RSA** is related to the **integer factorization** problem, while **Diffie–Hellman** and **DSA** are related to the **discrete logarithm** problem. 