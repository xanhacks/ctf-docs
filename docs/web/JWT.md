---
title: JWT Attacks
description: JWT Attacks cheatsheet
---

# JWT Attacks

## Definition

JSON Web Token (JWT) is a standard for representing claims securely between two parties. JWTs are commonly used as a means of authenticating users and transmitting information between parties in the form of a digitally signed and encoded JSON object.

There are several potential attack vectors associated with JWT, including:

1. Tampering with the payload: An attacker may try to modify the contents of the JWT payload to gain unauthorized access to protected resources or to perform actions that the user did not authorize.
2. Replay attacks: An attacker may try to reuse a previously issued JWT to gain unauthorized access to protected resources. To protect against replay attacks, JWTs should be issued with a short expiration time and should include a unique nonce (a random value that is used once) to prevent reuse.
3. Signature forging: An attacker may try to forge the signature on a JWT in order to gain unauthorized access to protected resources. To protect against this type of attack, JWTs should be signed using a secure signing algorithm and key.
4. Weak keys: If an attacker is able to guess or obtain the key used to sign a JWT, they may be able to forge the signature and gain unauthorized access to protected resources. To protect against this type of attack, it is important to use strong keys and to keep them secure.
5. Token leakage: If a JWT is leaked or stolen, an attacker may be able to gain unauthorized access to the protected resources. To protect against this type of attack, it is important to transmit JWTs securely and to store them in a secure manner.

To protect against these types of attacks, it is important to implement JWT in a secure manner and to follow best practices for generating, signing, and validating JWTs.

## Attacks

- `alg: none`
- Weak H256 secret `john jwt.out --wordlist=jwt.secrets.list` or `hashcat -a 0 -m 16500 <jwt> <wordlist>`
- Use `jwk` header to generate public key and sign token with it
- Use `kid` header to `../../../../dev/null` and sign with null byte b64 key `AA==`.
- SQL Injeciton in `kid` parameter.