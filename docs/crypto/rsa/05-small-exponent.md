---
title: Very small exponent
description: RSA - Attack using small exponent
---

# Attack on a very small public exponent (e)

## Introduction

For encryption, `rsa` uses :

$$
c = m^e [n]
$$

If `e` is very small, you can do a root of n-th degree on `c` to find `m`.

## Example

> Write-up for the challenge `BreizhCTF2023` from `BreizhCTF 2022`.

We have two files, a `ciphertext` and a `public key`.

```bash
$ ls
position.enc  pubkey.pem
$ base64 -w 0 position.enc
BHUhTDufM2B4OmG88bkKeydszUC70enM+3TqBuuGRUw/hDHlnLCxavTP66ZeB1xGoikaahuhVOoPjLPeOtyBnu33s0mJCuwNVLJk2AAOiodduWDBakhl%
$ cat pubkey.pem
-----BEGIN PUBLIC KEY-----
MIIBHzANBgkqhkiG9w0BAQEFAAOCAQwAMIIBBwKCAQB58ZBK8WsDP7sySY3CoyK9
Z4W2E3/nME2zePjXD28L9WcBzGMucmSZBNsC1fwxzrHaIPZ9EgGfAwyrTWFoprWb
03jf9NzTh38Y9xQ1l05L7J1RbW87v2qvNAvi94y0PJ2n8nE6oeRDfBLWCIzb/Bmv
QX5LCk6GwMW4az3H3JEH3RT1feLFGjnxDDysrPRmVkEr6KiewmSIW43Djdg2+RMR
zvLI/o79iPmYO2fA2qGf73OlrcGwDq2VeA5v49ytxbCIbb50oj1JMftCNLNm+Q03
urdgAvcijncqriBZyHs7/2KdS+8gyXnOPH+1MLnvSCJu6WUqkKGf284DzTtiDE7t
AgED
-----END PUBLIC KEY-----
```

The public exponent is 3, to find the cleartext message we can do the third root of the ciphertext.

Source code :

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long 
from gmpy2 import iroot
from base64 import b64decode


pub_key = """-----BEGIN PUBLIC KEY-----
MIIBHzANBgkqhkiG9w0BAQEFAAOCAQwAMIIBBwKCAQB58ZBK8WsDP7sySY3CoyK9
Z4W2E3/nME2zePjXD28L9WcBzGMucmSZBNsC1fwxzrHaIPZ9EgGfAwyrTWFoprWb
03jf9NzTh38Y9xQ1l05L7J1RbW87v2qvNAvi94y0PJ2n8nE6oeRDfBLWCIzb/Bmv
QX5LCk6GwMW4az3H3JEH3RT1feLFGjnxDDysrPRmVkEr6KiewmSIW43Djdg2+RMR
zvLI/o79iPmYO2fA2qGf73OlrcGwDq2VeA5v49ytxbCIbb50oj1JMftCNLNm+Q03
urdgAvcijncqriBZyHs7/2KdS+8gyXnOPH+1MLnvSCJu6WUqkKGf284DzTtiDE7t
AgED
-----END PUBLIC KEY-----"""
ciphertext = b64decode("BHUhTDufM2B4OmG88bkKeydszUC70enM+3TqBuuGRUw/hDHlnLCxavTP66ZeB1xGoikaahuhVOoPjLPeOtyBnu33s0mJCuwNVLJk2AAOiodduWDBakhl")

rsa_pub_key = RSA.import_key(pub_key)
print("e =", rsa_pub_key.e)

c = bytes_to_long(ciphertext)
print("c =", c)

m, success = iroot(c, rsa_pub_key.e)
if success:
    print("m =", long_to_bytes(m))
```

Output :

```
e = 3
c = 5724429365887192937975880152728551254971364525753671743693147523302441587707804097718439038173546355026701325414799056205074425733698744528930791075004105312923906122185518441456605039101517459937804505729125
m = b'BZHCTF{sur3m3nt_3n_fr4nc3_!!}'
```