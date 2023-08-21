---
title: AES - Padding oracle
description: AES - Padding oracle 
---

## Introduction

AES typically employs block encryption. When the plaintext length is not a multiple of the block size, padding is added to complete the block.

Example of padding:

```python
>>> from Crypto.Util.Padding import pad
>>> pad(b"A"*10, 16)
b'AAAAAAAAAA\x06\x06\x06\x06\x06\x06'
>>> pad(b"A"*11, 16)
b'AAAAAAAAAAA\x05\x05\x05\x05\x05'
>>> pad(b"A"*12, 16)
b'AAAAAAAAAAAA\x04\x04\x04\x04'
>>> pad(b"A"*13, 16)
b'AAAAAAAAAAAAA\x03\x03\x03'
```

## Write-Up

> Write-up for the challenge `AES 101` from `SSTF 2023 (Samsung CTF)`

In this challenge, we will exploit the differing responses between a successful and an unsuccessful unpadding operation to leak the `Intermediate Plaintext` (IP). Once we have access to the IP, we can forge an IV to manipulate the plaintext decrypted by AES, even without knowing the key.

![AES CBC Decryption](https://i.stack.imgur.com/sEOmw.png)

A successful unpadding operation will display either the `flag` or the `Wrong CipherText` message. Conversely, an unsuccessful operation will present the `Try again` message.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from secret import key, flag


while True:
	try:
		iv = bytes.fromhex(input("IV(hex): "))
		if len(iv) != 16:
			raise Exception
		msg = bytes.fromhex(input("CipherText(hex): "))
		if len(msg) % 16:
			raise Exception
	except:
		print("Wrong input.")
		exit(0)

	cipher = AES.new(key, AES.MODE_CBC, iv)
	plaintext = cipher.decrypt(msg)
	try:
		plaintext = unpad(plaintext, 16)
	except:
		print("Try again.")
		continue

	if plaintext == b"CBC Magic!":
		print(flag)
		break
	else:
		print("Wrong CipherText.")

```

To begin, we'll leak the last byte of the IP by brute-forcing this byte until we identify valid padding. A legitimate padding matches `b"\x01"`. Thus, by XORing our brute-forced value with `b"\x01"`, we can obtain the last byte of the IP.

Then, to leak the penultimate byte, we'll brute-force the plaintext until the end matches `b"\x02\x02"` (valid unpadding!). Subsequently, we'll search for `"\x03\x03\x03"` and so on.

Our objective is to reconstruct all 16 bytes of the IP. To retrieve the flag, we'll simply XOR the IP with the flag to satisfy the equation:

```
PLAINTEXT = IP ^ IV = IP ^ (IP ^ PLAINTEXT_GOAL) = PLAINTEXT_GOAL
```

Once the equation holds true, we have the flag!

```python
from pwn import remote, xor
from binascii import hexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad


HOST, PORT = "aes.sstf.site", 1337
BLOCK_SIZE = 16
PLAINTEXT_GOAL = pad(b"CBC Magic!", BLOCK_SIZE)
CIPHERTEXT = hexlify(b"A" * BLOCK_SIZE)
# FOUND_IP = [203, 52, 219, 240, 162, 204, 245, 124, 153, 47, 38, 161, 18, 125, 149, 107]
FOUND_IP = [0] * BLOCK_SIZE


conn = remote(HOST, PORT)
for i in range(1, BLOCK_SIZE + 1):
    for j in range(256):
        prefix = b"A" * (BLOCK_SIZE - i)
        bf_byte = int.to_bytes(j, 1)
        padding = xor(FOUND_IP, i)[BLOCK_SIZE + 1 - i:]
        iv = prefix + bf_byte + padding

        conn.sendlineafter(b"IV(hex): ", hexlify(iv))
        print(b"IV send: " + iv)
        conn.sendlineafter(b"CipherText(hex): ", CIPHERTEXT)

        data = conn.recvline().strip()
        if data != b"Try again.":
            FOUND_IP[BLOCK_SIZE - i] = iv[-i] ^ i
            print("=" * 30)
            print(FOUND_IP)
            break


iv = xor(PLAINTEXT_GOAL, FOUND_IP)
conn.sendlineafter(b"IV(hex): ", hexlify(iv))
conn.sendlineafter(b"CipherText(hex): ", CIPHERTEXT)
flag = conn.recvline().strip()
print(flag)
```

Execution:

```
[...]
b'IV send: \xd7$\xcb\xe0\xb2\xdc\xe5l\x89?6\xb1\x02m\x85{'
b'IV send: \xd8$\xcb\xe0\xb2\xdc\xe5l\x89?6\xb1\x02m\x85{'
b'IV send: \xd9$\xcb\xe0\xb2\xdc\xe5l\x89?6\xb1\x02m\x85{'
b'IV send: \xda$\xcb\xe0\xb2\xdc\xe5l\x89?6\xb1\x02m\x85{'
b'IV send: \xdb$\xcb\xe0\xb2\xdc\xe5l\x89?6\xb1\x02m\x85{'
==============================
[203, 52, 219, 240, 162, 204, 245, 124, 153, 47, 38, 161, 18, 125, 149, 107]
b'SCTF{CBC_p4dd1n9_0racle_477ack_5tArts_h3re}'
```
