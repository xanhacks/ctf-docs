---
title: Authentication enumeration / bruteforce
description: Authentication enumeration and bruteforce cheatsheet
---

# Authentication enumeration / bruteforce 

## Methodology

- Enumeration depending on :
    - Response
        - Code (ex: 302 redirection)
        - Length (ex: error / success message)
        - Time (ex: password hashing can take some time)
    - Account is locked only if you try to bruteforce an existing username
- Bypass IP block
    - Header `X-Forwarded-For`
    - Reset the error count by alternating successful login and bruteforce try
- Bypass 2FA
    - Bruteforce 2FA Token
    - Use the token of another account

## GraphQL Batching Attack 

A batching attack refers to abusing this batch query feature to perform many GraphQL operations within one single web request. The batching attack helps facilitate brute force attacks by reducing the total number of potential requests needed to be successful.

Example with OTP token bruteforcing :

![GraphQL_Batching_Attack.png](/assets/img/web/GraphQL_Batching_Attack.png)