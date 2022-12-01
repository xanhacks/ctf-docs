---
title: Easy reports
description: Bug bounty tips.
---

# Easy reports

## Sensitive information leak via Referrer header

Sensitive information (ex: password reset token) leak via Referrer header

Example :

- Request password reset to your email address
- Click on the password reset link
- Dont change password
- Click any 3rd party websites(eg: Facebook, twitter)
- Intercept the request in burpsuite proxy- 
- Check if the referer header is leaking password reset token.

Source : [book.hacktricks.xyz](https://book.hacktricks.xyz/pentesting-web/reset-password)

## nOtWASP bottom 10: vulnerabilities that make you cry

1. Autocomplete=off not set
2. Missing httponly flag
3. Tabnabbing
4. Missing security headers
5. Ex-XSS
6. CVE-XXXX Unspecified vulnerability in unspecified component
7. CSV Injection with no impact
8. Missing rate-limit/CAPTCHA
9. Useless information disclosure (ex: Apache version)
10. Excessive concurrent sessions

Source : [portswigger.net](https://portswigger.net/research/notwasp-bottom-10-vulnerabilities-that-make-you-cry)