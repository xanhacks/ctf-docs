---
title: Enumeration
description: Introduction to enumeration, espacially for big companies.
---

# Enumeration

## Sub-domains

Using [amass](https://github.com/OWASP/Amass).

```bash
$ amass enum -passive -d domain.com -o dns_amass.lst -o dns_tech.lst
$ wc -l dns_amass.lst
2534 dns_amass.lst
```

Using google dorks.

```
site:*.example.com
```

## Server & Technology

Using [httpx](https://github.com/projectdiscovery/httpx).

```
$ httpx -title -server -status-code -tech-detect -list dns_amass.lst
https://migration.domain.com [302] [302 Found] []
https://example.domain.com [403] [403 Forbidden] [Apache] [Apache]
https://api.domain.com [403] [403 Forbidden] []
https://alerts.domain.com [200] [] [] [AngularJS,Java]
https://grafana.domain.com [200] [] [] [AngularJS,Java]
https://prom.domain.com [200] [] [] [AngularJS,Java]
[...]
$ httpx -title -server -status-code -tech-detect -list dns_amass.lst -fc 401,403,404,502,503 -o dns_availabe.lst
[...]
```