---
title: Scanner
description: Introduction to web vulnerabilites scanner
---

# Scanner

## General

### nuclei

Fast and customizable vulnerability scanner based on simple YAML.

> Github [link](https://github.com/projectdiscovery/nuclei).

#### Installation

Download [release](https://github.com/projectdiscovery/nuclei/releases/latest) binary.

#### Examples

```
➜ nuclei -disable-update-check -silent -u https://www.xanhacks.xyz
[2022-09-01 05:54:21] [google-floc-disabled] [http] [info] https://www.xanhacks.xyz
[2022-09-01 05:54:26] [metatag-cms] [http] [info] https://www.xanhacks.xyz [Hugo 0.101.0]
[2022-09-01 05:54:27] [tech-detect:jsdelivr] [http] [info] https://www.xanhacks.xyz
[2022-09-01 05:54:36] [ssl-dns-names] [ssl] [info] https://www.xanhacks.xyz [www.xanhacks.xyz]
[2022-09-01 05:54:41] [http-missing-security-headers:content-security-policy] [http] [info] https://www.xanhacks.xyz
[2022-09-01 05:54:41] [http-missing-security-headers:permission-policy] [http] [info] https://www.xanhacks.xyz
[2022-09-01 05:54:41] [http-missing-security-headers:clear-site-data] [http] [info] https://www.xanhacks.xyz
[2022-09-01 05:54:41] [http-missing-security-headers:access-control-allow-headers] [http] [info] https://www.xanhacks.xyz
[2022-09-01 05:54:41] [http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] https://www.xanhacks.xyz
```

## XSS - Cross Site Scripting

### kxss

Request the URLs, check the response body for any reflected parameters. There will be many false positives here.

> Github [link](https://github.com/tomnomnom/hacks/tree/master/kxss).

#### Installation

```
➜ go install github.com/tomnomnom/hacks/kxss@latest
```

#### Examples

```
➜ echo 'https://example.com/?search=a' | kxss
param search is reflected and allows " on https://example.com/?search=a
param search is reflected and allows ' on https://example.com/?search=a
param search is reflected and allows < on https://example.com/?search=a
param search is reflected and allows > on https://example.com/?search=a
```