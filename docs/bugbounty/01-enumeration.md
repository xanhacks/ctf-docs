---
title: Enumeration
description: Introduction to enumeration (domains, subdomains, path, technologies, ...)
---

# Enumeration

## Sub-domains

### Amass

Amass performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.

> Github [link](https://github.com/OWASP/Amass).

#### Installation

Download [release](https://github.com/OWASP/Amass/releases/latest) binary.

#### Examples

```bash
➜ amass enum -passive -d domain.com -o dns_amass.lst -o dns_tech.lst
➜ wc -l dns_amass.lst
2534 dns_amass.lst
```

### Google dorks

```bash
site:*.example.com
```

### assetfinder

Find domains and subdomains potentially related to a given domain.

> Github [link](https://github.com/tomnomnom/assetfinder).

#### Installation

```
➜ go install github.com/tomnomnom/assetfinder@latest
```

#### Examples

```
➜ echo xanhacks.xyz | assetfinder | sort -u
decoder.xanhacks.xyz
docs.xanhacks.xyz
dorks.xanhacks.xyz
www.xanhacks.xyz
xanhacks.xyz
```

## Paths

### getallurls (gau)

getallurls (gau) fetches known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and URLScan for any given domain.

> Github [link](https://github.com/lc/gau).

#### Installation

```
go install github.com/lc/gau/v2/cmd/gau@latest
```

#### Examples

```
➜ cat domains.lst | gau
➜ echo xanhacks.xyz | gau --fc 404 --threads 5 --subs --o gau_wayback.out
```

### unfurl

Pull out bits of URLs provided on stdin.

> Github [link](https://github.com/tomnomnom/unfurl).

#### Installation

```
➜ go install github.com/tomnomnom/unfurl@latest
```

#### Examples

```
➜ head gau_wayback.out
https://www.xanhacks.xyz/
https://www.xanhacks.xyz/apple-touch-icon.png
https://www.xanhacks.xyz/assets/built/main.min.js?v=02b714b121
https://www.xanhacks.xyz/assets/built/main.min.js?v=ca9e4c8359
https://www.xanhacks.xyz/assets/built/screen.css?v=02b714b121
https://www.xanhacks.xyz/assets/built/screen.css?v=ca9e4c8359
https://www.xanhacks.xyz/assets/css/fonts/latin-ext700n.woff2
https://www.xanhacks.xyz/assets/css/fonts/latin400n.woff2
https://www.xanhacks.xyz/assets/css/fonts/latin800n.woff2
https://www.xanhacks.xyz/assets/css/fonts/muli.css?v=02b714b121

➜ head gau_wayback.out | unfurl --unique domains
www.xanhacks.xyz

# keys, values, keypairs
➜ head gau_wayback.out | unfurl --unique keypairs
v=02b714b121
v=ca9e4c8359

➜ head gau_wayback.out | unfurl format %d%p
www.xanhacks.xyz/
www.xanhacks.xyz/apple-touch-icon.png
www.xanhacks.xyz/assets/built/main.min.js
www.xanhacks.xyz/assets/built/screen.css
www.xanhacks.xyz/assets/css/fonts/latin-ext700n.woff2
www.xanhacks.xyz/assets/css/fonts/latin400n.woff2
www.xanhacks.xyz/assets/css/fonts/latin800n.woff2
www.xanhacks.xyz/assets/css/fonts/muli.css
```

## Server & Technology

### httpx

httpx is a fast and multi-purpose HTTP toolkit allow to run multiple probers using retryablehttp library, it is designed to maintain the result reliability with increased threads.

> Github [link](https://github.com/projectdiscovery/httpx).

#### Installation

```
➜ go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

#### Example

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

## Parameters

### Arjun

Arjun can find query parameters for URL endpoints.

> Github [link](https://github.com/s0md3v/Arjun).

#### Installation

```
➜ python3 -m pip install arjun
```

#### Examples

```
➜ arjun -u https://0a1d003d04377e8ac078557300b70020.web-security-academy.net/
    _
   /_| _ '
  (  |/ /(//) v2.1.51
      _/

[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Analysing HTTP response for potential parameter names
[+] Heuristic scanner found 1 parameter: search
[*] Logicforcing the URL endpoint
[✓] name: search, factor: body length
```

## Scope

### inscope

Prototype tool for filtering URLs and domains supplied on stdin to make sure they meet one of a set of regular expressions.

> Github [link](https://github.com/tomnomnom/hacks/tree/master/inscope).

#### Installation

```
➜ go install github.com/tomnomnom/hacks/inscope@latest
```

#### Examples

```
➜ cat domains.lst
https://example.com/footle
https://inscope.example.com/some/path?foo=bar
https://outofscope.example.net/bar

➜ cat .scope
.*\.example\.com$
^example\.com$
.*\.example\.net$
!.*outofscope\.example\.net$

➜ cat domains.lst | inscope
https://example.com/footle
https://inscope.example.com/some/path?foo=bar
```