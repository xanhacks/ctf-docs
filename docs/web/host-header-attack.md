
# Host header attack

## Definition

A **Host header attack** is a type of cyber attack in which an attacker **manipulates the Host header of a request in order to trick a web server** into thinking the request is coming from a different website. This can allow the attacker to access resources or information that they would not normally have access to, or to perform actions on the targeted website that they would not normally be able to do. The Host header is a field in the HTTP request header that specifies the domain name of the website that the client is trying to access. By modifying this field, an attacker can direct the server to respond to their request as if it were coming from a different website.

## Cheatsheet

- `Host: exploit-XXXX`
- `X-Forwarded-Host: exploit-XXXXX`
- `GET /admin` bypass with `Host: localhost`
- Enum local networks : `Host: 192.168.0.67`, from 1 to 255
- Absolute URL in path :

```
POST https://example.com/admin/delete HTTP/1.1
Host: 192.168.0.15
...
```

- Submit double Host header (link $HOST/resource/toto.js, spoof host in cache)
- Bypass host header check with `Connection: keep-alive`, [connection-state-attack](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-host-validation-bypass-via-connection-state-attack)

## References

- [PortSwigger - HTTP Host header attacks](https://portswigger.net/web-security/host-header)