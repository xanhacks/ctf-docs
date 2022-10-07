---
title: Others
description: Others.
---

# Others

## UTF-8 rockyou

```bash
$ iconv -f ISO-8859-1 -t UTF-8 rockyou.txt > rockyou_utf8.txt
```

## Edit binary file

```
$ xxd -ps binary > binary.hex
$ vim binary.hex
$ xxd -r -ps binary.hex
```

## Self-signed HTTPs certificates

openssl command :

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout cert.key -out cert.crt
```

nginx config :

```
    ssl_certificate /etc/nginx/certs/cert.crt;
	ssl_certificate_key /etc/nginx/certs/cert.key;
```

## Certbot - Let's Encrypt

```
$ sudo apt install -y python3-certbot-nginx
$ certbot -d domain.com --manual --preferred-challenges dns certonly
[...]
Ask for TXT DNS entry

$ dig TXT _acme-challenge.domain.com
[...]
_acme-challenge.domain.com. 3585 IN TXT  "8E5TrjR230ThxG2RntJYnaJcslXOx5DsDki40T11_GU"

cd /etc/letsencrypt/archive/domain.com
$ ls
cert1.pem  chain1.pem  fullchain1.pem  privkey1.pem
```