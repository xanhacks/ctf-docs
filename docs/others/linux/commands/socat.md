---
title: socat
description: socat - Multipurpose relay (SOcket CAT).
---

# socat - Multipurpose relay (SOcket CAT)

## Port forwarding

From `localhost:8888` to `10.2.130.7:4444`.

```bash
$ socat TCP4-LISTEN:8888,reuseaddr,fork TCP4:10.2.130.7:4444
```

## TCP to program

```bash
$ socat TCP-LISTEN:9001,reuseaddr,fork,forever,keepalive EXEC:'python3 example.py'
```

> References [www.redhat.com](https://www.redhat.com/sysadmin/getting-started-socat).