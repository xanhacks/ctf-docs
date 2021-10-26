---
title: Proxy tab
description: Burpsuite proxy tab cheatsheets
---

# Burpsuite Proxy tab

## HTTP Proxy

### Filter HTTP History only for scope items

![Site map for scope items]({{ base_url }}/assets/img/web/burp_sitemap_scope.png)

## Options

### Intercepts only scope URLs

![Intercepts only scope URLs in Burpsuite]({{ base_url }}/assets/img/web/burp_and_scope.png)

Websockets will still be intercepted, you can disable it by unchecking this two boxes :

![Remove interception of Websockets in Burpsuite]({{ base_url }}/assets/img/web/burp_remove_websockets.png)

### Match and replace

Replace string or regex from request or response to a specific string.

![Macth and replace rules]({{ base_url }}/assets/img/web/burp_match_replace_xss.png)
