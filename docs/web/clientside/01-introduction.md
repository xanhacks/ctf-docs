---
title: Introduction 
description: Introduction to client side web pentesting
---

# Introduction to client side

## Same-origin policy (SOP)

The same-origin policy is a critical security mechanism that restricts how a document or script loaded by one origin can interact with a resource from another origin.

Two URLs have the same origin if the protocol, port, and host are the same for both.

> References : [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy).

## Cross-Origin Resource Sharing (CORS)

Cross-Origin Resource Sharing (CORS) is an HTTP-header based mechanism that allows a server to indicate any origins (domain, scheme, or port) other than its own from which a browser should permit loading resources.

For security reasons, browsers restrict cross-origin HTTP requests initiated from scripts. For example, XMLHttpRequest and the Fetch API follow the same-origin policy. This means that a web application using those APIs can only request resources from the same origin the application was loaded from **unless the response from other origins includes the right CORS headers**.

> References : [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS).

## Not "safe" headers

List of forbidden headers : `Accept-Charset`, `Accept-Encoding`, `Access-Control-Request-Headers`, `Access-Control-Request-Method`, `Connection`, `Content-Length`, `Cookie`, `Cookie2`, `Date`, `DNT`, `Expect`, `Host`, `Keep-Alive`, `Origin`, `Referer`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, `Via`.

This headers cannot be set by Javascript when you are makeing a request.