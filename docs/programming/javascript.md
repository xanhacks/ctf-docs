---
title: Javascript
description: Javascript cheatsheets for Web pentester.
---

# Javascript cheatsheets for Web pentester

## Making HTTP Requests

### Using fetch

Fetch API is not supported by all browsers, you can detect it by using this snippet :

```js
if (window.fetch) {
  // run my fetch request here
} else {
  // do something with XMLHttpRequest?
}
```

Exemple of a synchronous GET request :

```js
let response = await fetch('https://api.example.com/users');

if (response.ok) { // status code : 2XX
  let json = await response.json();
} else {
  console.log("Error: " + response.status);
}
```

Example of an asynchronous POST request sending and reiceiving JSON data :

```js
fetch('https://api.example.com/users', {
	method: 'POST',
	headers: {
		'Content-Type': 'application/json'
	},
	body: JSON.stringify({
		username: "john",
		email: "john@example.com"
	})
})
.then(response => response.json())
.then(data => console.log(data))
.catch(err => console.log(err))
```

To send cookies to another domain, you can use `credentials: 'include'`.

List of forbidden headers : `Accept-Charset`, `Accept-Encoding`, `Access-Control-Request-Headers`, `Access-Control-Request-Method`, `Connection`, `Content-Length`, `Cookie`, `Cookie2`, `Date`, `DNT`, `Expect`, `Host`, `Keep-Alive`, `Origin`, `Referer`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, `Via`.

> More information on [javascript.info](https://javascript.info/fetch) and [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch).

### Using XHR (XMLHttpRequest)

Synchronous HTTP GET request :

```js
let xhr = new XMLHttpRequest();
xhr.open('GET', 'https://developer.mozilla.org/', false);
xhr.send();

if (xhr.status === 200) {
  console.log(xhr.responseText);
}
```

Asynchronous HTTP GET request :

```js
let xhr = new XMLHttpRequest();
xhr.open('GET', 'http://example.com/index.php?param=1');

xhr.onload = function() {
  if (xhr.status !== 200) {
    console.log(`Error ${xhr.status}`);
  } else {
    console.log(xhr.response);
  }
};

xhr.send();
```

Asynchronous HTTP POST request with JSON data :

```js
const data = {
    "id": "17",
    "email": "john@example.com"
};

let xhr = new XMLHttpRequest();

xhr.open('POST', '/api/users');
xhr.setRequestHeader('Content-Type', 'application/json');

xhr.onload = function() {
  if (xhr.status !== 200) {
    console.log(`Error ${xhr.status}`);
  } else {
    console.log(xhr.response);
  }
};

xhr.send(JSON.stringify(data));
```

> More information on [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest).