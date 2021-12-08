---
title: Wordpress
description: Pentesting wordpress
---

## Authenticated RCE

From `/wp-admin`, click on `Appearance/Themes/Editor`.

Then, replace the `404.php` page to your reverse shell (example of [PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)).

Generic URL :

- `http://<HOST>/<WP_PATH>/wp-content/themes/<THEME>/404.php`

Example :

- `http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php`

## Manually list plugins

```bash
$ feroxbuster -n -o wp_plugins.out -w wp_plugins.lst --url http://internal.thm/blog/wp-content/plugins/

$ feroxbuster -n -o wp_plugins.out -w wp_plugins.lst --url http://<HOST>/<WP_PATH>/wp-content/plugins/
```

Plugin list can be found, [here](https://github.com/Perfectdotexe/WordPress-Plugins-List/blob/master/plugins.txt).