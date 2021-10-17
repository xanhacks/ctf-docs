---
title: Others
description: Others.
---

## MySQL vertical format

Use `--vertical` to enable the vertical format or ending query with `\G`, example : `SELECT * FROM users \G`.

```sql
> SELECT * FROM city WHERE countrycode='AUT';
*************************** 1. row ***************************
	ID: 1523
	Name: Wien
	CountryCode: AUT
	District: Wien
	Info: {"Population": 1608144}
```

> Source [dev.mysql.com](https://dev.mysql.com/doc/mysql-shell/8.0/en/mysql-shell-output-vertical.html).