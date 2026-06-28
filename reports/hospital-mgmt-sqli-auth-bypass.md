# Vulnerability Report

## Summary
- **Title**: SQL Injection Authentication Bypass in hospital-management-system-in-php
- **Affected Version**: all versions (as of 2026-06-28)
- **CWE**: CWE-89 (SQL Injection), CWE-287 (Improper Authentication)
- **CVSS 3.1 Score**: 9.8 Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Vendor**: projectworldsofficial
- **Product**: hospital-management-system-in-php
- **Repository**: https://github.com/projectworldsofficial/hospital-management-system-in-php

## Description

hospital-management-system-in-php contains multiple SQL injection vulnerabilities throughout its `library.php` file. The `secure()` function (line 17-20) uses `htmlentities()` for sanitization, which only encodes HTML entities but does NOT prevent SQL injection. PHP's `htmlentities()` without the `ENT_QUOTES` flag does not escape single quotes (`'`), which are the SQL string delimiter.

### Authentication Bypass via SQL Injection (line 29)

```php
function secure($unsafe_data) {
    return htmlentities($unsafe_data);  // Does NOT escape single quotes
}

function login($email_id_unsafe, $password_unsafe, $table = 'users') {
    $email_id = secure($email_id_unsafe);
    $password = secure($password_unsafe);
    $sql = "SELECT COUNT(*) FROM $table WHERE email = '$email_id' AND password = '$password';";
    $result = $connection->query($sql);
}
```

**PoC**: Login with email `' OR '1'='1' -- ` and any password bypasses authentication.

### Additional SQL Injection vectors

- **line 83-89** `register()`: INSERT with string concatenation
- **line 156** `enter_patient_info()`: `$age` and `$weight` are unquoted in SQL
- **line 200** `update_appointment_info()`: `$column_name` is user-controlled and directly concatenated into UPDATE SET clause, allowing modification of arbitrary columns
- **line 313** `delete()`: DELETE with string concatenation

### Plaintext Password Storage (CWE-256)

Passwords are stored and compared in plaintext (line 29: `password = '$password'`).

### SQL Statement Leakage (CWE-209)

Line 202 echoes the full SQL statement: `echo $sql;`

## Impact

Unauthenticated attacker can bypass login, access all patient records, modify medical data, and extract the entire database.

## Credit
- Discovered by: goutou (https://github.com/goutouanquan)
- Contact: goutouanquan@163.com
