# Vulnerability Report

## Summary
- **Title**: Multiple SQL Injection and XSS in php-inventory-management-system
- **Affected Version**: all versions (as of 2026-06-28)
- **CWE**: CWE-89 (SQL Injection), CWE-79 (Cross-site Scripting)
- **CVSS 3.1 Score**: 9.8 Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Vendor**: stemword
- **Product**: php-inventory-management-system
- **Repository**: https://github.com/stemword/php-inventory-management-system

## Description

php-inventory-management-system contains multiple critical SQL injection vulnerabilities and a reflected XSS vulnerability.

### SQL Injection in createOrder.php (CWE-89)

In `php_action/createOrder.php` lines 10-27, all POST parameters are directly interpolated into SQL INSERT statements without any sanitization, escaping, or parameterized queries:

```php
$clientName = $_POST['clientName'];           // line 11 - no sanitization
$clientContact = $_POST['clientContact'];     // line 12

$sql = "INSERT INTO orders (...) VALUES ('$orderDate', '$clientName', '$clientContact', ...)";  // line 27
$connect->query($sql);                        // line 31
```

Additionally, at lines 43 and 50, `$_POST['productName'][$x]` is concatenated directly into SELECT and UPDATE queries:

```php
$updateProductQuantitySql = "SELECT ... WHERE product.product_id = ".$_POST['productName'][$x]."";  // line 43
$updateProductTable = "UPDATE product SET quantity = '...' WHERE product_id = ".$_POST['productName'][$x]."";  // line 50
```

### XSS in orders.php (CWE-79)

In `orders.php` line 513, `$_GET['i']` is echoed directly into an HTML attribute without `htmlspecialchars()`:

```php
<input type="hidden" name="orderId" id="orderId" value="<?php echo $_GET['i']; ?>" />
```

**PoC**: `orders.php?i="><script>alert(document.cookie)</script>`

## Impact

- **SQL Injection**: An authenticated attacker can extract the entire database, modify or delete data, and potentially execute OS commands via SQL (depending on DB privileges).
- **XSS**: An attacker can steal session cookies and hijack authenticated sessions.

## Suggested Fix

Use prepared statements (PDO or MySQLi) for all SQL queries. Apply `htmlspecialchars()` to all user input rendered in HTML.

## Credit
- Discovered by: goutou (https://github.com/goutouanquan)
- Contact: goutouanquan@163.com
