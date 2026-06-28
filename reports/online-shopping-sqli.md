# Vulnerability Report

## Summary
- **Title**: Multiple SQL Injection in online-shopping-system-advanced
- **Affected Version**: all versions (as of 2026-06-28)
- **CWE**: CWE-89 - SQL Injection
- **CVSS 3.1 Score**: 9.8 Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Vendor**: PuneethReddyHC
- **Product**: online-shopping-system-advanced
- **Repository**: https://github.com/PuneethReddyHC/online-shopping-system-advanced

## Description

online-shopping-system-advanced contains multiple SQL injection vulnerabilities in `action.php`. POST parameters are directly interpolated into SQL queries via `mysqli_query()` without any sanitization, escaping, or parameterized queries.

### Vulnerable code locations in action.php:

**Line 83-84** — Category filter:
```php
$cid = $_POST["cid"];
$sql = "SELECT * FROM products Where product_cat='$cid'";
```

**Line 110** — Product listing with pagination:
```php
$product_query = "SELECT * FROM products,categories WHERE product_cat = '$cat_id' AND product_cat=cat_id LIMIT $start,$limit";
```
`$cat_id` from `$_POST["cid"]` and `$start` from `$_POST["pageNumber"]` without `(int)` cast.

**Line 180-181** — Category selection:
```php
$id = $_POST["cat_id"];
$sql = "SELECT * FROM products,categories WHERE product_cat = '$id' AND product_cat=cat_id";
```

**Line 184-185** — Brand selection:
```php
$id = $_POST["brand_id"];
$sql = "SELECT * FROM products,categories WHERE product_brand = '$id' AND product_cat=cat_id";
```

**Line 188-189** — Search (LIKE injection):
```php
$keyword = $_POST["keyword"];
$sql = "SELECT * FROM products,categories WHERE product_cat=cat_id AND product_keywords LIKE '%$keyword%'";
```

## Impact

Unauthenticated attacker can extract the entire database (including user credentials, order details, payment information), modify or delete data, and potentially execute OS commands depending on database privileges.

## Credit
- Discovered by: goutou (https://github.com/goutouanquan)
- Contact: goutouanquan@163.com
