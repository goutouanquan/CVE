# Vulnerability Report

## Summary
- **Title**: Multiple Reflected XSS in mpgram-web
- **Affected Version**: all versions (as of 2026-06-28)
- **CWE**: CWE-79 - Improper Neutralization of Input During Web Page Generation
- **CVSS 3.1 Score**: 6.1 Medium (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
- **Vendor**: shinovon
- **Product**: mpgram-web
- **Repository**: https://github.com/shinovon/mpgram-web

## Description

mpgram-web, a lightweight PHP Telegram web client, contains multiple reflected cross-site scripting (XSS) vulnerabilities. User-controlled input from `$_GET` and `$_POST` parameters is directly echoed into HTML output without any sanitization or encoding.

### XSS in write.php via `$_GET['n']` (line 58)

```php
$name = $_GET['n'] ?? null;
if ($name) {
    echo '<b>'.$name.'</b><br>';  // No htmlspecialchars()
}
```

**PoC**: `write.php?c=123&n=<script>alert(document.cookie)</script>`

### XSS in write.php, msg.php, chatsearch.php, botcallback.php via `$_GET['c']` / `$_POST['c']`

```php
$id = $_POST['c'] ?? $_GET['c'] ?? die;
echo '<input type="hidden" name="c" value="'.$id.'">';  // No escaping
echo '<a href="chat.php?c='.$id.'">Back</a>';           // No escaping
```

**PoC**: `msg.php?c="><script>alert(1)</script>&m=1`

### XSS in msg.php via `$_POST['m']` / `$_GET['m']` (line 348)

```php
echo '<input type="hidden" name="m" value="'.$msg.'">';  // No escaping
```

### XSS in exportuser.php via `$_COOKIE['user']` (line 9)

```php
echo $_COOKIE['user'];  // Raw cookie output
```

## Impact

An attacker can craft a malicious URL that, when clicked by an authenticated mpgram-web user, executes arbitrary JavaScript in the user's browser session. Combined with the lack of HttpOnly flags on session cookies, this enables full session hijacking of the victim's Telegram web session.

## Suggested Fix

Apply `htmlspecialchars()` to all user-controlled output:

```diff
- echo '<b>'.$name.'</b><br>';
+ echo '<b>'.htmlspecialchars($name, ENT_QUOTES, 'UTF-8').'</b><br>';

- echo '<input type="hidden" name="c" value="'.$id.'">';
+ echo '<input type="hidden" name="c" value="'.htmlspecialchars($id, ENT_QUOTES, 'UTF-8').'">';
```

## Credit
- Discovered by: goutou (https://github.com/goutouanquan)
- Contact: goutouanquan@163.com
