# Vulnerability Report

## Summary
- **Title**: SQL Injection in Online-Voting-System-using-php-and-mysql
- **Affected Version**: all versions (as of 2026-06-28)
- **CWE**: CWE-89 - SQL Injection
- **CVSS 3.1 Score**: 9.8 Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Vendor**: rezwanh001
- **Product**: Online-Voting-System-using-php-and-mysql
- **Repository**: https://github.com/rezwanh001/Online-Voting-System-using-php-and-mysql

## Description

Online-Voting-System-using-php-and-mysql contains SQL injection vulnerabilities due to inconsistent input sanitization. While `firstname` and `lastname` parameters use `addslashes()`, the `email` and `voter_id` parameters are used directly in SQL queries without any sanitization.

## Vulnerability Details

### 1. Unauthenticated SQL Injection in registeracc.php (CRITICAL)

**Complete attack chain:**
- **Input**: `$_POST['email']` (line 85) and `$_POST['voter_id']` (line 87) — NO sanitization
- **Contrast**: `$_POST['firstname']` (line 83) and `$_POST['lastname']` (line 84) DO use `addslashes()`
- **SQL construction**: Line 91 — `"INSERT INTO tbMembers(first_name, last_name, email, voter_id, password) VALUES ('$myFirstName','$myLastName', '$myEmail','$myVoterid', '$newpass')"`
- **Execution**: `$mysqli->query(...)` (line 91)
- **Authentication**: None — this is the public registration page

```php
$myFirstName = addslashes( $_POST['firstname'] );  // line 83: sanitized
$myLastName = addslashes( $_POST['lastname'] );     // line 84: sanitized
$myEmail = $_POST['email'];                          // line 85: NOT sanitized
$myVoterid = $_POST['voter_id'];                     // line 87: NOT sanitized

$sql = $mysqli->query( "INSERT INTO tbMembers(..., email, voter_id, ...) VALUES ('$myFirstName','$myLastName', '$myEmail','$myVoterid', '$newpass')" );
```

**PoC**: Register with `email=x','x',(SELECT password FROM tbMembers LIMIT 1))-- ` to extract existing user password hashes via error-based or UNION injection.

### 2. Authenticated SQL Injection in manage-profile.php (HIGH)

**Complete attack chain:**
- **Input**: `$_POST['email']` (line 33) and `$_POST['voter_id']` (line 35) — NO sanitization
- **SQL construction**: Line 39 — `"UPDATE tbMembers SET ..., email='$myEmail', voter_id = '$myVoterid', password='$newpass' WHERE member_id = '$myId'"`
- **Authentication**: Requires login (session check exists)

```php
$myEmail = $_POST['email'];                          // line 33: NOT sanitized
$myVoterid = $_POST['voter_id'];                     // line 35: NOT sanitized

$sql = $mysqli->query( "UPDATE tbMembers SET first_name='$myFirstName', last_name='$myLastName', email='$myEmail', voter_id = '$myVoterid', password='$newpass' WHERE member_id = '$myId'" );
```

**PoC**: Update profile with `email=x' WHERE member_id=1-- ` to modify any user's record, including setting a known password on the admin account.

### 3. Plaintext Password in Cookie (MEDIUM)

In `admin/checklogin.php` lines 40-41, the admin password is stored in a plaintext cookie:
```php
setcookie('$email',$_POST['myusername'], time()+30*24*60*60);
setcookie('$pass', $_POST['mypassword'],time()+30*24*60*60);
```

## Impact

1. **Unauthenticated attacker** can extract all voter data, admin credentials, and vote records via SQL injection in the registration form
2. **Authenticated attacker** can modify any user's account including admin accounts via SQL injection in the profile update form
3. **Vote manipulation** is possible by modifying vote records through SQL injection, undermining the integrity of the entire voting system

## Suggested Fix

Apply `$mysqli->escape_string()` or use prepared statements for ALL user inputs, not just firstname and lastname.

## Credit
- Discovered by: goutou (https://github.com/goutouanquan)
- Contact: goutouanquan@163.com
