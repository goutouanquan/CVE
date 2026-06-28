# Vulnerability Report

## Summary
- **Title**: Privilege Escalation via validateRole() Logic Bypass in Azuriom
- **Affected Version**: all versions (as of 2026-06-28)
- **CWE**: CWE-269 - Improper Privilege Management
- **CVSS 3.1 Score**: 8.1 High (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)
- **Vendor**: Azuriom
- **Product**: Azuriom
- **Repository**: https://github.com/Azuriom/Azuriom

## Description

Azuriom contains a privilege escalation vulnerability in the `validateRole()` method of `app/Http/Controllers/Admin/UserController.php`. The method is intended to prevent lower-power admin users from assigning themselves or others to higher-power roles. However, the authorization check at line 229 has a logic flaw:

```php
|| (! $user->isAdmin() && $user->role->power < $role->power)
```

When `$user->isAdmin()` returns `true` (i.e., the user has a role with `is_admin=true`), the expression `!$user->isAdmin()` evaluates to `false`, which short-circuits the entire AND expression. The power-level check `$user->role->power < $role->power` is never evaluated.

This means any admin user, regardless of their power level, can change their own role (or other users' roles) to any role including the highest-power super-admin role, completely bypassing the power hierarchy.

Additionally, `Gate::before()` in `AppServiceProvider.php` returns `true` for all abilities when the user is admin, bypassing all policy checks including `RolePolicy`.

## Proof of Concept

1. Have two admin roles: "Moderator" (is_admin=true, power=3) and "Super Admin" (is_admin=true, power=10)
2. Log in as a user with the "Moderator" role
3. Navigate to admin user edit page
4. Change own role to "Super Admin"
5. The `validateRole()` check passes because `!isAdmin()` is false, skipping the power comparison
6. User is now Super Admin with full privileges

## Impact

Any user with an `is_admin=true` role can escalate to the highest privilege level in the system, regardless of their assigned power level. Combined with the `Gate::before` bypass and the lack of power checks on sensitive operations (disable2fa, ban, forcePasswordChange), this enables complete admin panel takeover.

## Suggested Fix

```diff
- || (! $user->isAdmin() && $user->role->power < $role->power)) {
+ || $user->role->power < $role->power) {
```

Remove the `!$user->isAdmin()` guard so the power check always applies.

## Credit
- Discovered by: goutou (https://github.com/goutouanquan)
- Contact: goutouanquan@163.com
