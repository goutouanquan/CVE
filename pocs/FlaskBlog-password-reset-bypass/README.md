# FlaskBlog Password Reset Authentication Bypass

## Vulnerability

FlaskBlog's password reset mechanism can be bypassed by submitting an empty verification code, allowing an unauthenticated attacker to reset any user's password.

## Root Cause

In `app/routes/password_reset.py` line 55:

```python
if code == password_reset_codes_storage.get(username, ""):
```

- `password_reset_codes_storage.get(username, "")` returns `""` when no reset was requested
- `form.validate()` is never called, so `InputRequired` validator is never enforced
- Empty code `""` matches default `""`, bypassing verification

## Usage

```bash
pip install requests beautifulsoup4
python poc.py http://localhost:1283 admin NewPassword123
```

## Impact

Unauthenticated account takeover of any user including admin.
