# Vulnerability Report

## Summary
- **Title**: Hardcoded Secrets and Authentication Bypass in Node-SpliderApi
- **Affected Version**: all versions (as of 2026-06-28)
- **CWE**: CWE-798 - Use of Hard-coded Credentials
- **CVSS 3.1 Score**: 7.5 High (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
- **Vendor**: ecitlm
- **Product**: Node-SpliderApi
- **Repository**: https://github.com/ecitlm/Node-SpliderApi

## Description

Node-SpliderApi commits its `.env.development` file to version control containing multiple secrets. The `.gitignore` only ignores `.env.production` but not `.env.development`. The exposed secrets include:

1. **API signing key**: `appKey=44cb0b75f52f4596a57773b9173416a6` — used for API request signature validation
2. **JWT secret**: `jwtSecret=kjhgyhvfsdcvbjk` — a 15-character keyboard pattern used for signing/verifying JWT tokens
3. **Database credentials**: `username=root`, `password=''`

Additionally, `ApiSign=false` disables API signature validation entirely, and the JWT secret is weak enough to be brute-forced.

Combined with multiple SSRF vulnerabilities in the crawler endpoints (video-detail, tt-news-detail, video-list, joke, bank-card, down-img) where user-controlled parameters are interpolated into outbound HTTP request URLs without validation, the application's security posture is critically deficient.

## Affected Files
- `.env.development` — committed secrets
- `src/utils/api-sign.js` line 10 — auth bypass when ApiSign=false
- `src/utils/jwt.js` line 8 — weak JWT secret
- `src/controller/163/video-detail.js` — SSRF via vid parameter
- `src/controller/163/tt-news-detail.js` — SSRF via item_id parameter
- `src/controller/bank-card.js` — parameter injection via cardNo

## Credit
- Discovered by: goutou (https://github.com/goutouanquan)
- Contact: goutouanquan@163.com
