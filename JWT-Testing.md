# JWT Testing Methodology

Goal: find insecure token handling, signature bypass, weak secrets, token leakage, replay, and authorization escalation via JWTs.

## Quick checks

* Look for tokens in: Authorization header (Bearer), Cookies, URL params, POST/JSON bodies, localStorage/sessionStorage.
* Check cookie flags: HttpOnly, Secure, SameSite.
* Check token expiry (`exp`), issued at (`iat`), `nbf`, `aud`, `iss`, `sub`, `role`, `scope`, `admin`.
* Check alg header: `alg:none`, `HS256`, `RS256` and `kid` header handling.

## Common attack patterns

* **alg: none** — craft header `{"alg":"none"}` and remove signature.
* **HMAC vs RSA confusion** — sign token using HMAC with public RSA key as secret or switch alg from RS256 -> HS256.
* **Weak secret brute-force** — short or guessable HS keys.
* **kid header attacks** — point `kid` to attacker-controlled key or URL if server fetches keys.
* **Claim tampering** — change `role`, `isAdmin`, `user_id`, `sub`.
* **Replay/Session fixation** — reuse old/expired tokens if server does not validate `exp` or revocation.
* **Token injection** — place token in URL or headers in unexpected places to bypass checks.

## Test payloads (header/payload examples)

Header (alg none):

```
{"alg":"none","typ":"JWT"}
```

Payload tamper example:

```
{"sub":"victim-user-id","role":"admin","exp":9999999999}
```

HS256 brute/secret test — use Burp Intruder to replace payload and re-sign with guessed secrets.

## Parameters/Places to fuzz

```
authorization
Authorization
token
jwt
access_token
id_token
refresh_token
cookie: session
session_token
x-access-token
x-id-token
```

## Testing steps

1. Capture a valid token and decode it (base64) to view header/payload.
2. Test `alg:none` by removing signature and replaying.
3. Test alg switch (RS256 -> HS256) and try signing with public key as secret.
4. Modify claims (`role`, `isAdmin`, `sub`, `user_id`) and re-sign (or attempt to if `alg:none`).
5. Brute-force HS secrets using wordlists (be careful with rate limits and rules of engagement).
6. Test `kid` header manipulation and see if the server loads keys from external sources.
7. Test refresh token handling and revocation logic (logout should invalidate tokens).
8. Check token placement: try sending token in multiple locations to see if one bypasses checks.

## Detection and response checks

* Server validates signature and `alg`.
* Server checks `iss`, `aud`, `exp`, `nbf` and `iat` properly.
* Server performs token revocation/blacklist for logout/refresh.
* Keys rotate and `kid` is validated against trusted keyset.

## Reporting checklist

* Example of original valid token (redacted) and exact modified token used.
* Steps to reproduce with requests (curl or Burp raw requests).
* Impact: what actions can be performed with tampered token.
* Recommended fixes: enforce alg, validate signatures, use strong secrets, implement revocation, secure cookie flags.

---
