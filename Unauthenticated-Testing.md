# Unauthenticated Testing Methodology

Goal: identify vulnerabilities that can be exploited without logging in — bypassing authentication or accessing unintended resources.

## Quick checks

* Enumerate all public-facing endpoints before login.
* Check for forgotten admin panels, APIs, and dev/test endpoints.
* Look for functionality that should be behind authentication but is accessible directly.
* Test HTTP methods (GET, POST, PUT, DELETE) without auth.
* Check if APIs accept unauthenticated requests with certain parameters.
* Review JavaScript files for hidden API paths.

## Common attack patterns

* **IDORs without auth** — change object IDs in public endpoints.
* **Forced browsing** — direct access to `/admin`, `/dashboard`, `/profile` without login.
* **Unprotected APIs** — REST or GraphQL endpoints responding without a token.
* **Password reset abuse** — reset tokens issued without verifying identity.
* **Unauthenticated file upload** — upload malicious files without restrictions.
* **Debug endpoints** — `/debug`, `/status`, `/actuator` returning sensitive info.
* **Parameter injection** — sending `isAdmin=true` in unauthenticated requests.

## Parameters/Places to fuzz

```
id
user_id
account
email
file
path
redirect
role
isAdmin
```

## Testing steps

1. Map all unauthenticated endpoints via directory brute-force (e.g., ffuf, dirsearch).
2. Try accessing authenticated pages directly without cookies/tokens.
3. Replay authenticated requests without credentials to see if they still work.
4. Enumerate API endpoints from web app/mobile app and test without auth headers.
5. Modify parameters to escalate privileges or retrieve other users’ data.
6. Check file upload endpoints for unauthenticated access.
7. Test password reset flows for missing identity checks.

## Detection and response checks

* Verify that all sensitive endpoints return `401` or `403` without proper auth.
* Confirm that rate limits apply even before login (prevent brute-force).
* Ensure CORS policies are not overly permissive for public endpoints.

## Reporting checklist

* List all unauthenticated endpoints tested.
* Document which ones allowed unintended access.
* Show proof-of-concept request/response pairs.
* Recommend enforcing authentication, restricting public endpoints, and validating identity before sensitive actions.

--- 