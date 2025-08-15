# Cache Poisoning Testing Methodology

Goal: find cache-key confusion and poisoning that causes attacker-controlled content to be served to other users.

## Quick checks

* Identify caching layers: CDN (Cloudflare, Akamai), reverse proxy (Varnish), application caches.
* Check response headers: `Cache-Control`, `Vary`, `Surrogate-Control`, `Age`, `Expires`.
* Identify whether responses are cacheable (200 OK, cacheable headers) and if cookies are considered in the cache key.

## Common poisoning vectors

* **Host header / X-Forwarded-Host** manipulation — if cache key includes host and server uses it to build response.
* **Vary header misconfiguration** — missing `Vary` or including attacker-controlled headers in key.
* **Cacheable responses with user-specific content** — HTML pages that vary by user but are cached globally.
* **Cached redirects** — attacker forces a redirect that gets cached and used for others.
* **Cache key using query params unsafely** — unvalidated query params controlling content.

## Test payloads / headers to try

```
Host: attacker.example.com
X-Forwarded-Host: attacker.example.com
X-Forwarded-Proto: https
Accept-Encoding: (set unique string)
User-Agent: (unique string)
X-My-Test: poison-<random>
Cookie: test=1
Cache-Control: public, max-age=86400
Surrogate-Control: max-age=86400
```

## Testing steps

1. Find a cacheable endpoint (200 OK with Cache-Control: public or CDN headers).
2. Send a request with a unique marker (random string) in a header or param and a payload that appears in response.
3. Request the same resource from another client (or clear cache key) to see if marker is served to others.
4. Manipulate `Host`/`X-Forwarded-Host` and other headers to see if they affect response content and key.
5. Check for cached redirects and error pages.
6. For CDNs, test behavior with and without `www` and across different edge locations if possible.

## Detection and mitigation

* Ensure `Vary` correctly lists the headers that affect response (and not attacker-controllable ones).
* Do not cache user-specific pages publicly. Use `Cache-Control: private` for user content.
* Validate and normalize `Host` and forwarded headers; don't use untrusted host data to build cache keys or links.
* Shorten TTLs for dynamic content and use proper cache invalidation on updates.

## Reporting checklist

* Endpoint and exact request headers used to produce poisoning (include unique marker).
* Evidence that cached response served the poisoned content to other clients.
* Suggested fixes: mark user responses private, normalize host, adjust Vary, restrict CDN caching rules, add cache key segmentation per-authentication state.

---

