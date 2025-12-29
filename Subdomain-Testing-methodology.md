# Subdomain Testing Methodology

## Goal
Expand the attack surface by identifying and testing subdomains for vulnerabilities such as Broken Access Control (BAC), Insecure Direct Object References (IDOR), Cross-Site Scripting (XSS), and misconfigurations.

---

## Step 1. Check Scope
- Review the program’s scope on HackerOne, Intigriti, or Bugcrowd.
- If `*.target.com` is listed → all subdomains are in scope.
- If only `www.target.com` is listed → only test that.
- Respect any exclusions (e.g., `mail.target.com`, `vpn.target.com`).

---

## Step 2. Find Subdomains

### Passive Discovery (Beginner-Friendly)
- [crt.sh](https://crt.sh/) → search: `%.target.com`
- [dnsdumpster.com](https://dnsdumpster.com/) → mapping and records
- Google Dork → `site:target.com -www`
- Firefox Dev Tools → **Network tab** while browsing the main site

### Optional Tools (as skills grow)
- `subfinder -d target.com`
- `assetfinder target.com`
- `amass enum -d target.com`

✅ Take notes of all discovered subdomains.

---

## Step 3. Prioritize Subdomains
Focus on high-value or weak targets:
- `api.target.com` → API endpoints (IDOR, BAC).
- `dev.target.com` / `staging.target.com` → testing environments.
- `admin.target.com` → admin portals.
- `old.target.com` / `v1.target.com` → outdated software.
- Any unusual names (uploads, backups, beta).

---

## Step 4. Test Each Subdomain

### Access Control (BAC / IDOR)
- Test login pages → check for role switching or unauthorized access.
- Test API endpoints:
  - Manipulate IDs (`user_id`, `order_id`, etc.).
  - Verify if other users’ data is accessible.
- Check if cookies/sessions from `www.target.com` work on subdomains.

### Cross-Site Scripting (XSS)
- Look for:
  - Search boxes, feedback forms, contact forms.
  - URL parameters (`?q=`, `?search=`, `?id=`).
- Send payloads via Burp Intruder or manually.

### Misconfigurations / Information Disclosure
- Check for:
  - `/robots.txt`
  - `/sitemap.xml`
  - `/admin`, `/login`, `/dashboard`
  - Directory listings (`/uploads/`, `/backup/`)
- Review HTTP response headers for version info or debug data.

### Forgotten / Hidden Assets
- Try common paths:
  - `/test`, `/dev`, `/staging`
  - `/phpinfo.php`
  - `/swagger/`, `/api-docs`

---

## Step 5. Document Findings
- Keep a record of each subdomain:
  - URL
  - Functionality
  - Test results
- Report only valid vulnerabilities that are in scope.

---

## Quick Workflow
1. Check program scope → look for `*.target.com`.  
2. Discover subdomains → crt.sh, dnsdumpster, Firefox Network tab.  
3. Prioritize (`api`, `dev`, `admin`, `staging`).  
4. Test each with:
   - BAC/IDOR checks  
   - XSS payloads  
   - Misconfigurations & disclosures  
5. Document → report valid issues.  

---
