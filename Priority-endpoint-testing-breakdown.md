# Priority Endpoint Testing Breakdown: Test These First on Any Target

1. User Account Management Endpoints (Highest value for BAC)
Test anything related to users, identity, sessions, and settings. 

Common URL Endpoint Paths :

    /account
    /user
    /profile
    /settings
    /preferences
    /login
    /logout
    /register
    /password

Why?
- Often have IDORs, privilege escalation, session mismanagement
- Check if you can : 
    - Access another user’s profile
    - Change passwords without old password
    - Update email and bypass verification
    - Stay logged in after deleting/changing session tokens


2. Object Ownership and Resource ID Endpoints (BAC, IDOR, Object-Level issues)

Common Paths : 
    
    /orders
    /transactions
    /invoices
    /carts
    /notes
    /messages
    /uploads
    /files
    /posts

Why? 
- These almost always include “user_id”, “id”, “resource_id” in URL or JSON
- Look for : 
    - Changing an ID and still getting 200 OK
    - Replaying the same actions from attacker’s session with Victims “id”
    - Tampering with HTTP method GET -> PUT, POST, PATCH, DELETE


3. Admin/Privilege-Restricted Endpoints (Critical Vertical Privilege Escalation)

Common Paths :

    /admin
    /staff
    /moderator
    /internal
    /superuser
    /panel
    /roles

Why? 
- Look for : 
    - Weak JWT or session checks 