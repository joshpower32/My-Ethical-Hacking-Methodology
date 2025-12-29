# GraphQL CSRF & WAF Bypass via HTTP Method Override
1. Executive Summary
    This methodology explores a technique to bypass Cross-Site Request Forgery (CSRF) protections and Web Application Firewalls (WAF) on GraphQL-based applications. By utilizing HTTP Method Overriding, it is often possible to "trick" security filters into treating a state-changing POST request as a non-state-changing GET request, thereby skipping CSRF token validation while still executing the backend mutation.

2. Technical Context
    The Vulnerability
    Modern web applications often implement CSRF protection strictly for POST, PUT, and DELETE requests. GET requests are frequently exempted under the assumption that they are idempotent (do not change state).

    The Bypass (Method Override)
    Many backend frameworks and WAFs support method overriding to accommodate clients with limited HTTP support. By appending ?_method=GET or using headers like X-HTTP-Method-Override: GET, a researcher can bypass the security gate while the underlying application still processes the original action.

3. Methodology & Test Cases
Phase 1: Identifying the Target
    Locate high-impact GraphQL mutations that perform state changes. Examples identified during research include:

    Preference Changes: setUserLocalePreference (Impact: Integrity/UI manipulation).

    Data Management: bookmarkStore / unbookmarkStore (Impact: Unauthorized data modification).

    Session Management: REST-based logout endpoints (Impact: Unauthorized session termination).

Phase 2: Testing the WAF Bypass
Baseline Request (Original):

HTTP

    POST /graphql/updateMutation HTTP/2
    Host: target-app.com
    Content-Type: application/json
    X-Csrftoken: [VALID_TOKEN]

    {"operationName":"updateMutation","variables":{"id":"123"},"query":"mutation..."}
    Bypass Attempt (HTML PoC): Using a standard HTML form to force the method override:

HTML

    <form action="https://target-app.com/graphql/updateMutation?_method=GET" method="POST">
        <input type="hidden" name="operationName" value="updateMutation">
        <input type="hidden" name="variables" value='{"id":"123"}'>
        <input type="hidden" name="query" value="mutation updateMutation($id: ID!) { ... }">
    </form>


Phase 3: Handling Content-Type Enforcement
    If the server returns a 400 Bad Request citing "Invalid Content-Type," the backend strictly requires application/json. Research suggests two advanced delivery methods:

    The "JSON-in-a-Name" Trick: Using enctype="text/plain" to "swallow" the equals sign and create valid JSON.

HTML

    <form action="https://target-app.com/graphql/endpoint?_method=GET" method="POST" enctype="text/plain">
        <input type="hidden" name='{"operationName":"...","ignore":"' value='"}'>
    </form>

    Pure GET Transition: Attempting to move the entire payload into URL parameters to bypass body-parsing requirements.



4. Key Findings & Observations
    WAF Transparency: The _method=GET parameter effectively downgraded the security posture from 403 Forbidden to 400 Bad Request, proving that the CSRF filter was successfully bypassed.

    Defense in Depth: Even when CSRF filters are bypassed, strict Content-Type enforcement and JSON schema validation at the application layer can serve as a final line of defense against cross-site forms.

5. Remediation Recommendations
    Method Enforcement: Disable support for method overriding parameters (like _method) unless strictly required.

    Universal CSRF Protection: Apply CSRF validation to all requests that trigger state changes, regardless of the HTTP method used.

    Strict Content-Type Validation: Maintain strict enforcement of application/json for all GraphQL endpoints.