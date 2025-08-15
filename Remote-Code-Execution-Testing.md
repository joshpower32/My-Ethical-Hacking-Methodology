# Remote Code Execution (RCE) Testing Methodology

Goal: find injection points where attacker-controlled input is executed as code on the server.

## Quick checks

* Identify endpoints that handle file uploads, command execution, template rendering, or code evaluation.
* Look for parameters passed to system commands (ping, nslookup, convert, tar, etc.).
* Check for template engines (Twig, Jinja2, Freemarker) with unescaped input.
* Look for deserialization points in JSON, XML, or binary formats.

## Common attack patterns

* **Command injection** — `;`, `&&`, `|`, backticks in parameters.
* **Template injection** — `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`.
* **File upload RCE** — uploading webshells or scripts that get executed.
* **Deserialization RCE** — sending crafted serialized objects to trigger gadget chains.
* **Language-specific eval** — PHP `eval()`, Python `eval/exec`, Node.js `vm.runInThisContext()`.

## Test payloads

**Command injection basics:**

```
; id
&& whoami
| uname -a
`cat /etc/passwd`
```

**Windows command injection:**

```
& whoami
| dir
```

**Template injection:**

```
{{7*7}}
${7*7}
<%= 7*7 %>
```

## Parameters/Places to fuzz

```
cmd
command
exec
execute
shell
path
file
filename
template
```

## Testing steps

1. Identify input reflected in command output, error messages, or delays.
2. Inject time-based commands (`ping -c 5 127.0.0.1`) to confirm execution.
3. For file uploads, attempt to upload simple script (e.g., PHP: `<?php echo system($_GET['cmd']); ?>`) and access it.
4. Test template rendering contexts with math payloads, then escalate to file read or RCE payloads.
5. In suspected deserialization points, test with harmless serialized objects to confirm processing, then try gadget chains.
6. Use Burp Collaborator or similar to detect out-of-band execution.

## Detection and response checks

* Ensure user input is not concatenated into system commands.
* Restrict file uploads to safe types, validate on server side.
* Use safe template rendering (disable code execution features).
* Implement allowlists for commands and arguments.

## Reporting checklist

* Endpoint and vulnerable parameter.
* Exact payloads used and observed output/effect.
* Evidence of code execution (command output, file creation, OOB interaction).
* Recommended mitigations: parameterized APIs, strict validation, sandboxing, avoiding dangerous functions.

---