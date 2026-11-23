# Needs validation: volgenic/vault, run 1

These are five leads. Each passed an independent Phase 3 verifier and a fresh-eyes Phase 5 verifier, at commit 9b36136. None of them is a confirmed vulnerability, and none has a severity. Each one waits on a fact that is outside this repository, or that only a live call could show, and this audit makes no live calls. They are listed in priority order. Every trace is repository-relative.

## 1. Proxy forwards caller-chosen method/path override headers, so an upstream that honors them escapes the key's method and path rule

Fingerprint: `rules.rs/check_caller_headers/method-and-path-override-headers-not-refused`

**Why this priority:** The proxy's method/path rule is the vault's main limit on what an API key is used for. The fix is a five-entry denylist addition.

The proxy binds an API key to its rule's methods and path prefix (README.md:190: the key goes 'only to the rule's host, method and path'). That binding is checked only against the request line: rules::check_against_rule (src/rules.rs:231-243) compares the caller's method and path with the rule. The caller header filter, rules::check_caller_headers (src/rules.rs:258-285), is a denylist of transport and routing headers (REFUSED_HEADERS at src/rules.rs:45-59, plus the x-forwarded- and proxy- prefixes at :275-276). It does not refuse request-rewriting headers such as X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override, X-Original-URL or X-Rewrite-URL. proxy::send (src/proxy.rs:88-94) appends every accepted header to the request it sends to the rule's host with the key in the rule's header. Every agent on the machine can call proxy (src/protocol.rs:3-4). So a request such as POST /v1/public/items/1 with x-http-method-override: DELETE passes a 'GET,POST /v1/public' rule, while a direct DELETE is refused rule_mismatch. The hunter's bounded probe of proxy::check (agents/hunter-proxy/artifacts/out.txt) shows that result, and the source reproduces it deterministically. If the upstream honors such a header, it performs a method or path the owner's rule did not grant, using the owner's key. Google APIs document X-HTTP-Method-Override, Rack::MethodOverride and Symfony/Laravel honor method overrides on POST, and IIS and Symfony honor X-Original-URL and X-Rewrite-URL. A query or body parameter such as _method=DELETE has the same effect through a channel the vault cannot filter generically, so a header denylist narrows the problem but cannot close it alone. The impact exists only when an upstream the owner has a rule for honors an override, and only when that rule is narrower than the key's own scope at the provider.

**Root cause claimed:** rules::check_caller_headers enforces a denylist (REFUSED_HEADERS plus the x-forwarded-* and proxy-* prefixes) aimed at transport and routing headers. It has no entry for the well-known method-override and URL-rewrite headers. The vault's method and path decision (check_against_rule on the request line) and the upstream's effective method and path can therefore differ.

**Trace:**

- entrypoint: `src/protocol.rs:674` (parse_request "proxy"). Any same-UID agent's socket request: method, path and the headers object are parsed into Request::Proxy.
- propagation: `src/server.rs:1476` (Server::proxy). After check_destination, proxy::check is the only gate before the audited send.
- propagation: `src/proxy.rs:58` (proxy::check). check_against_rule compares only the request-line method and path with the rule.
- propagation: `src/rules.rs:272` (check_caller_headers). A header name is refused only when it is in REFUSED_HEADERS, is the rule's own header, or starts with x-forwarded- or proxy-. x-http-method-override, x-http-method, x-method-override, x-original-url and x-rewrite-url all pass.
- sink: `src/proxy.rs:105` (proxy::send). The accepted override headers, appended at line 93, are sent to the rule's host with the key in the rule's header, which is inserted at line 99.

**Evidence:**

- `src/rules.rs:45`: REFUSED_HEADERS lists only transport, routing and auth headers, with no method-override or URL-rewrite header.
- `src/rules.rs:275`: The prefix refusals cover only x-forwarded- and proxy-.
- `src/rules.rs:233`: The method binding checks only the request-line method against rule.methods.
- `src/proxy.rs:93`: Every accepted caller header is appended to the outgoing request.
- `README.md:190`: The stated control: the key goes only to the rule's host, method and path.
- `src/protocol.rs:4`: Every agent on the machine can make every socket request, proxy included.

**What it waits on:**

- Whether any upstream the owner holds an API-key rule for honors X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override, X-Original-URL or X-Rewrite-URL (or a _method parameter) is a provider fact outside the repository, and no provider may be called in this audit.
- Whether any of the owner's real rules restrict method or path more narrowly than the key's own scope at the provider (for example a GET-only or single-path rule on a key that can also write or delete). Without that, the override gains nothing the rule did not already grant.

**How to settle it:**

- Locally, with a bounded fixture: Source alone shows that proxy::check accepts the override headers and refuses the direct method (src/rules.rs:45-59, 272-277; agents/hunter-proxy/artifacts/out.txt). To show the upstream effect without a provider, add a probe binary in the audit wrapper. It starts a loopback HTTPS fixture with a self-signed certificate. The fixture dispatches on X-HTTP-Method-Override when the request line is POST (the Rack/Symfony behavior) and records the effective method and path. The probe builds its own reqwest blocking Client that trusts the fixture's certificate and resolves the rule host to 127.0.0.1 (ClientBuilder::resolve). It then calls proxy::send with a dummy key and a rule such as 'GET,POST https://api.example.test:<port>/v1/public'. Expected result: the fixture records DELETE /v1/public/items/1 while the vault checked POST, and a direct DELETE is refused rule_mismatch before any connection is made. Proposed fix: add x-http-method-override, x-http-method, x-method-override, x-original-url and x-rewrite-url to REFUSED_HEADERS in src/rules.rs, which also covers stream calls that use check_caller_headers. Document in README.md that query and body overrides (_method) are not filtered and remain the upstream's to refuse.
- Observed by the owner, with no audit traffic sent to a provider unless the owner approves that run: Owner-observed, with no provider calls: run `vault list` and, for each api_key secret, read its rule (methods and path prefix). For each rule whose methods or path are narrower than what the key itself can do at the provider, check the provider's documentation for X-HTTP-Method-Override / X-HTTP-Method / X-Method-Override, X-Original-URL / X-Rewrite-URL, or _method support. Google APIs document X-HTTP-Method-Override. If any rule is both narrower than its key and points at a host that honors an override, this is a real escape of the rule binding for that key.

## 2. Path check allows '..;' segments and double-encoded dots, which some upstream servers normalize outside the rule's path prefix

Fingerprint: `rules.rs/check_path/dotdot-semicolon-and-double-encoding-pass-prefix`

**Why this priority:** Same boundary as the lead above: a rule's path prefix. The fix is two refusals in check_path.

An API key's rule binds it to a path prefix, and the README states the key goes 'only to the rule's host, method and path' (README.md:190). check_path refuses literal '.'/'..' segments and the single-encoded forms %2f, %5c, %2e and %00, and path_within then compares the raw path with the prefix on whole segments. A segment such as '..;' or a double-encoded '%252e%252e' passes both checks: '..;' is not equal to '..', and '%252e' contains no '%2e' substring. reqwest's URL parser does not treat either as a dot segment, so the bytes reach the wire unchanged. The hunter's probe (agents/hunter-proxy/artifacts/out.txt, lines 8-9) shows proxy::check accepting GET /v1/public/..;/admin/keys and GET /v1/public/%252e%252e/admin under a rule with prefix /v1/public, with the wire path unchanged. Some upstreams strip path parameters before resolving dot segments, as Tomcat-style servlet containers do with '..;'. Others decode twice. Such an upstream would route these requests to /v1/admin/keys and /v1/admin, outside the granted prefix, with the owner's key. Any caller of the socket can reach this path; the host relays agent requests to it.

**Root cause claimed:** The rule's path binding is decided on the vault's own literal segment view, while an upstream router may apply a different normalization before matching (path-parameter stripping or a second percent-decode). check_path does not refuse a segment whose part before ';' is '.' or '..', and it does not refuse '%25' followed by an encoded dot, slash or backslash.

**Trace:**

- entrypoint: `src/protocol.rs:674` (parse_request "proxy"). The caller chooses the proxy request's path string (ProxyWire.path).
- propagation: `src/server.rs:1476` (proxy op handler). The caller's path, unchanged, goes to proxy::check against the key's rule.
- propagation: `src/rules.rs:188` (check_path). Only single-encoded %2f, %5c, %2e and %00 are refused; '%252e' has no '%2e' substring and passes.
- propagation: `src/rules.rs:193` (check_path). Only segments exactly equal to '.' or '..' are refused; '..;' is a different segment and passes.
- propagation: `src/rules.rs:210` (path_within). The raw path /v1/public/..;/admin/keys starts with /v1/public followed by '/', so it counts as under the prefix.
- sink: `src/proxy.rs:101` (proxy::send). The request goes to the rule's host with the key header inserted at line 99, and the path is unchanged.

**Evidence:**

- `src/rules.rs:188`: The list of refused encodings lacks the double-encoded forms (%25).
- `src/rules.rs:193`: Dot segments are refused only on an exact match, so '..;' passes.
- `src/proxy.rs:79`: The URL is built from the checked path, and Url::parse at line 80 does not treat '..;' or '%252e%252e' as dot segments.
- `README.md:190`: Stated control: the key goes only to the rule's host, method and path.
- `agents/hunter-proxy/artifacts/out.txt:8`: Probe: under prefix /v1/public, GET /v1/public/..;/admin/keys is ACCEPTED, and the wire path is unchanged.
- `agents/hunter-proxy/artifacts/out.txt:9`: Probe: GET /v1/public/%252e%252e/admin is ACCEPTED, and the wire path is unchanged.

**What it waits on:**

- It is unknown whether any upstream the owner holds an API-key rule for (with a prefix narrower than '/') normalizes '..;' segments or double-decodes paths before routing and authorizing. That is a provider fact outside the repository, and no provider may be called to find out.

**How to settle it:**

- Locally, with a bounded fixture: Run a loopback HTTPS fixture (for example an embedded Tomcat) that strips ';' path parameters before resolving dot segments, plus a second fixture that percent-decodes twice. Build with the test-upstream feature and a rule for 127.0.0.1 with prefix /v1/public, then send GET /v1/public/..;/admin/keys and GET /v1/public/%252e%252e/admin through proxy::send. Record which route the fixture reached (expected: /v1/admin/keys and /v1/admin). Source fix: in check_path, refuse any segment whose part before its first ';' is '.' or '..', and refuse '%25' anywhere in the path (or at least '%25' followed by 2e, 2f or 5c). Apply the same check to stream paths if they are agent-chosen.
- Observed by the owner, with no audit traffic sent to a provider unless the owner approves that run: Owner-observed and non-destructive: list each API-key rule whose path prefix is narrower than '/' (vault list shows the rules). For each provider, check its public documentation or server headers to see whether its API front end is a Java servlet container or otherwise strips ';' path parameters or double-decodes paths. Send no requests that use the key.

## 3. Google AI login stream: query-string forms of the refused API-key and quota-project headers pass to Cloud Code

Fingerprint: `src/kinds.rs:GOOGLE_AI_LOGIN:query-system-parameters-unrefused`

**Why this priority:** Could bill another Cloud project or use another key under the owner's Google sign-in.

The google_ai_login kind states that another way of naming a credential or a billed project (an API key, a cookie, a quota project) is refused so a call only uses the owner's plan (src/kinds.rs:217-218), and implements that only as the refused caller headers x-goog-api-key, cookie and x-goog-user-project (src/kinds.rs:230). stream::plan splits the caller's path with rules::check_path_and_query, which checks the query only for printable ASCII (src/rules.rs:165-166), matches the kind's path prefixes against the path part alone (src/stream.rs:115, src/rules.rs:207-208), compares only headers with spec.refused_headers (src/stream.rs:119), and rebuilds path?query verbatim (src/stream.rs:80-81). Streamer::request then sends https://<cloudcode host>/v1internal:<method>?<caller query> with the owner's Authorization: Bearer token inserted by the vault (src/stream.rs:439). So a same-UID socket caller can send POST /v1internal:generateContent?key=<key>&userProject=<project> (or $userProject / quotaUser) and the vault forwards those Google system-parameter equivalents of the refused headers with the owner's Google AI token. Source alone shows the stated control is header-only; whether Cloud Code honors the query forms on /v1internal with an OAuth bearer, and what that would bill or attribute, is upstream behavior not visible here. The request body is also forwarded uninspected; that is a separate surface not claimed here.

**Root cause claimed:** The kind table expresses the 'no other credential or billed project' rule only as a caller-header denylist (KindSpec::refused_headers); stream::plan forwards the caller's query after rules::check_path_and_query, which validates only characters, so query-parameter equivalents of the refused headers (key, userProject/$userProject, quotaUser) are never compared against the kind's policy.

**Trace:**

- entrypoint: `src/protocol.rs:694` (parse_request stream). A same-UID socket caller's stream request carries a caller-chosen path, including its query string, into Request::Stream.
- propagation: `src/server.rs:1159` (Server::stream). The caller's path and headers are passed to stream::plan for the stored google_ai_login record; only the query-stripped path is logged (line 1140).
- propagation: `src/rules.rs:165` (check_path_and_query). The query is accepted when every byte is printable ASCII; its parameter names and values are not inspected.
- propagation: `src/stream.rs:80` (plan). path_and_query is rebuilt as path?query and kept for the upstream request; the prefix check (line 115) uses only the path and the refused list is applied only to headers (line 119).
- sink: `src/stream.rs:439` (Streamer::request). The URL https://<cloudcode host>/v1internal:<method>?key=...&userProject=... is built from plan.path_and_query and sent with the owner's Authorization: Bearer access token set by the vault.

**Evidence:**

- `src/kinds.rs:217`: Stated control: another way of naming a credential or a billed project (an API key, a cookie, a quota project) is refused so a call only ever uses the owner's plan.
- `src/kinds.rs:230`: The control is implemented only as refused header names x-goog-api-key, cookie, x-goog-user-project.
- `src/rules.rs:166`: The only query check is that every byte is ASCII graphic; no parameter is refused.
- `src/rules.rs:208`: path_within for the '/v1internal:' prefix is applied to the path part only, so /v1internal:generateContent?key=X is in scope.
- `src/stream.rs:119`: spec.refused_headers is passed only to rules::check_caller_headers; nothing compares it with the query.

**What it waits on:**

- Whether daily-cloudcode-pa.googleapis.com / cloudcode-pa.googleapis.com honor Google's system query parameters key=, userProject= (or $userProject) and quotaUser= on /v1internal calls made with an OAuth bearer token is upstream behavior not visible in this repository.
- Whether the owner's Google account holds serviceusage.services.use on any billed Cloud project such a parameter could name (the financial impact) is account state outside source.

**How to settle it:**

- Locally, with a bounded fixture: In the scratch copy, add a temporary pub wrapper in src/stream.rs (scratch only) and a probe bin that builds a dummy google_ai_login Record and calls stream::plan with method POST, path '/v1internal:generateContent?key=AIzaDUMMY&userProject=dummy-project' and no headers; expect Ok with path_and_query containing both parameters. Then call it with path '/v1internal:generateContent' and headers [("x-goog-api-key","AIzaDUMMY")] and separately [("x-goog-user-project","dummy-project")]; expect a header-refused error. No network: plan is pure.
- Observed by the owner, with no audit traffic sent to a provider unless the owner approves that run: Owner-observed, no-cost, with the owner's approval of the run: in a Google Cloud project the owner controls with no billing attached, open its APIs & Services metrics for the Gemini for Google Cloud / Cloud Code API, make one vault stream call to POST /v1internal:loadCodeAssist with ?userProject=<that project id>, and separately one with ?key=<a restricted test API key from that project>. If the call is attributed to that project in its metrics, or refused with a project/key-specific error (e.g. API not enabled / permission denied on that project), the query form reaches Google's parameter handling and the bypass is real; if both calls behave identically to a call without the parameters and nothing is attributed to the project, the parameters are ignored and the candidate is rejected.

## 4. A stream caller who can make the upstream answer 401 to a valid token gets the login marked Refused, which stops the vault renewing it

Fingerprint: `src/server.rs:stream:caller-induced-401-marks-login-refused`

**Why this priority:** An availability risk to a signed-in login. It needs two facts from outside the repository.

For a login kind (Codex, Grok, Google AI), Streamer::run holds back any 401 on a login call (stream.rs:344) before classification. Server::stream then renews the login with early=false (server.rs:1209-1214), which calls the token server and rotates the refresh token with no early-gap throttle, and retries the same caller-shaped request once. If the retry also gets 401, server.rs:1231 records HealthState::Refused for the renewed version, ignoring whether the body said expired. While that entry stands, renewable() returns None (server.rs:1271), so upkeep (server.rs:1401) and pre-call renewal (server.rs:1165) skip the login, health/status report it refused, and the caller gets credential_refused (sign in again). The caller picks the method, any path under the kind's prefixes, the body, and every header outside the set and refused lists; for Grok the kind table says the caller's own x-xai-token-auth and x-grok-* headers pass through (kinds.rs:189). Recovery is source-visible and limits the impact: stream does not gate the call itself on Refused, and a later 2xx at the same version is classified Works (stream.rs:428, server.rs:1252), which clears Refused (health.rs:56). So the login dies only if no call succeeds at that version before its access token expires, and an attacker who alternates an induced-401 call with a 2xx call forces one refresh-token rotation per cycle. At the socket itself this is no more than same-UID self-impact: any socket caller can delete or rename the login outright (server.rs:733). It matters only if the host relays a container agent's stream path and headers while denying that agent delete and rename, and only if some caller-controlled input makes the real upstream answer 401 to a valid token. Both facts are outside this repository.

**Root cause claimed:** Server::stream reads any 401 on a caller-shaped request (caller path, body and pass-through headers) after a fresh renewal as proof the login is dead, and writes Refused to the health book (server.rs:1231). Refused then gates renewal by (id, version) in renewable() (server.rs:1271), stays sticky against later non-Works observations (health.rs:55-57), and persists in health.json. The health signal that controls token upkeep comes from replies to requests the caller shaped, not only from the token server's answer.

**Trace:**

- entrypoint: `src/server.rs:1135` (Server::stream). A socket caller (or the host relaying an agent's call) asks to stream with a login secret. It chooses the host from the kind's list, the method, the path, the headers and the body.
- propagation: `src/stream.rs:119` (stream::plan). Caller headers pass through except the set, the refused, x-forwarded-* and proxy-* ones (rules.rs:258-286). The path may be anything under the kind's prefixes.
- propagation: `src/kinds.rs:189` (GROK_LOGIN). Source says the caller's own x-xai-token-auth and x-grok-* headers pass through to cli-chat-proxy.grok.com. Only x-api-key and cookie are refused beyond authorization.
- propagation: `src/stream.rs:344` (Streamer::run). With hold_auth_error (always true for a login kind), any 401 status is returned as end=auth_error before the body is read or classified, whatever caused it.
- propagation: `src/server.rs:1214` (Server::stream 401 branch). renew_login with early=false: a token-server renewal that rotates the refresh token, throttled only by RENEW_RETRY after a failed renewal. Then the same plan and body are retried once.
- propagation: `src/server.rs:1231` (Server::stream 401 branch). A second 401 records HealthState::Refused for the renewed version and answers credential_refused.
- sink: `src/server.rs:1271` (Server::renewable). Refused at the current version makes renewable() return None, so upkeep (server.rs:1401) and pre-call renewal (server.rs:1165) stop renewing the login until a Works observation or a new version.

**Evidence:**

- `src/server.rs:1209`: The renew-and-retry runs for any held 401 when the login is renewable. Nothing checks whether the 401 is about the token or about the caller's request.
- `src/server.rs:1231`: self.observe(record, HealthState::Refused, Some(401), None) after the retry's 401. The body is never read, so an 'expired' 401 is also recorded as Refused.
- `src/health.rs:55`: A Refused entry stays for its version until a Works reply. Expired cannot clear it.
- `src/health.rs:5`: The book is written to health.json and survives a daemon restart.
- `src/server.rs:1315`: The early-gap throttle applies only when early is true. The 401 path passes false, so each induced-401 cycle costs one refresh-token rotation.
- `src/stream.rs:428`: Recovery: a non-held reply is classified, and a 2xx is Works. server.rs:1252 records it, which clears Refused at that version (health.rs:56). Stream itself does not refuse a Refused login, so an ordinary successful call heals the state while the access token is valid.
- `src/server.rs:733`: Calibration: delete (and rename at server.rs:736) have no gate beyond the peer-UID check. A socket-level caller can already remove the login, so the candidate has impact only through a host relay that permits stream but not delete or rename.
- `src/kinds.rs:281`: classify_login also maps a plain 401 to Refused. For login kinds this arm is not reached on the stream path, because the 401 is held at stream.rs:344 first. It shows the same design reading of 401 as a dead credential.

**What it waits on:**

- Whether any caller-controllable input in scope makes the real upstream answer 401 while the bearer token is valid. In scope are a path under /backend-api/codex, /backend-api/wham/usage, /v1 or /v1internal, a pass-through header such as Grok's x-xai-token-auth or x-grok-*, or a body. This is upstream behavior, and finding out needs a live provider call, which this audit forbids.
- Whether volgenic/host relays a container agent's stream path and headers to the vault unchanged while denying that agent the delete and rename ops. If any principal that can reach stream can also call delete or rename (server.rs:733-740), the impact is no more than same-UID self-impact under the accepted design (protocol.rs:3-4).

**How to settle it:**

- Locally, with a bounded fixture: In a scratch copy built with feature test-upstream, point the Grok kind at a loopback fixture. The fixture answers 401 only when the request carries x-xai-token-auth and 200 otherwise, and a loopback token-server fixture always renews. Send one stream call with that header. Expect two upstream requests and one renewal; health.json and health then show refused at version N+1, and upkeep skips the login. Send one call without the header: expect a 2xx, and health shows works at N+1, which confirms the self-healing path. Repeat the pair and count one token-server call per cycle.
- Observed by the owner, with no audit traffic sent to a provider unless the owner approves that run: Owner check, no paid call. In volgenic/host, read the stream relay for container agents: list which caller headers and paths it forwards, and whether those agents can reach delete or rename. If they can, close the candidate as self-impact. If they cannot, use provider documentation or a scout (no live request) to check whether cli-chat-proxy.grok.com, chatgpt.com/backend-api/codex or cloudcode-pa answer 401 to a malformed client header, path or body when the token is valid.

## 5. Caller-supplied names, methods, paths and hosts reach the owner's terminal raw in `vault audit` and `vault status`

Fingerprint: `vault:main.rs:show_audit:raw-audit-text-to-terminal`

**Why this priority:** This pull request's fix H-01 already closes the terminal side, for `vault audit` and `vault status`. Validation now decides only whether the daemon should also filter the text when it stores it.

The daemon copies caller-supplied text into audit events without removing control characters. This covers unknown secret names (event.name via SecretRef::label, which protocol::secret_ref never validates), the proxy and stream method (truncated to 16 chars) and path (200 chars, copied before rules::check_path), a refused host (253 chars) and RuleMismatch detail, which repeats the full method. `vault audit` (show_audit) prints these fields with plain `{}`. So does the recent-changes list in `vault status`, which includes denied delete and rename events because is_change does not look at the outcome. A local probe of the library showed that ESC, CR, LF and OSC/BEL bytes are kept as JSON escapes on disk, come back as raw bytes after read_all and the JSON reply round trip, and survive into the show_audit format string. On a terminal they could erase or overwrite earlier audit lines, forge audit-looking lines or send OSC commands, while the CLI still prints 'hash chain intact'. Sibling fields (fill notes, mirror-report detail, lease job, sign recipient, request_id) do strip control characters, so the filter is applied unevenly. Direct socket callers are same-UID, which is an accepted trade-off, so the case needs a cross-boundary relayed producer. volgenic/core's vault relay sanitizes proxy, delete and rename fields. volgenic/host's browser engine passes an agent's `account` unfiltered into `fill`, so whether some relay upstream of it filters `account` decides whether this is reachable.

**Root cause claimed:** Audit events store caller-controlled strings verbatim (src/server.rs:391, 949, 1142-1145, 1426-1429, 1434, 1455; names unvalidated at src/protocol.rs:647 and src/model.rs:326). show_audit and status print the decoded audit fields with plain Display and do not escape control characters (src/main.rs:863-879, 849; src/vault.rs:1211), unlike the filtered sibling fields (src/fill.rs:75, src/server.rs:832, 902, 1056).

**Trace:**

- entrypoint: `src/server.rs:690` (Server::dispatch Request::Fill). A fill request carries a caller-chosen secret name (relayed from the host browser engine's `account`) and origin. Only engine, tab and on_behalf_of pass through fill::note.
- propagation: `src/protocol.rs:647` (secret_ref). A name becomes SecretRef::Name with no validation (only an id is checked)
- propagation: `src/server.rs:949` (Server::fill error branch). On a fill denial (for example no_such_login) the raw SecretRef label, with any characters including ESC, CR and LF, becomes event.name
- propagation: `src/server.rs:1428` (Server::proxy). Same root cause for proxy: the raw method (16 chars) and raw path (200 chars, before check_path) are copied into the event. A refused host is copied raw at line 1455, and RuleMismatch detail at line 1434
- propagation: `src/audit.rs:155` (append_line). The event is serialized as JSON and appended to the chain. Control characters are kept as JSON escapes (probe: \u001b, \r\n and \u0007 on disk)
- propagation: `src/server.rs:340` (Server::audit_report). Audit lines are read back and returned to the CLI as AuditReply. Once decoded, the control characters are raw again (probe: ESC, CR/LF and BEL present after read_all and a JSON round trip)
- sink: `src/main.rs:879` (show_audit). name, method, host, path, detail and peer_program are formatted with {} and printed raw to the owner's terminal (probe: 5 raw ESC bytes in the show_audit-formatted line)

**Evidence:**

- `src/main.rs:863`: The event name is padded and printed with {:<22}, with no escaping
- `src/main.rs:865`: method, host and path are concatenated raw into the printed line
- `src/main.rs:849`: vault status prints recent changes (built at src/vault.rs:1211 from event and raw name) raw. Denied delete and rename count as changes because is_change (src/audit.rs:90) ignores the outcome
- `src/model.rs:326`: SecretRef::label returns the caller's name unvalidated
- `src/server.rs:1455`: A refused caller host is logged raw, up to 253 characters
- `src/rules.rs:234`: RuleMismatch detail repeats the full, untruncated method. It is stored as event.detail at src/server.rs:1434 (stream: src/stream.rs:113, stored at src/server.rs:1150)
- `src/fill.rs:75`: Sibling control: fill notes strip control characters. The same filter is applied at src/server.rs:832, 902 and 1056, but not to these fields
- `agents/verify-p3-audittext/artifacts/out.txt:1`: Local library probe (dummy data, hygiene wrapper; pending parent promotion). The on-disk line holds JSON escapes, and after read_all plus a JSON round trip the decoded name, method and path again contain ESC, CR/LF and OSC/BEL bytes. The show_audit-formatted line carries 5 raw ESC bytes

**What it waits on:**

- No in-repo cross-boundary producer is established. Whether any relay in front of volgenic/host fleet/browser/engine.mjs:1149 (which passes String(args.account) unfiltered to the vault's fill name) rejects control characters in `account` is outside this repository. A read-only grep of volgenic/core lib found no browser sign-in relay to inspect, so the agent-to-host path for `account` was not located
- The core vault relay (volgenic/core lib/volgenic/core/host/vault_ops.ex, per the hunter's read-only check) sanitizes the proxy, delete and rename name, method, path and host, so no other relayed producer of these fields was identified. Direct socket callers are same-UID, which is accepted
- The CLI output path was not exercised end to end against a daemon, because running `vault daemon` is outside the execution boundary. Only the library append, read_all, JSON round trip and show_audit format were reproduced, under a hygiene wrapper with no OS sandbox, and the out.txt artifact depends on parent-side promotion

**How to settle it:**

- Locally, with a bounded fixture: Done here (agents/verify-p3-audittext/artifacts/out.txt). A scratch probe built an AuditEvent with name "x\u001b[1A\u001b[2Kforged\r\n...", method "G\u001b[2K", host "h\u001b[2K.example" and path "/p\u001b]0;title\u0007". It appended the event with vault::audit::append to a scratch log, read it back with vault::audit::read_all, round-tripped it through serde_json and formatted it as show_audit does: the raw ESC, CR/LF and BEL bytes survive. Regression case for the fix: show_audit, the status recent-changes builder and every audit field printer escape non-printable characters (for example with char::escape_debug or a shared printable() filter), or the daemon filters them where it builds the AuditEvent and in with_peer. The same fixture must then print as visible escapes.
- Observed by the owner, with no audit traffic sent to a provider unless the owner approves that run: Owner-observed and non-destructive. From a container agent, call the browser sign-in tool with `account` set to a dummy string such as "nosuch\u001b[2K\rFAKE LINE" against any page with a login form, so the vault refuses it with no_such_login. Then run `vault audit | cat -v` on the host and check whether the fill-denied line shows ^[ escape bytes (reachable) or whether the request was refused upstream with a validation error (not reachable). Also confirm which service relays the agent's browser tool call to the host engine, and whether it validates `account`.
