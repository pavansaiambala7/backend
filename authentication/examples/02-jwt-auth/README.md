# 02 — JWT authentication: RS256 access tokens + rotating refresh tokens

A stateless Spring Boot REST API that issues and verifies its own tokens, done the way 2026 production
systems do it: a short-lived **RS256 JWT access token** in the response body, an **opaque refresh token** in
an `HttpOnly; Secure; SameSite=Strict` cookie, **rotation on every refresh with reuse detection**, a
**JWKS endpoint** with `kid`-based key rotation, and a resource server that validates signature, `typ`,
`iss`, `aud`, `exp`, `nbf` and `iat` and then authorizes by **scope**.

**Read with:**

- [Chapter 06 — Tokens and JWT](../../docs/06-tokens-and-jwt.md): sections
  [7 (validation checklist)](../../docs/06-tokens-and-jwt.md#7-the-complete-validation-checklist),
  [9 (refresh rotation with reuse detection)](../../docs/06-tokens-and-jwt.md#9-refresh-token-rotation-with-reuse-detection),
  [12 (kid, JWKS and rotation)](../../docs/06-tokens-and-jwt.md#12-key-management-kid-jwks-caching-and-rotation),
  [15 (attacks)](../../docs/06-tokens-and-jwt.md#15-common-attacks-and-mistakes) and
  [17 (Spring)](../../docs/06-tokens-and-jwt.md#17-spring-boot-4--spring-security-7) are implemented here
- [Chapter 08 — OAuth 2, section 8 (refresh token grant)](../../docs/08-oauth-2.md#8-refresh-token-grant): the same rotation rules an authorization server applies
- [Chapter 04 — Sessions, cookies and CSRF, section 7](../../docs/04-sessions-cookies-and-csrf.md#7-csrf-in-depth): why the cookie endpoints need CSRF protection
- [Chapter 13 — Authorization, section 9 (scopes vs fine-grained permissions)](../../docs/13-authorization-rbac-abac-rebac.md#9-oauth-scopes-vs-fine-grained-permissions)
- [Chapter 14 — Production architecture](../../docs/14-production-architecture-and-checklist.md): key rotation, JWKS caching, clock skew, lifetimes and logout

Stack: Java 21, Spring Boot 4.1.1 (Spring Framework 7.0, Spring Security 7.1.1), Nimbus JOSE + JWT,
Spring Data JPA, H2.

> **When to use this design.** This is a *first-party* token service: the API checks the password itself
> and both sides are yours. As soon as several applications, third parties or an external identity
> provider are involved, use an authorization server with OAuth 2 + OpenID Connect instead
> ([`../03-oauth2-oidc/`](../03-oauth2-oidc/)); the resource-server half of this example stays the same.
> For browser apps, the BFF pattern ([chapter 06, section 11](../../docs/06-tokens-and-jwt.md#11-where-to-store-tokens-in-browsers))
> keeps even the access token out of the browser; here the SPA holds it **in memory only**, never in
> `localStorage`.

---

## What it demonstrates

| Security property | How | Where |
|---|---|---|
| Short-lived, asymmetric access tokens | RS256, 15 minutes, RFC 9068 profile: header `typ: at+jwt` and `kid`; claims `iss`, `sub`, `aud`, `scope`, `client_id`, `iat`, `nbf`, `exp`, `jti` | [`AccessTokenService`](src/main/java/com/backend/auth/jwt/token/AccessTokenService.java) |
| Algorithm allowlist | `NimbusJwtDecoder...jwsAlgorithm(RS256)`: the verifier picks the algorithm, so `alg: none` and HS256-with-the-public-key never reach a claim check; keys are bound to RS256 | [`JwtConfig`](src/main/java/com/backend/auth/jwt/token/JwtConfig.java), [`InMemorySigningKeyStore`](src/main/java/com/backend/auth/jwt/keys/InMemorySigningKeyStore.java) |
| Full claim validation | `JwtValidators.createAtJwtValidator()`: `typ`, `iss`, `aud`, required `sub`/`jti`/`client_id`; `exp`/`nbf` with a **30 s** skew; `iat` not in the future | `JwtConfig` |
| Keys never chosen by the token | Verification keys come only from the server's own key set; `jwk`, `jku`, `x5u` headers are ignored; unknown `kid` fails | `JwtConfig` |
| JWKS with rotation | `GET /.well-known/jwks.json` publishes public keys only, `Cache-Control: max-age=300, public`; `publishNewKey` → `activate` → `retire` | [`JwksController`](src/main/java/com/backend/auth/jwt/keys/JwksController.java), `InMemorySigningKeyStore` |
| Opaque refresh tokens, hashed at rest | 256 bits from `SecureRandom`, Base64URL; only the SHA-256 hash is stored | [`OpaqueTokens`](src/main/java/com/backend/auth/jwt/refresh/OpaqueTokens.java), [`schema.sql`](src/main/resources/schema.sql) |
| Rotation with reuse detection | Each refresh marks the token used and issues a successor in the same family; presenting a used token revokes the whole family; row lock + compare-and-set make concurrent use count as reuse | [`RefreshTokenService`](src/main/java/com/backend/auth/jwt/refresh/RefreshTokenService.java), [`RefreshTokenRepository`](src/main/java/com/backend/auth/jwt/refresh/RefreshTokenRepository.java) |
| Bounded refresh lifetime | Idle timeout 1 day, absolute 7 days per family (rotation never extends a login) | [`RefreshToken`](src/main/java/com/backend/auth/jwt/refresh/RefreshToken.java) |
| Hardened refresh cookie | `__Secure-` prefix, `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/auth`, no `Domain`; never in the JSON body | [`RefreshCookies`](src/main/java/com/backend/auth/jwt/web/RefreshCookies.java) |
| CSRF protection for the cookie endpoints | `SameSite=Strict` + required `X-CSRF-Protection` header + `Origin` allowlist + `Sec-Fetch-Site` check; login accepts JSON only | [`AuthEndpointCsrfFilter`](src/main/java/com/backend/auth/jwt/security/AuthEndpointCsrfFilter.java) |
| Real logout | `POST /auth/logout` revokes the family and expires the cookie; always `204` | [`AuthController`](src/main/java/com/backend/auth/jwt/web/AuthController.java) |
| Account changes take effect | Every refresh re-loads the user: disabled accounts lose their family, scope changes apply at the next refresh | [`AuthService`](src/main/java/com/backend/auth/jwt/web/AuthService.java) |
| Scope-based authorization | `hasAuthority("SCOPE_orders:read")` / `SCOPE_orders:write`; 403 with `insufficient_scope`; everything not listed is denied; orders are still filtered by owner | [`SecurityConfig`](src/main/java/com/backend/auth/jwt/security/SecurityConfig.java), [`OrderController`](src/main/java/com/backend/auth/jwt/api/OrderController.java) |
| Argon2id password hashes | `DelegatingPasswordEncoder` with Argon2id (m=19456 KiB, t=2, p=1) by default, bcrypt accepted for legacy hashes and upgraded at login; unknown users cost the same hash | [`UserConfig`](src/main/java/com/backend/auth/jwt/user/UserConfig.java) |
| No account enumeration | One `401 invalid_credentials` body for unknown user and wrong password; one `401 invalid_refresh_token` for every refresh failure (the reason is only logged) | [`ErrorResponse`](src/main/java/com/backend/auth/jwt/web/ErrorResponse.java) |

## The flow

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (SPA in memory, or mobile app)
    participant A as /auth endpoints
    participant DB as refresh_token table
    participant K as Signing key store
    participant R as /api (resource server)

    C->>A: POST /auth/login {username, password} + X-CSRF-Protection
    A->>A: Argon2id verify (dummy hash for unknown users)
    A->>K: Sign RS256 access token with the active kid (15 min)
    A->>DB: Insert SHA-256(RT1), new family F, expires in 7 days
    A-->>C: 200 {access_token, expires_in: 900} + Set-Cookie RT1 (HttpOnly, Secure, SameSite=Strict, Path=/auth)

    C->>R: GET /api/orders, Authorization: Bearer <access token>
    R->>K: Public key for kid (RS256 only)
    R->>R: Verify signature, typ, iss, aud, exp/nbf/iat (30 s skew), then SCOPE_orders:read
    R-->>C: 200 orders of the token's subject

    Note over C,A: About 15 minutes later the access token expires
    C->>A: POST /auth/refresh, Cookie RT1 + X-CSRF-Protection
    A->>DB: SELECT ... FOR UPDATE by SHA-256(RT1); mark RT1 used
    A->>DB: Insert SHA-256(RT2), same family F, parent RT1
    A-->>C: 200 new access token + Set-Cookie RT2

    Note over C,A: An attacker who copied RT1 replays it
    C->>A: POST /auth/refresh, Cookie RT1 (already used)
    A->>DB: Reuse detected: revoke every token in family F
    A-->>C: 401 invalid_refresh_token, cookie cleared
    Note over C,A: RT2 is now dead too: both parties must log in again

    C->>A: POST /auth/logout, Cookie RTn + X-CSRF-Protection
    A->>DB: Revoke family
    A-->>C: 204, cookie expired (access tokens already issued live until exp)
```

## Project layout

```text
src/main/java/com/backend/auth/jwt/
├── JwtAuthApplication.java          Boot entry point, Clock bean
├── keys/                            SigningKeyStore (rotation-ready, kid = RFC 7638 thumbprint), JWKS endpoint
├── token/                           AccessTokenService (issuing), JwtConfig (encoder, decoder, validators)
├── refresh/                         RefreshToken entity, repository, rotation + reuse detection
├── user/                            DEMO users from configuration, Argon2id password encoder
├── security/                        two filter chains, CSRF filter for the cookie endpoints
├── web/                             /auth/login, /auth/refresh, /auth/logout, cookie handling
└── api/                             /api/me, /api/orders (the protected resources)
src/main/resources/
├── application.yml                  issuer, audience, lifetimes, cookie, allowed origins, DEMO users
└── schema.sql                       refresh_token table
```

## Run it

```bash
./mvnw spring-boot:run          # http://localhost:8082
./mvnw test                     # 53 tests, no network needed
```

The signing key is generated in memory at startup and the database is an in-memory H2 instance, so a
restart invalidates every token. DEMO users (configured as Argon2id hashes in `application.yml`):

| User | Password | Scopes |
|---|---|---|
| `alice` | `alice-demo-passphrase` | `orders:read orders:write` |
| `bob` | `bob-demo-passphrase` | `orders:read` |

## curl walkthrough

The responses below are from a real run, trimmed to the relevant lines; tokens, ids and times will differ.
`curl` keeps `Secure` cookies for `http://localhost` (as browsers do), so the cookie jar behaves like a browser.

```bash
BASE=http://localhost:8082
JAR=$(mktemp)                                         # curl cookie jar = the browser's cookie store
b64url_decode() { local p; p=$(tr '_-' '/+'); while [ $(( ${#p} % 4 )) -ne 0 ]; do p="$p="; done; printf %s "$p" | base64 -d; }
b64url_encode() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
```

**1. The public keys.** No authentication; cacheable for 5 minutes; no private parameters.

```bash
curl -s "$BASE/.well-known/jwks.json" | jq .
```

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "U1aMZanM_JIiRw4pMtqZMU2lU3_Devj5MJw30dUaa4E",
      "alg": "RS256",
      "iat": 1791447956,
      "n": "tGUi5rBRbzSthAwc3QwK1HfZXfVBGFuUHj7UM59OI1KFfwxlLZ1NK1Gir_5LZUuxWbVQ...Ryp3VNDj8f-qQ"
    }
  ]
}
```

**2. Log in.** The access token is in the body; the refresh token only in the hardened cookie.

```bash
curl -s -D - -o login.json -c "$JAR" -H 'Content-Type: application/json' -H 'X-CSRF-Protection: 1' \
     -d '{"username":"alice","password":"alice-demo-passphrase"}' "$BASE/auth/login" | grep -iE '^HTTP|^Set-Cookie|^Cache-Control'
jq . login.json
ACCESS=$(jq -r .access_token login.json)
```

```http
HTTP/1.1 200
Set-Cookie: __Secure-refresh_token=InlQcDZNAQ93Wd_vccNh7-k2CloUFfcG03-goXZh5qU; Path=/auth; Max-Age=86400; Expires=Fri, 09 Oct 2026 08:26:43 GMT; Secure; HttpOnly; SameSite=Strict
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
```

```json
{
  "access_token": "eyJraWQiOiJVMWFNWmFuTV9KSWlSdzRwTXRxWk1VMmxVM19EZXZqNU1KdzMwZFVhYTRFIiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJhbGljZSIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "orders:read orders:write"
}
```

**3. Look inside the token.** A JWS is only Base64URL-encoded: anyone holding it can read the claims, so
it carries no secrets.

```bash
cut -d. -f1 <<< "$ACCESS" | b64url_decode | jq -c .
cut -d. -f2 <<< "$ACCESS" | b64url_decode | jq .
```

```json
{"kid":"U1aMZanM_JIiRw4pMtqZMU2lU3_Devj5MJw30dUaa4E","typ":"at+jwt","alg":"RS256"}
{
  "sub": "alice",
  "aud": "jwt-demo-api",
  "nbf": 1791448003,
  "scope": "orders:read orders:write",
  "iss": "http://localhost:8082",
  "exp": 1791448903,
  "iat": 1791448003,
  "jti": "4a80bae0-b7ab-4ab5-88a0-501efd73722b",
  "client_id": "jwt-demo-web"
}
```

**4. Call the API with it** (and without it).

```bash
curl -s -H "Authorization: Bearer $ACCESS" "$BASE/api/me" | jq .
curl -si "$BASE/api/me" | grep -iE '^HTTP|^WWW-Authenticate'
```

```json
{
  "expires_at": "2026-10-08T08:41:43Z",
  "subject": "alice",
  "token_id": "4a80bae0-b7ab-4ab5-88a0-501efd73722b",
  "authorities": [
    "FACTOR_BEARER",
    "SCOPE_orders:read",
    "SCOPE_orders:write"
  ]
}
```

```http
HTTP/1.1 401
WWW-Authenticate: Bearer resource_metadata="http://localhost:8082/.well-known/oauth-protected-resource"
```

`SCOPE_` authorities come from the `scope` claim. `FACTOR_BEARER` is added by Spring Security 7 to record
*how* the request authenticated (useful for MFA rules), and the `resource_metadata` link points to the
RFC 9728 document Spring Security 7 serves for every resource server.

**5. Scopes.** Alice may create orders; Bob (`orders:read` only) may list but not create.

```bash
curl -s -H "Authorization: Bearer $ACCESS" -H 'Content-Type: application/json' \
     -d '{"item":"notebook","quantity":2}' "$BASE/api/orders" | jq -c .
BOB=$(curl -s -H 'Content-Type: application/json' -H 'X-CSRF-Protection: 1' \
     -d '{"username":"bob","password":"bob-demo-passphrase"}' "$BASE/auth/login" | jq -r .access_token)
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $BOB" "$BASE/api/orders"
curl -si -H "Authorization: Bearer $BOB" -H 'Content-Type: application/json' \
     -d '{"item":"pen","quantity":1}' "$BASE/api/orders" | grep -iE '^HTTP|^WWW-Authenticate'
```

```text
{"id":"8784657c-c410-4db0-8391-bd31a56b8331","owner":"alice","item":"notebook","quantity":2,"createdAt":"2026-10-08T08:26:43.449138285Z"}
200
HTTP/1.1 403
WWW-Authenticate: Bearer error="insufficient_scope", error_description="The request requires higher privileges than provided by the access token.", error_uri="https://tools.ietf.org/html/rfc6750#section-3.1"
```

**6. Forgeries fail.** Change `sub` to `admin` and keep the signature; then try the classic `alg: none`.

```bash
HEADER=$(cut -d. -f1 <<< "$ACCESS"); SIG=$(cut -d. -f3 <<< "$ACCESS")
ADMIN=$(cut -d. -f2 <<< "$ACCESS" | b64url_decode | sed 's/"sub":"alice"/"sub":"admin"/' | b64url_encode)
curl -si -H "Authorization: Bearer $HEADER.$ADMIN.$SIG" "$BASE/api/me" | grep -iE '^HTTP|^WWW-Authenticate'
NONE=$(printf '{"alg":"none","typ":"at+jwt"}' | b64url_encode)
curl -si -H "Authorization: Bearer $NONE.$ADMIN." "$BASE/api/me" | grep -iE '^HTTP|^WWW-Authenticate'
```

```http
HTTP/1.1 401
WWW-Authenticate: Bearer error="invalid_token", error_description="An error occurred while attempting to decode the Jwt: Signed JWT rejected: Invalid signature", ...
HTTP/1.1 401
WWW-Authenticate: Bearer error="invalid_token", error_description="Unsupported algorithm of none", ...
```

**7. CSRF: the cookie alone is not enough.** A forged request carries the cookie but cannot add the custom
header, and a browser would label it with a foreign `Origin`.

```bash
curl -si -b "$JAR" -X POST "$BASE/auth/refresh" | grep -E '^HTTP|^\{'
curl -si -b "$JAR" -X POST -H 'X-CSRF-Protection: 1' -H 'Origin: https://evil.example' "$BASE/auth/refresh" | head -1
```

```http
HTTP/1.1 403
{"error":"csrf_check_failed","error_description":"Cross-site request refused"}
HTTP/1.1 403
```

**8. Refresh: the refresh token rotates.**

```bash
OLD=$(awk '/refresh_token/ {print $7}' "$JAR")
curl -si -b "$JAR" -c "$JAR" -X POST -H 'X-CSRF-Protection: 1' "$BASE/auth/refresh" | grep -iE '^HTTP|^Set-Cookie'
NEW=$(awk '/refresh_token/ {print $7}' "$JAR")
echo "old=$OLD"; echo "new=$NEW"
```

```http
HTTP/1.1 200
Set-Cookie: __Secure-refresh_token=2p3XwQLIMimdop4TZ3LGWAYqy7lkv-fCX8SysDt9PDY; Path=/auth; Max-Age=86400; Expires=Fri, 09 Oct 2026 08:26:43 GMT; Secure; HttpOnly; SameSite=Strict
old=InlQcDZNAQ93Wd_vccNh7-k2CloUFfcG03-goXZh5qU
new=2p3XwQLIMimdop4TZ3LGWAYqy7lkv-fCX8SysDt9PDY
```

**9. Replay the old refresh token** (what a thief would do): rejected, and the whole family dies, so the
current token stops working too.

```bash
curl -si -X POST -H 'X-CSRF-Protection: 1' -b "__Secure-refresh_token=$OLD" "$BASE/auth/refresh" | grep -iE '^HTTP|^Set-Cookie|^\{'
curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'X-CSRF-Protection: 1' -b "__Secure-refresh_token=$NEW" "$BASE/auth/refresh"
```

```http
HTTP/1.1 401
Set-Cookie: __Secure-refresh_token=; Path=/auth; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Strict
{"error":"invalid_refresh_token","error_description":"Refresh token is missing, expired or revoked; log in again"}
401
```

The server log records the security event (identifiers only, never the token):

```text
WARN ... RefreshTokenService : Refresh token reuse detected: subject=alice family=05bf36e0-b706-4f6e-b2c8-4895bfefe698 token=85b84e2a-0276-4ffa-a3db-04c7e4e71e71; family revoked
```

**10. Log out.** The family is revoked server-side (deleting the cookie alone would not be enough).

```bash
curl -s -o /dev/null -c "$JAR" -H 'Content-Type: application/json' -H 'X-CSRF-Protection: 1' \
     -d '{"username":"alice","password":"alice-demo-passphrase"}' "$BASE/auth/login"
BEFORE=$(awk '/refresh_token/ {print $7}' "$JAR")
curl -si -b "$JAR" -c "$JAR" -X POST -H 'X-CSRF-Protection: 1' "$BASE/auth/logout" | grep -iE '^HTTP|^Set-Cookie'
curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'X-CSRF-Protection: 1' -b "__Secure-refresh_token=$BEFORE" "$BASE/auth/refresh"
```

```http
HTTP/1.1 204
Set-Cookie: __Secure-refresh_token=; Path=/auth; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Strict
401
```

## Configuration

| Property | Default | Meaning |
|---|---|---|
| `auth.jwt.issuer` | `http://localhost:8082` | `iss`; verifiers compare it exactly |
| `auth.jwt.audience` | `jwt-demo-api` | `aud`; a token for another API is refused |
| `auth.jwt.client-id` | `jwt-demo-web` | `client_id` (required by RFC 9068) |
| `auth.jwt.access-token-ttl` | `15m` | Access-token lifetime (5-15 min) |
| `auth.jwt.clock-skew` | `30s` | Tolerance for `exp`, `nbf`, `iat` (at most 60 s) |
| `auth.refresh-token.cookie-name` | `__Secure-refresh_token` | The prefix makes browsers require `Secure` |
| `auth.refresh-token.cookie-path` | `/auth` | The cookie never travels to `/api/**` |
| `auth.refresh-token.idle-timeout` | `1d` | Unused this long: log in again |
| `auth.refresh-token.absolute-lifetime` | `7d` | One login never lasts longer, however active |
| `auth.csrf.allowed-origins` | `http://localhost:8082` | Browser origins allowed to call `/auth/**` |
| `auth.users` | alice, bob | DEMO users: username, Argon2id hash, scopes |

## Design decisions (the "why")

**Why the refresh token is a cookie and the access token is not.** The refresh token is the long-lived
secret (days), so it goes where JavaScript cannot read it: an `HttpOnly` cookie restricted to `/auth`. The
access token must be attached to API calls by the client, so it is returned in the body and kept in memory;
after a page reload the SPA simply calls `/auth/refresh`. Its 15-minute lifetime caps the damage if XSS
steals it. Native mobile apps would instead receive the refresh token in the body and keep it in the
Keychain or Android Keystore.

**Why `/auth/refresh` needs CSRF protection although it only returns JSON.** A forged cross-site request
cannot read the response, but it can still log the user out, or rotate the token behind the real client's
back so that the client's next refresh looks like reuse and kills the session. `SameSite=Strict` stops
cross-site requests in current browsers, but not *same-site* ones (a compromised sibling subdomain) and not
older clients, so three independent checks are layered on top
([`AuthEndpointCsrfFilter`](src/main/java/com/backend/auth/jwt/security/AuthEndpointCsrfFilter.java)):
a **required custom header** (forms cannot set headers; cross-origin `fetch` with one needs a CORS
preflight this server never approves), an **`Origin` allowlist**, and **`Sec-Fetch-Site: cross-site`**
rejection. The header carries no secret, so no token synchronization is needed. This only holds while
CORS stays strict: never reflect arbitrary origins with `Access-Control-Allow-Credentials: true`
([chapter 04, section 7.7](../../docs/04-sessions-cookies-and-csrf.md#77-why-cors-is-not-csrf-protection)).
The bearer-token API needs none of this, because browsers never add an `Authorization` header by themselves.

**Why the cookie path is `/auth` and not `/auth/refresh`.** Logout must read the cookie too, so `/auth` is
the narrowest path that covers both. The `__Secure-` prefix stops plain-HTTP origins from planting a cookie
of the same name; `__Host-` would be stronger but forces `Path=/`, which would send the refresh token on
every API call.

**Why reuse revokes the whole family.** When a used token comes back, two parties hold copies and the
server cannot tell which is legitimate, so it revokes both and logs the event. Two tabs refreshing at the
same moment look exactly like this; the fix belongs in the client (one refresh in flight, shared by all
callers), which is why the test for concurrent refreshes expects reuse detection rather than two successes.

**Why the rotation code returns a result instead of throwing.** Reuse detection *writes* (it revokes the
family) and then rejects. Throwing an unchecked exception from the `@Transactional` method would roll that
revocation back. [`RefreshResult`](src/main/java/com/backend/auth/jwt/refresh/RefreshResult.java) keeps
the revocation committed.

**Three Spring Security 7.1 details this example handles explicitly** (see [`JwtConfig`](src/main/java/com/backend/auth/jwt/token/JwtConfig.java)
and [`AuthService`](src/main/java/com/backend/auth/jwt/web/AuthService.java)):

1. `JwtValidators.createAtJwtValidator()` puts a `JwtTimestampValidator` with the default 60 s skew into
   both its `exp` and `iat` entries. Setting a tighter skew means replacing **both**, otherwise tokens that
   expired up to 60 s ago still pass (`clockSkewToleranceIsTheConfiguredThirtySecondsNotTheLibraryDefaultSixty`
   catches this).
2. `JwtIssuedAtValidator` is a *freshness* check meant for DPoP proofs (`iat` within the skew of now, in both
   directions). Used on access tokens it would reject every token older than the skew, so a custom "not issued
   in the future" check is used instead.
3. A successful password login adds a `FACTOR_PASSWORD` authority. Copying `authentication.getAuthorities()`
   into the `scope` claim would leak it; scopes are taken from the user record instead.

## How the tests prove it

`./mvnw test` runs 53 tests: MockMvc tests against the full filter chains, plus one class on a real Tomcat
(random port) that verifies tokens the way a separate service would and checks the `Set-Cookie` header on
the wire. Attack tokens are built with Nimbus directly
([`TestTokens`](src/test/java/com/backend/auth/jwt/TestTokens.java)), so each differs from a valid token in
exactly one way.

| Property | Test |
|---|---|
| Login returns a working RS256 token with `kid`, `typ: at+jwt`, all required claims and a 15-minute lifetime | `LoginTests.loginReturnsAShortLivedRs256AccessTokenThatTheApiAccepts` |
| Refresh cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/auth`, host-only; not in the body | `LoginTests.loginSetsAHardenedRefreshCookieScopedToTheAuthPath`, `ExternalVerifierTests.refreshCookieOnTheWireIsHttpOnlySecureSameSiteStrictAndPathScoped` |
| Wrong password and unknown user are indistinguishable | `LoginTests.wrongPasswordAndUnknownUserGetTheSameAnswerAndNoCookie` |
| Tampered signature or payload → 401 | `AccessTokenValidationTests.tamperedSignatureIsRejected`, `tamperedPayloadIsRejected` |
| Wrong audience / wrong issuer → 401 | `AccessTokenValidationTests.wrongAudienceIsRejected`, `wrongIssuerIsRejected`, `ExternalVerifierTests` (audience of another API) |
| Expired, not-yet-valid or future-issued token → 401; skew is 30 s, not 60 s | `AccessTokenValidationTests.expiredTokenIsRejected`, `clockSkewToleranceIsTheConfiguredThirtySecondsNotTheLibraryDefaultSixty`, `tokenNotYetValidIsRejected`, `tokenIssuedInTheFutureIsRejected` |
| `alg: none` and HS256-signed-with-our-public-key (algorithm confusion) → 401 | `AccessTokenValidationTests.unsignedAlgNoneTokenIsRejected`, `hs256TokenSignedWithOurPublicKeyIsRejected` |
| Attacker's key (claiming our `kid`, or embedded as `jwk`), unknown `kid` → 401 | `AccessTokenValidationTests.tokenSignedByAnotherKeyClaimingOurKidIsRejected`, `keyEmbeddedInTheTokenHeaderIsNeverTrusted`, `unknownKidIsRejected` |
| ID-token-like JWT (`typ: JWT` or no `typ`) and missing required claims → 401 | `AccessTokenValidationTests.jwtOfAnotherTypeIsNotAcceptedAsAnAccessToken`, `tokenMissingRequiredClaimsIsRejected` |
| Insufficient scope → 403 `insufficient_scope`; unlisted endpoints denied; orders stay with their owner | `ApiAuthorizationTests` |
| Refresh rotates: new token, old one marked used, same family, same absolute expiry | `RefreshTokenTests.refreshRotatesTheRefreshTokenAndIssuesANewAccessToken` |
| Reusing a rotated token revokes the whole family (and only that family) | `RefreshTokenTests.reusingARotatedRefreshTokenRevokesTheWholeFamily`, `reuseRevokesOnlyThatFamilyNotTheUsersOtherLogins` |
| Concurrent refreshes with one token rotate once; the loser counts as reuse | `RefreshTokenTests.concurrentRefreshesWithTheSameTokenRotateOnceAndTheLoserIsTreatedAsReuse` |
| Logout revokes the family and expires the cookie; access tokens live until `exp` | `RefreshTokenTests.logoutRevokesTheFamilyAndClearsTheCookie`, `accessTokenIssuedBeforeLogoutKeepsWorkingUntilItExpires`, `logoutWithoutAValidCookieStillSucceedsSoItRevealsNothing` |
| Only the SHA-256 hash is stored | `RefreshTokenTests.onlyTheSha256HashOfTheRefreshTokenIsStored` |
| Idle and absolute expiry; disabled accounts and scope changes picked up at refresh | `RefreshTokenTests.idleRefreshTokenExpires`, `familyEndsAtItsAbsoluteLifetimeHoweverActive`, `disabledAccountCannotRefreshAndItsFamilyIsRevoked`, `scopeChangesTakeEffectAtTheNextRefresh` |
| CSRF: missing header, foreign or `null` origin, `Sec-Fetch-Site: cross-site` → 403 and nothing changes | `AuthEndpointCsrfTests` |
| JWKS lists the signing `kid`, is cacheable, never contains private parameters | `JwksTests` |
| Key rotation: publish, activate, retire without breaking valid tokens | `KeyRotationTests.rotationWithoutDowntime` |
| Another service can verify tokens with only the JWKS URL | `ExternalVerifierTests.aSeparateResourceServerCanVerifyTokensUsingOnlyTheJwksUrl` |

## What you would change for production

- **Keys in a KMS or HSM.** Generate and keep the private key in AWS KMS, Google Cloud KMS, Azure Key
  Vault or an HSM and sign through it (or at minimum load it from a secret manager), so it never sits in
  application memory or on disk. Every instance must sign with the same keys. Automate rotation (for
  example every 90 days) with the publish → wait one JWKS cache lifetime → activate → wait the longest
  token lifetime plus skew → retire sequence, and alert on unexpected key use.
- **Separate verifiers.** Other services use `NimbusJwtDecoder.withJwkSetUri(...)` (or
  `spring.security.oauth2.resourceserver.jwt.*` properties) with the same RS256 allowlist, issuer, audience
  and `at+jwt` validator; give each API its own audience. Rate-limit unknown-`kid` refetches at the gateway.
- **Real database.** PostgreSQL (or similar) with Flyway, the unique index on `token_hash`, an index on
  `family_id`, and a scheduled job that deletes rows some days after `expires_at`. The `SELECT ... FOR UPDATE`
  plus compare-and-set update work the same way there.
- **Immediate access-token revocation where it matters.** Logout cannot recall an access token already
  issued (`accessTokenIssuedBeforeLogoutKeepsWorkingUntilItExpires`). If 15 minutes is too long, add a
  `jti` deny-list in Redis (TTL = remaining lifetime), a per-user "tokens valid after" timestamp for "log out
  everywhere", or shorten the lifetime to 5 minutes for high-risk APIs.
- **Sender-constrained tokens.** For public clients holding refresh tokens or high-value APIs, bind tokens to
  a client key with DPoP (RFC 9449, supported by Spring Security 7's resource server) or mTLS (RFC 8705), so
  a stolen token is useless elsewhere.
- **Browser apps: prefer a BFF.** If the client is a browser SPA, the BFF pattern keeps the access token on
  the server too ([`../03-oauth2-oidc/`](../03-oauth2-oidc/)). If you keep this design, serve the SPA from
  the same site, keep a strict CSP, and never copy tokens into `localStorage` or `sessionStorage`.
- **Login hardening.** Add throttling per username, IP and username+IP with exponential backoff (as in
  [`../01-session-auth/`](../01-session-auth/)), breached-password checks at registration and password
  change, and a second factor ([`../04-mfa-totp/`](../04-mfa-totp/)). Revoke all refresh-token families on
  password change, password reset, MFA reset and account disable.
- **TLS everywhere.** HTTPS only, HSTS, `server.forward-headers-strategy=native` behind a TLS-terminating
  proxy, and `auth.csrf.allowed-origins` set to your real front-end origin(s).
- **Monitoring.** Alert on refresh-token reuse (a likely stolen token), spikes in `invalid_token` and
  `insufficient_scope`, and signing-key access anomalies. Log `jti`, `sub`, family id and the validation
  result, never the tokens themselves.
- **Consider an identity provider.** Once more than one application needs login, MFA, account recovery and
  federation, a dedicated authorization server (Keycloak, Spring Authorization Server, or a managed IdP)
  usually costs less than growing this into one.
