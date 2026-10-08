# 08 — OAuth 2.0: The Authorization Framework

OAuth 2.0 (RFC 6749 and RFC 6750, October 2012) lets a user give an application **limited, revocable access** to an API **without handing over their password**. The application gets an **access token**: a short-lived credential with a defined scope, issued by an **authorization server** that the API trusts. This chapter covers the whole framework as it should be used in 2026: roles and client types, the authorization code grant step by step with raw HTTP, PKCE, the other grants, client authentication, introspection, revocation, metadata, dynamic registration, the attacks found over the last decade, and why OAuth on its own is **not** a login protocol.

> **Where this fits in the evolution**
>
> - **Before:** Apps asked users for their passwords to other sites (the "password anti-pattern"), or used proprietary delegation schemes such as Google AuthSub, Yahoo BBAuth and Flickr's API auth. [OAuth 1.0a](07-oauth-1.md) (2009, RFC 5849 in 2010) standardized delegation, but every request needed a fiddly HMAC signature.
> - **What it solved:** OAuth 2.0 dropped per-request signatures and relied on TLS instead. It defined separate **grants** for different client types (web servers, browsers, native apps, machines) and split the **authorization server** from the **resource server**, so one token service can protect many APIs.
> - **What came next:** OAuth 2.0 is a loose *framework*. Its first editor withdrew his name in 2012, saying it was too open-ended to be secure by default. A decade of fixes followed: **PKCE** (RFC 7636, 2015), the **OAuth 2.0 Security Best Current Practice** (RFC 9700, January 2025), sender-constrained tokens, and the **OAuth 2.1** consolidation, which is still an IETF draft in October 2026. See [Modern OAuth 2.1 and extensions](09-modern-oauth-2.1-and-extensions.md). For **login**, use [OpenID Connect](10-openid-connect.md), which is built on top of OAuth 2.0.

---

## Table of contents

1. [The problem OAuth solves](#1-the-problem-oauth-solves)
2. [Roles, endpoints and tokens](#2-roles-endpoints-and-tokens)
3. [Clients: confidential vs public, and registration](#3-clients-confidential-vs-public-and-registration)
4. [The authorization code grant, step by step](#4-the-authorization-code-grant-step-by-step)
5. [PKCE (RFC 7636): required for every client](#5-pkce-rfc-7636-required-for-every-client)
6. [Client credentials grant](#6-client-credentials-grant)
7. [Device authorization grant (RFC 8628)](#7-device-authorization-grant-rfc-8628)
8. [Refresh token grant](#8-refresh-token-grant)
9. [Deprecated grants: implicit and password](#9-deprecated-grants-implicit-and-password)
10. [Scopes and consent](#10-scopes-and-consent)
11. [The state parameter and CSRF on the callback](#11-the-state-parameter-and-csrf-on-the-callback)
12. [Redirect URIs: exact matching](#12-redirect-uris-exact-matching)
13. [Client authentication at the token endpoint](#13-client-authentication-at-the-token-endpoint)
14. [Token introspection (RFC 7662)](#14-token-introspection-rfc-7662)
15. [Token revocation (RFC 7009)](#15-token-revocation-rfc-7009)
16. [Authorization server metadata (RFC 8414)](#16-authorization-server-metadata-rfc-8414)
17. [Dynamic client registration (RFC 7591)](#17-dynamic-client-registration-rfc-7591)
18. [Choosing a grant](#18-choosing-a-grant)
19. [Vulnerabilities in depth](#19-vulnerabilities-in-depth)
20. [OAuth is authorization, not authentication](#20-oauth-is-authorization-not-authentication)
21. [Production best practices (2026)](#21-production-best-practices-2026)
22. [Common attacks and mistakes](#22-common-attacks-and-mistakes)
23. [Spring Boot 4 / Spring Security 7](#23-spring-boot-4--spring-security-7)
24. [Interview questions](#interview-questions)
25. [References](#references)

---

## 1. The problem OAuth solves

Suppose a printing service wants to print photos stored in your cloud photo account. Before OAuth, the printing service would ask for your photo-account **username and password**. That has serious problems:

| Problem with sharing the password | Consequence |
|---|---|
| The third party can do **everything** you can | No way to grant "read photos only" |
| Access lasts **until you change your password** | Changing it breaks every other app that has it |
| You cannot revoke **one** app | All or nothing |
| The third party must **store** your password | Its breach becomes your breach |
| Users learn to type passwords into third-party pages | Phishing becomes normal behavior |
| MFA and passkeys cannot work | The third party can only replay a password |

OAuth replaces the password with a **token** that is:

- **Scoped**: only `photos.read`, not "delete account".
- **Short-lived**: minutes, not forever.
- **Revocable per app**: you can disconnect the printing service without affecting anything else.
- **Issued after the user logs in at the real site**: the third party never sees the password, and the real site can use MFA, passkeys or SSO.

The core idea is **delegated authorization**: the user (resource owner) authorizes a client to access their resources, and the authorization server records that decision and issues tokens.

---

## 2. Roles, endpoints and tokens

RFC 6749 defines four roles:

| Role | What it is | Example |
|---|---|---|
| **Resource owner** | The entity that can grant access, usually the end user | Jane |
| **Client** | The application that wants access on the owner's behalf | `orders-web`, a web app |
| **Authorization server (AS)** | Authenticates the owner, gets consent, issues tokens | Keycloak, Okta, Entra ID, Spring Authorization Server |
| **Resource server (RS)** | The API that holds the protected data and accepts tokens | `https://api.example.com` |

```mermaid
flowchart LR
    RO["Resource owner (user)"]
    UA["User agent (browser)"]
    C["Client app"]
    AS["Authorization server"]
    RS["Resource server (API)"]
    RO -->|"uses"| UA
    UA -->|"front channel: redirects"| AS
    UA -->|"front channel: redirects"| C
    C -->|"back channel: token request over TLS"| AS
    C -->|"API call with access token"| RS
    RS -.->|"validates token: JWKS or introspection"| AS
```

**Front channel vs back channel.** The *front channel* is communication through the browser via redirects. Anything there can be seen, logged, or tampered with by the user, browser extensions, or other sites. The *back channel* is a direct, server-to-server TLS connection between client and AS. OAuth's main design trick is to send only a **short-lived, single-use code** through the front channel and to deliver the **tokens** over the back channel.

### Endpoints

| Endpoint | Channel | Purpose | Defined in |
|---|---|---|---|
| Authorization endpoint | Front | User login and consent, returns a code | RFC 6749 |
| Token endpoint | Back | Exchanges a grant (code, refresh token, client credentials) for tokens | RFC 6749 |
| Redirection endpoint (callback) | Front, at the client | Receives the code | RFC 6749 |
| Device authorization endpoint | Back | Starts the device flow | RFC 8628 |
| Introspection endpoint | Back | RS asks "is this token active, and what is it for?" | RFC 7662 |
| Revocation endpoint | Back | Client says "I am done with this token" | RFC 7009 |
| Metadata (`/.well-known/oauth-authorization-server`) | Back | Discovery of all the above | RFC 8414 |
| Registration endpoint | Back | Dynamic client registration | RFC 7591 |
| JWKS URI | Back | Public keys to verify JWT access tokens | RFC 8414, RFC 7517 |

### Tokens

| Token | Who uses it | Typical lifetime (2026) | Format |
|---|---|---|---|
| **Authorization code** | Client, once | 30-60 seconds (RFC 6749 recommends a maximum of 10 minutes) | Opaque random string |
| **Access token** | Client sends it to the RS | 5-15 minutes | Opaque (needs introspection) or JWT ([RFC 9068](09-modern-oauth-2.1-and-extensions.md#12-jwt-access-tokens-rfc-9068)) |
| **Refresh token** | Client sends it to the AS only | Hours to weeks, rotated on each use | Opaque, stored hashed at the AS |

RFC 6749 says nothing about the access token format. To the client, an access token is **opaque**: the client must not parse it or depend on its contents. Only the RS and AS interpret it. If the client needs to know *who* the user is, it needs an [ID token from OpenID Connect](10-openid-connect.md).

---

## 3. Clients: confidential vs public, and registration

### Client types

RFC 6749 classifies clients by whether they can **keep a secret**:

| Type | Can keep a credential secret? | Examples | Authenticates to the token endpoint with |
|---|---|---|---|
| **Confidential** | Yes. Code and secrets run on a server you control | Server-side web app, BFF, backend service, batch job | `private_key_jwt`, mTLS, or a client secret |
| **Public** | No. Code runs on the user's device and can be extracted | Single-page app (SPA) running only in the browser, mobile app, desktop app, CLI | Nothing (`none`). PKCE protects the code instead |

A secret embedded in a mobile app or JavaScript bundle is **not** a secret. Anyone can decompile the app or open DevTools. Treat such clients as public and do not issue them client secrets.

RFC 6749 also names three client *profiles*: **web application** (confidential), **user-agent-based application** (public, for example an SPA) and **native application** (public). See [Modern OAuth](09-modern-oauth-2.1-and-extensions.md) for RFC 8252 (native apps) and RFC 10017 (browser-based apps, published August 2026). RFC 10017 recommends a **BFF** (backend for frontend), which turns a browser app into a confidential client.

### Client registration

Before any flow, the client is **registered** at the AS, either manually in an admin console or through [dynamic registration](#17-dynamic-client-registration-rfc-7591). Registration records:

| Field | Why it matters |
|---|---|
| `client_id` | Public identifier. It is not a secret |
| Client credential | Secret, public key (JWKS), or certificate, for confidential clients only |
| **Redirect URIs** | The exact URIs where codes may be sent. This is the most security-critical setting |
| Allowed grant types | For example only `authorization_code` and `refresh_token`. Never enable grants a client does not need |
| Allowed scopes | The maximum scope this client can ever obtain |
| Token endpoint auth method | `private_key_jwt`, `tls_client_auth`, `client_secret_basic`, or `none` |
| Display data | Name, logo and URLs shown on the consent screen |
| Token settings | Lifetimes, refresh token rotation, sender-constraining |

---

## 4. The authorization code grant, step by step

This is the grant you will use for almost every case where a **user** is involved. With PKCE it is the recommended flow for every client type: web apps, SPAs via a BFF, mobile and desktop apps.

The examples use these hosts:

- Client app (confidential, server-side): `https://app.example.com`, `client_id=orders-web`
- Authorization server: `https://auth.example.com` (Spring Authorization Server default endpoint paths)
- Resource server: `https://api.example.com`

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant B as Browser
    participant C as Client app (orders-web)
    participant AS as Authorization server
    participant RS as Resource server (API)
    U->>B: Click Connect my orders
    B->>C: GET /connect
    C->>C: Create state and PKCE code_verifier, store both in session
    C-->>B: 302 to AS authorize endpoint with state and code_challenge
    B->>AS: GET /oauth2/authorize?response_type=code...
    AS->>AS: Validate client_id, exact redirect_uri, scope, PKCE params
    AS-->>B: Login page (password, passkey, MFA)
    U->>AS: Authenticate and approve consent
    AS-->>B: 302 to redirect_uri with code, state, iss
    B->>C: GET /callback with code and state
    C->>C: Check state matches session, check iss
    C->>AS: POST /oauth2/token with code, code_verifier, client authentication
    AS->>AS: Verify client, code unused and unexpired, redirect_uri, PKCE
    AS-->>C: 200 access_token, refresh_token, expires_in
    C->>RS: GET /orders with Authorization Bearer token
    RS->>RS: Validate signature, iss, aud, exp, scope
    RS-->>C: 200 orders JSON
```

### Step 1 — The client prepares the request

The client generates two random values and stores them **server-side in the user's session**, together with which AS this flow is for:

| Value | How to generate | Purpose |
|---|---|---|
| `state` | At least 128 bits from a CSPRNG, base64url-encoded | Binds the callback to this browser session (CSRF protection) |
| `code_verifier` | 32 random bytes, base64url-encoded, giving 43 characters (RFC 7636 allows 43-128) | PKCE secret, never sent through the front channel |
| `code_challenge` | `BASE64URL(SHA-256(code_verifier))` | Sent in the authorization request |

Example values (the verifier and challenge are the test vector from RFC 7636, Appendix B):

```text
state          = RJgHM0z7XRTlwXFcQm3EMA
code_verifier  = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
code_challenge = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
```

### Step 2 — Redirect to the authorization endpoint

The client redirects the browser:

```http
HTTP/1.1 302 Found
Location: https://auth.example.com/oauth2/authorize?response_type=code&client_id=orders-web&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=orders.read%20orders.write&state=RJgHM0z7XRTlwXFcQm3EMA&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
Set-Cookie: SESSION=8f1c2a...; Path=/; Secure; HttpOnly; SameSite=Lax
Cache-Control: no-store
```

The browser follows it (line breaks added for readability only):

```http
GET /oauth2/authorize?response_type=code
    &client_id=orders-web
    &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
    &scope=orders.read%20orders.write
    &state=RJgHM0z7XRTlwXFcQm3EMA
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    &code_challenge_method=S256 HTTP/1.1
Host: auth.example.com
```

| Parameter | Required | Meaning |
|---|---|---|
| `response_type=code` | Yes | Ask for an authorization code |
| `client_id` | Yes | Which client is asking |
| `redirect_uri` | Required if the client has more than one registered, and always recommended | Where to send the code. Must exactly match a registered value |
| `scope` | Optional (the AS may apply a default) | Space-separated list of permissions requested |
| `state` | Recommended (required in practice) | Opaque CSRF value, echoed back unchanged |
| `code_challenge`, `code_challenge_method=S256` | Required by RFC 9700 for public clients, recommended for all, and required by the OAuth 2.1 draft | PKCE |

> **Cookie note.** The client's session cookie must be sent on the callback, which is a top-level navigation coming from the AS site. `SameSite=Lax` cookies are sent on top-level `GET` navigations, but `SameSite=Strict` cookies are not. With `Strict`, the callback arrives without a session, so the state lookup fails. If you use `response_mode=form_post` (a cross-site `POST`), even `Lax` cookies are dropped and you need a dedicated, short-lived `SameSite=None; Secure` cookie for the flow. See [Sessions, cookies and CSRF](04-sessions-cookies-and-csrf.md).

### Step 3 — The AS validates, authenticates the user, and asks for consent

Before it shows anything, the AS checks:

1. `client_id` exists and is allowed to use `response_type=code`.
2. `redirect_uri` **exactly matches** a registered URI (simple string comparison, see [section 12](#12-redirect-uris-exact-matching)).
3. If either check fails, the AS **must not redirect**. It shows an error page instead, otherwise it becomes an open redirector.
4. Requested scopes are allowed for this client.
5. PKCE parameters are present (the AS should require them) and the method is `S256`.

Then the AS authenticates the user however it likes (password plus MFA, passkey, upstream SSO; this is invisible to the client) and shows a **consent screen**: "orders-web wants to: read your orders, create orders. Allow / Deny." First-party clients are often configured to skip consent.

### Step 4 — The authorization response

On approval, the AS redirects back with a single-use code:

```http
HTTP/1.1 302 Found
Location: https://app.example.com/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=RJgHM0z7XRTlwXFcQm3EMA&iss=https%3A%2F%2Fauth.example.com
Cache-Control: no-store
```

`iss` is the authorization server's issuer identifier, added by RFC 9207 to defend against [mix-up attacks](#195-mix-up-attacks). Servers that support it advertise `authorization_response_iss_parameter_supported: true` in their metadata.

If the user denies the request, or something else goes wrong **after** the client and redirect URI were validated, the AS redirects with an error:

```http
HTTP/1.1 302 Found
Location: https://app.example.com/callback?error=access_denied&error_description=The%20user%20denied%20the%20request&state=RJgHM0z7XRTlwXFcQm3EMA&iss=https%3A%2F%2Fauth.example.com
```

| Authorization error code | Meaning |
|---|---|
| `invalid_request` | Missing or duplicated parameter, malformed request |
| `unauthorized_client` | This client may not use this response type |
| `access_denied` | The user or the AS refused |
| `unsupported_response_type` | The AS does not support this response type |
| `invalid_scope` | Unknown or disallowed scope |
| `server_error`, `temporarily_unavailable` | AS-side problems (these cannot be sent as HTTP 5xx because this is a redirect) |

### Step 5 — The client handles the callback

```http
GET /callback?code=SplxlOBeZQQYbYS6WxSbIA&state=RJgHM0z7XRTlwXFcQm3EMA&iss=https%3A%2F%2Fauth.example.com HTTP/1.1
Host: app.example.com
Cookie: SESSION=8f1c2a...
```

The client must:

1. Load the pending flow from the session. If there is none, reject.
2. Compare `state` with the stored value in **constant time**, then **delete** it (one-time use).
3. If `iss` is present, check it equals the issuer this flow was started with.
4. Handle `error` responses without echoing `error_description` into HTML unescaped (it is attacker-controllable).
5. Redeem the code immediately, then redirect the browser to a clean URL so the code does not stay in history or leak through `Referer`. Serve the callback with `Referrer-Policy: no-referrer`.

### Step 6 — The token request (back channel)

```http
POST /oauth2/token HTTP/1.1
Host: auth.example.com
Authorization: Basic b3JkZXJzLXdlYjo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
Content-Type: application/x-www-form-urlencoded
Accept: application/json

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

(The body is shown on several lines for readability. On the wire it is one `&`-joined string.) The `Authorization: Basic` header is `client_secret_basic` client authentication. In production, prefer [`private_key_jwt` or mTLS](#13-client-authentication-at-the-token-endpoint).

### Step 7 — The AS validates the token request

The AS must check all of the following, and reject on any failure with `invalid_grant` (or `invalid_client` for authentication failures):

| Check | Why |
|---|---|
| Client authentication succeeds (confidential clients) | Only the real client can redeem codes |
| The code exists, has not expired and has **not been used** | Codes are single-use. On reuse, RFC 6749 says the AS should revoke tokens already issued from that code |
| The code was issued to **this** `client_id` | Prevents one client from redeeming another's code |
| `redirect_uri` is identical to the one in the authorization request | Required by RFC 6749 when it was sent. Stops code injection via a different callback |
| `SHA-256(code_verifier)` equals the stored `code_challenge` | PKCE |
| If the authorization request had **no** challenge, a `code_verifier` is **rejected** | Prevents the PKCE downgrade attack |

### Step 8 — The token response

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjIwMjYtMTAtYSJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiIyNDgyODk3NjEwMDEiLCJhdWQiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbSIsImNsaWVudF9pZCI6Im9yZGVycy13ZWIiLCJzY29wZSI6Im9yZGVycy5yZWFkIG9yZGVycy53cml0ZSIsImlhdCI6MTc5MTQ1MDAwMCwiZXhwIjoxNzkxNDUwNjAwLCJqdGkiOiJlZXlTLWVUeEh4QnhRY0xwIn0.sig",
  "token_type": "Bearer",
  "expires_in": 600,
  "refresh_token": "y2E86uW8sioGF3EkSZ5MDdbiiyxiHDPwhug_XPD5ZnU",
  "scope": "orders.read orders.write"
}
```

- `Cache-Control: no-store` is required by RFC 6749 so proxies and browsers never cache tokens.
- `scope` must be included if the granted scope differs from what was requested. The client must check it, because the user or AS may have granted less.
- If the access token is a JWT, its decoded payload might look like this ([RFC 9068 profile](09-modern-oauth-2.1-and-extensions.md#12-jwt-access-tokens-rfc-9068), header `typ: at+jwt`):

```json
{
  "iss": "https://auth.example.com",
  "sub": "248289761001",
  "aud": "https://api.example.com",
  "client_id": "orders-web",
  "scope": "orders.read orders.write",
  "iat": 1791450000,
  "exp": 1791450600,
  "jti": "eeyS-eTxHxBxQcLp"
}
```

| Token endpoint error | HTTP status | Meaning |
|---|---|---|
| `invalid_request` | 400 | Malformed request |
| `invalid_client` | 400 or 401 (401 with `WWW-Authenticate` is required if the client authenticated with the `Authorization` header) | Client authentication failed |
| `invalid_grant` | 400 | Code or refresh token invalid, expired, revoked, used, or issued to another client. Also redirect URI mismatch and PKCE failure |
| `unauthorized_client` | 400 | Client not allowed to use this grant type |
| `unsupported_grant_type` | 400 | AS does not support it |
| `invalid_scope` | 400 | Scope invalid or exceeds what was granted |

### Step 9 — Calling the API with a bearer token (RFC 6750)

```http
GET /orders?status=open HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjIwMjYtMTAtYSJ9.eyJpc3Mi...sig
```

RFC 6750 defines three ways to send a bearer token. Only the first is acceptable today:

| Method | Status |
|---|---|
| `Authorization: Bearer <token>` header | **Use this** |
| Form-encoded body parameter `access_token` | Allowed with restrictions, rarely needed |
| URI query parameter `?access_token=` | **Do not use.** It leaks into logs, history and `Referer`. RFC 6750 says it should not be used, and the OAuth 2.1 draft removes it |

"Bearer" means **whoever holds the token can use it**, like cash. This is why lifetimes are short, tokens are audience-restricted, and high-risk systems use [sender-constrained tokens (DPoP or mTLS)](09-modern-oauth-2.1-and-extensions.md#6-sender-constrained-tokens).

### Step 10 — The resource server validates the token

The RS must validate the token on **every request**:

- **JWT access token:** verify the signature with a key from the AS's JWKS (choosing it by `kid`, with the algorithm taken from an allowlist and never from the token header alone), then check `iss`, `aud` (must include this API), `exp`, `nbf`, and the scopes. See [Tokens and JWT](06-tokens-and-jwt.md).
- **Opaque access token:** call the [introspection endpoint](#14-token-introspection-rfc-7662) and cache the result briefly.

Error responses tell the client what went wrong:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="orders", error="invalid_token", error_description="The access token expired"
```

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer realm="orders", error="insufficient_scope", scope="orders.write"
```

| RFC 6750 error | Status | Client reaction |
|---|---|---|
| `invalid_request` | 400 | Fix the request |
| `invalid_token` | 401 | Refresh the token or re-authorize |
| `insufficient_scope` | 403 | Ask the user for the extra scope ([incremental consent](#10-scopes-and-consent)) |

Scopes say what the **client** may do. The RS must still check what the **user** may do: a token with `orders.read` must not let user A read user B's orders. See [Authorization: RBAC, ABAC, ReBAC](13-authorization-rbac-abac-rebac.md).

---

## 5. PKCE (RFC 7636): required for every client

**PKCE** (Proof Key for Code Exchange, pronounced "pixie", RFC 7636, September 2015) binds the authorization code to the client instance that started the flow. Without the original `code_verifier`, a stolen code is useless.

### The attack PKCE was designed for: code interception

Native apps often receive the callback on a custom URI scheme such as `com.example.orders:/callback`. On mobile operating systems, a malicious app can register the same scheme and receive the code.

```mermaid
sequenceDiagram
    autonumber
    participant L as Legit app
    participant M as Malicious app (same URI scheme)
    participant B as System browser
    participant AS as Authorization server
    L->>B: Open authorize URL (no PKCE)
    B->>AS: User logs in and consents
    AS-->>B: Redirect to com.example.orders:/callback?code=abc
    B-->>M: OS delivers the redirect to the malicious app
    M->>AS: POST /token code=abc, client_id=orders-mobile
    AS-->>M: Access token for the victim
    Note over M,AS: A public client has no secret, so the AS cannot tell the apps apart
```

### How S256 PKCE stops it

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant AS as Authorization server
    participant X as Attacker with a stolen code
    C->>C: code_verifier = 32 random bytes, base64url
    C->>C: code_challenge = BASE64URL(SHA256(code_verifier))
    C->>AS: Authorization request with code_challenge, method S256
    AS->>AS: Store challenge with the code it issues
    AS-->>C: code (may be intercepted)
    X->>AS: POST /token code, but no verifier or a wrong one
    AS-->>X: 400 invalid_grant
    C->>AS: POST /token code plus code_verifier
    AS->>AS: SHA256(verifier) equals stored challenge
    AS-->>C: Tokens
```

The challenge travels through the front channel, but SHA-256 is one-way, so seeing the challenge does not reveal the verifier. The verifier travels only over the back channel, at redemption time.

| Rule | Detail |
|---|---|
| Verifier format | 43-128 characters from `[A-Z] [a-z] [0-9] - . _ ~`. Generate 32 random bytes and base64url-encode them without padding |
| Method | **`S256` only.** `plain` (challenge equals verifier) exists for clients that cannot compute SHA-256. In 2026 that is no client, so reject `plain` |
| One verifier per flow | Never reuse a verifier across authorization requests |
| AS support | The AS must support PKCE and advertise `code_challenge_methods_supported: ["S256"]` |
| Downgrade protection | If the authorization request had no `code_challenge`, the AS must reject a token request containing a `code_verifier`. If it had one, the verifier is mandatory |

### Why PKCE is now required for every client, including confidential ones

PKCE was created for public clients, but the [OAuth 2.0 Security BCP (RFC 9700)](09-modern-oauth-2.1-and-extensions.md#2-the-oauth-20-security-bcp-rfc-9700-rule-by-rule) and the OAuth 2.1 draft extend it to everyone. The reasons:

1. **Authorization code injection.** An attacker who steals a code (through `Referer`, logs, an open redirector or a malicious browser extension) cannot redeem it at the token endpoint without the client secret. But they can **inject it into their own session at the legitimate client**: they start a login at the client in their own browser, then replace the code in the callback with the stolen one. The legitimate client redeems it with its own secret, and the attacker's session is now attached to the victim's account or data. Client authentication does not help, because the real client makes the request. PKCE does help: the verifier stored in the attacker's session does not match the challenge from the victim's flow.
2. **CSRF protection.** Because the verifier is stored in the session that started the flow, a callback injected into a different session fails at the token endpoint. RFC 9700 lets clients rely on PKCE for CSRF protection when the AS is known to enforce it. Keeping `state` as well costs nothing.
3. **One rule is easier than two.** No need to decide per client whether PKCE is needed.
4. **It is cheap.** One random value and one hash.

RFC 9700 makes PKCE a **MUST for public clients** and **RECOMMENDED for confidential clients**. It allows confidential OpenID Connect clients to use `nonce` instead, under strict conditions. The OAuth 2.1 draft (revision 16, September 2026) goes further and requires PKCE for authorization code flows by default. The house rule for this guide is simple: **always use PKCE with S256**.

---

## 6. Client credentials grant

For **machine-to-machine** calls where no user is involved, such as a nightly batch job calling the orders API, the client authenticates as itself and receives a token for its own permissions.

```mermaid
sequenceDiagram
    autonumber
    participant J as Batch job (orders-batch)
    participant AS as Authorization server
    participant RS as Orders API
    J->>AS: POST /oauth2/token grant_type=client_credentials, scope, client authentication
    AS->>AS: Authenticate client, check allowed scopes
    AS-->>J: access_token (no refresh token)
    J->>J: Cache token until shortly before exp
    J->>RS: GET /orders with Authorization Bearer token
    RS-->>J: 200
```

```http
POST /oauth2/token HTTP/1.1
Host: auth.example.com
Authorization: Basic b3JkZXJzLWJhdGNoOlpxM3ZWOXBMMm1YYzhSa1RuQjR3WWE=
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=orders.read
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "access_token": "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "orders.read"
}
```

Key points:

- **Only for confidential clients.** A public client has no credential to authenticate with.
- **No refresh token.** RFC 6749 says the AS should not issue one. The client can request a new access token at any time.
- **Cache the token** until shortly before `exp` (for example 30-60 seconds early). Do not request a new token per API call; that overloads the AS.
- **Prefer asymmetric client authentication** (`private_key_jwt`, mTLS) or **workload identity federation** over long-lived shared secrets. See [Service-to-service and zero trust](12-service-to-service-and-zero-trust.md).
- The token's `sub` is usually the client itself. The RS must not mistake a client-credentials token for a user token. Check `client_id`, the absence of a user subject, or a dedicated scope.

---

## 7. Device authorization grant (RFC 8628)

Smart TVs, consoles, CLIs and IoT devices either have no browser or have a terrible keyboard. The **device authorization grant** (RFC 8628, August 2019), often called the "device code flow", lets the user approve on a second device, such as their phone.

```mermaid
sequenceDiagram
    autonumber
    participant D as TV app
    participant AS as Authorization server
    participant U as User on phone
    D->>AS: POST /oauth2/device_authorization client_id, scope
    AS-->>D: device_code, user_code WDJB-MJHT, verification_uri, interval 5
    D->>D: Show code and URL or QR code on screen
    U->>AS: Open verification_uri, log in, enter WDJB-MJHT, approve
    loop Every interval seconds
        D->>AS: POST /oauth2/token grant_type=device_code, device_code
        AS-->>D: 400 authorization_pending (until the user approves)
    end
    AS-->>D: 200 access_token, refresh_token
```

**1. Device authorization request** (the examples follow RFC 8628):

```http
POST /oauth2/device_authorization HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

client_id=tv-app&scope=media.read
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://auth.example.com/activate",
  "verification_uri_complete": "https://auth.example.com/activate?user_code=WDJB-MJHT",
  "expires_in": 1800,
  "interval": 5
}
```

**2. Polling the token endpoint:**

```http
POST /oauth2/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code
&device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS
&client_id=tv-app
```

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{"error": "authorization_pending"}
```

| Polling error | Client reaction |
|---|---|
| `authorization_pending` | Keep polling at `interval` |
| `slow_down` | Increase the interval by 5 seconds, then keep polling |
| `access_denied` | Stop. The user said no |
| `expired_token` | Stop. Start a new device authorization |

**Security considerations:**

- **Device code phishing.** An attacker starts a device flow themselves, then sends the victim the `user_code` with a convincing story ("enter this code to join the meeting"). If the victim approves, the attacker's device gets the victim's tokens. Phishing campaigns against Microsoft 365 users have used exactly this technique. Mitigations: show the client name and device details prominently on the approval page, ask "Did you start this on a device in front of you?", keep `expires_in` short (5-15 minutes), allow the grant only for clients that really need it, and alert on unusual approvals.
- **User code brute force.** RFC 8628 suggests user codes with enough entropy (for example 8 characters from a 20-letter consonant alphabet, about 34.5 bits) **and** rate limiting on the verification page.
- Use the device flow **only** for input-constrained devices. Any device with a usable browser should use the authorization code grant with PKCE.

---

## 8. Refresh token grant

Access tokens are short-lived on purpose. A **refresh token** lets the client get a new access token without sending the user back through the authorization endpoint.

```http
POST /oauth2/token HTTP/1.1
Host: auth.example.com
Authorization: Basic b3JkZXJzLXdlYjo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=y2E86uW8sioGF3EkSZ5MDdbiiyxiHDPwhug_XPD5ZnU
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "access_token": "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 600,
  "refresh_token": "1B6Kif29I_uhKaoev5VXC-RReWvATaGgeW8w8-HZfPU",
  "scope": "orders.read orders.write"
}
```

The client may send a `scope` parameter to ask for a **narrower** scope. It can never be broader than the original grant.

### Rotation with reuse detection

Refresh tokens are long-lived and powerful, so they are the most valuable thing to steal. **Rotation** means every use returns a **new** refresh token and invalidates the old one. **Reuse detection** means that if an already-used refresh token is presented again, the AS assumes theft and revokes the **whole token family** (every refresh and access token descended from the original grant).

```mermaid
sequenceDiagram
    autonumber
    participant C as Legit client
    participant A as Attacker
    participant AS as Authorization server
    C->>AS: refresh with RT1
    AS-->>C: AT2 plus RT2, RT1 marked used
    A->>AS: refresh with stolen RT1
    AS->>AS: RT1 already used, reuse detected
    AS->>AS: Revoke the whole family RT1, RT2 and their access tokens
    AS-->>A: 400 invalid_grant
    C->>AS: refresh with RT2
    AS-->>C: 400 invalid_grant, user must log in again
```

Reuse detection cannot tell which party is the attacker, so it punishes both. That is the point: the legitimate user logs in again, and the stolen token family is dead.

**Storage and lifetimes (house positions):**

| Setting | Recommendation |
|---|---|
| Storage at the AS | Store only a **hash** (SHA-256 is enough because refresh tokens are 256-bit random values, not passwords), plus family ID, client, user, scopes, expiry, and a used flag |
| Storage at the client | Server-side (BFF, backend) or the OS keychain or keystore (mobile). **Never** `localStorage` |
| Rotation | On every use, with reuse detection. Allow a small grace window (a few seconds) for concurrent requests that race with the same token, if your clients need it |
| Idle timeout | For example 1-7 days without use, depending on risk |
| Absolute lifetime | For example 7-30 days for typical apps, and hours for high-risk apps such as banking or admin consoles. Then the user must log in again (with MFA if applicable). Longer lifetimes for consumer mobile apps should come with sender-constrained refresh tokens |
| Sender-constraining | For public clients, RFC 9700 requires refresh tokens to be **either rotated or sender-constrained** (DPoP or mTLS). High-security profiles such as FAPI 2.0 sender-constrain them and actually discourage rotation, because rotation adds nothing once the token is bound to a key. See [chapter 09](09-modern-oauth-2.1-and-extensions.md#17-fapi-20) |
| Revocation | Revoke on logout, password change, MFA reset, account disable, and consent withdrawal |

The runnable example [../examples/02-jwt-auth/](../examples/02-jwt-auth/) implements rotating refresh tokens with reuse detection.

---

## 9. Deprecated grants: implicit and password

RFC 6749 defined two grants that are now deprecated. RFC 9700 says clients **SHOULD NOT** use the implicit grant and that the password grant **MUST NOT** be used. The OAuth 2.1 draft removes both.

### Implicit grant (`response_type=token`)

The AS returned the **access token directly in the redirect URL fragment**:

```http
HTTP/1.1 302 Found
Location: https://spa.example.com/callback#access_token=2YotnFZFEjr1zCsicMWpAA&token_type=Bearer&expires_in=3600&state=xyz
```

It was designed in 2012 because browsers could not make cross-origin `POST` requests to a token endpoint (CORS was not widely available). Why it is deprecated:

| Problem | Explanation |
|---|---|
| **Token in the URL** | Fragments stay in browser history, can be read by any script on the page, and survive redirects. An open redirector on the client's domain can forward the fragment to an attacker |
| **No client authentication and no code redemption step** | Anyone who obtains the token can use it. There is no step where the AS can verify the client |
| **Access token injection** | An attacker can put a token issued for a *different* client into the victim's callback. The SPA cannot tell |
| **No refresh tokens** | Apps did "silent renew" in hidden iframes, which depends on third-party cookies that browsers now block |
| **Cannot be sender-constrained** | The token is issued through the front channel, so it cannot be bound to a client key at issuance |
| **The original reason is gone** | CORS is universal, so SPAs can use authorization code plus PKCE. Better still, use a BFF |

### Resource owner password credentials grant (`grant_type=password`)

The client collected the user's username and password and sent them to the token endpoint:

```http
POST /oauth2/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=jane&password=hunter2&client_id=legacy-app
```

It was meant as a migration path from HTTP Basic for highly trusted first-party apps. Why it must not be used:

| Problem | Explanation |
|---|---|
| **The client sees the password** | Exactly the anti-pattern OAuth was invented to remove |
| **Trains users to type passwords into apps** | Makes phishing look normal |
| **Incompatible with modern authentication** | MFA, passkeys, risk-based checks, federation and SSO all need the AS's own UI |
| **No consent step** | The AS cannot ask the user what to grant |
| **Brute force target** | The token endpoint becomes a password-guessing oracle |
| **Wrong trust model** | The AS cannot distinguish the user acting from the client acting |

**Migration:** replace both with the authorization code grant plus PKCE (via a BFF for browser apps). For first-party native apps that want a native login UI, use the system browser per RFC 8252 (with passkeys the experience is now very smooth), or track the IETF's work on first-party native app flows as a draft. Do not fall back to the password grant.

---

## 10. Scopes and consent

A **scope** is a space-separated list of case-sensitive strings naming permissions the client is requesting:

```text
scope=orders.read orders.write profile.read
```

RFC 6749 does not define any scope names. Design guidance:

| Guideline | Example |
|---|---|
| Name scopes as `resource.action` | `orders.read`, `orders.write`, `invoices.approve` |
| Keep them coarse enough for users to understand on a consent screen | Avoid hundreds of scopes such as `orders.line_items.discount.update` |
| Least privilege: request only what you need, when you need it | Ask for `orders.write` only when the user first creates an order (**incremental authorization**) |
| Scopes limit the **client**, not the **user** | The API still checks the user's own permissions |
| Use audience or resource indicators to limit **where** a token works | `aud=https://api.example.com` (see [RFC 8707](09-modern-oauth-2.1-and-extensions.md#10-resource-indicators-rfc-8707)) |
| For fine-grained, transactional permissions, use RAR | "Pay 123.50 EUR to Merchant A" (see [RFC 9396](09-modern-oauth-2.1-and-extensions.md#9-rich-authorization-requests-rar-rfc-9396)) |

**Consent** is the user's decision to grant the requested scopes to this client:

- Show the **client's name, logo and owner**, and the scopes in plain language.
- Mark clients that registered dynamically or are unverified ("This app has not been verified").
- Remember consent per (user, client, scope set), and let users review and revoke it on an account page.
- First-party clients may skip consent, but only for clients you control.
- The AS may grant **less** than requested. The client must read the `scope` in the token response.
- Protect the consent page against **clickjacking** with `Content-Security-Policy: frame-ancestors 'none'`.

---

## 11. The state parameter and CSRF on the callback

Without protection, an attacker can complete half of a flow themselves and make the **victim's browser** finish it:

1. The attacker starts an authorization flow with *their own* account and gets a valid code at the AS.
2. They stop before the callback and send the victim a link: `https://app.example.com/callback?code=ATTACKER_CODE`.
3. The victim's browser calls the callback with the victim's session cookie. The client redeems the attacker's code and **links the attacker's resources to the victim's session**. For example, the victim's uploads now go to the attacker's cloud drive, or the victim is logged into the attacker's account (login CSRF).

```mermaid
sequenceDiagram
    autonumber
    participant A as Attacker
    participant V as Victim browser
    participant C as Client app
    participant AS as Authorization server
    A->>AS: Start flow with attacker account, obtain code X
    A->>V: Lure: link to app callback with code X
    V->>C: GET /callback?code=X with victim session cookie
    C->>C: state missing or not in victim session, reject
    Note over C: Without state or PKCE checks the client would redeem X into the victim session
```

**Defense:** the `state` parameter (or PKCE, as explained in [section 5](#5-pkce-rfc-7636-required-for-every-client)):

- Generate at least 128 bits of randomness per flow and store it in the user's server-side session (or a signed, `HttpOnly` cookie tied to the session).
- On the callback, require a match, compare in constant time, then **delete it** (single use).
- If you need to return the user to a page after login, store the return URL **in the session** under the state value. Do not put a raw URL in `state`, and validate return URLs against an allowlist to avoid creating an open redirector.

---

## 12. Redirect URIs: exact matching

The redirect URI decides **where the code goes**. If an attacker can make the AS send a code to a URL they control, the flow is broken. RFC 9700 requires **exact string matching** of redirect URIs against pre-registered values. The one exception is the port number of `localhost` loopback redirect URIs for native apps (RFC 8252).

| Registered | Requested | Lax matcher | Exact matcher | Attack |
|---|---|---|---|---|
| `https://app.example.com/callback` | `https://app.example.com/callback/../redirect?to=evil.com` | Prefix match accepts | Rejected | Path traversal to an open redirector |
| `https://*.example.com/callback` | `https://attacker-controlled.example.com/callback` | Wildcard accepts | Wildcards not allowed | Subdomain takeover (a dangling DNS record) |
| `https://app.example.com` | `https://app.example.com.evil.com/cb` | Naive prefix match accepts | Rejected | Attacker-owned domain |
| `https://app.example.com/callback` | `https://app.example.com/callback?next=//evil.com` | Query ignored | Rejected | Open redirect after the callback |
| `https://app.example.com/callback` | `http://app.example.com/callback` | Scheme ignored | Rejected | Code sent over plain HTTP |

Rules:

- Register **full** redirect URIs. No wildcards, no prefix matching, no pattern matching.
- Use `https` everywhere, except `http://127.0.0.1:{any port}/...` loopback redirects for native apps.
- Always send `redirect_uri` in the authorization request, and require the same value at the token endpoint.
- On an invalid `client_id` or `redirect_uri`, show an error page. **Never redirect.**
- Remove stale redirect URIs, and monitor DNS for dangling records on domains used in redirect URIs.

---

## 13. Client authentication at the token endpoint

Confidential clients must prove who they are when redeeming codes, refreshing, or using client credentials.

| Method | `token_endpoint_auth_method` | What is sent | Shared secret? | Replay of a captured credential | Recommendation |
|---|---|---|---|---|---|
| HTTP Basic | `client_secret_basic` | `Authorization: Basic base64(id:secret)` | Yes | Unlimited until the secret is rotated | Acceptable for low-risk clients, rotate secrets |
| Form post | `client_secret_post` | `client_id` and `client_secret` in the body | Yes | Unlimited | Avoid. Bodies are more likely to be logged |
| HMAC JWT | `client_secret_jwt` | JWT signed with the shared secret (HS256) | Yes | Limited by `exp` and `jti` | Rarely worth it. The AS must store the secret in usable form |
| **Private key JWT** | `private_key_jwt` (RFC 7523) | JWT signed with the client's private key | **No** | Limited by `exp` and `jti` | **Recommended** |
| **Mutual TLS** | `tls_client_auth`, `self_signed_tls_client_auth` (RFC 8705) | Client certificate in the TLS handshake | **No** | Not possible without the private key | **Recommended**. Also enables certificate-bound tokens |
| None | `none` | Only `client_id` | No | Not applicable | Public clients only, always with PKCE |

RFC 9700 recommends that authorization servers use **asymmetric** client authentication (mTLS or `private_key_jwt`) where possible. The AS then stores only public keys, so a breach of the AS's client database leaks nothing usable, and keys can be rotated by publishing a new JWKS.

### client_secret_basic

```http
POST /oauth2/token HTTP/1.1
Host: auth.example.com
Authorization: Basic b3JkZXJzLXdlYjo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=orders.read
```

A classic interoperability bug: RFC 6749 says the client ID and secret must be **form-URL-encoded before** being joined with `:` and base64-encoded. Secrets containing `:`, `+` or `%` break clients that skip this step.

### client_secret_post

```http
POST /oauth2/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=orders.read&client_id=orders-batch&client_secret=Zq3vV9pL2mXc8RkTnB4wYa
```

### private_key_jwt (RFC 7523)

The client registers a public key (or a `jwks_uri`) and signs a short-lived JWT for each token request:

```http
POST /oauth2/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
&client_id=orders-web
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6Im9yZGVycy13ZWItMjAyNi0xMCIsInR5cCI6IkpXVCJ9.eyJpc3Mi...sig
```

The decoded assertion:

```json
{ "alg": "ES256", "kid": "orders-web-2026-10", "typ": "JWT" }
```

```json
{
  "iss": "orders-web",
  "sub": "orders-web",
  "aud": "https://auth.example.com",
  "jti": "86-YxrlBg8w_HwZEZWTTrRQ0dLMe0ej_",
  "iat": 1791450000,
  "exp": 1791450060
}
```

The AS checks the signature against the client's registered keys, `iss` and `sub` equal the `client_id`, `aud` identifies this AS, `exp` is in the near future (lifetimes of about 60 seconds are typical), and `jti` has not been seen before (keep a replay cache until `exp`).

> **Audience note (2025-2026).** RFC 7523 allowed several audience values, including the token endpoint URL. In January 2025, University of Stuttgart researchers disclosed an "audience injection" attack that exploits that ambiguity when a client talks to more than one AS. The IETF draft `draft-ietf-oauth-rfc7523bis` (an OAuth working group Internet-Draft, not yet an RFC at the time of writing) requires the AS's **issuer identifier** as the **single** `aud` value for client authentication. New implementations should send the issuer identifier as a plain string, and authorization servers should accept it.

### tls_client_auth and self_signed_tls_client_auth (RFC 8705)

The client presents an X.509 certificate during the TLS handshake with the token endpoint. The body contains only `client_id`:

```http
POST /oauth2/token HTTP/1.1
Host: mtls.auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=orders.read&client_id=orders-batch
```

- `tls_client_auth`: the certificate is issued by a trusted CA, and the AS matches a registered subject DN or SAN (for example `tls_client_auth_san_dns=batch.internal.example.com`).
- `self_signed_tls_client_auth`: the client registers its self-signed certificate (in its JWKS), and the AS matches the exact certificate.
- If TLS terminates at a load balancer, the proxy must pass the verified certificate to the AS in a header the AS trusts, and must strip that header from incoming requests.
- mTLS also enables **certificate-bound access tokens**. See [chapter 09](09-modern-oauth-2.1-and-extensions.md#62-mutual-tls-rfc-8705).

---

## 14. Token introspection (RFC 7662)

With **opaque** access tokens, the resource server cannot read the token. It asks the AS instead:

```http
POST /oauth2/introspect HTTP/1.1
Host: auth.example.com
Authorization: Basic b3JkZXJzLWFwaTpSazJuVDh2UXg0TG1QOXNX
Content-Type: application/x-www-form-urlencoded
Accept: application/json

token=mF_9.B5f-4.1JqM&token_type_hint=access_token
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "active": true,
  "client_id": "orders-web",
  "sub": "248289761001",
  "scope": "orders.read orders.write",
  "aud": "https://api.example.com",
  "iss": "https://auth.example.com",
  "token_type": "Bearer",
  "exp": 1791450600,
  "iat": 1791450000
}
```

For any token that is expired, revoked, unknown or not meant for the caller, the response is just:

```json
{ "active": false }
```

| Topic | Guidance |
|---|---|
| Authentication | The introspection endpoint must require authentication (the RS is itself a client). Otherwise it is a token-scanning oracle |
| Privacy | Return only the claims the calling RS needs. The AS may answer `active: false` if the token is not meant for that RS |
| Caching | Cache positive results for a short time, never beyond `exp` (for example 30-60 seconds). This trades revocation latency for load |
| Opaque vs JWT | JWTs are validated locally (fast, no AS dependency, revocation lags until `exp`). Opaque tokens with introspection give instant revocation and keep claims private, at the cost of a network call |
| Hybrid ("phantom token") | Clients get opaque tokens, and an API gateway introspects them and forwards a short-lived JWT to internal services |

---

## 15. Token revocation (RFC 7009)

A client tells the AS it no longer needs a token, for example on logout or when a user disconnects an integration:

```http
POST /oauth2/revoke HTTP/1.1
Host: auth.example.com
Authorization: Basic b3JkZXJzLXdlYjo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
Content-Type: application/x-www-form-urlencoded

token=1B6Kif29I_uhKaoev5VXC-RReWvATaGgeW8w8-HZfPU&token_type_hint=refresh_token
```

```http
HTTP/1.1 200 OK
```

- The AS returns **200 even if the token was already invalid or unknown**. The client cannot do anything useful with that error, and different answers would leak information.
- Revoking a **refresh token** should also invalidate access tokens from the same grant, if the AS can.
- Clients authenticate as usual. A client may revoke only its own tokens.
- Revoking a **JWT** access token does not stop resource servers that validate it locally until it expires. This is why access tokens stay short-lived. If you need instant cut-off, use introspection or a `jti` denylist for high-risk APIs.

---

## 16. Authorization server metadata (RFC 8414)

Instead of hard-coding endpoint URLs, clients fetch a JSON document from a well-known location derived from the AS's **issuer identifier**:

```http
GET /.well-known/oauth-authorization-server HTTP/1.1
Host: auth.example.com
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: max-age=3600

{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth2/authorize",
  "token_endpoint": "https://auth.example.com/oauth2/token",
  "jwks_uri": "https://auth.example.com/oauth2/jwks",
  "introspection_endpoint": "https://auth.example.com/oauth2/introspect",
  "revocation_endpoint": "https://auth.example.com/oauth2/revoke",
  "device_authorization_endpoint": "https://auth.example.com/oauth2/device_authorization",
  "registration_endpoint": "https://auth.example.com/connect/register",
  "response_types_supported": ["code"],
  "grant_types_supported": [
    "authorization_code", "refresh_token", "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code"
  ],
  "token_endpoint_auth_methods_supported": ["private_key_jwt", "tls_client_auth", "client_secret_basic"],
  "token_endpoint_auth_signing_alg_values_supported": ["ES256", "PS256", "RS256"],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["orders.read", "orders.write"],
  "authorization_response_iss_parameter_supported": true
}
```

Rules:

- The client **must check** that `issuer` in the document is identical to the issuer it used to build the URL. Otherwise an attacker who can influence the metadata URL could substitute their own endpoints.
- For an issuer with a path, such as `https://auth.example.com/tenant1`, RFC 8414 inserts the well-known segment **before** the path: `https://auth.example.com/.well-known/oauth-authorization-server/tenant1`. OpenID Connect Discovery instead **appends** `/.well-known/openid-configuration` to the issuer. Many servers serve both. See [OpenID Connect](10-openid-connect.md#9-discovery).
- Cache metadata (hours), but refresh it on errors and periodically. Spring's `issuer-uri` property uses this document (or the OIDC equivalent) to discover endpoints.

---

## 17. Dynamic client registration (RFC 7591)

Some ecosystems cannot register every client by hand: open banking, multi-tenant SaaS integrations, and AI agents connecting to tools. **Dynamic client registration** (RFC 7591, July 2015) lets a client register itself through an API. (Some newer ecosystems prefer a lighter alternative being standardized as an IETF draft, *Client ID Metadata Documents*, where the `client_id` is an `https` URL that serves the client's metadata. The Model Context Protocol's 2026 authorization revision deprecated RFC 7591 in favor of it.)

```http
POST /connect/register HTTP/1.1
Host: auth.example.com
Authorization: Bearer <initial access token issued by the AS operator>
Content-Type: application/json

{
  "client_name": "Orders Reporting",
  "redirect_uris": ["https://reports.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://reports.example.com/.well-known/jwks.json",
  "scope": "orders.read"
}
```

```http
HTTP/1.1 201 Created
Content-Type: application/json
Cache-Control: no-store

{
  "client_id": "c-7f3a9d21",
  "client_id_issued_at": 1791450000,
  "client_name": "Orders Reporting",
  "redirect_uris": ["https://reports.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://reports.example.com/.well-known/jwks.json",
  "scope": "orders.read",
  "registration_access_token": "reg-23410913-abewfq.123483",
  "registration_client_uri": "https://auth.example.com/connect/register?client_id=c-7f3a9d21"
}
```

The `registration_access_token` and `registration_client_uri` come from RFC 7592 (Experimental), which defines reading, updating and deleting registrations.

| Risk | Mitigation |
|---|---|
| Anyone registers a phishing client with a convincing name | Protect registration with an **initial access token** or signed **software statements**. Label dynamically registered clients as unverified on the consent screen |
| SSRF: the AS fetches attacker-supplied URLs (`jwks_uri`, `logo_uri`, `sector_identifier_uri`) | Fetch only `https` URLs, block internal address ranges, use timeouts and size limits, fetch through an egress proxy |
| Client floods | Rate-limit registrations, expire unused clients |
| Over-broad defaults | Grant the minimum grant types and scopes. Require PKCE and asymmetric authentication |

---

## 18. Choosing a grant

```mermaid
flowchart TD
    Q1{"Is a user involved?"}
    Q1 -->|"No"| CC["Client credentials (or workload identity federation)"]
    Q1 -->|"Yes"| Q2{"Does the device have a usable browser?"}
    Q2 -->|"No: TV, CLI, IoT"| DEV["Device authorization grant (RFC 8628)"]
    Q2 -->|"Yes"| Q3{"What kind of app?"}
    Q3 -->|"Server-side web app"| WEB["Authorization code + PKCE, confidential client"]
    Q3 -->|"Browser SPA"| SPA["BFF: backend does code + PKCE, browser gets a session cookie"]
    Q3 -->|"Mobile or desktop app"| NAT["Authorization code + PKCE via system browser (RFC 8252)"]
    Q3 -->|"Service calling another API for the user"| TE["Token exchange (RFC 8693)"]
    Q4["Need to know WHO the user is?"] --> OIDC["Add OpenID Connect: scope openid, validate the ID token"]
```

Never choose the implicit or password grant.

---

## 19. Vulnerabilities in depth

### 19.1 Authorization code interception

- **What:** A code is captured on its way to the client, by a malicious app with the same custom URI scheme, a malicious browser extension, or logs.
- **Mitigation:** PKCE with S256 for every client. Short code lifetime (30-60 s). Single-use codes, with revocation of issued tokens if a code is reused. Claimed `https` redirect URIs (Universal Links, App Links) for mobile apps.

### 19.2 Authorization code injection

- **What:** A stolen code is injected into the attacker's own session at the legitimate client (see [section 5](#5-pkce-rfc-7636-required-for-every-client)).
- **Mitigation:** PKCE (the verifier is tied to the session that started the flow). For OpenID Connect, also `nonce`.

### 19.3 CSRF on the callback

- **What:** The victim's browser is made to complete a flow the attacker started, linking the attacker's account or resources to the victim's session.
- **Mitigation:** `state` bound to the session (single use), or PKCE when the AS enforces it. Use both.

### 19.4 Open redirectors

Two flavors:

- **At the client:** an endpoint such as `/go?url=...` on the client's domain. Combined with lax redirect URI matching, the AS sends the code to the open redirector, which forwards it (and, for the old implicit flow, the fragment) to the attacker. The 2014 "Covert Redirect" disclosure was this class of bug.
- **At the AS:** an AS that redirects to an unvalidated `redirect_uri` on errors becomes an open redirector itself. Attackers also register clients with a phishing redirect URI and craft requests that fail (for example with an invalid scope), so the trusted AS domain bounces the victim to the phishing page.
- **Mitigation:** Exact redirect URI matching. No open redirects anywhere on client domains (allowlist return URLs). The AS never redirects when `client_id` or `redirect_uri` is invalid, and is careful about redirecting to unverified clients without user interaction.

### 19.5 Mix-up attacks

- **What:** A client that works with **several** authorization servers (for example "Log in with A" and "Log in with B") is tricked into sending a code or token from honest AS **A** to attacker-controlled AS **B**. Typically the user picks B, the attacker redirects them to A, and the client, believing it is talking to B, redeems A's code at B's token endpoint.

```mermaid
sequenceDiagram
    autonumber
    participant U as User browser
    participant C as Client (supports AS A and AS B)
    participant B as Attacker AS B
    participant A as Honest AS A
    U->>C: Choose login with B
    C->>C: Store expected AS = B in session
    C-->>U: Redirect to B authorize endpoint
    U->>B: Authorization request
    B-->>U: Redirect to honest AS A instead, with the client id at A
    U->>A: User logs in at A (it looks legitimate)
    A-->>U: Redirect to client callback with code from A, iss = A
    U->>C: Callback with code from A
    C->>C: iss is A but the session expected B, reject
    Note over C,B: Without the iss check the client would send A's code to B's token endpoint
```

- **Mitigation:** The **`iss` authorization response parameter** (RFC 9207): the client compares it with the AS it started the flow with. Alternatively, use a **distinct redirect URI per AS** and check which AS the callback belongs to. OpenID Connect clients can also check `iss` in the ID token, but that only helps once the code has been redeemed at the correct token endpoint.

### 19.6 Token and code leakage via Referer, history and logs

- **What:** Codes in callback URLs and tokens in query strings leak through the `Referer` header (when the callback page loads third-party images or scripts, or the user clicks a link), browser history, server and proxy access logs, analytics tools, and error trackers.
- **Mitigation:**
  - Codes are single-use and short-lived, and PKCE makes a leaked code useless anyway.
  - Serve callback pages with `Referrer-Policy: no-referrer`, load no third-party content on them, and redirect to a clean URL right after processing.
  - Never put access tokens in URLs. Use the `Authorization` header.
  - Scrub `Authorization` headers, `code`, `access_token`, `refresh_token`, `client_secret` and `client_assertion` from logs, traces and error reports.
  - Send `Cache-Control: no-store` on token responses.

### 19.7 Insufficient redirect URI validation

- **What:** Wildcards, prefix matching, or ignored schemes and queries let attackers choose a redirect URI under their control ([section 12](#12-redirect-uris-exact-matching)).
- **Mitigation:** Exact string matching, `https` only, no wildcards, and monitoring for subdomain takeover.

### 19.8 Other issues listed in RFC 9700

| Issue | Mitigation |
|---|---|
| **Clickjacking** of the login or consent page | `Content-Security-Policy: frame-ancestors 'none'` (or `X-Frame-Options: DENY`) |
| **307 redirects** after the user posts credentials to the AS: the browser re-posts the form, password included, to the client | The AS uses `303 See Other` for redirects after `POST` |
| **Access token leakage at a compromised or counterfeit resource server** | Audience-restricted tokens (`aud`, RFC 8707). Sender-constrained tokens |
| **Stolen access token replay** | Short lifetimes. DPoP or mTLS binding |
| **TLS-terminating reverse proxies** that forward spoofable headers (client certificate, client IP) | The proxy strips and sets these headers. The AS trusts them only from the proxy |
| **Client impersonating a user**: a client registers a `client_id` equal to a user's `sub`, so client-credentials tokens look like user tokens | The AS does not let clients choose their `client_id` or token `sub`. The RS distinguishes client tokens from user tokens |

---

## 20. OAuth is authorization, not authentication

OAuth answers **"may this client access this resource?"**. It does **not** answer **"who is the user, and did they just log in?"**. Using a plain OAuth access token as proof of login ("we got a token, and `/me` returned an ID, so log them in") is called **pseudo-authentication**, and it is broken:

| Missing piece | Why it matters |
|---|---|
| **No audience for the client** | An access token is meant for the resource server, not for your app. A token issued to *another* app (for example a malicious quiz app the victim also used) works just as well when replayed to your backend, so the attacker logs in as the victim. This is **token substitution**, a confused deputy problem |
| **No authentication event information** | No `auth_time`, no `acr` or `amr`, so you cannot tell when or how the user logged in |
| **No `nonce`** | No binding between your login request and the token you received |
| **Token format is opaque to clients** | Clients are not supposed to parse access tokens. Each provider's `/me` endpoint is different |
| **Delegation can happen without the user present** | A refresh token keeps working long after the user left |

**OpenID Connect** fixes this with the **ID token**: a signed JWT whose `aud` is **your** `client_id`, with `iss`, `sub`, `auth_time`, `nonce`, `acr` and `amr`, and a standard validation procedure. If you need login, use OIDC. See [OpenID Connect](10-openid-connect.md#1-why-openid-connect-exists).

---

## 21. Production best practices (2026)

**Grants and flows**

- Authorization code **plus PKCE (S256)** for every client that involves a user. Client credentials for machines. Device grant only for input-constrained devices.
- No implicit grant, no password grant. Disable them at the AS.
- Browser apps: a **BFF** that is a confidential client and keeps tokens server-side. The browser gets an `HttpOnly; Secure; SameSite` session cookie. Never put tokens in `localStorage`. See [modern OAuth](09-modern-oauth-2.1-and-extensions.md#5-oauth-for-browser-based-apps-rfc-10017).
- Native apps: the system browser (ASWebAuthenticationSession, Android Custom Tabs), never embedded web views. Claimed `https` redirect URIs where possible.

**Redirects and CSRF**

- Exact redirect URI matching, `https` only, no wildcards.
- `state` with at least 128 bits, single use, bound to the session, plus PKCE.
- Validate `iss` in authorization responses (RFC 9207) when you use more than one AS.

**Tokens**

| Item | Recommendation |
|---|---|
| Authorization code | Single use, 30-60 s lifetime, bound to the client, the redirect URI and the PKCE challenge |
| Access token | 5-15 minutes, audience-restricted (`aud`), minimal scopes |
| JWT access token signing | ES256 or RS256 (RSA keys of at least 2048 bits, 3072 for long-lived keys) or EdDSA. Publish keys with `kid` in a JWKS. Rotate keys at least yearly and immediately on compromise. Keep old public keys published until all tokens signed with them have expired |
| Refresh token | Rotated on every use with reuse detection, stored hashed, with idle and absolute expiry. Sender-constrained where the risk justifies it |
| Sender-constraining | DPoP or mTLS for high-value APIs (finance, health, admin), and for public clients holding long-lived refresh tokens |

**Client authentication**

- `private_key_jwt` (aud = issuer identifier) or mTLS for confidential clients. If you must use secrets, generate at least 256-bit random secrets, store them in a secret manager, and rotate them (for example every 90 days) with overlap.
- Public clients: `none` plus PKCE. Never ship secrets in apps.

**Resource servers**

- Validate signature (algorithm allowlist), `iss`, `aud`, `exp`, `nbf` and scopes on every request. Cache the JWKS and refresh it when an unknown `kid` appears (rate-limited).
- Enforce user-level authorization in addition to scopes.
- Return proper RFC 6750 `WWW-Authenticate` errors.

**Operations**

- Publish RFC 8414 metadata. Clients configure only the issuer.
- Scrub tokens, codes and secrets from logs. `Cache-Control: no-store` on token responses.
- Rate-limit the token, device, introspection and registration endpoints.
- Monitor refresh token reuse events, mass consent grants to one new client, and device-flow approvals from unusual locations.
- Give users a page to review and revoke connected apps.

---

## 22. Common attacks and mistakes

| Attack or mistake | What goes wrong | Mitigation |
|---|---|---|
| No PKCE | Intercepted or injected codes can be redeemed | PKCE S256 for every client, enforced by the AS |
| `plain` PKCE method allowed | The challenge equals the verifier, so interception of the request reveals it | Accept only `S256` |
| PKCE downgrade | Attacker strips `code_challenge`, then redeems with any verifier | AS rejects a `code_verifier` when no challenge was sent, and requires PKCE |
| Missing or static `state` | CSRF on the callback, login CSRF | Random per-flow `state` bound to the session, single use |
| Wildcard or prefix redirect URI matching | Codes sent to attacker-controlled URLs | Exact string matching |
| Open redirector on the client or AS | Codes or tokens forwarded to the attacker. AS used for phishing | Allowlisted return URLs. No redirect on invalid client or redirect URI |
| Mix-up with several authorization servers | Code from honest AS sent to attacker's token endpoint | Check `iss` (RFC 9207) or use a per-AS redirect URI |
| Implicit grant | Tokens in URLs, token injection, no refresh | Code plus PKCE, preferably via a BFF |
| Password grant | Client sees passwords, no MFA, phishing | Code plus PKCE |
| Tokens in `localStorage` | Any XSS steals long-lived tokens | BFF with `HttpOnly` cookies, or in-memory tokens plus DPoP for browser-only apps |
| Access token in query string | Leaks via logs, history, `Referer` | `Authorization: Bearer` header only |
| Long-lived access tokens (hours or days) | Stolen tokens stay useful, revocation lags | 5-15 minute access tokens plus refresh |
| Refresh tokens not rotated or bound | A stolen refresh token gives months of access | Rotation with reuse detection, or sender-constraining |
| Client secret in a mobile app or SPA | Anyone can extract it and impersonate the client | Treat as a public client. Use PKCE and no secret |
| RS does not check `aud` | A token for API X is accepted by API Y | Validate `aud`. Use resource indicators |
| RS checks scope but not user permissions | User A reads user B's data with a valid token | Object-level authorization in the API |
| Using an access token as proof of login | Token substitution, account takeover | OpenID Connect ID token validation |
| Unauthenticated introspection endpoint | Token scanning and data leakage | Require RS authentication, return minimal claims |
| Tokens and codes in logs | Credential leakage to anyone with log access | Scrub sensitive parameters and headers |
| Device code phishing | Victim approves the attacker's device | Clear device context on the approval page, short expiry, restrict the grant |
| Consent page can be framed | Clickjacking into granting access | `frame-ancestors 'none'` |
| 307 redirect after the login form post | User's password re-posted to the client | Use 303 |
| Open dynamic registration with URL fetching | Phishing clients, SSRF against the AS | Initial access tokens or software statements. SSRF protections |

---

## 23. Spring Boot 4 / Spring Security 7

Spring Boot 4 renamed the OAuth starters (the old names still work but are deprecated):

| Purpose | Spring Boot 4 starter |
|---|---|
| OAuth client (login, calling APIs) | `spring-boot-starter-security-oauth2-client` |
| Resource server | `spring-boot-starter-security-oauth2-resource-server` |
| Authorization server (part of Spring Security 7) | `spring-boot-starter-security-oauth2-authorization-server` |

### 23.1 A service calling an API with client credentials (`oauth2Client`)

`application.yml`:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          orders-batch:
            provider: example
            client-id: orders-batch
            client-secret: ${ORDERS_BATCH_SECRET}      # from a secret manager, never committed
            client-authentication-method: client_secret_basic
            authorization-grant-type: client_credentials
            scope: orders.read
        provider:
          example:
            issuer-uri: https://auth.example.com       # endpoints discovered via metadata
```

Java configuration:

```java
import static org.springframework.security.oauth2.client.web.client.RequestAttributeClientRegistrationIdResolver.clientRegistrationId;

@Configuration
class OrdersApiClientConfig {

    // Works outside an HTTP request (schedulers, batch jobs).
    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository registrations,
            OAuth2AuthorizedClientService authorizedClients) {
        var provider = OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials()        // fetches and caches tokens, renews them near expiry
                .build();
        var manager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(registrations, authorizedClients);
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }

    @Bean
    RestClient ordersRestClient(OAuth2AuthorizedClientManager manager) {
        return RestClient.builder()
                .baseUrl("https://api.example.com")
                .requestInterceptor(new OAuth2ClientHttpRequestInterceptor(manager))
                .build();
    }
}

@Service
class NightlyReport {

    private final RestClient orders;

    NightlyReport(RestClient ordersRestClient) {
        this.orders = ordersRestClient;
    }

    String openOrders() {
        return orders.get()
                .uri("/orders?status=open")
                .attributes(clientRegistrationId("orders-batch"))   // which registration supplies the token
                .retrieve()
                .body(String.class);
    }
}
```

To replace the client secret with `private_key_jwt`, set `client-authentication-method: private_key_jwt` (and drop `client-secret`), then give the client credentials provider a token response client that signs a client assertion with your private key:

```java
// clientSigningKey: an EC or RSA JWK with its private part, loaded from a keystore or KMS.
// Its public part is registered at the AS (or published at the client's jwks_uri).
var tokenClient = new RestClientClientCredentialsTokenResponseClient();
tokenClient.addParametersConverter(
        new NimbusJwtClientAuthenticationParametersConverter<>(registration -> clientSigningKey));

var provider = OAuth2AuthorizedClientProviderBuilder.builder()
        .clientCredentials(cc -> cc.accessTokenResponseClient(tokenClient))
        .build();
```

### 23.2 Authorization code without login (`oauth2Client`), with PKCE

Use this when a logged-in user connects a third-party account (for example "connect your calendar") and you need tokens, not a login:

```java
@Bean
SecurityFilterChain web(HttpSecurity http, ClientRegistrationRepository registrations) throws Exception {
    var resolver = new DefaultOAuth2AuthorizationRequestResolver(registrations, "/oauth2/authorization");
    resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce()); // explicit PKCE (already the Spring Security 7 default)

    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/", "/error").permitAll()
            .anyRequest().authenticated())
        .formLogin(Customizer.withDefaults())                  // the app's own login (see chapter 04)
        .oauth2Client(client -> client
            .authorizationCodeGrant(code -> code.authorizationRequestResolver(resolver)));
    return http.build();
}
```

Spring Security generates and checks `state`, stores the authorization request in the session, and redeems the code. In Spring Security 7, every client registration sends PKCE by default: the per-registration `ClientSettings.requireProofKey` setting defaults to `true`, and public clients (`client-authentication-method: none`) always get PKCE. The explicit `withPkce()` customizer above is therefore redundant but harmless (it does nothing when a challenge is already present), and it keeps PKCE on even if someone sets `requireProofKey(false)`.

### 23.3 Resource server validating JWT access tokens

`application.yml`:

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://auth.example.com          # iss is validated, JWKS discovered and cached
          audiences: https://api.example.com            # aud must contain this API
          jws-algorithms: RS256, ES256                  # algorithm allowlist
```

```java
@Configuration
@EnableWebSecurity
class ApiSecurityConfig {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/api/orders/**").hasAuthority("SCOPE_orders.read")
                .requestMatchers(HttpMethod.POST, "/api/orders/**").hasAuthority("SCOPE_orders.write")
                .anyRequest().denyAll())
            .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // Bearer tokens in the Authorization header are not sent automatically by browsers,
            // so CSRF does not apply. Keep CSRF on for any cookie-authenticated endpoint.
            .csrf(csrf -> csrf.disable());
        return http.build();
    }
}
```

Spring maps the `scope` claim to `SCOPE_` authorities, validates the signature, `iss`, `exp` and `nbf` (with 60 seconds of clock skew by default) and, with `audiences` set, `aud`. Failures produce RFC 6750 `WWW-Authenticate: Bearer error="invalid_token"` responses.

For **opaque** tokens, switch to introspection:

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        opaquetoken:
          introspection-uri: https://auth.example.com/oauth2/introspect
          client-id: orders-api
          client-secret: ${ORDERS_API_SECRET}
```

```java
.oauth2ResourceServer(rs -> rs.opaqueToken(Customizer.withDefaults()))
```

The runnable multi-module example [../examples/03-oauth2-oidc/](../examples/03-oauth2-oidc/) contains an authorization server (Spring Authorization Server with OIDC), a resource server, and a BFF client app using `oauth2Login`.

---

## Interview questions

**1. What are the four OAuth 2.0 roles?**
Resource owner (usually the user), client (the app wanting access), authorization server (authenticates the user, gets consent, issues tokens) and resource server (the API that accepts tokens).

**2. Why does the authorization code grant use a code instead of returning the token directly?**
The front channel (browser redirects) is exposed to history, logs, extensions and `Referer`. A short-lived, single-use code goes through it, and the tokens are delivered over a direct TLS back channel where the client can authenticate. With PKCE, even a leaked code is useless.

**3. What does PKCE protect against, and why do confidential clients need it too?**
It binds the code to the client instance that started the flow via `code_verifier`, so intercepted codes cannot be redeemed. Confidential clients need it because client authentication does not stop **code injection**, where a stolen code is replayed through the attacker's own session at the legitimate client. PKCE also provides CSRF protection.

**4. Why are the implicit and password grants deprecated?**
Implicit puts tokens in URLs (leakage, injection, no client authentication, no refresh, no sender-constraining), and its reason for existing (no CORS) is gone. Password exposes user credentials to the client, blocks MFA, passkeys and federation, and trains users to be phished. RFC 9700 says implicit SHOULD NOT and password MUST NOT be used.

**5. What is the difference between confidential and public clients?**
Confidential clients run on servers and can protect a credential, so they authenticate at the token endpoint. Public clients (SPAs, mobile, desktop, CLI) cannot keep secrets, so they use `none` plus PKCE and never get a client secret.

**6. How should a resource server validate a JWT access token?**
Verify the signature with a JWKS key chosen by `kid`, with the algorithm taken from an allowlist (not trusting the header). Then check `iss`, `aud` (includes this API), `exp` and `nbf`, then scopes, then the user's own permissions on the specific object.

**7. What is refresh token rotation with reuse detection?**
Each refresh returns a new refresh token and invalidates the old one. If an old one is used again, the AS assumes theft and revokes the whole token family, forcing re-login.

**8. What is a mix-up attack and how is it prevented?**
A client that uses several authorization servers is tricked into sending a code from an honest AS to an attacker's AS. It is prevented by checking the `iss` parameter in the authorization response (RFC 9207) or using distinct redirect URIs per AS.

**9. Introspection or JWT access tokens: when do you pick each?**
JWTs are verified locally (fast, no AS dependency), but revocation waits for expiry, so keep them short-lived. Opaque tokens with introspection give instant revocation and keep claims private, but add a network call (cache briefly). Gateways often combine them ("phantom token").

**10. Why is "we got an OAuth access token, so the user is logged in" wrong?**
An access token is meant for the API, not for your client. It has no audience for your app, no authentication time or method, and no nonce, so tokens issued to other apps can be substituted. Use OpenID Connect and validate the ID token.

---

## References

- RFC 6749 — The OAuth 2.0 Authorization Framework (2012): https://www.rfc-editor.org/rfc/rfc6749
- RFC 6750 — The OAuth 2.0 Authorization Framework: Bearer Token Usage (2012): https://www.rfc-editor.org/rfc/rfc6750
- RFC 6819 — OAuth 2.0 Threat Model and Security Considerations (2013): https://www.rfc-editor.org/rfc/rfc6819
- RFC 7636 — Proof Key for Code Exchange by OAuth Public Clients (PKCE) (2015): https://www.rfc-editor.org/rfc/rfc7636
- RFC 8628 — OAuth 2.0 Device Authorization Grant (2019): https://www.rfc-editor.org/rfc/rfc8628
- RFC 7009 — OAuth 2.0 Token Revocation (2013): https://www.rfc-editor.org/rfc/rfc7009
- RFC 7662 — OAuth 2.0 Token Introspection (2015): https://www.rfc-editor.org/rfc/rfc7662
- RFC 8414 — OAuth 2.0 Authorization Server Metadata (2018): https://www.rfc-editor.org/rfc/rfc8414
- RFC 7591 — OAuth 2.0 Dynamic Client Registration Protocol (2015): https://www.rfc-editor.org/rfc/rfc7591
- RFC 7592 — OAuth 2.0 Dynamic Client Registration Management Protocol (Experimental, 2015): https://www.rfc-editor.org/rfc/rfc7592
- draft-ietf-oauth-client-id-metadata-document — OAuth Client ID Metadata Document (Internet-Draft): https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/
- RFC 7521 — Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants (2015): https://www.rfc-editor.org/rfc/rfc7521
- RFC 7523 — JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants (2015): https://www.rfc-editor.org/rfc/rfc7523
- draft-ietf-oauth-rfc7523bis — Updates to OAuth 2.0 JWT Client Authentication and Assertion-Based Authorization Grants (Internet-Draft): https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/
- RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens (2020): https://www.rfc-editor.org/rfc/rfc8705
- RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens (2021): https://www.rfc-editor.org/rfc/rfc9068
- RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification (2022): https://www.rfc-editor.org/rfc/rfc9207
- RFC 9700 — Best Current Practice for OAuth 2.0 Security (BCP 240, January 2025): https://www.rfc-editor.org/rfc/rfc9700
- RFC 8252 — OAuth 2.0 for Native Apps (BCP 212, 2017): https://www.rfc-editor.org/rfc/rfc8252
- RFC 10017 — OAuth 2.0 for Browser-Based Applications (BCP 212, August 2026): https://www.rfc-editor.org/rfc/rfc10017
- draft-ietf-oauth-v2-1 — The OAuth 2.1 Authorization Framework (Internet-Draft, revision 16, September 2026): https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/
- OWASP OAuth 2.0 Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- Spring Security reference — OAuth 2.0 Client: https://docs.spring.io/spring-security/reference/servlet/oauth2/client/index.html
- Spring Security reference — OAuth 2.0 Resource Server: https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/index.html
- Spring Security reference — OAuth 2.0 Authorization Server: https://docs.spring.io/spring-security/reference/servlet/oauth2/authorization-server/index.html
