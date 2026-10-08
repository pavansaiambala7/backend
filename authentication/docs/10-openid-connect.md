# 10 — OpenID Connect: Authentication on Top of OAuth 2.0

OAuth 2.0 tells an application **what it may access**. It deliberately says nothing about **who the user is** or **how and when they logged in**. OpenID Connect (OIDC) adds exactly that: a signed **ID token** issued to the application itself, a standard **UserInfo** endpoint, standard claims and scopes, discovery, key distribution, and logout. This chapter explains why plain OAuth fails as a login protocol, then covers OIDC end to end: ID token claims and validation, the authorization code flow with PKCE in raw HTTP, discovery and JWKS rotation, logout, the quirks of Google, Microsoft and Apple, safe account linking, and choosing an identity provider.

> **Where this fits in the evolution**
>
> - **Before:** OpenID 1.0 (2005) and 2.0 (2007) offered decentralized login with URLs as identifiers, but were complex, phishable and unpopular with users. Meanwhile developers misused [OAuth 2.0](08-oauth-2.md) access tokens for "Log in with ..." buttons, a pattern called **pseudo-authentication** that led to account takeover bugs. Enterprises used [SAML](05-enterprise-sso-ldap-kerberos-saml.md), which is XML-heavy and browser-only.
> - **What it solved:** **OpenID Connect Core 1.0** (OpenID Foundation, final in **February 2014**) layered a standard identity token and user info API on top of OAuth 2.0. It is JSON and JWT based, works for web, mobile and SPAs, and is simple enough for every major platform to adopt. The current text incorporates **errata set 2** (December 2023) and was published as **ISO/IEC 26131:2024**.
> - **What came next:** The logout specifications (RP-Initiated, Front-Channel, Back-Channel; final in September 2022), the hardening rules of [RFC 9700 and OAuth 2.1](09-modern-oauth-2.1-and-extensions.md) (PKCE everywhere, no implicit flow), FAPI 2.0 for high-security deployments, and [passkeys](11-mfa-passwordless-and-passkeys.md) as the authentication method *behind* the OpenID provider.

---

## Table of contents

1. [Why OpenID Connect exists](#1-why-openid-connect-exists)
2. [What OIDC adds to OAuth 2.0](#2-what-oidc-adds-to-oauth-20)
3. [The ID token](#3-the-id-token)
4. [Validating an ID token](#4-validating-an-id-token)
5. [Authorization code flow with PKCE, step by step](#5-authorization-code-flow-with-pkce-step-by-step)
6. [Implicit and hybrid flows (legacy)](#6-implicit-and-hybrid-flows-legacy)
7. [Scopes, claims and request parameters](#7-scopes-claims-and-request-parameters)
8. [The UserInfo endpoint](#8-the-userinfo-endpoint)
9. [Discovery](#9-discovery)
10. [JWKS and key rotation](#10-jwks-and-key-rotation)
11. [Dynamic client registration](#11-dynamic-client-registration)
12. [Sessions and logout](#12-sessions-and-logout)
13. [Social login: Google, Microsoft, Apple](#13-social-login-google-microsoft-apple)
14. [Account linking pitfalls](#14-account-linking-pitfalls)
15. [Choosing an identity provider](#15-choosing-an-identity-provider)
16. [Production best practices (2026)](#16-production-best-practices-2026)
17. [Common attacks and mistakes](#17-common-attacks-and-mistakes)
18. [Spring Boot 4 / Spring Security 7](#18-spring-boot-4--spring-security-7)
19. [Interview questions](#interview-questions)
20. [References](#references)

---

## 1. Why OpenID Connect exists

### 1.1 The pseudo-authentication trap

Around 2010-2013 many apps implemented "Log in with *Provider*" like this:

1. Run an OAuth flow (often the implicit grant) and get an **access token**.
2. Call the provider's `/me` API with it, read the user ID, and log the user in.

Mobile apps often went one step further: the app obtained the access token itself and sent it to its backend (`POST /login {"access_token": "..."}`). The backend called `/me` and created a session for whoever that token belonged to.

This looks reasonable, but an access token says only "the bearer may call this API". It does **not** say **which application** the user was logging into. Security researchers showed this class of bug against many real websites and mobile apps in the early 2010s.

### 1.2 Token substitution: a confused deputy

```mermaid
sequenceDiagram
    autonumber
    participant V as Victim
    participant Q as Attacker quiz app (also uses Provider login)
    participant P as Provider (OAuth AS and API)
    participant T as Target app backend (uses access tokens as login proof)
    V->>Q: Log in with Provider to play a quiz
    Q->>P: OAuth flow for client quiz-app
    P-->>Q: Access token for the victim, issued to quiz-app
    Q->>T: POST /login with the victim access token
    T->>P: GET /me with that token
    P-->>T: id 12345 (the victim)
    T-->>Q: Session cookie for victim account 12345
    Note over T: The target never checked who the token was issued to
```

The target backend is a **confused deputy**: it uses its trust in the provider's API to grant access, without checking that the token was meant for **it**. Any app the victim ever logged into with the same provider can take over the victim's account at the target.

### 1.3 Other gaps in plain OAuth

| Missing in OAuth 2.0 | Consequence for login |
|---|---|
| No token **audience** for the client | Token substitution (above) |
| No **authentication time** or **method** | Cannot require "logged in within 5 minutes" or "used MFA" |
| No **nonce** binding the response to the request | Replay and injection of tokens from other sessions |
| No standard **user identifier** or **claims** | Every provider's `/me` is different. Fragile parsing |
| Access tokens are **opaque to clients** by design | Clients that parse them break when the format changes |
| No standard **discovery**, **key distribution** or **logout** | Hard-coded endpoints, no coordinated sign-out |

### 1.4 The OIDC answer

OIDC adds an **ID token**: a JWT **issued to the client** (`aud` = your `client_id`), signed by the provider, containing the user's stable identifier (`iss` + `sub`), when and how they authenticated (`auth_time`, `acr`, `amr`), and the `nonce` your client sent. The client validates it with a standard procedure. A token issued to the quiz app has `aud=quiz-app`, so the target app rejects it.

If a backend must accept a login from a mobile app, the app sends the **ID token** (not an access token), and the backend validates it with `aud` equal to its own client ID. Better still, the backend runs the code flow itself.

---

## 2. What OIDC adds to OAuth 2.0

**Roles.** OIDC renames the OAuth roles for the login use case:

| OAuth 2.0 | OpenID Connect |
|---|---|
| Authorization server | **OpenID Provider (OP)**, also called identity provider (IdP) |
| Client | **Relying Party (RP)** |
| Resource owner | **End-User** |

**What OIDC adds:**

| Feature | Specification |
|---|---|
| ID token (JWT) with standard claims and validation rules | Core 1.0 |
| `openid` scope, which turns an OAuth request into an OIDC request | Core 1.0 |
| `nonce` parameter | Core 1.0 |
| UserInfo endpoint and standard claims (`name`, `email`, ...) | Core 1.0 |
| Authentication request parameters: `prompt`, `max_age`, `acr_values`, `login_hint`, `id_token_hint`, `claims` | Core 1.0 |
| Pairwise subject identifiers (privacy) | Core 1.0 |
| Discovery (`/.well-known/openid-configuration`) | Discovery 1.0 |
| Dynamic client registration | Registration 1.0 |
| Logout and session coordination | RP-Initiated, Front-Channel, Back-Channel Logout and Session Management 1.0 |
| Additional response types and `form_post` response mode | OAuth 2.0 Multiple Response Type Encoding Practices, Form Post Response Mode |
| Certification program for providers and relying parties | OpenID Foundation |

An OIDC request is simply an OAuth 2.0 authorization request with `scope` containing `openid`. Everything you know from [chapter 08](08-oauth-2.md) (code flow, PKCE, state, exact redirect URIs, client authentication) still applies.

---

## 3. The ID token

An ID token is a **signed JWT** (JWS), optionally also encrypted (JWE), that the OP issues to the RP. It is a statement: "**this** issuer authenticated **this** user, for **this** client, at **this** time, using **these** methods, in response to **this** request (nonce)."

### 3.1 Claims

| Claim | Required? | Meaning and rules |
|---|---|---|
| `iss` | Required | Issuer identifier: an `https` URL with no query or fragment. Must **exactly** match the issuer you configured |
| `sub` | Required | Subject: the user's identifier, **locally unique and never reassigned** within the issuer. At most 255 ASCII characters, case-sensitive. **Use `iss` + `sub` as the account key** |
| `aud` | Required | Audience: must contain your `client_id`. May be a string or an array |
| `exp` | Required | Expiry time (seconds since the epoch) |
| `iat` | Required | Issued-at time |
| `auth_time` | Required if `max_age` was requested or `auth_time` was requested as an essential claim | When the user actually authenticated (which may be long before `iat` if an OP session was reused) |
| `nonce` | Required if the request contained a `nonce` | Echo of the request's `nonce`. Binds the ID token to your session |
| `acr` | Optional | Authentication Context Class Reference: the assurance level achieved, for example `urn:example:acr:mfa` (values are deployment-specific) |
| `amr` | Optional | Authentication Methods References: an array such as `["pwd", "otp"]` or `["hwk", "user"]` (values registered by RFC 8176) |
| `azp` | Optional | Authorized party: the client the ID token was issued to. Relevant when `aud` contains several values |
| `at_hash` | Optional in the code flow, required when an access token is issued together with the ID token from the authorization endpoint | Hash of the access token issued alongside: `BASE64URL(left half of SHA-256(access_token))` for RS256 or ES256 |
| `c_hash` | Hybrid flow only | Hash of the authorization code, computed the same way |
| `sid` | Optional (defined by the logout specs) | OP session ID, used for front-channel and back-channel logout |

Standard user claims (`name`, `email`, `email_verified`, `picture`, `locale`, ...) may also appear, depending on scopes and provider.

### 3.2 A decoded ID token

Header:

```json
{ "alg": "RS256", "kid": "2026-10-a", "typ": "JWT" }
```

Payload:

```json
{
  "iss": "https://auth.example.com",
  "sub": "248289761001",
  "aud": "orders-web",
  "azp": "orders-web",
  "exp": 1791450600,
  "iat": 1791450000,
  "auth_time": 1791449990,
  "nonce": "eSRpnW2k3vVx1GALHB_rRw",
  "acr": "urn:example:acr:mfa",
  "amr": ["pwd", "otp", "mfa"],
  "at_hash": "ZTGoPwpi335nu8FhtzggfA",
  "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
  "name": "Jane Doe",
  "email": "jane@example.com",
  "email_verified": true
}
```

Here `at_hash` is the hash of the access token `Q8wC2fU1nK7vRm3xY9pLs0tZbH4eJ6dA_GiN5oTqWkE` returned in the same token response (see [section 5](#5-authorization-code-flow-with-pkce-step-by-step)).

### 3.3 ID token vs access token

| | ID token | Access token |
|---|---|---|
| Audience | **The client** (`aud` = `client_id`) | **The resource server (API)** |
| Purpose | Tell the client who logged in, when and how | Authorize API calls |
| Format | Always a JWT | Opaque or JWT (RFC 9068), opaque **to the client** |
| Who validates it | The client | The resource server |
| Send it to APIs? | **No** | Yes |
| Lifetime | Short (minutes). It is consumed at login, not reused | Short (5-15 minutes), renewed with refresh tokens |

Two rules follow. **Never use an ID token as an API bearer token**: its audience is wrong, and APIs that accept it are open to token confusion (JWT access tokens carry `typ: at+jwt` to prevent this). **Never use an access token as proof of login**: that was [section 1](#1-why-openid-connect-exists).

---

## 4. Validating an ID token

OIDC Core section 3.1.3.7 defines the procedure. Use a well-tested, OpenID-certified library (Spring Security, Nimbus, `jose4j`, and similar) rather than writing it yourself. You should still know every step:

1. **Decrypt** if the ID token is encrypted (only if you registered for encryption).
2. **`iss`** must exactly equal the issuer you trust for this flow (from discovery). For multi-tenant providers, see [section 13](#13-social-login-google-microsoft-apple).
3. **`aud`** must contain your `client_id`. Reject the token if `aud` contains audiences you do not trust.
4. If there are several audiences, check `azp`. If `azp` is present, it must equal your `client_id`. (Errata set 2 made `azp` checking depend on the extensions in use, but this strict rule is a safe default and is what Spring Security enforces.)
5. **Signature**: verify it with the OP's key from the **JWKS** published at the discovery document's `jwks_uri`, selected by `kid`. The algorithm must be on your allowlist and must be the one registered for your client (default `RS256`). Never accept `alg: none`. Never let the token header choose the key (`jku`, `x5u`, embedded `jwk`) or switch algorithm families (for example HS256 verified with an RSA public key used as an HMAC secret). The spec allows skipping signature checks for ID tokens received directly from the token endpoint over TLS. **Verify anyway**: it is cheap, and tokens get passed around later.
6. **`exp`**: the current time must be before `exp` (allow a small clock skew, for example 60 seconds).
7. **`iat`**: reject tokens issued too far in the past, according to your policy.
8. **`nonce`**: must equal the value you stored in the session for this flow. Use it once, then delete it.
9. **`acr`**: if you requested a level (`acr_values` or an essential `acr` claim), check that it is acceptable.
10. **`auth_time`**: if you sent `max_age`, check that `now - auth_time <= max_age`. Otherwise force re-authentication (`prompt=login`).
11. **`at_hash`**: if present, check that it matches the access token you received.

```mermaid
flowchart TD
    A["ID token received"] --> B{"iss equals expected issuer?"}
    B -->|"No"| X["Reject"]
    B -->|"Yes"| C{"aud contains client_id, azp ok?"}
    C -->|"No"| X
    C -->|"Yes"| D{"alg on allowlist, kid found in JWKS, signature valid?"}
    D -->|"No"| X
    D -->|"Yes"| E{"exp in future, iat recent?"}
    E -->|"No"| X
    E -->|"Yes"| F{"nonce equals session value?"}
    F -->|"No"| X
    F -->|"Yes"| G{"acr and auth_time meet requirements?"}
    G -->|"No"| R["Re-authenticate with acr_values or prompt=login"]
    G -->|"Yes"| H["Accept: look up account by iss and sub, start a new local session"]
```

After validation, **create your own application session** (a server-side session with a **new session ID**, to prevent session fixation). Do not keep using the ID token as a session token. See [Sessions, cookies and CSRF](04-sessions-cookies-and-csrf.md).

---

## 5. Authorization code flow with PKCE, step by step

This is the **only** flow you should use for new OIDC integrations, for every client type. Browser apps should run it from a BFF. The hosts are the same as in chapter 08: RP `https://app.example.com` (`client_id=orders-web`, confidential), OP `https://auth.example.com`.

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant RP as Relying party (orders-web BFF)
    participant OP as OpenID Provider
    B->>RP: GET /oauth2/authorization/example
    RP->>RP: Create state, nonce, PKCE verifier, store in session
    RP-->>B: 302 to OP authorize with scope openid, state, nonce, code_challenge
    B->>OP: GET /oauth2/authorize
    OP-->>B: Login page
    B->>OP: Credentials or passkey, then consent
    OP-->>B: 302 to RP callback with code, state, iss
    B->>RP: GET /login/oauth2/code/example with code and state
    RP->>RP: Check state and iss
    RP->>OP: POST /oauth2/token code, code_verifier, client authentication
    OP-->>RP: id_token, access_token, refresh_token
    RP->>RP: Validate ID token incl. nonce, look up account by iss and sub
    RP->>OP: Optional GET /userinfo with access token
    OP-->>RP: Claims with the same sub
    RP-->>B: 302 to app, Set-Cookie new session ID, HttpOnly, Secure, SameSite=Lax
```

### Step 1 — Authentication request

```http
HTTP/1.1 302 Found
Location: https://auth.example.com/oauth2/authorize?response_type=code&client_id=orders-web&redirect_uri=https%3A%2F%2Fapp.example.com%2Flogin%2Foauth2%2Fcode%2Fexample&scope=openid%20profile%20email&state=RJgHM0z7XRTlwXFcQm3EMA&nonce=eSRpnW2k3vVx1GALHB_rRw&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
Set-Cookie: SESSION=4c1f0e...; Path=/; Secure; HttpOnly; SameSite=Lax
```

```http
GET /oauth2/authorize?response_type=code
    &client_id=orders-web
    &redirect_uri=https%3A%2F%2Fapp.example.com%2Flogin%2Foauth2%2Fcode%2Fexample
    &scope=openid%20profile%20email
    &state=RJgHM0z7XRTlwXFcQm3EMA
    &nonce=eSRpnW2k3vVx1GALHB_rRw
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    &code_challenge_method=S256 HTTP/1.1
Host: auth.example.com
```

(Line breaks added for readability.) The differences from plain OAuth are `openid` in `scope` and the `nonce`.

### Step 2 — Authentication response

```http
HTTP/1.1 302 Found
Location: https://app.example.com/login/oauth2/code/example?code=SplxlOBeZQQYbYS6WxSbIA&state=RJgHM0z7XRTlwXFcQm3EMA&iss=https%3A%2F%2Fauth.example.com
```

The RP checks `state` (CSRF) and `iss` (mix-up), as in [chapter 08](08-oauth-2.md#4-the-authorization-code-grant-step-by-step).

OIDC-specific errors you may see: `login_required`, `consent_required`, `interaction_required` and `account_selection_required` (typically returned when `prompt=none` was sent and the OP cannot complete silently).

### Step 3 — Token request

```http
POST /oauth2/token HTTP/1.1
Host: auth.example.com
Authorization: Basic b3JkZXJzLXdlYjo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fapp.example.com%2Flogin%2Foauth2%2Fcode%2Fexample
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

### Step 4 — Token response

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "access_token": "Q8wC2fU1nK7vRm3xY9pLs0tZbH4eJ6dA_GiN5oTqWkE",
  "token_type": "Bearer",
  "expires_in": 600,
  "refresh_token": "G5n7ZvprjVuI2s4D40WdwoAcDopmZdIWRty5ntymVeU",
  "scope": "openid profile email",
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMjYtMTAtYSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiIyNDgyODk3NjEwMDEiLCJhdWQiOiJvcmRlcnMtd2ViIiwibm9uY2UiOiJlU1JwblcyazN2VngxR0FMSEJfclJ3In0.sig"
}
```

### Step 5 — Validate and create the session

The RP validates the ID token ([section 4](#4-validating-an-id-token)), finds or creates the local account keyed by (`iss`, `sub`), **rotates the session ID**, and stores what it needs: the user ID, `sid` (for back-channel logout), the ID token (as `id_token_hint` for logout), and the access and refresh tokens if it calls APIs. Tokens stay on the server; the browser only gets the session cookie.

---

## 6. Implicit and hybrid flows (legacy)

OIDC Core defines three flows, selected by `response_type`:

| `response_type` | Flow | What comes through the browser | Status in 2026 |
|---|---|---|---|
| `code` | Authorization code | Code only | **Use this, with PKCE** |
| `id_token` | Implicit | ID token in the URL fragment | Legacy. Avoid |
| `id_token token` | Implicit | ID token and access token in the fragment | **Deprecated**: access tokens in the front channel (RFC 9700) |
| `code id_token` | Hybrid | Code plus ID token (the ID token contains `c_hash`) | Legacy. FAPI 1.0 Advanced used it as a "detached signature" to protect the code. FAPI 2.0 replaced that with PAR, PKCE and `iss` |
| `code token`, `code id_token token` | Hybrid | Code plus access token | Avoid. Access token in the front channel |

**Why they existed:** in 2014, SPAs could not call token endpoints cross-origin, and the hybrid flow let a client verify the code's integrity before redeeming it.

**Why they are legacy:** tokens in the front channel leak (history, logs, open redirectors, scripts), cannot be sender-constrained, and invite token injection. The `form_post` response mode (the OP returns parameters in an auto-submitted HTML form `POST` instead of the URL) reduces leakage via history and `Referer`, but the tokens still pass through the browser. PKCE plus `nonce` plus `iss` now protects the code flow better than the hybrid tricks did.

If you maintain an old SPA using `id_token token`, migrate it to a **BFF** with the code flow. See [RFC 10017 in chapter 09](09-modern-oauth-2.1-and-extensions.md#5-oauth-for-browser-based-apps-rfc-10017).

---

## 7. Scopes, claims and request parameters

### 7.1 Standard scopes

| Scope | Claims it requests |
|---|---|
| `openid` | **Required.** Makes the request an OIDC request. Returns `sub` |
| `profile` | `name`, `family_name`, `given_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` |
| `email` | `email`, `email_verified` |
| `address` | `address` (a JSON object) |
| `phone` | `phone_number`, `phone_number_verified` |
| `offline_access` | Requests a **refresh token** usable when the user is not present. Core requires the OP to obtain consent (for example with `prompt=consent`). Some providers use their own mechanism instead (Google uses `access_type=offline`) |

Scopes other than `openid` request claims **if available and if the user consents**. Ask for the minimum: many apps need only `openid` plus `email`.

### 7.2 Claim reliability

| Claim | Can you use it as an identifier? | Notes |
|---|---|---|
| `sub` (with `iss`) | **Yes** | Stable, unique and never reassigned within the issuer |
| `email` | **No** | Can change, can be reassigned (corporate addresses), may be unverified, may be a relay address |
| `preferred_username` | **No** | Changeable, not unique across tenants. The spec says not to rely on it |
| `phone_number` | **No** | Numbers are recycled by carriers |
| `name`, `picture` | No | Display only |

### 7.3 Authentication request parameters

| Parameter | Purpose | Example |
|---|---|---|
| `nonce` | Binds the ID token to this request. **Always send it** | `nonce=eSRpnW2k3vVx1GALHB_rRw` |
| `prompt` | `none` (no UI: fail if interaction is needed), `login` (force re-authentication), `consent`, `select_account` | `prompt=login` before a sensitive action |
| `max_age` | Maximum seconds since the last active authentication. The OP re-authenticates if older, and `auth_time` becomes required | `max_age=300` |
| `acr_values` | Requested authentication context classes, in order of preference | `acr_values=urn:example:acr:phr` |
| `login_hint` | Pre-fill the user identifier | `login_hint=jane@example.com` |
| `id_token_hint` | A previously issued ID token, for example with `prompt=none` | |
| `claims` | JSON requesting individual claims, marking them as essential or asking for specific values | See below |
| `response_mode` | `query`, `fragment`, `form_post` | `form_post` (Apple requires it when requesting name or email) |
| `ui_locales`, `display` | UI language and display mode | `ui_locales=de-DE` |

Requesting an essential `acr` and specific claims with the `claims` parameter:

```json
{
  "id_token": {
    "acr": { "essential": true, "values": ["urn:example:acr:phr"] },
    "auth_time": { "essential": true }
  },
  "userinfo": {
    "email": { "essential": true },
    "email_verified": { "essential": true }
  }
}
```

Note that `acr_values` and non-essential `acr` requests are **hints**: the OP may authenticate at a lower level and still issue an ID token. **Always check the `acr` you received.**

---

## 8. The UserInfo endpoint

The UserInfo endpoint returns claims about the user, authorized with the **access token**:

```http
GET /userinfo HTTP/1.1
Host: auth.example.com
Authorization: Bearer Q8wC2fU1nK7vRm3xY9pLs0tZbH4eJ6dA_GiN5oTqWkE
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "sub": "248289761001",
  "name": "Jane Doe",
  "given_name": "Jane",
  "family_name": "Doe",
  "preferred_username": "j.doe",
  "email": "jane@example.com",
  "email_verified": true,
  "picture": "https://auth.example.com/avatars/248289761001.jpg"
}
```

Rules:

- The response's `sub` **must equal** the `sub` in the ID token. If not, discard the response (this defends against token substitution).
- The response may be a **signed JWT** (`application/jwt`) if the client registered `userinfo_signed_response_alg`. Then validate it like an ID token (`iss`, `aud`, signature).
- Call it at login if the ID token lacks claims you need. Do not call it on every request; store the claims in your session or user table.
- Which claims appear in the ID token and which come only from UserInfo varies by provider. Keep ID tokens small, and fetch profile data from UserInfo when needed.

---

## 9. Discovery

Clients should configure **only the issuer URL**. Everything else comes from the discovery document at `{issuer}/.well-known/openid-configuration` (OpenID Connect Discovery 1.0).

```http
GET /.well-known/openid-configuration HTTP/1.1
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
  "userinfo_endpoint": "https://auth.example.com/userinfo",
  "jwks_uri": "https://auth.example.com/oauth2/jwks",
  "end_session_endpoint": "https://auth.example.com/connect/logout",
  "registration_endpoint": "https://auth.example.com/connect/register",
  "revocation_endpoint": "https://auth.example.com/oauth2/revoke",
  "introspection_endpoint": "https://auth.example.com/oauth2/introspect",
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "response_types_supported": ["code"],
  "response_modes_supported": ["query", "form_post"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256", "ES256"],
  "token_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_basic", "tls_client_auth"],
  "code_challenge_methods_supported": ["S256"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "name", "email", "email_verified"],
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true,
  "frontchannel_logout_supported": true,
  "authorization_response_iss_parameter_supported": true
}
```

| Required metadata | |
|---|---|
| `issuer`, `authorization_endpoint`, `jwks_uri`, `response_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported` | Always |
| `token_endpoint` | Unless the OP supports only the implicit flow |
| `userinfo_endpoint` | Recommended |

Rules:

- The `issuer` value in the document **must exactly equal** the issuer you used to build the URL. It must also equal `iss` in every ID token. Spring Security checks both.
- Note the URL construction difference: OIDC **appends** the well-known path (`https://auth.example.com/tenant1/.well-known/openid-configuration`), while RFC 8414 **inserts** it before the issuer's path. See [chapter 08](08-oauth-2.md#16-authorization-server-metadata-rfc-8414).
- Fetch the document at startup and cache it (hours). Refetch on failures. Only ever fetch it over `https`.
- Discovery 1.0 also defines WebFinger-based issuer discovery from an email address. It is rarely used outside special deployments.

---

## 10. JWKS and key rotation

The OP publishes its **public** signing keys as a JWK Set at `jwks_uri`:

```json
{
  "keys": [
    {
      "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "2026-10-a",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP...",
      "e": "AQAB"
    },
    {
      "kty": "EC", "use": "sig", "alg": "ES256", "kid": "2027-01-a", "crv": "P-256",
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    }
  ]
}
```

### Rotation without downtime

```mermaid
sequenceDiagram
    autonumber
    participant OP as OpenID Provider
    participant J as JWKS endpoint
    participant RP as Relying parties (caching JWKS)
    OP->>J: Phase 1: publish new key 2027-01-a next to 2026-10-a
    Note over RP: Wait at least the maximum JWKS cache lifetime
    OP->>OP: Phase 2: start signing new tokens with 2027-01-a
    RP->>J: Unknown kid seen, refetch JWKS (rate limited)
    J-->>RP: Both keys
    Note over OP: Wait until all tokens signed with 2026-10-a have expired
    OP->>J: Phase 3: remove 2026-10-a
```

**OP side:**

- Publish the new key **before** using it, for at least the clients' maximum cache time.
- Keep the old public key until every token signed with it has expired (ID tokens, JWT access tokens, logout tokens), plus a margin.
- Rotate on a schedule (for example every 3-12 months) and **immediately** on suspected compromise. In an emergency, remove the compromised key at once and accept that some clients will refetch.
- Keep private keys in an HSM or KMS. RSA keys of at least 2048 bits (3072 recommended for long-lived keys), or P-256 for ES256.

**RP side:**

- Fetch keys **only** from the `jwks_uri` in the trusted discovery document. Ignore `jku`, `x5u` and embedded `jwk` headers in ID tokens.
- Select the key by `kid`. Check that the key's type and `alg` fit the allowlisted algorithm.
- Cache the JWKS (respect `Cache-Control`, typically 5-60 minutes).
- On an unknown `kid`, refetch **once**, with rate limiting (for example at most once per minute), so attackers cannot use random `kid` values to flood the OP.

Spring Security's `NimbusJwtDecoder` and the OIDC client handle caching and unknown-`kid` refetching. More on JWT pitfalls in [Tokens and JWT](06-tokens-and-jwt.md).

---

## 11. Dynamic client registration

**OpenID Connect Dynamic Client Registration 1.0** (compatible with [RFC 7591](08-oauth-2.md#17-dynamic-client-registration-rfc-7591)) lets RPs register at runtime. It adds OIDC-specific metadata:

```http
POST /connect/register HTTP/1.1
Host: auth.example.com
Authorization: Bearer <initial access token>
Content-Type: application/json

{
  "client_name": "Orders Reporting",
  "application_type": "web",
  "redirect_uris": ["https://reports.example.com/login/oauth2/code/example"],
  "post_logout_redirect_uris": ["https://reports.example.com/"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://reports.example.com/.well-known/jwks.json",
  "id_token_signed_response_alg": "ES256",
  "subject_type": "pairwise",
  "backchannel_logout_uri": "https://reports.example.com/logout/connect/back-channel/example",
  "backchannel_logout_session_required": true,
  "default_max_age": 43200,
  "require_auth_time": true
}
```

**Pairwise subject identifiers** (`subject_type: pairwise`): the OP gives each RP (or each *sector*, a group of redirect hosts declared via `sector_identifier_uri`) a **different** `sub` for the same user. Colluding RPs cannot correlate users by `sub`. Consequence: two of **your own** apps registered separately will see different `sub` values for the same person unless they share a sector identifier.

Security concerns are the same as for RFC 7591: protect registration with initial access tokens or software statements, guard against SSRF when the OP fetches `jwks_uri`, `logo_uri` or `sector_identifier_uri`, and label unverified clients on consent screens.

---

## 12. Sessions and logout

### 12.1 There are several sessions

```mermaid
flowchart LR
    U["User browser"]
    RPA["RP A session (app cookie)"]
    RPB["RP B session (app cookie)"]
    OPS["OP session (IdP cookie)"]
    UP["Upstream IdP session (for example corporate SSO)"]
    U --- RPA
    U --- RPB
    U --- OPS
    OPS --- UP
```

Logging out of RP A does **not** end the OP session. The user clicks "Log in" again and is signed straight back in. Logging out at the OP does **not** end RP sessions unless the RPs are notified. Full **single logout** requires the specifications below, and even then it is best effort.

| Specification (all Final, September 2022) | Direction | Mechanism | Reliability in 2026 |
|---|---|---|---|
| **RP-Initiated Logout 1.0** | RP to OP | Browser redirect to `end_session_endpoint` | Good |
| **Front-Channel Logout 1.0** | OP to RPs | OP page loads hidden iframes of each RP's logout URL | **Poor**: browsers block third-party cookies in iframes, so the RP often cannot see its session cookie |
| **Back-Channel Logout 1.0** | OP to RPs | OP POSTs a signed **logout token** directly to each RP | **Good**: no browser involved. The RP must be reachable from the OP |
| Session Management 1.0 | RP polls OP | Hidden iframe with `postMessage` polling the OP's session state | **Poor**: depends on third-party cookie access. Avoid for new systems |

**Recommendation:** use **RP-initiated logout** plus **back-channel logout**. Also revoke refresh tokens at logout (RFC 7009) and keep RP session lifetimes bounded.

### 12.2 RP-Initiated Logout

The RP ends its own session, then sends the browser to the OP:

```http
GET /connect/logout?id_token_hint=eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMjYtMTAtYSJ9...&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2F&state=Q1t2aXHvTnu7bD9w&client_id=orders-web HTTP/1.1
Host: auth.example.com
```

| Parameter | Purpose |
|---|---|
| `id_token_hint` | Tells the OP which session and client this is. Recommended |
| `post_logout_redirect_uri` | Where to return. Must be **pre-registered** and exactly matched, otherwise this is an open redirect |
| `state` | Echoed back to the RP |
| `client_id` | Identifies the RP when no `id_token_hint` is sent |
| `logout_hint`, `ui_locales` | Optional hints |

The OP may ask the user to confirm (to stop cross-site logout forgery), ends its session, notifies other RPs (back-channel or front-channel), then redirects:

```http
HTTP/1.1 302 Found
Location: https://app.example.com/?state=Q1t2aXHvTnu7bD9w
```

### 12.3 Back-Channel Logout

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant RPA as RP A
    participant OP as OpenID Provider
    participant RPB as RP B
    B->>RPA: POST /logout with CSRF token
    RPA->>RPA: Invalidate local session, revoke refresh token
    RPA-->>B: 302 to OP end_session_endpoint with id_token_hint
    B->>OP: GET /connect/logout
    OP->>OP: End OP session sid 08a5019c
    OP->>RPB: POST backchannel_logout_uri with logout_token (sid, sub)
    RPB->>RPB: Validate logout token, delete sessions with that sid
    RPB-->>OP: 200 OK
    OP-->>B: 302 to RP A post_logout_redirect_uri
```

The OP sends a form-encoded `POST`:

```http
POST /logout/connect/back-channel/example HTTP/1.1
Host: app.example.com
Content-Type: application/x-www-form-urlencoded

logout_token=eyJ0eXAiOiJsb2dvdXQrand0IiwiYWxnIjoiUlMyNTYiLCJraWQiOiIyMDI2LTEwLWEifQ.eyJpc3Mi...sig
```

Decoded logout token:

```json
{ "typ": "logout+jwt", "alg": "RS256", "kid": "2026-10-a" }
```

```json
{
  "iss": "https://auth.example.com",
  "sub": "248289761001",
  "aud": "orders-web",
  "iat": 1791453600,
  "exp": 1791453720,
  "jti": "bWJq-9mX2Lr4",
  "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
  "events": {
    "http://schemas.openid.net/event/backchannel-logout": {}
  }
}
```

The RP must validate it carefully, because an attacker who can forge it can log users out (denial of service). An attacker who can make the RP accept an ID token *as* a logout token, or the reverse, can cause worse confusion:

1. Signature, `iss`, `aud` (your `client_id`), `iat` and `exp`, exactly as for an ID token.
2. `typ` is `logout+jwt` when the OP sets it (recommended explicit typing).
3. It contains `sub`, `sid`, or both.
4. `events` contains the member `http://schemas.openid.net/event/backchannel-logout`.
5. It does **not** contain `nonce` (this prevents an ID token being used as a logout token).
6. `jti` has not been seen before (keep a replay cache until `exp`).

Then terminate every session matching `sid` (or all sessions of `sub` if no `sid`), and respond:

```http
HTTP/1.1 200 OK
Cache-Control: no-store
```

Return `400 Bad Request` if validation fails. The spec notes that some frameworks send `204 No Content` for an empty success response, and OPs should treat that as success too.

**Implementation consequences:** you need to find sessions by `sid` or `sub`, so store `sid` with each session (Spring Security keeps an `OidcSessionRegistry` for this, in memory by default). With several app instances, use a shared session store such as Spring Session with Redis **and** provide a shared `OidcSessionRegistry` bean, so that a logout received by one instance finds and kills the session everywhere.

---

## 13. Social login: Google, Microsoft, Apple

Each big provider implements OIDC with its own quirks. These are the ones that cause bugs and security issues.

### 13.1 Google

| Topic | Detail |
|---|---|
| Issuer and discovery | `https://accounts.google.com`, discovery at `https://accounts.google.com/.well-known/openid-configuration` |
| `iss` values | Google documents that ID tokens may carry `https://accounts.google.com` **or** `accounts.google.com`. Accept exactly these two, nothing else |
| Identifier | `sub`. Google explicitly says to use `sub`, not `email`, as the user key |
| `email_verified` | Check it before trusting `email` for anything |
| Workspace accounts | The `hd` claim contains the hosted domain. To restrict login to your company, check `hd` (and that it is present). Do not just check the email suffix: consumer accounts can use any address as their email |
| Refresh tokens | Google-specific `access_type=offline` (and `prompt=consent` to get a new refresh token) instead of the `offline_access` scope |

### 13.2 Microsoft Entra ID

| Topic | Detail |
|---|---|
| Endpoints | `https://login.microsoftonline.com/{tenant}/v2.0`. `{tenant}` is a tenant ID or domain, or `common`, `organizations` or `consumers` for multi-tenant apps |
| Multi-tenant issuer validation | For `common` or `organizations`, the discovery document's `issuer` contains a `{tenantid}` placeholder. Each ID token's real `iss` is `https://login.microsoftonline.com/{tid}/v2.0`. You must check that `iss` matches the token's `tid` claim **and** that `tid` is a tenant you accept. Otherwise any Entra tenant in the world can log in |
| Identifiers | `sub` is **pairwise**: unique per user **per application**. `oid` is the user's object ID, stable across apps within a tenant. Key accounts on (`iss`, `sub`) or (`tid`, `oid`) |
| `email` and `preferred_username` | **Not** safe for identification or authorization. `email` can be unverified and editable by tenant admins |
| nOAuth (2023) | Researchers at Descope showed that multi-tenant apps which **merged accounts by the `email` claim** could be taken over: an attacker set the victim's address as the email of a user in a tenant the attacker controls, then signed in with Microsoft. Microsoft changed defaults to omit unverified email claims for most apps (the `removeUnverifiedEmailClaim` app setting) and added optional claims that indicate verified domain ownership (such as `xms_edov`). Later research in 2025 reported that many apps were still affected. **Never link or authorize by email** |
| Customer identity | For customer-facing (CIAM) apps, Microsoft now directs new projects to Entra External ID rather than Azure AD B2C |

### 13.3 Sign in with Apple

| Topic | Detail |
|---|---|
| Issuer and keys | `https://appleid.apple.com`, keys at `https://appleid.apple.com/auth/keys` |
| Client ID | The **Services ID** for web, or the app's **bundle ID** for native apps |
| Client secret | Not a static string: a **JWT you sign with ES256** using a private key from your Apple developer account, valid for at most 6 months. Automate its regeneration |
| Name | Returned **only on the first authorization**, and **not** in the ID token: it arrives as a `user` JSON form field in the first callback. If you do not store it then, you cannot get it again without the user revoking and re-authorizing |
| `response_mode=form_post` | Required when requesting the `name` or `email` scope. The callback is a cross-site `POST`, so a `SameSite=Lax` session cookie is **not sent** and the state lookup fails. Use a dedicated short-lived `SameSite=None; Secure` cookie for the pending authorization request, or a stateless signed request store |
| Private relay email | Users can hide their email. You receive an address at `privaterelay.appleid.com` (claim `is_private_email`), which forwards to the user. It will never match an existing account's email |
| Identifier | `sub` is stable for the user across apps of the same developer team |

### 13.4 Plain OAuth providers (for example GitHub)

Some providers offer only OAuth 2.0 for user login, without OIDC. GitHub is the common example: you get an access token and call its user API. Using that safely requires that **your own server** ran the code flow, as a confidential client, with your own redirect URI, so the token is known to come from **your** client. Never accept such access tokens from apps or browsers as login proof. Key accounts on the provider's immutable numeric user ID, not on the login name (which users can change).

---

## 14. Account linking pitfalls

Most real-world OIDC account takeovers are not cryptographic failures. They come from **how the app maps an external identity to a local account**.

### 14.1 The rules

1. **Key federated identities on (`iss`, `sub`).** Store them in a separate table (`user_id`, `issuer`, `subject`, `linked_at`). A user may have several.
2. **Never look up or link accounts by `email`** (or `preferred_username`, or phone) alone.
3. **Check `email_verified`** before using an email for anything, and remember that "verified" means verified **by that provider, under its rules**. Treat a provider's email as authoritative only where that provider controls the domain (for example Google for `gmail.com`, or a workforce IdP for its own verified corporate domains).
4. **To link a new external identity to an existing account, require proof of ownership of the existing account**: the user logs in to it (password plus MFA, or passkey) first, or confirms through a link sent to the account's verified email. Do not silently merge.
5. **Re-authenticate** before linking or unlinking identities, and never let a user unlink their last login method.
6. **Notify** the user by email when a new login method is linked.

```mermaid
flowchart TD
    A["Valid ID token: iss, sub, email, email_verified"] --> B{"Identity iss plus sub already linked?"}
    B -->|"Yes"| L["Log in as the linked user"]
    B -->|"No"| C{"Local account with this email exists?"}
    C -->|"No"| N["Create a new account linked to iss plus sub"]
    C -->|"Yes"| D["Do NOT auto-link"]
    D --> E["Ask the user to sign in to the existing account first or confirm via its verified email"]
    E --> F{"Ownership proven?"}
    F -->|"Yes"| G["Link iss plus sub, notify the user by email"]
    F -->|"No"| H["Refuse, or create a separate account"]
```

### 14.2 Attacks this prevents

| Attack | How it works | Prevented by |
|---|---|---|
| **Email-based takeover** (for example nOAuth) | Attacker controls an IdP account whose (unverified or editable) `email` equals the victim's, and the app auto-links by email | Key on `iss` + `sub`. Never auto-link by email |
| **Pre-account hijacking** | Attacker registers a local account with the victim's email *before* the victim signs up. Later the victim signs in with Google, the app merges, and the attacker's password still works. A 2022 USENIX Security study by Sudhodanan and Paverd found this class of flaw in many popular services | Require email verification before a local account is usable. Do not merge federated logins into unverified local accounts. On any merge, invalidate pre-existing passwords and sessions, or require the owner to confirm |
| **Untrusted issuer** | A multi-tenant setup accepts tokens from any tenant or any issuer | Allowlist issuers (and tenants). Validate `iss` exactly |
| **Recycled identifiers** | Phone number or corporate email reassigned to a new person | Never use them as keys |
| **Provider mix-up** | Two IdPs both issue `sub=12345` | The key is (`iss`, `sub`), never `sub` alone |

---

## 15. Choosing an identity provider

| Option | Type | Strengths | Consider |
|---|---|---|---|
| **Keycloak** | Open source, self-hosted (a CNCF project) | Full OIDC and SAML, federation, MFA and passkeys, fine-grained admin, no per-user fees | You operate it: upgrades, HA, database, backups, security patching |
| **Auth0 / Okta** (Okta acquired Auth0 in 2021) | Managed (SaaS) | Fast to integrate, large SDK ecosystem, workforce (Okta) and customer identity (Auth0) | Pricing per active user, vendor lock-in, data residency options |
| **Microsoft Entra ID** (formerly Azure AD) | Managed | The default for workforce identity in Microsoft-centric organizations, conditional access, device signals. Entra External ID for customer-facing apps | Multi-tenant validation pitfalls ([section 13.2](#132-microsoft-entra-id)), claim semantics |
| **Amazon Cognito** | Managed (AWS) | Tight AWS integration, user pools and identity pools | Customization limits, feature differences across tiers |
| **Google** (Google Sign-In, Google Cloud Identity Platform or Firebase Authentication) | Managed | Consumer login with Google accounts, simple CIAM on Google Cloud | Google-specific behaviors ([section 13.1](#131-google)) |
| **Spring Authorization Server** (part of Spring Security 7) | Framework you build on | Full control, OIDC-compliant core, runs in your JVM stack | You build login UI, MFA, admin, user management and operations yourself |

**Selection criteria:**

- **Standards and certification:** OpenID Certified for the profiles you need. PKCE, PAR, DPoP or mTLS, back-channel logout, SAML (for enterprise customers), SCIM (user provisioning).
- **Authentication methods:** passkeys (WebAuthn), TOTP, phishing-resistant MFA policies, step-up (`acr`) support.
- **Multi-tenancy and B2B:** per-customer federation ("bring your own IdP"), organization support.
- **Operations:** SLA, regions and data residency, audit logs, rate limits, incident history.
- **Migration:** importing existing password hashes (bcrypt, Argon2id), so users do not have to reset passwords. Exporting users if you leave.
- **Cost model:** monthly active users, enterprise connections and add-on features.

Whatever you choose, your applications should depend only on **standard OIDC** (issuer URL, discovery, JWKS, standard claims), so you can switch providers later.

---

## 16. Production best practices (2026)

**Flow**

- Authorization code flow **with PKCE (S256)**, **`state`** and **`nonce`**, for every client. Validate `iss` in the authorization response (RFC 9207) when you use more than one provider.
- Run it from a **confidential client**: a server-side app or a BFF. Use `private_key_jwt` or mTLS for client authentication where the provider supports it.
- No implicit or hybrid flows for new work.

**Tokens and validation**

- Validate every ID token fully ([section 4](#4-validating-an-id-token)) with a maintained, OpenID-certified library. Allowlist algorithms (`RS256`, `ES256`, `PS256`, `EdDSA`). Allow clock skew of 60 seconds or less.
- ID tokens are for the client only. Do not send them to APIs, and do not store them in `localStorage`.
- Keep access tokens at 5-15 minutes. Rotate refresh tokens with reuse detection, store them server-side, and revoke them at logout.

**Accounts**

- Key on (`iss`, `sub`). Allowlist issuers (and tenants).
- Never auto-link by email. Check `email_verified`. Require proof of ownership when linking.

**Sessions and logout**

- After login, issue your **own** session cookie with a **new session ID** (`HttpOnly`, `Secure`, `SameSite=Lax`). Apply idle and absolute timeouts appropriate to the risk ([chapter 04](04-sessions-cookies-and-csrf.md)).
- Implement RP-initiated logout and **back-channel logout**. Register exact `post_logout_redirect_uri` values.
- Use `max_age` or `prompt=login` and `acr_values` for sensitive actions, and verify `auth_time`, `acr` and `amr` in the returned ID token. Prefer phishing-resistant authentication (passkeys) at the OP. See [MFA and passkeys](11-mfa-passwordless-and-passkeys.md).

**Keys and discovery**

- Configure only the issuer. Cache discovery for hours, JWKS for minutes, and refetch JWKS on unknown `kid` with rate limiting.
- As an OP: rotate signing keys with overlap (publish, wait, sign, retire), keep private keys in an HSM or KMS, and use RSA keys of at least 2048 bits or P-256 EC keys.

**Monitoring**

- Log and alert on ID token validation failures (by reason), nonce mismatches, unknown-issuer attempts, unusual account-linking activity, and back-channel logout failures.

---

## 17. Common attacks and mistakes

| Attack or mistake | What goes wrong | Mitigation |
|---|---|---|
| Using an OAuth access token (or a `/me` call) as login proof | Token substitution: tokens issued to other apps log in as the victim | Use OIDC. Validate an ID token whose `aud` is your `client_id` |
| Backend accepts ID tokens from mobile apps without checking `aud` | Same substitution, with ID tokens issued to other clients | Validate `aud` (and `azp`) against your own client IDs |
| Missing or unchecked `nonce` | Replay or injection of ID tokens from other sessions | Send a random `nonce`, store it in the session, require a match, use once |
| Missing `state` or PKCE | CSRF on the callback, login CSRF, code injection | `state` plus PKCE (S256) |
| Not validating `iss` exactly | Tokens from other issuers or tenants accepted | Exact match against configured or allowlisted issuers |
| Multi-tenant Entra app not checking `tid` | Users from any tenant can log in | Validate `iss` against `tid` and a tenant allowlist |
| Accepting `alg: none` or algorithm confusion | Forged ID tokens | Algorithm allowlist. Never let the header choose the algorithm family |
| Fetching keys from `jku`, `x5u` or an embedded `jwk` | Attacker supplies their own signing key | Keys only from the discovery `jwks_uri` |
| No JWKS refresh on unknown `kid` | Outage when the OP rotates keys | Refetch on unknown `kid`, rate-limited |
| Refetching JWKS on every unknown `kid` without limits | Denial of service against the OP and your app | Rate-limit refetches |
| Linking accounts by email | Account takeover (nOAuth, pre-account hijacking) | Key on `iss` + `sub`. Prove ownership before linking |
| Trusting `email` without `email_verified` | Attacker claims any email | Require `email_verified: true` and a trusted issuer |
| Ignoring `auth_time` after requesting `max_age` | Stale sessions pass as fresh logins | Check `now - auth_time <= max_age` |
| Trusting requested `acr_values` instead of the returned `acr` | The OP may have used weaker authentication | Check the returned `acr` (and `amr`) |
| ID token used as an API access token | Token confusion, wrong audience | APIs accept only access tokens (`typ: at+jwt`, correct `aud`) |
| ID or access tokens stored in `localStorage` | Stolen by XSS | BFF. Tokens server-side, `HttpOnly` session cookie |
| Keeping the ID token as the session | No server-side revocation, expiry mismatch | Create your own server-side session with a new ID |
| Not implementing back-channel logout | Users disabled at the IdP stay logged into apps | Back-channel logout, bounded session lifetimes, refresh token checks |
| Relying on front-channel logout or session iframes | Silently fails when browsers block third-party cookies | Back-channel logout |
| Logout token not fully validated (`events`, no `nonce`, `jti`) | Forged or replayed logouts, token type confusion | All six validation checks in [section 12.3](#123-back-channel-logout) |
| Unregistered or pattern-matched `post_logout_redirect_uri` | Open redirect after logout | Exact match against registered URIs |
| Apple name not stored on the first login | The name is lost for good | Persist the `user` form field on the first callback |
| `SameSite=Lax` session cookie with `form_post` callbacks | Callback arrives without the session, login fails | Separate `SameSite=None; Secure` cookie for the pending request |
| UserInfo `sub` not compared with the ID token `sub` | Mixed or substituted user data | Require equality, otherwise discard |

---

## 18. Spring Boot 4 / Spring Security 7

Starter: `spring-boot-starter-security-oauth2-client` (the Spring Boot 4 name). Spring Security's OIDC login validates the ID token (`iss`, `aud`, `azp`, `exp`, `iat`, signature via the JWKS, and `nonce`, which it generates and checks automatically), maps claims to an `OidcUser`, and supports RP-initiated and back-channel logout.

### 18.1 Configuration

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          example:                                   # your own OP (for example Spring Authorization Server or Keycloak)
            provider: example
            client-id: orders-web
            client-secret: ${ORDERS_WEB_SECRET}       # or private_key_jwt, see chapter 08
            client-authentication-method: client_secret_basic
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            scope: openid, profile, email
          google:                                    # Spring knows Google's endpoints
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope: openid, email
        provider:
          example:
            issuer-uri: https://auth.example.com     # discovery, JWKS and exact iss validation
```

### 18.2 Security filter chain

```java
@Configuration
@EnableWebSecurity
class WebSecurityConfig {

    @Bean
    SecurityFilterChain web(HttpSecurity http, ClientRegistrationRepository registrations) throws Exception {
        // Explicit PKCE. Spring Security 7 already sends it for every registration (requireProofKey defaults to true)
        var authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(
                registrations, OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        authorizationRequestResolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

        // RP-initiated logout: after the local logout, redirect to the OP's end_session_endpoint
        var oidcLogoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(registrations);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/");   // must be registered at the OP

        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/error", "/css/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            .oauth2Login(login -> login
                .authorizationEndpoint(endpoint -> endpoint.authorizationRequestResolver(authorizationRequestResolver))
                .userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService())))
            .logout(logout -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler))
            // Back-channel logout endpoint: {baseUrl}/logout/connect/back-channel/{registrationId}
            .oidcLogout(logout -> logout.backChannel(Customizer.withDefaults()));
        // CSRF protection stays enabled (the default): the session cookie authenticates browser requests.
        return http.build();
    }

    // Map a "roles" claim from the ID token to Spring authorities, keeping the default ones.
    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        var delegate = new OidcUserService();
        return request -> {
            OidcUser user = delegate.loadUser(request);
            Set<GrantedAuthority> authorities = new HashSet<>(user.getAuthorities());
            List<String> roles = user.getIdToken().getClaimAsStringList("roles");
            if (roles != null) {
                roles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
            }
            return new DefaultOidcUser(authorities, user.getIdToken(), user.getUserInfo(), IdTokenClaimNames.SUB);
        };
    }
}
```

### 18.3 Using the authenticated user

```java
record CurrentUser(String issuer, String subject, String email, boolean emailVerified, Instant authTime) {}

@RestController
class MeController {

    private final AccountService accounts;

    MeController(AccountService accounts) {
        this.accounts = accounts;
    }

    @GetMapping("/me")
    CurrentUser me(@AuthenticationPrincipal OidcUser user) {
        // The account key is (issuer, subject), never the email.
        accounts.findOrCreateByIssuerAndSubject(user.getIssuer().toString(), user.getSubject());
        return new CurrentUser(
                user.getIssuer().toString(),
                user.getSubject(),
                user.getEmail(),
                Boolean.TRUE.equals(user.getEmailVerified()),
                user.getAuthenticatedAt());
    }
}
```

Notes:

- The `issuer-uri` triggers discovery at startup and makes Spring require an exact `iss` match. For multi-tenant Entra apps, add a custom ID token validator that checks `iss` against `tid` and your tenant allowlist.
- Back-channel logout needs the OP to reach `https://app.example.com/logout/connect/back-channel/example`. With several app instances, use Spring Session (for example with Redis) plus a shared `OidcSessionRegistry` bean (the default registry is in memory), so the logout reaches every instance.
- The [../examples/03-oauth2-oidc/](../examples/03-oauth2-oidc/) multi-module example runs a Spring Authorization Server with OIDC, a resource server, and this kind of BFF client using `oauth2Login`.

---

## Interview questions

**1. What is the difference between OAuth 2.0 and OpenID Connect?**
OAuth 2.0 is delegated **authorization**: it gives a client an access token for an API. OIDC is an **authentication** layer on top: it adds the ID token (issued to the client, saying who logged in, when and how), UserInfo, standard claims and scopes, discovery and logout. You request it by adding `openid` to the scope.

**2. Why can't you use an OAuth access token to log a user in?**
Access tokens are meant for the resource server, not the client. They carry no audience for your app, no authentication time or method, and no nonce. A token that another app obtained for the same user can be replayed to your backend: token substitution, a confused deputy.

**3. Which claims must you validate in an ID token?**
Signature (allowlisted algorithm, key from JWKS by `kid`), `iss` (exact), `aud` (contains your client ID, plus `azp` if several audiences), `exp`, `iat`, `nonce` (equals the session value), and, when requested, `auth_time` (against `max_age`) and `acr`. Also `at_hash` when present.

**4. What are `state` and `nonce`, and why do you need both?**
`state` protects the redirect callback against CSRF: it is checked by the client before redeeming the code. `nonce` is embedded in the ID token and binds the token to the client session that made the request, preventing replay and injection of ID tokens. PKCE additionally binds the code to the client instance.

**5. What should be the primary key for a federated user?**
The pair (`iss`, `sub`). `sub` is unique and never reassigned **within** an issuer. Email, username and phone can change, be reassigned, or be unverified.

**6. Explain the risk of linking accounts by email.**
If any accepted IdP lets an attacker present the victim's email (unverified, editable, or from a domain the IdP is not authoritative for), the app merges the attacker into the victim's account. That was the nOAuth issue with Entra ID. Pre-account hijacking works in the other direction. Link only after the user proves ownership of the existing account.

**7. How do RP-initiated, front-channel and back-channel logout differ?**
RP-initiated: the RP redirects the browser to the OP's `end_session_endpoint` to end the OP session. Front-channel: the OP loads RP logout URLs in iframes, which is unreliable now that third-party cookies are blocked. Back-channel: the OP POSTs a signed logout token server-to-server, and the RP kills sessions by `sid` or `sub`. Recommended: RP-initiated plus back-channel.

**8. How does JWKS key rotation work without breaking clients?**
Publish the new key first and wait at least the client cache lifetime, then start signing with it. Keep the old key until all tokens signed with it have expired, then remove it. Clients cache the JWKS and refetch when they see an unknown `kid`, with rate limiting.

**9. Why are the implicit and hybrid flows considered legacy?**
They return tokens through the browser, where they leak, can be injected, and cannot be sender-constrained. The code flow with PKCE, `nonce` and `iss`, ideally run by a BFF, gives stronger guarantees.

**10. What is special about multi-tenant Microsoft Entra apps?**
The discovery issuer is a template. Each token's `iss` contains the tenant ID, so you must validate `iss` against `tid` and an allowlist of tenants. `sub` is pairwise per app, `oid` is stable within a tenant, and `email` must not be used for identity or authorization.

---

## References

- OpenID Connect Core 1.0 incorporating errata set 2 (2014, errata December 2023): https://openid.net/specs/openid-connect-core-1_0.html
- ISO/IEC 26131:2024 — OpenID Connect Core 1.0 incorporating errata set 2: https://www.iso.org/standard/89056.html
- OpenID Connect Discovery 1.0: https://openid.net/specs/openid-connect-discovery-1_0.html
- OpenID Connect Dynamic Client Registration 1.0: https://openid.net/specs/openid-connect-registration-1_0.html
- OpenID Connect RP-Initiated Logout 1.0 (Final, 2022): https://openid.net/specs/openid-connect-rpinitiated-1_0.html
- OpenID Connect Front-Channel Logout 1.0 (Final, 2022): https://openid.net/specs/openid-connect-frontchannel-1_0.html
- OpenID Connect Back-Channel Logout 1.0 (Final, 2022, errata set 1 December 2023): https://openid.net/specs/openid-connect-backchannel-1_0.html
- OpenID Connect Session Management 1.0 (Final, 2022): https://openid.net/specs/openid-connect-session-1_0.html
- OAuth 2.0 Multiple Response Type Encoding Practices: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
- OAuth 2.0 Form Post Response Mode: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
- OpenID Foundation certification: https://openid.net/certification/
- RFC 6749 — The OAuth 2.0 Authorization Framework: https://www.rfc-editor.org/rfc/rfc6749
- RFC 7636 — Proof Key for Code Exchange (PKCE): https://www.rfc-editor.org/rfc/rfc7636
- RFC 9700 — Best Current Practice for OAuth 2.0 Security (January 2025): https://www.rfc-editor.org/rfc/rfc9700
- RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification: https://www.rfc-editor.org/rfc/rfc9207
- RFC 7519 — JSON Web Token (JWT): https://www.rfc-editor.org/rfc/rfc7519
- RFC 7515 — JSON Web Signature (JWS): https://www.rfc-editor.org/rfc/rfc7515
- RFC 7517 — JSON Web Key (JWK): https://www.rfc-editor.org/rfc/rfc7517
- RFC 8176 — Authentication Method Reference Values: https://www.rfc-editor.org/rfc/rfc8176
- RFC 8725 — JSON Web Token Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725
- RFC 7009 — OAuth 2.0 Token Revocation: https://www.rfc-editor.org/rfc/rfc7009
- RFC 7591 — OAuth 2.0 Dynamic Client Registration Protocol: https://www.rfc-editor.org/rfc/rfc7591
- Google — OpenID Connect documentation: https://developers.google.com/identity/openid-connect/openid-connect
- Microsoft — ID token claims reference: https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
- Microsoft — Secure applications and APIs by validating claims: https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation
- Apple — Sign in with Apple documentation: https://developer.apple.com/documentation/signinwithapple
- Descope — nOAuth: How Microsoft OAuth Misconfiguration Can Lead to Full Account Takeover (2023): https://www.descope.com/blog/post/noauth
- Sudhodanan and Paverd — Pre-hijacked Accounts: An Empirical Study of Security Failures in User Account Creation on the Web (USENIX Security 2022): https://www.usenix.org/conference/usenixsecurity22/presentation/sudhodanan
- OWASP OAuth 2.0 Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- Spring Security reference — OAuth 2.0 Login: https://docs.spring.io/spring-security/reference/servlet/oauth2/login/index.html
- Spring Security reference — OIDC Logout: https://docs.spring.io/spring-security/reference/servlet/oauth2/login/logout.html
