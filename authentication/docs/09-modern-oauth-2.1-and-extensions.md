# 09 — Modern OAuth: OAuth 2.1, the Security BCP and Extensions

OAuth 2.0 as published in 2012 was a flexible framework with many optional, and some insecure, modes. Over the following fourteen years the IETF and the OpenID Foundation hardened it: they published a security best current practice (RFC 9700), rules for native and browser apps, ways to bind tokens to keys (mTLS, DPoP), ways to protect and enrich the authorization request (PAR, JAR, RAR), and delegation for microservices (token exchange). This chapter walks through each one: **the problem it solves, how it works, and when you should adopt it**. It ends with OAuth 2.1, which consolidates all of this but is **still a draft**, plus FAPI 2.0 and GNAP.

> **Where this fits in the evolution**
>
> - **Before:** [OAuth 2.0](08-oauth-2.md) (RFC 6749 and 6750, 2012) with implicit and password grants, bearer-only tokens, loose redirect URI rules, and no protection against code interception.
> - **What it solved:** Real attacks found in deployed systems (code interception on mobile, token leakage from the implicit grant, mix-up, open redirectors, stolen bearer tokens) led to targeted fixes. RFC 9700 (January 2025) collected the rules in one document. RFC 10017 (August 2026) settled how browser apps should use OAuth.
> - **What came next:** **OAuth 2.1** (Internet-Draft `draft-ietf-oauth-v2-1`, revision 16, September 2026, **not yet an RFC**) folds the fixes into one spec. **FAPI 2.0** (final in 2025) profiles OAuth for high-risk APIs. **GNAP** (RFC 9635, 2024) is a clean-slate redesign that may eventually succeed OAuth, though adoption is small so far. For login on top of all this, see [OpenID Connect](10-openid-connect.md).

---

## Table of contents

1. [What changed after 2012](#1-what-changed-after-2012)
2. [The OAuth 2.0 Security BCP (RFC 9700), rule by rule](#2-the-oauth-20-security-bcp-rfc-9700-rule-by-rule)
3. [OAuth 2.1: the consolidation (draft)](#3-oauth-21-the-consolidation-draft)
4. [OAuth for native apps (RFC 8252)](#4-oauth-for-native-apps-rfc-8252)
5. [OAuth for browser-based apps (RFC 10017)](#5-oauth-for-browser-based-apps-rfc-10017)
6. [Sender-constrained tokens](#6-sender-constrained-tokens)
7. [Pushed Authorization Requests (PAR, RFC 9126)](#7-pushed-authorization-requests-par-rfc-9126)
8. [JWT-Secured Authorization Requests (JAR, RFC 9101)](#8-jwt-secured-authorization-requests-jar-rfc-9101)
9. [Rich Authorization Requests (RAR, RFC 9396)](#9-rich-authorization-requests-rar-rfc-9396)
10. [Resource Indicators (RFC 8707)](#10-resource-indicators-rfc-8707)
11. [Token Exchange (RFC 8693)](#11-token-exchange-rfc-8693)
12. [JWT access tokens (RFC 9068)](#12-jwt-access-tokens-rfc-9068)
13. [Issuer identification (RFC 9207)](#13-issuer-identification-rfc-9207)
14. [Step-up authentication challenge (RFC 9470)](#14-step-up-authentication-challenge-rfc-9470)
15. [Protected resource metadata (RFC 9728)](#15-protected-resource-metadata-rfc-9728)
16. [CIBA: decoupled authentication](#16-ciba-decoupled-authentication)
17. [FAPI 2.0](#17-fapi-20)
18. [GNAP (RFC 9635): a possible successor](#18-gnap-rfc-9635-a-possible-successor)
19. [Adoption guide](#19-adoption-guide)
20. [Common attacks and mistakes](#20-common-attacks-and-mistakes)
21. [Spring Boot 4 / Spring Security 7](#21-spring-boot-4--spring-security-7)
22. [Interview questions](#interview-questions)
23. [References](#references)

---

## 1. What changed after 2012

| Year | Specification | Problem it addressed |
|---|---|---|
| 2013 | RFC 6819 Threat Model, RFC 7009 Revocation | Documented threats. Let clients revoke tokens |
| 2015 | RFC 7636 PKCE | Code interception on mobile, later code injection everywhere |
| 2015 | RFC 7591 Dynamic Registration, RFC 7523 JWT client auth, RFC 7662 Introspection | Scale, asymmetric client authentication, opaque token validation |
| 2017 | RFC 8252 Native Apps (BCP 212) | Embedded web views, custom-scheme hijacking |
| 2018 | RFC 8414 AS Metadata | Discovery without hard-coding |
| 2019 | RFC 8628 Device Grant | Devices without browsers |
| 2020 | RFC 8705 mTLS, RFC 8707 Resource Indicators, RFC 8693 Token Exchange, RFC 8725 JWT BCP | Token binding, audience restriction, delegation, JWT pitfalls |
| 2021 | RFC 9068 JWT Access Tokens, RFC 9101 JAR, RFC 9126 PAR, OpenID CIBA Core (final) | Interoperable JWT tokens, request integrity, decoupled flows |
| 2022 | RFC 9207 Issuer Identification | Mix-up attacks |
| 2023 | RFC 9396 RAR, RFC 9449 DPoP, RFC 9470 Step-up | Fine-grained consent, application-level token binding, step-up MFA |
| 2024 | RFC 9635 GNAP | Clean-slate successor protocol |
| 2025 | **RFC 9700 Security BCP** (January), RFC 9728 Protected Resource Metadata (April), FAPI 2.0 Security Profile (final, February) and Message Signing (final, September) | Consolidated security rules, resource discovery, high-security profile |
| 2026 | **RFC 10017 Browser-Based Applications** (BCP 212, August), OAuth 2.1 draft revision 16 (September) | SPA architecture guidance, consolidation in progress |

---

## 2. The OAuth 2.0 Security BCP (RFC 9700), rule by rule

**RFC 9700**, *Best Current Practice for OAuth 2.0 Security* (BCP 240, January 2025, by Lodderstedt, Bradley, Labunets and Fett), updates the security advice of RFC 6749, RFC 6750 and RFC 6819. It spent more than eight years as an Internet-Draft. It is the single most important document for anyone running OAuth in production. The rules below are grouped by topic. Normative keywords (MUST, SHOULD) follow the RFC.

### 2.1 Protecting redirect-based flows

| Rule | Level | Why |
|---|---|---|
| Compare redirect URIs by **exact string matching** with pre-registered values. The only exception is the port of loopback redirect URIs for native apps | MUST | Pattern, wildcard and prefix matching have been bypassed again and again ([chapter 08, section 12](08-oauth-2.md#12-redirect-uris-exact-matching)) |
| Clients and authorization servers must not expose **open redirectors** | MUST NOT | Open redirectors forward codes and tokens to attackers, and lend a trusted domain to phishing |
| Clients must prevent **CSRF** on the redirect endpoint. PKCE provides this if the AS supports it; otherwise use a one-time `state` value (or the OIDC `nonce`) bound to the user agent | MUST | Stops attackers from making victims complete attacker-initiated flows |
| Clients that use **more than one AS** must defend against **mix-up**: use the `iss` response parameter (RFC 9207) or a distinct redirect URI per AS | MUST | Stops codes from an honest AS being sent to an attacker's token endpoint |
| Clients must prevent **authorization code injection**. **Public clients MUST use PKCE.** For confidential clients, PKCE is RECOMMENDED; OpenID Connect clients may use `nonce` instead under the conditions in the RFC | MUST | A stolen code replayed through the attacker's session at the real client |
| Authorization servers **must support PKCE**, must enforce the `code_verifier` when a challenge was sent, must prevent **PKCE downgrade**, and should publish `code_challenge_methods_supported` | MUST | Makes PKCE enforceable and discoverable |
| Use the **S256** challenge method | SHOULD | `plain` exposes the verifier in the front channel |
| Do not use the **implicit grant** or any response type that returns access tokens in the authorization response, unless token injection and leakage are prevented | SHOULD NOT | Token leakage via URLs, token injection, no sender-constraining |

### 2.2 Token replay prevention

| Rule | Level | Why |
|---|---|---|
| Authorization and resource servers should use **sender-constrained access tokens** (mTLS or DPoP) | SHOULD | A stolen bearer token works for anyone. A sender-constrained token needs the private key |
| **Refresh tokens for public clients** must be **sender-constrained or rotated** (with reuse detection) | MUST | Public clients cannot authenticate, so a stolen refresh token would otherwise work indefinitely |

### 2.3 Access token privilege restriction

| Rule | Level | Why |
|---|---|---|
| Restrict access token privileges to the minimum needed: **audience-restrict** tokens to specific resource servers, and restrict scopes or actions | SHOULD | A token leaked by (or stolen from) one API cannot be replayed at another |
| Resource servers must verify that the token was issued for them (audience) and for the requested action | MUST, when the token is restricted | Otherwise the restriction is meaningless |

### 2.4 Grants and client authentication

| Rule | Level | Why |
|---|---|---|
| The **resource owner password credentials grant** must not be used | MUST NOT | Exposes passwords to clients, defeats MFA and federation |
| Authorization servers should **authenticate clients** whenever feasible | SHOULD | Limits who can redeem codes and refresh tokens |
| Prefer **asymmetric client authentication**: mTLS (RFC 8705) or `private_key_jwt` (RFC 7523) | RECOMMENDED | No shared secrets stored at the AS. Easy key rotation |
| Do not let clients choose their `client_id` or claims (such as `sub`) in a way that could be confused with a genuine user | SHOULD NOT | Prevents a client from impersonating a user through client-credentials tokens |

### 2.5 Other recommendations

| Rule | Why |
|---|---|
| Use **authorization server metadata** (RFC 8414) so clients configure only the issuer | Correct, current endpoints and capability discovery |
| **No unencrypted transport** for authorization responses. Redirect URIs use `https`, except loopback for native apps. End-to-end TLS is recommended | Codes and tokens in clear text are trivially stolen |
| After the user submits credentials, the AS must **not** redirect with **HTTP 307**. Use 303 | 307 makes the browser re-post the form, password included, to the client |
| Prevent **clickjacking** of authorization pages (`Content-Security-Policy: frame-ancestors`) | Users can be tricked into clicking "Allow" in an invisible frame |
| Reverse proxies that terminate TLS must **sanitize** headers they forward (client certificate, client IP) | Otherwise attackers inject those headers |
| For in-browser flows using `postMessage`, senders specify the **exact target origin** and receivers check the **sender origin** | Stops other windows from stealing or injecting codes and tokens |
| Be careful about **redirecting users to clients the AS cannot vouch for**, for example on error responses | Attackers register clients with phishing redirect URIs and use the trusted AS domain to bounce victims |

### 2.6 The attack catalog

RFC 9700 also documents the attacks behind these rules: insufficient redirect URI validation, credential leakage via `Referer` and browser history, mix-up, code injection, access token injection, CSRF, PKCE downgrade, token leakage at compromised resource servers, misuse of stolen tokens, open redirection, 307 redirects, TLS-terminating proxies, refresh token theft, client impersonation of users, clickjacking, `postMessage` attacks, AS-assisted phishing redirects, and integrity of authorization requests. Each attack is explained with mitigations in [chapter 08, section 19](08-oauth-2.md#19-vulnerabilities-in-depth).

**How to use RFC 9700 in practice:** treat it as a checklist for every AS configuration and every client library you choose. If a vendor or library cannot meet a rule, document the exception and its compensating control.

---

## 3. OAuth 2.1: the consolidation (draft)

**Status (October 2026):** `draft-ietf-oauth-v2-1`, revision 16 (September 2026), is an active **Internet-Draft** of the IETF OAuth working group, edited by Dick Hardt, Aaron Parecki and Torsten Lodderstedt. It is **not an RFC**. Cite it as "work in progress". When it is published it will replace RFC 6749 and RFC 6750.

### What it consolidates

OAuth 2.1 adds **no new features**. It merges into one document:

- RFC 6749 (core) and RFC 6750 (bearer token usage)
- RFC 7636 (PKCE)
- RFC 8252 (native apps) and the browser-based apps guidance (now RFC 10017)
- The security rules of RFC 9700
- Parts of RFC 8414 (metadata) and related clarifications

### OAuth 2.0 (2012) vs OAuth 2.1 (draft)

| Topic | OAuth 2.0 (RFC 6749/6750) | OAuth 2.1 (draft) |
|---|---|---|
| PKCE | Optional, separate RFC | **Required** for the authorization code grant. The draft keeps only a narrow, carefully conditioned exception (confidential clients using the OpenID Connect `nonce`), so check the current text before relying on it |
| Redirect URI matching | Loosely specified | **Exact string matching** (except loopback ports for native apps) |
| Implicit grant | Defined | **Removed** |
| Password grant | Defined | **Removed** |
| Bearer token in a URI query string | Allowed with warnings | **Removed** |
| Refresh tokens for public clients | No special rules | Must be **sender-constrained or one-time use** (rotation) |
| Native and browser apps | Not covered | Guidance incorporated or referenced |
| Grants remaining | Code, implicit, password, client credentials, refresh | **Authorization code (with PKCE), client credentials, refresh token**, plus extension grants such as device code and token exchange |

### What this means for you

If you already follow **RFC 6749 plus RFC 9700**, you are effectively OAuth 2.1 compliant today. "Supports OAuth 2.1" on a vendor's page usually means "PKCE everywhere, exact redirects, no implicit, no password grant". Verify each point instead of trusting the label.

---

## 4. OAuth for native apps (RFC 8252)

**Problem.** Mobile and desktop apps used to show the login page in an **embedded web view** inside the app. The app fully controls that view: it can read the password as the user types, inject scripts, and capture cookies. Users cannot see the real URL bar, and the web view has no shared cookies, so there is no single sign-on. It also teaches users to type passwords into any app that asks.

**RFC 8252** (October 2017, BCP 212) requires native apps to use an **external user agent**: the system browser or an in-app browser tab that the app cannot inspect.

| Platform | Use | Do not use |
|---|---|---|
| iOS, macOS | `ASWebAuthenticationSession` | `WKWebView`, `UIWebView` |
| Android | Custom Tabs (or the system browser) | `WebView` |
| Desktop (Windows, Linux, macOS) | The default system browser plus a loopback redirect | Embedded browser controls |

```mermaid
sequenceDiagram
    autonumber
    participant App as Native app
    participant Br as System browser
    participant AS as Authorization server
    App->>App: Create code_verifier and state
    App->>Br: Open authorize URL with code_challenge
    Br->>AS: User logs in (passkey, SSO cookies available)
    AS-->>Br: Redirect to claimed https URL or loopback with code
    Br-->>App: OS hands the redirect to the app
    App->>AS: POST /token code plus code_verifier (public client, no secret)
    AS-->>App: Tokens, refresh token stored in Keychain or Keystore
```

### Redirect URI options

| Option | Example | Security | Notes |
|---|---|---|---|
| **Claimed `https` URL** (iOS Universal Links, Android App Links) | `https://app.example.com/oauth2redirect` | Best. The OS verifies domain ownership, so no other app can claim it | Preferred for mobile |
| **Private-use URI scheme** | `com.example.orders:/oauth2redirect` | Weaker. Other apps can register the same scheme, so PKCE is essential | Use a reverse-domain scheme you control |
| **Loopback interface** | `http://127.0.0.1:51004/oauth2redirect` | Good for desktop and CLI | Use the IP literal (`127.0.0.1` or `[::1]`), not `localhost`. The AS must accept **any port** |

**Rules:** native apps are **public clients**, so no client secrets, PKCE with S256, and `state`. Store refresh tokens in the platform keystore (iOS Keychain, Android Keystore). Consider DPoP with a hardware-backed key to bind refresh tokens. The OpenID Foundation's **AppAuth** libraries for iOS and Android implement RFC 8252.

**Adopt:** always, for any native app.

---

## 5. OAuth for browser-based apps (RFC 10017)

**Status:** **RFC 10017**, *OAuth 2.0 for Browser-Based Applications*, was published in **August 2026** as a Best Current Practice (it sits in BCP 212 alongside RFC 8252). Authors: Aaron Parecki, Philippe De Ryck and David Waite. It was a draft for over seven years.

### The core threat: malicious JavaScript in your origin

The RFC's analysis starts from the assumption that an attacker can run JavaScript in your app's origin, through XSS, a compromised npm dependency, or a malicious browser extension. It lists what such an attacker can do:

| Attack scenario | Description | Stopped by keeping tokens out of `localStorage`? |
|---|---|---|
| Single token exfiltration | Steal the current access token | Partly (in-memory tokens are harder to reach) |
| Persistent token theft | Steal the refresh token and use it for weeks from the attacker's machine | Partly |
| **Acquisition of new tokens** | Run a fresh, silent authorization flow (for example in a hidden iframe) and receive **new** tokens directly | **No.** Token storage does not matter: the attacker acts as the app |
| Proxying requests through the user's browser | Use the victim's live session to call APIs while the page is open | No. Only detection, short sessions and step-up help |

The key insight: if an attacker controls JavaScript in a **browser-only OAuth client**, they can obtain tokens no matter how cleverly the app stores them. **The only robust defense is to keep tokens out of the browser altogether.**

### The three architectural patterns

```mermaid
flowchart LR
    subgraph P1["Pattern 1: Backend for Frontend (recommended)"]
        B1["Browser: HttpOnly session cookie only"] --> BFF["BFF: confidential client, holds all tokens"]
        BFF --> API1["API"]
    end
    subgraph P2["Pattern 2: Token-mediating backend"]
        B2["Browser: holds access token"] --> API2["API"]
        TMB["Backend: confidential client, keeps refresh token"] -->|"hands out access tokens"| B2
    end
    subgraph P3["Pattern 3: Browser-based OAuth client"]
        B3["Browser: public client, holds all tokens"] --> API3["API"]
    end
```

| Pattern | How it works | Tokens in the browser? | Main trade-off |
|---|---|---|---|
| **1. Backend for Frontend (BFF)** | A server-side component on the app's own site is a **confidential client**. It runs the code flow with PKCE, stores the tokens, and gives the browser only an `HttpOnly; Secure; SameSite` session cookie. API calls go through the BFF, which attaches the access token | **None** | You need a backend, and must apply CSRF protection to the cookie-authenticated BFF endpoints |
| **2. Token-mediating backend** | The backend is a confidential client and runs the flow, but hands **access tokens** to the frontend, which calls APIs directly. The refresh token stays on the server | Access tokens only | Access tokens are exposed to XSS. Less backend traffic than a BFF |
| **3. Browser-based OAuth client** | The SPA itself is a **public client** running the code flow with PKCE in JavaScript | All, including refresh tokens | Most exposed. Needs in-memory storage, refresh token rotation, short lifetimes, and ideally DPoP with a non-extractable WebCrypto key |

The RFC also discusses **discouraged and deprecated patterns**, including the implicit grant. It also notes that a frontend and an API served from a **common domain** may not need OAuth at all: an ordinary server-side session cookie (see [chapter 04](04-sessions-cookies-and-csrf.md)) can be the simplest secure design.

**House position (consistent with RFC 10017):** use a **server-side session or the BFF pattern** for browser apps. Do **not** store tokens in `localStorage` or `sessionStorage`. Protect every cookie-authenticated state-changing request against CSRF.

### BFF flow

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser SPA
    participant BFF as BFF (same site as the SPA)
    participant AS as Authorization server
    participant API as API
    B->>BFF: GET /bff/login
    BFF-->>B: 302 to AS with state, PKCE, nonce
    B->>AS: Login and consent
    AS-->>B: 302 to BFF callback with code
    B->>BFF: GET /bff/callback?code=...
    BFF->>AS: POST /token code, verifier, private_key_jwt
    AS-->>BFF: access, refresh and ID tokens (stay on the server)
    BFF-->>B: Set-Cookie session, HttpOnly, Secure, SameSite=Lax
    B->>BFF: POST /bff/api/orders with cookie and CSRF header
    BFF->>API: POST /orders with Authorization Bearer or DPoP token
    API-->>BFF: 201
    BFF-->>B: 201
```

**Adopt:** BFF for any business or sensitive browser app. Browser-only clients only for low-risk apps where no backend is possible, with every mitigation the RFC lists.

---

## 6. Sender-constrained tokens

### 6.1 Why bearer tokens are not enough

A **bearer** token is like cash: whoever holds it can spend it. Tokens leak through XSS, logs, compromised proxies, malicious resource servers, and backups. Short lifetimes limit the damage but do not prevent it.

A **sender-constrained** (proof-of-possession) token is bound to a key held by the client. To use the token, the client must prove possession of the private key on every request. A stolen token without the key is useless.

| Mechanism | Binding happens at | Proof on each request | Token confirmation claim (`cnf`) |
|---|---|---|---|
| **mTLS** (RFC 8705) | TLS layer: the client certificate | TLS handshake with the same certificate | SHA-256 thumbprint of the client certificate (`x5t#S256` member) |
| **DPoP** (RFC 9449) | Application layer: a JWT signed per request | `DPoP` header containing a signed proof JWT | SHA-256 JWK thumbprint of the public key (`jkt` member) |

### 6.2 Mutual TLS (RFC 8705)

RFC 8705 (February 2020) does two things:

1. **Client authentication** with certificates (`tls_client_auth`, `self_signed_tls_client_auth`), covered in [chapter 08](08-oauth-2.md#13-client-authentication-at-the-token-endpoint).
2. **Certificate-bound access tokens**: when the client gets a token over an mTLS connection, the AS embeds the certificate's thumbprint. The RS requires mTLS and checks that the presented certificate matches.

Decoded JWT access token with a certificate binding (the thumbprint value is from RFC 8705):

```json
{
  "iss": "https://auth.example.com",
  "sub": "orders-batch",
  "aud": "https://api.example.com",
  "exp": 1791450300,
  "cnf": {
    "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"
  }
}
```

The RS computes `BASE64URL(SHA-256(DER of the client certificate from the TLS session))` and compares it with `cnf`. For opaque tokens, the same `cnf` value comes back from introspection.

Metadata: the AS advertises `tls_client_certificate_bound_access_tokens: true` and may publish `mtls_endpoint_aliases` (separate hostnames that request client certificates, so normal browser traffic is not prompted for one).

| Pros | Cons |
|---|---|
| Very strong. The private key never leaves the TLS stack (or an HSM) | Hard to use from browsers. Certificate management (issuance, rotation, revocation) is real work |
| Mature. Required option in FAPI. Natural fit with service meshes | TLS termination at load balancers and CDNs breaks the binding unless the verified certificate is forwarded securely |
| No per-request signing code in the application | One certificate per client instance to manage |

**Adopt mTLS when:** service-to-service traffic already runs on mTLS (service mesh, SPIFFE), in open banking (FAPI), and for B2B APIs with managed certificates.

### 6.3 DPoP (RFC 9449)

**DPoP** (Demonstrating Proof of Possession, RFC 9449, September 2023) binds tokens to a key pair at the **application layer**, so it works through TLS-terminating proxies and in browsers and mobile apps.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (holds a key pair)
    participant AS as Authorization server
    participant RS as Resource server
    participant X as Attacker with a stolen token
    C->>C: Generate key pair, private key non-extractable
    C->>AS: POST /token with DPoP proof (htm POST, htu token URL)
    AS-->>C: 400 use_dpop_nonce plus DPoP-Nonce header
    C->>AS: POST /token with a new proof that includes the nonce
    AS->>AS: Verify proof signature with the embedded public key
    AS-->>C: access_token bound to the key thumbprint, token_type DPoP
    C->>RS: GET /orders, Authorization DPoP token, DPoP proof with ath
    RS->>RS: Check proof, htm, htu, iat, jti, ath, and thumbprint equals cnf.jkt
    RS-->>C: 200 orders
    X->>RS: GET /orders with the stolen token but no valid proof
    RS-->>X: 401 invalid_dpop_proof
```

#### A DPoP proof JWT

The examples below are taken from RFC 9449. The proof is a JWT whose **header contains the public key** and which is signed with the matching private key.

Header:

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
    "crv": "P-256"
  }
}
```

Payload for a token request:

```json
{
  "jti": "-BwC3ESc6acc2lTc",
  "htm": "POST",
  "htu": "https://server.example.com/token",
  "iat": 1562262616
}
```

| Claim | Meaning |
|---|---|
| `typ: dpop+jwt` (header) | Explicit type, so a proof cannot be confused with other JWTs |
| `alg` (header) | An asymmetric algorithm (ES256, PS256, EdDSA). Never `none` or HMAC |
| `jwk` (header) | The **public** key. It must not contain private key material |
| `jti` | Unique ID, so the server can detect replayed proofs |
| `htm`, `htu` | HTTP method and target URI (without query and fragment) this proof is for |
| `iat` | Creation time. Servers accept only a short window |
| `ath` | For resource requests: `BASE64URL(SHA-256(access token))`, binding the proof to the token |
| `nonce` | A server-provided nonce, when the server requires one |

#### Token request and response

```http
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.signature

grant_type=authorization_code&client_id=s6BhdRkqt&code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&code_verifier=bEaL42izcC-o-xBk0K2vuJ6U-y1p9r_wW2dFWIWgjz-
```

If the server wants a fresh nonce first:

```http
HTTP/1.1 400 Bad Request
DPoP-Nonce: eyJ7S_zG.eyJH0-Z.HX4w-7v
Content-Type: application/json

{"error": "use_dpop_nonce", "error_description": "Authorization server requires nonce in DPoP proof"}
```

The client retries with `"nonce": "eyJ7S_zG.eyJH0-Z.HX4w-7v"` in a new proof and gets:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "access_token": "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
  "token_type": "DPoP",
  "expires_in": 2677,
  "refresh_token": "Q..Zkm29lexi8VnWg2zPW1x-tgGad0Ibc3s3EwM_Ni4-g"
}
```

The access token (or its introspection response) carries the key thumbprint:

```json
{ "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" } }
```

For **public clients**, the AS also binds the **refresh token** to the DPoP key, so a stolen refresh token cannot be used elsewhere. The optional `dpop_jkt` parameter in the authorization request binds the **authorization code** to the key as well.

#### Calling the resource server

```http
GET /protectedresource HTTP/1.1
Host: resource.example.org
Authorization: DPoP Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6...
```

The proof's payload now includes `ath`:

```json
{
  "jti": "e1j3V_bKic8-LAEB",
  "htm": "GET",
  "htu": "https://resource.example.org/protectedresource",
  "iat": 1562262618,
  "ath": "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
}
```

Note the authorization scheme is **`DPoP`**, not `Bearer`. A resource server that accepts DPoP tokens must refuse them under the `Bearer` scheme; otherwise the binding can be skipped.

#### What the server must check

1. Exactly one `DPoP` header, containing a well-formed JWT with `typ: dpop+jwt`.
2. `alg` is an allowed asymmetric algorithm, and the signature verifies with the embedded `jwk` (which contains no private key).
3. `htm` equals the request method, and `htu` equals the request URI (ignoring query and fragment).
4. `iat` is within an acceptable window (seconds to a few minutes), and the `nonce` matches if the server requires nonces.
5. `jti` has not been seen within that window (replay cache).
6. At the RS: `ath` equals the hash of the presented access token, and the proof key's thumbprint equals the token's `cnf.jkt`.

Errors at the RS use `WWW-Authenticate: DPoP error="invalid_dpop_proof"` or `error="use_dpop_nonce"` with a `DPoP-Nonce` header.

#### What DPoP does and does not protect

- **Protects against:** use of stolen access or refresh tokens from another machine (logs, backups, proxies, malicious resource servers, exfiltration by XSS).
- **Does not protect against:** an attacker running code **inside** the client while it is running. In a browser, XSS can call `crypto.subtle.sign` with a non-extractable key and create valid proofs as long as the page is open. DPoP turns "steal once, use anywhere for weeks" into "abuse only while you are on the victim's page".

### 6.4 Choosing mTLS or DPoP

| Question | mTLS | DPoP |
|---|---|---|
| Browser SPA or mobile app? | Impractical | **Yes** |
| Service mesh, B2B with PKI? | **Yes** | Possible |
| TLS terminated at a proxy or CDN? | Needs secure certificate forwarding | **Unaffected** |
| Implementation effort | Infrastructure (PKI, proxies) | Application code (a proof per request) and a replay cache |
| Performance | Handshake cost only | One signature per request, plus a verification at the RS |
| In FAPI 2.0 | Allowed | Allowed |

**Adopt sender-constraining when:** tokens grant access to money, health data, admin functions, or other high-value resources, or when public clients hold long-lived refresh tokens. That is the house position: **where the risk justifies it**.

---

## 7. Pushed Authorization Requests (PAR, RFC 9126)

**Problem.** In a normal flow, all authorization parameters (`redirect_uri`, `scope`, `code_challenge`, RAR details) travel through the **browser** as URL query parameters. They are not authenticated or integrity-protected, an attacker or extension can modify them, they leak into logs and history, and complex requests (RAR) can exceed URL length limits.

**Solution.** RFC 9126 (September 2021): the client first **POSTs** the authorization parameters directly to the AS over the back channel, **authenticating itself**. The AS validates them and returns a short-lived, single-use `request_uri`. The browser then carries only `client_id` and `request_uri`.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant AS as Authorization server
    participant B as Browser
    C->>AS: POST /par with all parameters and client authentication
    AS->>AS: Authenticate client, validate redirect_uri, scope, PKCE
    AS-->>C: 201 request_uri, expires_in 60
    C-->>B: 302 to /authorize with client_id and request_uri only
    B->>AS: GET /authorize with client_id and request_uri
    AS-->>B: Login and consent, then redirect with code
```

**Push request** (based on the RFC 9126 example):

```http
POST /as/par HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3

response_type=code&state=af0ifjsldkj&client_id=s6BhdRkqt3
&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
&code_challenge=K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U
&code_challenge_method=S256&scope=account-information
```

```http
HTTP/1.1 201 Created
Content-Type: application/json
Cache-Control: no-cache, no-store

{
  "request_uri": "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
  "expires_in": 60
}
```

**Authorization request:**

```http
GET /authorize?client_id=s6BhdRkqt3&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A6esc_11ACC5bwc014ltc14eY22c HTTP/1.1
Host: as.example.com
```

| Benefit | Why |
|---|---|
| Integrity and confidentiality of parameters | They never pass through the browser |
| Client authenticated **before** the user interacts | Fake or tampered requests are rejected before the login page. Phishing via crafted error redirects is harder |
| Early validation | Bad `redirect_uri` or scope fails in the back channel, not in front of the user |
| No URL size limits | Large RAR or claims requests fit easily |

Metadata: `pushed_authorization_request_endpoint`, and `require_pushed_authorization_requests: true` if the AS requires PAR (it can also be required per client). `request_uri` values should be single-use with lifetimes of seconds to a minute or two.

**Adopt:** whenever your AS supports it and you control the clients. It is **required in FAPI 2.0** and cheap to use for confidential clients. Spring Authorization Server supports PAR (added in version 1.5, now part of Spring Security 7).

---

## 8. JWT-Secured Authorization Requests (JAR, RFC 9101)

**Problem.** Authorization request parameters are unsigned, so neither the AS nor an auditor can prove which client asked for what. Some regulated ecosystems need **non-repudiation**.

**Solution.** RFC 9101 (August 2021): the client puts the authorization parameters into a **signed JWT** (a *request object*), optionally encrypted. It is passed by value (`request=`) or by reference (`request_uri=`, which combines naturally with PAR).

Request object header and payload:

```json
{ "typ": "oauth-authz-req+jwt", "alg": "PS256", "kid": "orders-web-2026-10" }
```

```json
{
  "iss": "orders-web",
  "aud": "https://auth.example.com",
  "client_id": "orders-web",
  "response_type": "code",
  "redirect_uri": "https://app.example.com/callback",
  "scope": "orders.read",
  "state": "RJgHM0z7XRTlwXFcQm3EMA",
  "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "code_challenge_method": "S256",
  "nbf": 1791450000,
  "exp": 1791450060,
  "jti": "86-YxrlBg8w_HwZEZWTTrRQ0dLMe0ej_"
}
```

```http
GET /oauth2/authorize?client_id=orders-web&request=eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiUFMyNTYiLCJraWQiOiJvcmRlcnMtd2ViLTIwMjYtMTAifQ.eyJpc3Mi...sig HTTP/1.1
Host: auth.example.com
```

Rules from RFC 9101: `client_id` must also appear as a plain parameter and match the one inside the object. The AS uses **only** the parameters inside the request object and ignores any duplicated outside it. It verifies the signature with the client's registered keys and checks `aud`, `exp` and `jti`.

The OpenID Foundation's **JARM** (JWT Secured Authorization Response Mode) does the same for the **response**, returning the code inside a signed JWT.

**Adopt:** when you need signed, auditable requests (FAPI 2.0 Message Signing, some open banking regimes). If you only need integrity and confidentiality, **PAR alone is simpler**.

---

## 9. Rich Authorization Requests (RAR, RFC 9396)

**Problem.** Scopes are flat strings. "payments" cannot express "**one** payment of **123.50 EUR** to **Merchant A**", or "read access to account **DE02...** until Friday". Teams end up inventing scope syntaxes like `payment:123.50:EUR:merchantA`.

**Solution.** RFC 9396 (May 2023) adds an `authorization_details` parameter: a JSON array of objects, each with a `type` defined by the AS. Example from the RFC:

```json
[
  {
    "type": "payment_initiation",
    "actions": ["initiate", "status", "cancel"],
    "locations": ["https://example.com/payments"],
    "instructedAmount": { "currency": "EUR", "amount": "123.50" },
    "creditorName": "Merchant A",
    "creditorAccount": { "iban": "DE02100100109307118603" },
    "remittanceInformationUnstructured": "Ref Number Merchant"
  }
]
```

How it flows:

1. The client sends `authorization_details` (URL-encoded JSON) in the authorization request. Because it can be large and is sensitive, send it **via PAR**.
2. The AS shows the details on the consent screen ("Pay 123.50 EUR to Merchant A").
3. The token response echoes the granted `authorization_details`, and the AS includes them in JWT access tokens or introspection responses.
4. The RS enforces them: this token may initiate exactly this payment.

Common fields: `type` (required), `locations`, `actions`, `datatypes`, `identifier`, `privileges`. The AS advertises supported types in `authorization_details_types_supported`.

**Adopt:** for transactional consent (payments, document signing, one-off data shares), regulated consent, or when your scope list is turning into a mini-language.

---

## 10. Resource Indicators (RFC 8707)

**Problem.** A client that calls several APIs gets one token valid for all of them. If any one API is compromised or malicious, it can replay the token against the others.

**Solution.** RFC 8707 (February 2020) adds a `resource` parameter, an absolute URI identifying the target API, to the authorization and token requests. The AS issues tokens whose `aud` is that resource.

```http
POST /oauth2/token HTTP/1.1
Host: auth.example.com
Authorization: Basic b3JkZXJzLXdlYjo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=1B6Kif29I_uhKaoev5VXC-RReWvATaGgeW8w8-HZfPU
&resource=https%3A%2F%2Finvoices.example.com
```

```json
{ "iss": "https://auth.example.com", "aud": "https://invoices.example.com", "scope": "invoices.read", "exp": 1791450600 }
```

- In the authorization request, the client may list several `resource` values. The user consents once.
- At the token endpoint, the client asks for a token for **one** resource at a time, using the same refresh token. Each token is audience-restricted.
- An unknown or disallowed resource produces the error `invalid_target`.

**Adopt:** whenever one client calls more than one API with the same AS. It implements RFC 9700's "audience-restrict access tokens" rule. Pair it with resource servers that **always** validate `aud`.

---

## 11. Token Exchange (RFC 8693)

**Problem.** In microservices, the edge API receives a user's token (`aud=gateway`). Downstream services need to act **on behalf of the user**. Common anti-patterns:

- **Forwarding the same token** everywhere, which requires a broad audience, so any compromised service can replay it against every other service.
- **Switching to a service account**, which loses the user's identity and permissions (a confused deputy waiting to happen).

**Solution.** RFC 8693 (January 2020) defines a grant where a client exchanges one token for another at the AS: a **new** token with a different audience, reduced scope, and optionally an `act` (actor) claim recording **who is acting for whom**.

```mermaid
sequenceDiagram
    autonumber
    participant U as User app
    participant O as Orders service
    participant AS as Authorization server
    participant I as Inventory service
    U->>O: POST /orders with token, aud orders, sub user 248289761001
    O->>AS: POST /token grant_type token-exchange, subject_token, audience inventory, own client auth
    AS->>AS: Policy check, may orders act for this user at inventory
    AS-->>O: New token, aud inventory, sub user, act orders service, short lifetime
    O->>I: POST /reservations with the exchanged token
    I->>I: Validate aud inventory, check sub and act
    I-->>O: 201
```

**Request:**

```http
POST /oauth2/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic b3JkZXJzLXNlcnZpY2U6VGhpc0lzQVNlY3JldA==

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
&subject_token=eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIyNDgyODk3NjEwMDEi...sig
&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
&audience=https%3A%2F%2Finventory.internal.example.com
&scope=inventory.reserve
&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "access_token": "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzI1NiJ9...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 60,
  "scope": "inventory.reserve"
}
```

**Decoded exchanged token (delegation):**

```json
{
  "iss": "https://auth.example.com",
  "sub": "248289761001",
  "aud": "https://inventory.internal.example.com",
  "scope": "inventory.reserve",
  "exp": 1791450060,
  "act": { "sub": "orders-service" }
}
```

| Concept | Meaning |
|---|---|
| `subject_token` | The token representing the party on whose behalf the request is made (usually the user) |
| `actor_token` (optional) | A token representing the acting party, if different from the authenticated client |
| `audience`, `resource` | Where the new token will be used |
| **Impersonation** | The new token looks as if the subject called directly. No `act` claim. Use sparingly |
| **Delegation** | The new token has `act`, so the downstream service and the audit log know the orders service acted for the user. **Preferred** |
| `may_act` | A claim in the subject token stating who is allowed to act for the subject |

The AS **must** apply policy: which clients may exchange which tokens, for which audiences, with which scopes. Never allow scope escalation. Keep exchanged tokens very short-lived (seconds to a few minutes).

Related work: the IETF draft **Transaction Tokens** (`draft-ietf-oauth-transaction-tokens`, an Internet-Draft) defines short-lived, internal tokens that carry user and request context through a call chain inside one trust domain. See [Service-to-service and zero trust](12-service-to-service-and-zero-trust.md).

**Adopt:** for any multi-hop microservice call that must preserve user identity, and for cross-domain delegation. Spring Authorization Server has supported the token exchange grant since 1.3 (2024), and Spring Security's OAuth client has a matching token exchange provider.

---

## 12. JWT access tokens (RFC 9068)

**Problem.** Many authorization servers issued JWT access tokens, each with different claims. Resource servers had to special-case each vendor, and some accepted **ID tokens as access tokens**, a dangerous confusion because ID tokens are meant for the client, not the API.

**Solution.** RFC 9068 (October 2021) standardizes a JWT access token profile.

| Element | Requirement |
|---|---|
| Header `typ` | `at+jwt` (or `application/at+jwt`). Resource servers **must** check it, which stops ID tokens or other JWTs being accepted as access tokens |
| Required claims | `iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti` |
| Optional claims | `auth_time`, `acr`, `amr`, `scope`, `groups`, `roles`, `entitlements` |
| Signing | Asymmetric signatures are expected (RS256 must be supported). Never `none` |
| Validation at the RS | `typ`, signature against the issuer's keys, `iss`, `aud` contains this RS, `exp`, then scopes and authorization claims |

```json
{ "typ": "at+jwt", "alg": "RS256", "kid": "2026-10-a" }
```

```json
{
  "iss": "https://auth.example.com",
  "sub": "248289761001",
  "aud": "https://api.example.com",
  "client_id": "orders-web",
  "scope": "orders.read",
  "iat": 1791450000,
  "exp": 1791450600,
  "jti": "eeyS-eTxHxBxQcLp",
  "auth_time": 1791449990,
  "acr": "urn:example:acr:mfa"
}
```

**Privacy note:** a signed JWT is readable by anyone who holds it, including the client and the browser in a token-mediating design. Do not put personal data in access tokens that is not needed for authorization. Use opaque tokens plus introspection, or encrypted JWTs, if that matters. JWT details and pitfalls are in [Tokens and JWT](06-tokens-and-jwt.md).

**Adopt:** whenever you use JWT access tokens. Configure resource servers to require `typ: at+jwt` once your AS emits it.

---

## 13. Issuer identification (RFC 9207)

**Problem.** **Mix-up attacks**: a client that supports several authorization servers cannot tell which AS sent an authorization response, so it can be tricked into sending a code to the wrong token endpoint ([chapter 08](08-oauth-2.md#195-mix-up-attacks)).

**Solution.** RFC 9207 (March 2022): the AS adds its issuer identifier as an `iss` parameter to every authorization response, both success and error. Example from the RFC:

```http
HTTP/1.1 302 Found
Location: https://client.example/cb?code=x1848ZT64p4IirMPT0R-X3141MFPTuBX-VFL_cvaplMH58&state=ZWVlNDBlYzA1NjdkMDNhYjg3ZjUxZjAyNGQzMTM2NzI&iss=https%3A%2F%2Fhonest.as.example
```

The client stores the expected issuer when it starts the flow and rejects the response if `iss` differs (simple string comparison). The AS advertises `authorization_response_iss_parameter_supported: true`. If the AS advertises support, a missing `iss` must also be rejected.

OpenID Connect ID tokens contain `iss` too, but the ID token arrives **after** the code has been sent to a token endpoint, which is too late to protect the code.

**Adopt:** always, if your AS supports it. It is mandatory in FAPI 2.0. It is a one-line check in the client.

---

## 14. Step-up authentication challenge (RFC 9470)

**Problem.** A user logged in with a password an hour ago. Now they want to transfer 5,000 EUR. The API wants a **stronger** or **more recent** authentication, but there was no standard way for an API to tell the client "this token is not good enough".

**Solution.** RFC 9470 (September 2023) defines a resource server error, `insufficient_user_authentication`, with `acr_values` and/or `max_age` hints. The client sends the user back to the AS with those values. The new token carries `acr` and `auth_time` that satisfy the API.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant RS as Payments API
    participant AS as Authorization server
    participant U as User
    C->>RS: POST /transfers with token, acr pwd, auth_time 1 hour ago
    RS-->>C: 401 insufficient_user_authentication, acr_values phr, max_age 300
    C->>AS: Authorization request with acr_values phr and max_age 300
    AS->>U: Ask for a passkey
    U->>AS: Passkey assertion
    AS-->>C: Code, then a new token with acr phr and a fresh auth_time
    C->>RS: POST /transfers with the new token
    RS-->>C: 201 transfer created
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="A different authentication level is required",
  acr_values="urn:example:acr:phr"
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="More recent authentication is required",
  max_age="300"
```

(Header values are folded across lines here for readability.)

The client then starts a normal authorization code flow with `acr_values=urn:example:acr:phr` and/or `max_age=300`. The AS must include `acr` and `auth_time` in the new access token (or introspection response) so the RS can verify them. `acr` values are deployment-specific: agree on names for "password", "MFA" and "phishing-resistant MFA (passkey)" across your AS and APIs. See [MFA, passwordless and passkeys](11-mfa-passwordless-and-passkeys.md).

**Adopt:** for sensitive operations (payments, changing email or MFA settings, admin actions, exporting data) where you want stronger or fresher authentication without forcing it at every login.

---

## 15. Protected resource metadata (RFC 9728)

**Problem.** RFC 8414 lets clients discover an authorization server, but a client meeting a new API did not know **which** AS protects it, which scopes it uses, or whether it requires DPoP.

**Solution.** RFC 9728 (April 2025): each resource server publishes metadata at `/.well-known/oauth-protected-resource`, and can point to it from its `401` responses.

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"
```

```json
{
  "resource": "https://api.example.com",
  "authorization_servers": ["https://auth.example.com"],
  "scopes_supported": ["orders.read", "orders.write"],
  "bearer_methods_supported": ["header"],
  "dpop_signing_alg_values_supported": ["ES256", "PS256"]
}
```

The client must check that `resource` matches the URL it used. RFC 9728 is used by ecosystems where clients meet APIs dynamically. For example, the Model Context Protocol (MCP) authorization specification for AI tool servers builds on the OAuth 2.1 draft, requires MCP servers to publish RFC 9728 metadata, and has clients discover the authorization server through RFC 8414 or OpenID Connect Discovery.

**Adopt:** for public or partner APIs consumed by generic clients and agents. Internal APIs with pre-configured clients rarely need it.

---

## 16. CIBA: decoupled authentication

**Problem.** Sometimes the device that **needs** the token is not the device the user is holding: a call-center agent's app verifying a caller, a point-of-sale terminal, a smart speaker, or a bank approving a payment started at a partner. Redirect-based flows do not fit.

**Solution.** **OpenID Connect Client-Initiated Backchannel Authentication (CIBA) Core 1.0** (OpenID Foundation Final Specification, 2021). The client asks the AS to authenticate a user identified by a hint. The AS contacts the user on their own **authentication device** (usually a banking or authenticator app). The client receives tokens when the user approves.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (call center app)
    participant AS as Authorization server (OpenID Provider)
    participant D as User phone app
    C->>AS: POST /bc-authorize login_hint, binding_message, scope openid
    AS-->>C: auth_req_id, expires_in 120, interval 5
    AS->>D: Push notification, approve request with code W4SCT
    D->>AS: User verifies the binding message and approves with biometrics
    loop Poll mode
        C->>AS: POST /token grant_type ciba, auth_req_id
        AS-->>C: 400 authorization_pending until approved
    end
    AS-->>C: ID token and access token
```

```http
POST /bc-authorize HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

scope=openid%20payments
&login_hint=jane%40example.com
&binding_message=W4SCT
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJQUzI1NiIsImtpZCI6ImNjLTIwMjYifQ...sig
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{ "auth_req_id": "1c266114-a1be-4252-8ad1-04986c5b9ac1", "expires_in": 120, "interval": 5 }
```

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aopenid%3Aparams%3Agrant-type%3Aciba
&auth_req_id=1c266114-a1be-4252-8ad1-04986c5b9ac1
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJQUzI1NiIsImtpZCI6ImNjLTIwMjYifQ...sig
```

Delivery modes: **poll** (client polls the token endpoint), **ping** (AS calls the client's notification endpoint, then the client fetches tokens), and **push** (AS delivers the tokens to the client; not allowed in the FAPI CIBA profile).

**Risks:** unsolicited approval requests lead to **push fatigue** (users approving to make prompts stop). Always show a `binding_message` on both screens, rate-limit requests per user, consider requiring a `user_code`, and make "Deny and report" easy.

**Adopt:** for decoupled scenarios such as call centers, in-store payments and open banking decoupled flows. Do not use it as a general login method.

---

## 17. FAPI 2.0

**FAPI** (originally "Financial-grade API") is an OpenID Foundation profile that removes OAuth's optionality for high-risk APIs. Status:

| Document | Status |
|---|---|
| FAPI 2.0 Security Profile | **Final**, approved February 2025 |
| FAPI 2.0 Attacker Model | **Final**, approved February 2025 |
| FAPI 2.0 Message Signing | **Final**, approved September 2025 |
| FAPI 1.0 (Baseline, Advanced) | Final (2021), still deployed in existing ecosystems |

The Security Profile was formally analyzed against its attacker model by researchers at the University of Stuttgart. Conformance tests and certification are available from the OpenID Foundation.

### Key requirements of the FAPI 2.0 Security Profile (summary)

| Area | Requirement |
|---|---|
| Clients | **Confidential clients only** |
| Client authentication | `private_key_jwt` or mTLS. No shared secrets |
| Authorization requests | **PAR required** |
| PKCE | Required, `S256` |
| Authorization code | Maximum lifetime of **60 seconds** |
| Mix-up defense | `iss` authorization response parameter (RFC 9207) |
| Access tokens | **Sender-constrained**, with mTLS or DPoP |
| Refresh tokens | Sender-constrained or bound to the authenticated confidential client. The profile says authorization servers **shall not use refresh token rotation** except in extraordinary circumstances, because rotation adds no security for sender-constrained tokens and causes operational failures |
| Grants | Authorization code (plus refresh). No implicit, no password grant |
| Redirect URIs | Pre-registered, `https`, exact matching |
| Cryptography | JWTs signed with **PS256, ES256 or EdDSA (Ed25519)**. RS256 is not allowed |
| Message Signing (optional add-on) | Signed requests (JAR), signed responses (JARM), signed introspection responses, and HTTP message signatures for non-repudiation |

Note the refresh token difference from this guide's general house position. Rotation with reuse detection is the right defense when refresh tokens are **bearer** tokens held by clients that might leak them. When refresh tokens are already bound to a key or a strongly authenticated confidential client, as FAPI requires, rotation adds operational risk without security benefit.

**Adopt FAPI 2.0 when:** you build open banking or open finance APIs, payment initiation, health data sharing, or any API where a stolen token means direct financial or legal harm. Even outside regulated sectors, it is an excellent checklist for "maximum security OAuth".

---

## 18. GNAP (RFC 9635): a possible successor

**GNAP** (Grant Negotiation and Authorization Protocol, **RFC 9635**, October 2024, Proposed Standard, edited by Justin Richer with Fabien Imbault) came out of the IETF GNAP working group. It redesigns delegated authorization from scratch instead of patching OAuth 2.0.

| OAuth 2.x | GNAP |
|---|---|
| Many grant types and endpoints | **One grant endpoint**. The client describes what it wants in a JSON request |
| Clients pre-registered, identified by `client_id` | Clients identified by their **key**. Registration is optional |
| Bearer tokens by default, binding bolted on | **Key-bound** requests and tokens by default |
| Redirect-centric | **Interaction modes negotiated**: redirect, user code, app link, push |
| Scopes plus RAR as an extension | Rich access descriptions built in, similar to RAR |
| One access token per request | **Multiple access tokens** in one grant |
| Identity layered on top (OIDC) | Subject information can be requested directly |

A simplified grant request:

```http
POST /gnap HTTP/1.1
Host: server.example.com
Content-Type: application/json
Signature-Input: sig1=...
Signature: sig1=...

{
  "access_token": {
    "access": [{ "type": "photo-api", "actions": ["read", "print"] }]
  },
  "client": {
    "key": { "proof": "httpsig", "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } }
  },
  "interact": {
    "start": ["redirect"],
    "finish": { "method": "redirect", "uri": "https://client.example.net/return/123455", "nonce": "LKLTI25DK82FX4T4QFZC" }
  }
}
```

The server responds with an interaction URL and a **continuation** handle that the client uses (with its key) to finish the grant and receive tokens.

**Status in 2026:** GNAP is published and technically interesting, but implementations and ecosystem support are small compared with OAuth 2.x, OpenID Connect and FAPI. **Adopt only** for greenfield ecosystems that need its features (key-bound clients without registration, negotiated interaction) and can accept limited library support. For most teams, the practical path is OAuth 2.0 plus RFC 9700 now, OAuth 2.1 when it is published.

---

## 19. Adoption guide

| Extension | Solves | Adopt when | Effort |
|---|---|---|---|
| RFC 9700 rules | The whole known attack catalog | **Always** | Configuration and review |
| PKCE (S256) | Code interception and injection, CSRF | **Always**, every client | Low (libraries do it) |
| RFC 8252 practices | Web view credential theft, scheme hijacking | **Always** for native apps | Low |
| BFF (RFC 10017) | Token theft from browsers | **Default** for browser apps | Medium (a backend component) |
| RFC 9207 `iss` | Mix-up | Always, if your AS supports it | Very low |
| Resource indicators (RFC 8707) | Token replay across APIs | One client calls several APIs | Low |
| JWT access tokens (RFC 9068) | Interop, token type confusion | You issue JWT access tokens | Low |
| PAR (RFC 9126) | Tampering and leakage of request parameters | Confidential clients, high-value flows, RAR | Low to medium |
| Token exchange (RFC 8693) | Identity propagation, least privilege | Multi-hop microservices, delegation | Medium (AS policy) |
| Step-up (RFC 9470) | Stronger or fresher login for sensitive actions | Payments, admin, account changes | Medium |
| DPoP (RFC 9449) | Stolen token replay (apps, browsers) | High-value APIs, public clients with refresh tokens | Medium |
| mTLS (RFC 8705) | Stolen token replay (services), client authentication | Service mesh, B2B, FAPI | Medium to high (PKI) |
| RAR (RFC 9396) | Transaction-specific consent | Payments, signing, regulated consent | Medium to high |
| JAR (RFC 9101), JARM | Signed requests and responses, non-repudiation | Regulated ecosystems | Medium |
| Protected resource metadata (RFC 9728) | API-to-AS discovery | Public APIs, agent ecosystems | Low |
| CIBA | Decoupled authentication | Call centers, POS, decoupled banking | High |
| FAPI 2.0 | All of the above as one profile | Open banking, payments, health | High |
| GNAP (RFC 9635) | A cleaner protocol design | Greenfield experiments | High (few libraries) |

---

## 20. Common attacks and mistakes

| Attack or mistake | What goes wrong | Mitigation |
|---|---|---|
| Claiming "OAuth 2.1 compliant" while the AS still allows implicit or password grants | False sense of security | Audit against RFC 9700. Disable legacy grants per client |
| Treating OAuth 2.1 as a published standard in contracts or audits | It is a draft and may still change | Cite RFC 6749, RFC 9700 and specific RFCs. Reference the draft as work in progress |
| Embedded web view for login in a native app | App can capture credentials, no SSO, phishing training | System browser (RFC 8252) |
| `localhost` instead of `127.0.0.1` for loopback redirects, or a fixed port | DNS or firewall surprises, port conflicts | IP literal, AS accepts any port |
| SPA stores refresh tokens in `localStorage` | XSS steals long-lived tokens | BFF. If impossible: memory only, rotation, DPoP |
| Assuming an in-memory token makes an SPA XSS-proof | XSS can still start a new silent flow and get fresh tokens | BFF keeps tokens off the browser entirely |
| BFF endpoints without CSRF protection | Cookie-authenticated requests forged cross-site | CSRF tokens or custom header plus `SameSite`, and origin checks |
| RS accepts a DPoP-bound token under the `Bearer` scheme | Binding bypassed | Require the `DPoP` scheme for bound tokens |
| DPoP proofs not checked for `htm`, `htu`, `iat`, `jti` or `ath` | Proof replay, proof reuse across endpoints | Implement every RFC 9449 check, with a replay cache |
| DPoP private key extractable in the browser | XSS exfiltrates the key, so binding is meaningless | WebCrypto key generated with `extractable: false`, stored in IndexedDB |
| mTLS terminated at a proxy that forwards a spoofable certificate header | Attacker forges the certificate header | Proxy strips incoming headers. AS and RS trust the header only from the proxy |
| PAR `request_uri` reusable or long-lived | Replay of a pushed request | Single use, lifetime of seconds to a minute or two |
| JAR object parameters mixed with unsigned outside parameters | Attacker overrides signed values | Use only the parameters inside the request object |
| RAR details not enforced at the RS | Token for 123.50 EUR used for 12,350 EUR | RS checks every detail against the request |
| One token forwarded through every microservice | A compromised service replays it everywhere | Token exchange per hop, audience-restricted, short-lived |
| Token exchange without AS policy | Any service can mint tokens for any audience, or escalate scope | Per-client allowlists of audiences and scopes. Never widen scope |
| RS accepts ID tokens as access tokens | Token type confusion, wrong audience | Require `typ: at+jwt` and correct `aud` |
| Not checking `iss` in authorization responses | Mix-up attacks | RFC 9207 check, or per-AS redirect URIs |
| Step-up `acr` values not agreed between AS and APIs | APIs accept weak logins, or loop forever | Document `acr` values. Test the step-up flow end to end |
| CIBA without binding messages or rate limits | Push fatigue, unsolicited approvals | `binding_message`, per-user rate limits, easy deny and report |
| Rotating sender-constrained refresh tokens in FAPI | Lost tokens and broken consents on network errors, no security gain | Follow FAPI 2.0: bind instead of rotating |

---

## 21. Spring Boot 4 / Spring Security 7

Spring Authorization Server is part of Spring Security 7 (Spring Boot 4 starter `spring-boot-starter-security-oauth2-authorization-server`). It supports PKCE, PAR, DPoP, mTLS client authentication and certificate-bound tokens, token exchange, the device grant, introspection, revocation, metadata, OpenID Connect and dynamic client registration.

### 21.1 Authorization server with modern client settings

```java
@Configuration
@EnableWebSecurity
class AuthorizationServerConfig {

    @Bean
    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
        http
            .oauth2AuthorizationServer(as -> as.oidc(Customizer.withDefaults()))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    RegisteredClientRepository registeredClients() {
        // BFF web app: confidential, private_key_jwt, PKCE, short-lived tokens, rotating refresh tokens
        RegisteredClient ordersWeb = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("orders-web")
            .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("https://app.example.com/login/oauth2/code/example")   // exact match
            .postLogoutRedirectUri("https://app.example.com/")
            .scope(OidcScopes.OPENID)
            .scope("orders.read")
            .scope("orders.write")
            .clientSettings(ClientSettings.builder()
                .requireProofKey(true)                                          // PKCE required
                .requireAuthorizationConsent(false)                             // first-party client
                .jwkSetUrl("https://app.example.com/.well-known/jwks.json")     // client's public keys
                .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.ES256)
                .build())
            .tokenSettings(TokenSettings.builder()
                .authorizationCodeTimeToLive(Duration.ofSeconds(60))
                .accessTokenTimeToLive(Duration.ofMinutes(10))
                .refreshTokenTimeToLive(Duration.ofHours(12))
                .reuseRefreshTokens(false)                                      // rotate on every use
                .build())
            .build();

        // Batch job: client credentials, mTLS client auth, certificate-bound access tokens (RFC 8705)
        RegisteredClient ordersBatch = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("orders-batch")
            .clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("orders.read")
            .clientSettings(ClientSettings.builder()
                .x509CertificateSubjectDN("CN=orders-batch,OU=Platform,O=Example Corp,C=US")
                .build())
            .tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(5))
                .x509CertificateBoundAccessTokens(true)
                .build())
            .build();

        return new InMemoryRegisteredClientRepository(ordersWeb, ordersBatch);   // use a JDBC repository in production
    }
}
```

Notes:

- `reuseRefreshTokens(false)` makes the server issue a new refresh token on every refresh. Check whether your version also revokes the **whole token family** when an old refresh token is replayed. If not, add that reuse detection yourself. [../examples/02-jwt-auth/](../examples/02-jwt-auth/) shows the logic.
- Sign tokens with a key from a `JWKSource` bean backed by a keystore or KMS, and rotate it with overlapping `kid`s.
- DPoP: the server binds tokens when the client sends a `DPoP` proof to the token endpoint, and resource servers can validate DPoP-bound tokens. See the Spring Security reference section "OAuth 2.0 DPoP-bound Access Tokens" for the configuration in your exact version.

### 21.2 Resource server enforcing step-up (RFC 9470)

```java
@Configuration
@EnableWebSecurity
class PaymentsApiSecurityConfig {

    static final String PHISHING_RESISTANT = "urn:example:acr:phr";   // agreed with the AS (passkey login)
    static final Duration MAX_AUTH_AGE = Duration.ofMinutes(5);

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        var standardDenied = new BearerTokenAccessDeniedHandler();
        http
            .securityMatcher("/api/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST, "/api/transfers/**")
                    .access((authentication, context) -> new AuthorizationDecision(isRecentStrongLogin(authentication.get())))
                .anyRequest().hasAuthority("SCOPE_payments.read"))
            .oauth2ResourceServer(rs -> rs
                .jwt(Customizer.withDefaults())                              // iss, aud, exp, signature via application.yml
                .accessDeniedHandler((request, response, ex) -> {
                    if (request.getRequestURI().startsWith("/api/transfers")) {
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.setHeader(HttpHeaders.WWW_AUTHENTICATE,
                            "Bearer error=\"insufficient_user_authentication\", "
                            + "error_description=\"A recent passkey login is required\", "
                            + "acr_values=\"" + PHISHING_RESISTANT + "\", max_age=\"" + MAX_AUTH_AGE.toSeconds() + "\"");
                    } else {
                        standardDenied.handle(request, response, ex);
                    }
                }))
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable());                                    // bearer tokens only, no cookies
        return http.build();
    }

    private static boolean isRecentStrongLogin(Authentication authentication) {
        if (!(authentication instanceof JwtAuthenticationToken token)) {
            return false;
        }
        Jwt jwt = token.getToken();
        Instant authTime = jwt.getClaimAsInstant("auth_time");
        return PHISHING_RESISTANT.equals(jwt.getClaimAsString("acr"))
            && authTime != null
            && authTime.isAfter(Instant.now().minus(MAX_AUTH_AGE))
            && token.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_payments.write"));
    }
}
```

The client reacts to the `401` by starting a new authorization request with `acr_values` and `max_age`. The runnable OAuth 2 and OIDC setup (authorization server, resource server, BFF client) is in [../examples/03-oauth2-oidc/](../examples/03-oauth2-oidc/).

---

## Interview questions

**1. What is RFC 9700 and why does it matter?**
The OAuth 2.0 Security Best Current Practice (BCP 240, January 2025). It updates the security guidance of RFC 6749, 6750 and 6819: exact redirect URI matching, PKCE (required for public clients), no implicit grant, no password grant, refresh token protection for public clients, sender-constrained and audience-restricted tokens, mix-up defenses, and more. It is the checklist for production OAuth.

**2. Is OAuth 2.1 a standard?**
Not yet. As of October 2026 it is an IETF Internet-Draft (revision 16). It adds no new features. It consolidates OAuth 2.0, PKCE, bearer usage, native and browser app guidance and RFC 9700, removing the implicit and password grants and requiring PKCE and exact redirect matching.

**3. Why must native apps use the system browser?**
Embedded web views are controlled by the app, which can capture credentials and cookies. They also break SSO and train users to enter passwords anywhere. RFC 8252 requires external user agents, plus PKCE, and claimed HTTPS, private-use scheme or loopback redirects.

**4. What does RFC 10017 recommend for SPAs, and why?**
It compares a BFF, a token-mediating backend and a browser-only client. Malicious JavaScript in the origin can obtain new tokens however existing ones are stored, so only a BFF, which keeps tokens server-side and gives the browser an HttpOnly cookie, removes token theft from the browser. It is the recommended choice for business and sensitive apps.

**5. How does DPoP work, and what does it not protect against?**
The client signs a proof JWT per request with a private key (`htm`, `htu`, `iat`, `jti`, `ath`). The AS binds the token to the key's thumbprint (`cnf.jkt`), and the RS checks the proof and the binding, so stolen tokens are useless without the key. It does not stop an attacker who runs code inside the live client, such as XSS, from using the key while the page is open.

**6. mTLS or DPoP?**
mTLS for services and B2B with PKI or a service mesh: strong, but hard in browsers and through TLS-terminating proxies. DPoP for browsers, mobile apps and proxy-heavy setups: application-level and flexible, but it needs per-request signing and replay caches.

**7. What problem does PAR solve?**
Authorization parameters in the browser URL are unauthenticated, tamperable, leaky and size-limited. PAR sends them over an authenticated back channel and returns a short-lived `request_uri`. It is required in FAPI 2.0.

**8. How does token exchange improve microservice security?**
Instead of forwarding one broad token everywhere, each hop exchanges the incoming token for a new short-lived one with the downstream audience, reduced scope and an `act` claim recording delegation. A compromised service can no longer replay tokens across the system, and audit trails show who acted for whom.

**9. What is the `iss` authorization response parameter for?**
RFC 9207 lets the client verify which AS issued an authorization response before redeeming the code. That prevents mix-up attacks in clients that support several authorization servers.

**10. Why does FAPI 2.0 discourage refresh token rotation when this guide recommends it?**
Rotation detects theft of **bearer** refresh tokens. FAPI requires refresh tokens to be bound to authenticated confidential clients or sender-constrained, so a stolen token is already useless. Rotation would only add failure modes, such as lost responses that break consents.

---

## References

- RFC 9700 — Best Current Practice for OAuth 2.0 Security (BCP 240, January 2025): https://www.rfc-editor.org/rfc/rfc9700
- draft-ietf-oauth-v2-1 — The OAuth 2.1 Authorization Framework (Internet-Draft, revision 16, September 2026): https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/
- RFC 8252 — OAuth 2.0 for Native Apps (BCP 212, 2017): https://www.rfc-editor.org/rfc/rfc8252
- RFC 10017 — OAuth 2.0 for Browser-Based Applications (BCP 212, August 2026): https://www.rfc-editor.org/rfc/rfc10017
- RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens (2020): https://www.rfc-editor.org/rfc/rfc8705
- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP) (2023): https://www.rfc-editor.org/rfc/rfc9449
- RFC 7638 — JSON Web Key (JWK) Thumbprint (2015): https://www.rfc-editor.org/rfc/rfc7638
- RFC 9126 — OAuth 2.0 Pushed Authorization Requests (2021): https://www.rfc-editor.org/rfc/rfc9126
- RFC 9101 — The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR) (2021): https://www.rfc-editor.org/rfc/rfc9101
- RFC 9396 — OAuth 2.0 Rich Authorization Requests (2023): https://www.rfc-editor.org/rfc/rfc9396
- RFC 8707 — Resource Indicators for OAuth 2.0 (2020): https://www.rfc-editor.org/rfc/rfc8707
- RFC 8693 — OAuth 2.0 Token Exchange (2020): https://www.rfc-editor.org/rfc/rfc8693
- RFC 9068 — JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens (2021): https://www.rfc-editor.org/rfc/rfc9068
- RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification (2022): https://www.rfc-editor.org/rfc/rfc9207
- RFC 9470 — OAuth 2.0 Step Up Authentication Challenge Protocol (2023): https://www.rfc-editor.org/rfc/rfc9470
- RFC 9728 — OAuth 2.0 Protected Resource Metadata (April 2025): https://www.rfc-editor.org/rfc/rfc9728
- RFC 8725 — JSON Web Token Best Current Practices (2020): https://www.rfc-editor.org/rfc/rfc8725
- RFC 9635 — Grant Negotiation and Authorization Protocol (GNAP) (October 2024): https://www.rfc-editor.org/rfc/rfc9635
- draft-ietf-oauth-transaction-tokens — Transaction Tokens (Internet-Draft): https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/
- OpenID Connect Client-Initiated Backchannel Authentication Flow — Core 1.0 (Final): https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
- FAPI 2.0 Security Profile (Final, February 2025): https://openid.net/specs/fapi-security-profile-2_0-final.html
- FAPI 2.0 Message Signing (Final, September 2025): https://openid.net/specs/fapi-message-signing-2_0-final.html
- FAPI Working Group (Attacker Model and other documents): https://openid.net/wg/fapi/
- JWT Secured Authorization Response Mode for OAuth 2.0 (JARM): https://openid.net/specs/oauth-v2-jarm.html
- OWASP OAuth 2.0 Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- Spring Security reference — OAuth 2.0 Authorization Server: https://docs.spring.io/spring-security/reference/servlet/oauth2/authorization-server/index.html
- Spring Security reference — OAuth 2.0 DPoP-bound Access Tokens: https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/dpop-tokens.html
