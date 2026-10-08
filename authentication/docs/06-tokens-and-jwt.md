# 06 — Tokens and JWT

A **token** is a string that stands in for a login: the client presents it instead of re-sending credentials. Tokens are either **opaque** (a random handle the issuer looks up) or **self-contained** (the token carries signed claims that any verifier with the right key can check locally). The **JSON Web Token (JWT)** is the dominant self-contained format. It is a common access-token format in OAuth 2 deployments and the only ID-token format in OpenID Connect. This chapter explains how JWTs are built, how to validate them properly, the attacks that have broken real systems, and how production systems handle refresh, revocation, browser storage and key rotation.

> **Where this fits in the evolution**
>
> - **Before:** [Server-side sessions](04-sessions-cookies-and-csrf.md) kept state on the server and worked well for one web app on one domain. [SAML](05-enterprise-sso-ldap-kerberos-saml.md) introduced signed XML assertions for cross-domain SSO, and [OAuth 1.0a](07-oauth-1.md) issued opaque tokens that had to be used with per-request signatures.
> - **What it solved:** APIs, mobile apps and microservices needed a compact, URL-safe, signed format that any service could verify **without calling the issuer or sharing a session store**. The IETF published JWT and the JOSE family (RFCs 7515-7519) in May 2015, and [OAuth 2.0](08-oauth-2.md) and [OpenID Connect](10-openid-connect.md) adopted it.
> - **What came next:** Real-world attacks (`alg: none`, algorithm confusion, missing audience checks) led to the **JWT Best Current Practices** (RFC 8725, 2020) and the **JWT access token profile** (RFC 9068, 2021). Bearer-token theft led to **sender-constrained tokens** (mTLS, RFC 8705; DPoP, RFC 9449). For browsers, the industry moved tokens **out of JavaScript** and behind a Backend-for-Frontend (RFC 10017, 2026). An update to the JWT BCP (draft-ietf-oauth-rfc8725bis) is still an Internet-Draft as of October 2026.

---

## Table of contents

1. [Why tokens exist](#1-why-tokens-exist)
2. [Opaque vs self-contained tokens](#2-opaque-vs-self-contained-tokens)
3. [JWT anatomy](#3-jwt-anatomy)
4. [The JOSE family of specifications](#4-the-jose-family-of-specifications)
5. [Claims and header parameters](#5-claims-and-header-parameters)
6. [Signing algorithms: HS256, RS256, PS256, ES256, EdDSA](#6-signing-algorithms-hs256-rs256-ps256-es256-eddsa)
7. [The complete validation checklist](#7-the-complete-validation-checklist)
8. [Access tokens, refresh tokens and ID tokens](#8-access-tokens-refresh-tokens-and-id-tokens)
9. [Refresh token rotation with reuse detection](#9-refresh-token-rotation-with-reuse-detection)
10. [Revocation strategies](#10-revocation-strategies)
11. [Where to store tokens in browsers](#11-where-to-store-tokens-in-browsers)
12. [Key management: kid, JWKS, caching and rotation](#12-key-management-kid-jwks-caching-and-rotation)
13. [Sender-constrained tokens and token sidejacking](#13-sender-constrained-tokens-and-token-sidejacking)
14. [Production best practices (2026)](#14-production-best-practices-2026)
15. [Common attacks and mistakes](#15-common-attacks-and-mistakes)
16. [PASETO and other alternatives](#16-paseto-and-other-alternatives)
17. [Spring Boot 4 / Spring Security 7](#17-spring-boot-4--spring-security-7)
18. [Interview questions](#interview-questions)
19. [References](#references)

---

## 1. Why tokens exist

After authentication, every later request must prove "this is still the same, already-authenticated caller". There are two broad ways to do that (see [foundations](00-foundations.md)):

| Model | The client holds | The server needs | Good fit |
|---|---|---|---|
| Server-side session | A random session ID (cookie) | A session store lookup on every request | First-party browser apps on one site |
| Token | A token (often in `Authorization: Bearer`) | Either a lookup (opaque token) or a signature check (self-contained token) | APIs, mobile apps, third-party clients, many independent services |

Most tokens are **bearer tokens** (RFC 6750): whoever holds the token can use it, like cash. That single fact drives most of this chapter: keep tokens short-lived, narrowly scoped (audience and scopes), away from places attackers can read them, and bound to the client where the risk justifies it.

---

## 2. Opaque vs self-contained tokens

An **opaque token** is a random string (for example 256 bits from a CSPRNG, Base64URL-encoded) with no meaning to anyone but the issuer. A **self-contained token** carries the facts (who, for which API, until when, with which permissions) plus a signature that proves the issuer wrote them.

```mermaid
flowchart LR
    subgraph Opaque["Opaque token (reference)"]
        C1["Client"] -->|"Bearer 8xK2...random"| R1["Resource server"]
        R1 -->|"introspect (RFC 7662)"| A1["Authorization server"]
        A1 -->|"active, sub, scope, exp"| R1
    end
    subgraph SelfContained["Self-contained token (JWT)"]
        C2["Client"] -->|"Bearer eyJhbGci..."| R2["Resource server"]
        R2 -.->|"fetch public keys once, cache"| J2["JWKS endpoint"]
        R2 -->|"verify signature and claims locally"| R2
    end
```

| Aspect | Opaque (reference) token | Self-contained token (JWT) |
|---|---|---|
| Validation | Lookup at the issuer (introspection) or shared store | Local signature + claim checks with cached public keys |
| Latency and availability | Network call per request (cache 30-60 s to soften it); issuer outage breaks APIs | No call per request; issuer only needed for key refresh |
| Revocation | Immediate (delete the record) | Hard: valid until `exp` unless you add a denylist or introspection |
| Size | 32-64 bytes | Typically 500 bytes to 2 KB, sent on every request |
| Privacy | Reveals nothing | Payload is readable by anyone holding it (Base64URL, not encryption) |
| Data freshness | Always current | Snapshot at issue time (roles, account status) |
| Best for | Refresh tokens, high-risk APIs, tokens that leave your trust boundary | Short-lived access tokens verified by many services |

**Production pattern:** short-lived **JWT access tokens** (5-15 minutes) verified locally, plus **opaque refresh tokens** stored hashed on the authorization server, rotated on every use and revocable instantly. This combines local verification with a bounded revocation window: "at most one access-token lifetime".

Some systems use the **phantom token** (or split token) pattern: the client receives an opaque token, and an API gateway introspects it once and forwards a JWT to internal services. External parties never see readable claims, and internal services still verify locally.

---

## 3. JWT anatomy

A signed JWT in **compact serialization** is three Base64URL-encoded parts joined by dots:

```text
BASE64URL(header) . BASE64URL(payload) . BASE64URL(signature)
```

Here is a real ES256-signed access token (line breaks added for readability; the real token is one line):

```text
eyJhbGciOiJFUzI1NiIsImtpZCI6IjIwMjYtMTAtZXMyNTYtYSIsInR5cCI6ImF0K2p3dCJ9
.
eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyXzhmMTRlNDVmIiwiYXVkIjoiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20iLCJjbGllbnRfaWQiOiJ3ZWItYmZmIiwic2NvcGUiOiJvcmRlcnM6cmVhZCBvcmRlcnM6d3JpdGUiLCJpYXQiOjE3OTE0NTAwMDAsIm5iZiI6MTc5MTQ1MDAwMCwiZXhwIjoxNzkxNDUwNjAwLCJqdGkiOiI1ZjBjMmQxZS05YjdhLTRjM2UtOGE2MS0yYjhmN2Q5ZTRjMTAifQ
.
4uDCAIFwHNdUEXAItSji353o1OgoBGz2R4c1R4ILZyvRzppWedi3pQdmYRdDrjgyuQFELitLqMEkfBA6wmjj7w
```

Decoded header (the **JOSE header**):

```json
{
  "alg": "ES256",
  "kid": "2026-10-es256-a",
  "typ": "at+jwt"
}
```

Decoded payload (the **claims set**):

```json
{
  "iss": "https://auth.example.com",
  "sub": "user_8f14e45f",
  "aud": "https://api.example.com",
  "client_id": "web-bff",
  "scope": "orders:read orders:write",
  "iat": 1791450000,
  "nbf": 1791450000,
  "exp": 1791450600,
  "jti": "5f0c2d1e-9b7a-4c3e-8a61-2b8f7d9e4c10"
}
```

The token was issued at 2026-10-08 09:00:00 UTC and expires ten minutes later (`exp - iat = 600`).

Key points:

- **Base64URL** (RFC 4648 Section 5) uses `-` and `_` instead of `+` and `/`, and JWTs drop the `=` padding, so the token is safe in URLs, headers and form fields.
- **The signature covers the exact bytes** `ASCII(BASE64URL(header) + "." + BASE64URL(payload))`, called the **JWS signing input**. Changing one character of the header or payload invalidates it.
- **Signed is not encrypted.** Anyone holding the token can decode the payload. Never put passwords, secrets, or sensitive personal data in a signed-only JWT. If claims must be confidential, use JWE (Section 4) or an opaque token.
- An ES256 signature is 64 bytes (86 Base64URL characters). An RS256 signature with a 2048-bit key is 256 bytes (342 characters), so RSA-signed tokens are noticeably larger.

How the signature is produced and checked:

```mermaid
sequenceDiagram
    autonumber
    participant AS as Authorization server
    participant C as Client
    participant RS as Resource server
    AS->>AS: Build header with alg, kid, typ and claims with iss, sub, aud, exp
    AS->>AS: signing input = b64url(header) + dot + b64url(payload)
    AS->>AS: signature = Sign(private key for kid, signing input)
    AS-->>C: access token
    C->>RS: GET /orders with Authorization Bearer token
    RS->>RS: Split into three parts, decode header
    RS->>RS: Check alg is in the allowlist, look up kid in cached JWKS
    RS->>RS: Verify signature with that public key
    RS->>RS: Validate typ, iss, aud, exp, nbf, then scopes
    RS-->>C: 200 OK, or 401 with WWW-Authenticate Bearer error invalid_token
```

---

## 4. The JOSE family of specifications

"JOSE" (JSON Object Signing and Encryption) is the IETF working group and the family of specifications that JWT builds on.

| Spec | Name | What it defines |
|---|---|---|
| RFC 7515 (2015) | JSON Web Signature (**JWS**) | How to sign arbitrary content: header, compact and JSON serializations, header parameters (`alg`, `kid`, `jku`, `jwk`, `x5u`, `x5c`, `typ`, `crit`) |
| RFC 7516 (2015) | JSON Web Encryption (**JWE**) | How to encrypt content: five-part compact form, key management + content encryption |
| RFC 7517 (2015) | JSON Web Key (**JWK**) | JSON representation of keys and key sets (JWKS: `{"keys":[...]}`) |
| RFC 7518 (2015) | JSON Web Algorithms (**JWA**) | The algorithm names: `HS256`, `RS256`, `PS256`, `ES256`, `RSA-OAEP-256`, `A256GCM`, `none`, and key-size rules |
| RFC 7519 (2015) | JSON Web Token (**JWT**) | A claims set (JSON) carried as a JWS or JWE payload; registered claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) |
| RFC 7638 (2015) | JWK Thumbprint | A stable hash of a public key, often used as `kid` and in DPoP |
| RFC 8037 (2017) | CFRG curves in JOSE | `OKP` key type, `EdDSA` with Ed25519/Ed448, X25519 key agreement |
| RFC 8725 (2020) | **JWT Best Current Practices** (BCP 225) | Algorithm verification, explicit typing, audience and issuer validation, do not trust received claims |
| RFC 9068 (2021) | **JWT Profile for OAuth 2.0 Access Tokens** | `typ: at+jwt`, required claims, validation rules for JWT access tokens |
| RFC 9864 (2025) | Fully-Specified Algorithms for JOSE and COSE | New identifiers such as `Ed25519` and `Ed448`; deprecates polymorphic identifiers like `EdDSA` |
| draft-ietf-oauth-rfc8725bis | JWT BCP update (**Internet-Draft**) | Intended to replace RFC 8725 with updated guidance; not yet an RFC |

### 4.1 JWS serializations

- **Compact serialization**: `header.payload.signature`, one signature, URL-safe. This is what "a JWT" almost always means.
- **JSON serialization**: a JSON object that can carry multiple signatures and an unprotected header. It is used in some document-signing and verifiable-credential contexts, rarely for access tokens.

### 4.2 JWE: when the claims must be secret

A compact JWE has **five** parts:

```text
BASE64URL(protected header) . BASE64URL(encrypted key) . BASE64URL(IV) . BASE64URL(ciphertext) . BASE64URL(authentication tag)
```

A JWE header names two algorithms: `alg` for **key management** (how the content key is protected, for example `RSA-OAEP-256` or `ECDH-ES+A256KW`) and `enc` for **content encryption** (for example `A256GCM`).

Use JWE when a token travels through parties that must not read it (for example an ID token containing personal data delivered through a browser, or a token passed through a third party). A **nested JWT** is signed first and then encrypted (`cty: "JWT"` in the outer header), so the recipient gets both confidentiality and proof of origin.

In practice, most APIs avoid JWE for access tokens: if the client must not read the claims, an **opaque token plus introspection** is simpler. Avoid `RSA1_5` (RSAES-PKCS1-v1_5) key management; RFC 8725 warns about its known padding-oracle weaknesses.

---

## 5. Claims and header parameters

### 5.1 Registered claims (RFC 7519 Section 4.1)

| Claim | Name | Meaning | Validation rule |
|---|---|---|---|
| `iss` | Issuer | Who issued the token (a URL for OAuth/OIDC) | **Exact string match** against the configured issuer |
| `sub` | Subject | Who the token is about (stable, unique within the issuer) | Use `iss` + `sub` together as the user key, never email |
| `aud` | Audience | Who the token is for (string or array) | **Must contain this service's identifier**; reject otherwise |
| `exp` | Expiration time | NumericDate (seconds since epoch) after which the token is invalid | Reject if `now > exp + skew` (skew at most 60 s) |
| `nbf` | Not before | Token is not valid before this time | Reject if `now < nbf - skew` |
| `iat` | Issued at | When the token was issued | Sanity check; reject tokens "from the future"; use for max-age rules |
| `jti` | JWT ID | Unique identifier for this token | Use for denylists and replay detection |

### 5.2 Access-token claims in RFC 9068

RFC 9068 standardizes JWT access tokens so resource servers from different vendors can validate them consistently:

- Header: `typ` **must** be `at+jwt` (the media type `application/at+jwt`). Resource servers must check it, which prevents an ID token or other JWT from being accepted as an access token.
- Required claims: `iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti`.
- Optional: `scope`, `auth_time`, `acr`, `amr`, and authorization attributes such as `groups`, `roles`, `entitlements`.
- Must be signed (unsigned `alg: none` is forbidden); `RS256` support is mandatory for interoperability.

### 5.3 Header parameters (RFC 7515 Section 4.1)

| Parameter | Meaning | Security note |
|---|---|---|
| `alg` | Signing algorithm | **Never let it choose your algorithm.** Check it against an allowlist tied to the key |
| `kid` | Key ID | A hint for selecting a key from **your** pre-configured key set. Treat as untrusted input |
| `typ` | Media type of the whole token (`JWT`, `at+jwt`, `dpop+jwt`, `logout+jwt`, `secevent+jwt`) | Use explicit typing to stop one kind of JWT being accepted as another |
| `cty` | Content type of the payload | `JWT` for nested tokens |
| `jku` | URL of a JWK Set | **Dangerous:** attacker-controlled URL. Ignore it, or match against a strict allowlist |
| `jwk` | Embedded public key | **Dangerous:** the token brings its own key. Never trust it for verification (DPoP proofs are the exception, where the key is then bound to the token) |
| `x5u`, `x5c` | Certificate URL / chain | Same risks as `jku`/`jwk` unless validated against a trusted CA and pinned identity |
| `crit` | Extensions that must be understood | Reject tokens with critical parameters you do not support |

### 5.4 Custom claims

- Keep tokens small: send coarse authorization data (scopes, roles, tenant), not full permission lists. Fine-grained decisions belong in the API ([authorization](13-authorization-rbac-abac-rebac.md)).
- Use collision-resistant names for private claims (`https://example.com/claims/tenant` or a clear prefix) when tokens cross organizations.
- No personal data you would not print in a log. Tokens end up in logs, crash reports and browser tools.

---

## 6. Signing algorithms: HS256, RS256, PS256, ES256, EdDSA

| Algorithm | Type | Key | Signature size | Strengths | Weaknesses | Use when |
|---|---|---|---|---|---|---|
| **HS256** | HMAC with SHA-256 (symmetric MAC) | Shared secret, **at least 256 bits** of randomness (RFC 7518 Section 3.2) | 32 bytes | Fast, simple | Every verifier can also **forge** tokens; secret must be distributed; weak secrets can be brute-forced offline | One service both issues and verifies (for example a monolith signing its own short-lived tokens) |
| **RS256** | RSASSA-PKCS1-v1_5 with SHA-256 | RSA, 2048 bits minimum (3072 for long-lived keys) | 256 bytes at 2048 bits | Universal support; mandatory in RFC 9068 and OIDC | Large tokens and keys; older padding scheme | Default interoperable choice, many verifiers |
| **PS256** | RSASSA-PSS with SHA-256 | RSA, 2048+ bits | 256 bytes at 2048 bits | Modern RSA padding with a security proof | Slightly less library support than RS256 | Regulated ecosystems (FAPI 2.0 allows PS256, ES256 and Ed25519 EdDSA, not RS256) |
| **ES256** | ECDSA with P-256 and SHA-256 | EC P-256 | 64 bytes | Small, fast signing, widely supported | Needs a good random nonce per signature (or deterministic RFC 6979); implementation bugs have been severe (Section 15) | Compact tokens, mobile, high volume |
| **EdDSA** (Ed25519) | Edwards-curve signatures | Ed25519 (RFC 8037) | 64 bytes | Deterministic, fast, hard to misuse | Uneven library support; RFC 9864 adds the fully-specified name `Ed25519` and deprecates the polymorphic `EdDSA` identifier | New systems where every verifier supports it |
| `none` | No signature | — | 0 | — | Anyone can forge | **Never accept** |

### 6.1 How to choose

```mermaid
flowchart TD
    Q1{"Does more than one service verify the token?"}
    Q1 -->|"No, issuer and verifier are the same service"| H["HS256 with a 256-bit random secret from a secret manager"]
    Q1 -->|"Yes"| Q2{"Do all verifiers support Ed25519?"}
    Q2 -->|"Yes"| E["EdDSA (Ed25519)"]
    Q2 -->|"No or unknown"| Q3{"Regulated profile such as FAPI 2.0?"}
    Q3 -->|"Yes"| P["PS256 or ES256"]
    Q3 -->|"No"| R["ES256 for compact tokens, or RS256 for maximum compatibility"]
```

The reason to prefer asymmetric algorithms whenever more than one service verifies: **with HMAC, verification and signing use the same key**. If five microservices verify HS256 tokens, a compromise of any one of them lets an attacker mint tokens accepted by all of them. With RS256/ES256/EdDSA, verifiers only hold public keys; only the issuer can sign.

Post-quantum note: RSA and elliptic-curve signatures are both vulnerable to a large quantum computer. Post-quantum signatures for JOSE are still being standardized. The practical preparation today is **algorithm agility**: allowlists in configuration, `kid`-based key selection and routine rotation, so changing algorithms later is a configuration change ([foundations](00-foundations.md)).

---

## 7. The complete validation checklist

A JWT is only as secure as its verifier. Use a maintained library (Nimbus JOSE + JWT in Spring, `jose4j`, `jjwt`, or your platform's equivalent) and configure it to do all of the following. Do not write your own parser.

| # | Check | Why |
|---|---|---|
| 1 | **Reject oversized input** (for example over 8 KB) before parsing | Avoids parser DoS and huge headers |
| 2 | Token has exactly 3 parts (JWS) and each decodes as Base64URL and valid UTF-8 JSON | Rejects malformed or JWE tokens when you expect JWS |
| 3 | **`alg` is in your allowlist**, and the allowlist is configured per issuer, not read from the token | Stops `alg: none` and algorithm confusion |
| 4 | **Select the key by `kid` from your own trusted key set** (JWKS fetched from the issuer's configured URL); the key's type and `alg` must match the token's `alg` | Stops key confusion and `jku`/`jwk`/`x5u` injection |
| 5 | **Verify the signature** before trusting any claim | Everything else depends on it |
| 6 | **`typ`** matches what this endpoint expects (`at+jwt` for access tokens) | Stops cross-JWT confusion (an ID token used as an access token) |
| 7 | **`iss`** equals the expected issuer exactly | Stops tokens from another issuer or tenant |
| 8 | **`aud`** contains this service's identifier | Stops a token for service A being replayed at service B |
| 9 | **`exp`** is present and in the future (skew at most 60 s) | Bounds the lifetime of a stolen token |
| 10 | **`nbf`** (if present) is not in the future; **`iat`** is not in the future | Rejects tokens not yet valid or minted with a bad clock |
| 11 | Token-specific claims: `client_id` (RFC 9068), `azp` and `nonce` (ID tokens), `cnf` (sender-constrained tokens) | Binds the token to the right client, request or key |
| 12 | Revocation check if your design has one (`jti` denylist, user token version) | Supports logout and incident response |
| 13 | **Authorization**: scopes, roles, tenant, and resource ownership | A valid token proves identity and grants, not permission for this specific object |
| 14 | On failure, return `401` with `WWW-Authenticate: Bearer error="invalid_token"`; log the reason server-side, not the token | Gives clients a standard signal without leaking detail |

A failed request looks like this (RFC 6750 Section 3):

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", error_description="The access token expired"
Content-Length: 0
```

A request with a valid token but insufficient scope gets `403` and `error="insufficient_scope"`.

```mermaid
flowchart TD
    T["Incoming Bearer token"] --> S{"Size and format OK?"}
    S -->|"No"| X["401 invalid_token"]
    S -->|"Yes"| A{"alg in allowlist for this issuer?"}
    A -->|"No"| X
    A -->|"Yes"| K{"kid found in trusted JWKS and key matches alg?"}
    K -->|"No, refresh JWKS once (rate limited)"| K2{"Found after refresh?"}
    K2 -->|"No"| X
    K2 -->|"Yes"| V
    K -->|"Yes"| V{"Signature valid?"}
    V -->|"No"| X
    V -->|"Yes"| C{"typ, iss, aud, exp, nbf, iat valid?"}
    C -->|"No"| X
    C -->|"Yes"| R{"Revoked? (optional jti or version check)"}
    R -->|"Yes"| X
    R -->|"No"| Z{"Scopes and ownership allow this action?"}
    Z -->|"No"| F["403 insufficient_scope or forbidden"]
    Z -->|"Yes"| OK["Process request"]
```

**Mutually exclusive validation rules (RFC 8725 Section 3.12):** if one issuer produces several kinds of JWTs (access tokens, ID tokens, logout tokens), make sure a token valid as one kind can never be valid as another. Different `typ` values, different `aud` values, and different required claims achieve that.

---

## 8. Access tokens, refresh tokens and ID tokens

These three are constantly confused in interviews and in code. They have different audiences, lifetimes and rules.

| | Access token | Refresh token | ID token (OIDC) |
|---|---|---|---|
| Purpose | Authorize calls to an API | Obtain new access tokens without user interaction | Tell the **client** who logged in, when and how |
| Audience | The resource server (`aud` = API identifier) | Only the authorization server | The client (`aud` = `client_id`) |
| Format | JWT (RFC 9068) or opaque | Opaque random value (256 bits), stored hashed | Always a signed JWT |
| Typical lifetime (2026) | 5-15 minutes | Rotated on every use; idle timeout 1-7 days, absolute lifetime 7-30 days | Minutes; consumed once at login |
| Sent to | APIs, in `Authorization: Bearer` | The token endpoint only | Nowhere after validation (optionally as `id_token_hint` at logout) |
| Revocation | Hard if JWT (short TTL, denylist) | Easy (delete or mark the record) | Not applicable; end the client session instead |
| Common mistake | Using it as proof of login in the client | Sending it to APIs, storing it in `localStorage` | Sending it to APIs as an access token |

Two rules to remember:

1. **Never use an OAuth access token as proof of identity in the client.** It was issued for an API, not for you; a token issued to a different client may be replayed at your login endpoint. Use the OIDC ID token, whose `aud` is your `client_id` ([OpenID Connect](10-openid-connect.md)).
2. **Never send an ID token to an API as a bearer token.** Its audience is the client. APIs must check `typ: at+jwt` and `aud` to reject it.

---

## 9. Refresh token rotation with reuse detection

Short access tokens mean frequent refreshes, so the refresh token becomes the long-lived, valuable credential. **Rotation** limits the damage if it leaks: every refresh returns a new refresh token and invalidates the old one. **Reuse detection** turns a leak into an alarm: if an already-used refresh token is presented again, either the legitimate client or an attacker is replaying it, and the server cannot tell which, so it revokes the whole **token family** (every token descended from the same login).

RFC 9700 (OAuth 2.0 Security BCP, January 2025) requires refresh tokens issued to public clients to be either **sender-constrained** (DPoP or mTLS) or **rotated with reuse detection**. Rotating for confidential clients too is cheap defense in depth.

```mermaid
sequenceDiagram
    autonumber
    participant C as Legitimate client
    participant M as Attacker
    participant AS as Authorization server
    participant DB as Token store
    C->>AS: Login completes (authorization code + PKCE)
    AS->>DB: Store hash(RT1), family F, status active
    AS-->>C: AT1 (10 min) + RT1
    Note over M: Attacker steals RT1 (malware, leaked log, backup)
    C->>AS: grant_type=refresh_token with RT1
    AS->>DB: RT1 active? yes. Mark RT1 used, store hash(RT2) in family F
    AS-->>C: AT2 + RT2
    M->>AS: grant_type=refresh_token with RT1
    AS->>DB: RT1 already used, reuse detected
    AS->>DB: Revoke every token in family F (RT2 is now dead)
    AS-->>M: 400 invalid_grant
    AS->>AS: Raise security event, notify user
    C->>AS: grant_type=refresh_token with RT2
    AS-->>C: 400 invalid_grant, user must log in again
```

If the attacker uses the stolen token **first**, the roles swap: the attacker gets RT2, and the legitimate client's next refresh with RT1 triggers detection and kills the attacker's RT2. Either way, the stolen token works for at most one refresh cycle.

### 9.1 The refresh request

```http
POST /oauth2/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic d2ViLWJmZjpzZWNyZXQtZnJvbS12YXVsdA==

grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA.Qm9Fv8m1xK2s
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMjYtMTAtcnMyNTYtYSIsInR5cCI6ImF0K2p3dCJ9...",
  "token_type": "Bearer",
  "expires_in": 600,
  "refresh_token": "8xLOxBtZp8.Wq3nC0vJ2kRr9sTq",
  "scope": "orders:read orders:write"
}
```

On reuse or expiry:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "invalid_grant",
  "error_description": "The refresh token is invalid"
}
```

Do not tell the caller *why* (reuse vs expiry); log the reason server-side.

### 9.2 Storage model

```sql
CREATE TABLE refresh_token (
    id            UUID PRIMARY KEY,
    family_id     UUID        NOT NULL,      -- one family per login
    user_id       UUID        NOT NULL,
    client_id     VARCHAR(100) NOT NULL,
    token_hash    CHAR(64)    NOT NULL UNIQUE, -- SHA-256 hex of the token, never the token itself
    parent_id     UUID,                       -- the token this one replaced
    issued_at     TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,       -- absolute lifetime of the family
    used_at       TIMESTAMPTZ,                -- set when rotated
    revoked_at    TIMESTAMPTZ,
    revoke_reason VARCHAR(50)
);
CREATE INDEX refresh_token_family ON refresh_token (family_id);
```

A fast hash (SHA-256) is correct here, unlike passwords: a refresh token is 256 random bits, so there is nothing to brute-force ([passwords chapter](02-passwords-and-credential-storage.md)). Storing only the hash means a database leak does not yield usable tokens.

### 9.3 Rotation logic

```java
@Transactional
public TokenPair refresh(String presentedToken, String clientId) {
    String hash = sha256Hex(presentedToken);
    RefreshToken current = repository.findByTokenHashForUpdate(hash)   // SELECT ... FOR UPDATE
            .orElseThrow(InvalidGrantException::new);

    if (!current.clientId().equals(clientId)) {
        throw new InvalidGrantException();                // bound to the client it was issued to
    }
    if (current.usedAt() != null || current.revokedAt() != null) {
        repository.revokeFamily(current.familyId(), "reuse_detected");
        securityEvents.refreshTokenReuse(current.userId(), current.familyId());
        throw new InvalidGrantException();
    }
    if (clock.instant().isAfter(current.expiresAt())) {
        throw new InvalidGrantException();
    }

    repository.markUsed(current.id(), clock.instant());
    String next = randomToken256();                       // SecureRandom, Base64URL
    repository.save(current.successor(sha256Hex(next), clock.instant()));
    String accessToken = accessTokenService.issue(current.userId(), clientId);
    return new TokenPair(accessToken, next);
}
```

The row lock (`FOR UPDATE`) makes two concurrent refreshes with the same token behave deterministically: one wins, the other is treated as reuse.

### 9.4 Practical issues

- **Concurrent refreshes from the same app** (two browser tabs, parallel mobile requests) look like reuse. Fix it on the client: a single refresh in flight, shared by all callers. Some identity providers offer a short, configurable grace window in which the previous token still returns the same successor; if you use one, keep it to seconds and log every use.
- **Lost responses** (network drop after the server rotated) force a re-login. That is the price of rotation; sender-constrained refresh tokens (DPoP) avoid it.
- **Idle and absolute limits**: expire a family after 1-7 days of no use and 7-30 days total, then require a full login (with MFA if applicable).
- **Revoke families** on logout, password change or reset, MFA reset, and account disable ([passwords chapter](02-passwords-and-credential-storage.md)).

The runnable implementation is in [../examples/02-jwt-auth/](../examples/02-jwt-auth/).

---

## 10. Revocation strategies

A self-contained token cannot be "deleted": every verifier holding the public key will accept it until `exp`. Choose a strategy that matches the risk.

| Strategy | How it works | Revocation latency | Cost | Use when |
|---|---|---|---|---|
| **Short TTL** + revocable refresh tokens | Access tokens live 5-15 min; revoke the refresh token family | Up to one access-token lifetime | None per request | Default for every system |
| **Denylist by `jti`** | Store revoked `jti` values in Redis with a TTL equal to the token's remaining lifetime; check on each request | Seconds (cache propagation) | One fast lookup per request; the list stays small because entries expire | Logout of a specific token, a known stolen token, high-value APIs |
| **Token versioning** (`revoked-before` timestamp) | Store `tokens_valid_after` per user (or per session); reject tokens with `iat` earlier than that, or embed a `ver` claim and compare | Seconds | One cacheable lookup per user | "Log out everywhere", password change, account disable |
| **Introspection** (RFC 7662) | Resource server asks the authorization server whether the token is active | Immediate, or the introspection cache TTL (30-60 s) | Network call per request or per cache miss | Opaque tokens, high-risk operations, tokens from external clients |
| **Revocation endpoint** (RFC 7009) | Client tells the authorization server to revoke a token (usually the refresh token) at logout | Immediate for refresh tokens; access tokens still need one of the strategies above | One call at logout | Every client on logout |
| **Remove the signing key** | Delete the key from the JWKS | After verifier caches refresh | Every token signed with that key dies | Key compromise only |

### 10.1 Revocation request (RFC 7009)

```http
POST /oauth2/revoke HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic d2ViLWJmZjpzZWNyZXQtZnJvbS12YXVsdA==

token=8xLOxBtZp8.Wq3nC0vJ2kRr9sTq&token_type_hint=refresh_token
```

```http
HTTP/1.1 200 OK
Content-Length: 0
```

The server responds `200` even for an unknown token, so the endpoint cannot be used to probe for valid tokens.

### 10.2 Introspection request (RFC 7662)

```http
POST /oauth2/introspect HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Accept: application/json
Authorization: Basic b3JkZXJzLWFwaTpyZXNvdXJjZS1zZXJ2ZXItc2VjcmV0

token=mF_9.B5f-4.1JqM
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "active": true,
  "client_id": "web-bff",
  "sub": "user_8f14e45f",
  "aud": "https://api.example.com",
  "iss": "https://auth.example.com",
  "scope": "orders:read",
  "token_type": "Bearer",
  "iat": 1791450000,
  "exp": 1791450600
}
```

An inactive, expired or unknown token returns only `{"active": false}`. The introspection endpoint must authenticate the caller (resource servers are clients of it). RFC 9701 (2025) defines a signed JWT response format for introspection when the result itself must be verifiable.

---

## 11. Where to store tokens in browsers

This is the most argued-about question in web authentication. The core facts:

- **XSS can always act as the user** while the page is open, wherever the token lives. What storage controls is whether XSS can **steal** the token and use it **elsewhere, later**.
- **Cookies are sent automatically**, which makes them immune to JavaScript theft (with `HttpOnly`) but exposed to CSRF ([chapter 04](04-sessions-cookies-and-csrf.md)).

| Location | Readable by injected JavaScript | Sent automatically (CSRF risk) | Survives reload | Verdict |
|---|---|---|---|---|
| `localStorage` | **Yes**, by any script on the origin, including compromised third-party scripts | No | Yes, across tabs and restarts | **Do not store tokens here** |
| `sessionStorage` | **Yes** | No | Per tab | Same problem, slightly shorter exposure |
| JavaScript memory (closure, private field) | Harder to read directly, but XSS can hook `fetch` or call the API as the user | No | No; needs a refresh mechanism after reload | Acceptable only for low-risk apps with short-lived tokens and no long-lived refresh token in the browser |
| Web worker or service worker holding tokens | Isolated from the page, but XSS can still send requests through it | No | Varies | Better than `localStorage`, complex, still exposes the API |
| `HttpOnly; Secure; SameSite` cookie containing the token | No | Yes, needs CSRF protection | Yes | Workable for a same-site API; cookie size limit (about 4 KB) constrains JWT size |
| **BFF**: tokens on the server, browser holds an opaque session cookie | **No token in the browser at all** | Yes, needs CSRF protection | Yes | **Recommended** |

### 11.1 The Backend-for-Frontend (BFF) pattern

RFC 10017, *OAuth 2.0 for Browser-Based Applications* (Best Current Practice, August 2026), compares three architectures: the **BFF**, the **token-mediating backend** (the backend obtains tokens but hands the access token to the browser), and the **browser-only client**. They are listed in decreasing order of security, and the BFF is the one that keeps tokens out of the browser entirely.

```mermaid
flowchart LR
    B["Browser (SPA)"] -->|"__Host-session cookie, HttpOnly, Secure, SameSite=Lax + CSRF token"| BFF["BFF (confidential OAuth client)"]
    BFF -->|"Authorization code + PKCE, refresh with rotation"| AS["Authorization server"]
    BFF -->|"Authorization: Bearer access token"| API["Resource server API"]
    BFF --- ST[("Server-side token store, encrypted")]
```

How it works:

1. The SPA navigates to the BFF's login endpoint. The BFF runs the authorization code flow with PKCE as a **confidential client**.
2. The BFF stores the access, refresh and ID tokens server-side (session store, encrypted at rest) and sets an opaque `__Host-` session cookie: `HttpOnly`, `Secure`, `SameSite=Lax` or `Strict`.
3. The SPA calls the BFF (same site). The BFF attaches the access token and forwards the request to the API, refreshing tokens as needed.
4. State-changing requests carry a CSRF token or a custom header the BFF checks.

The benefits: no token for XSS to exfiltrate, refresh tokens held by a confidential client, and a real server-side logout. The cost: a stateful backend component. In Spring, this is `oauth2Login()` plus a gateway or proxy ([OpenID Connect](10-openid-connect.md), [../examples/03-oauth2-oidc/](../examples/03-oauth2-oidc/), [production architecture](14-production-architecture-and-checklist.md)).

---

## 12. Key management: kid, JWKS, caching and rotation

### 12.1 Publishing keys: the JWKS endpoint

The issuer publishes its **public** keys as a JWK Set. Verifiers find the URL through configuration or discovery (`jwks_uri` in `/.well-known/openid-configuration` or `/.well-known/oauth-authorization-server`, RFC 8414).

```http
GET /oauth2/jwks HTTP/1.1
Host: auth.example.com
Accept: application/json
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=3600

{
  "keys": [
    {
      "kty": "RSA",
      "kid": "2026-10-rs256-a",
      "use": "sig",
      "alg": "RS256",
      "e": "AQAB",
      "n": "200lRcRTTz98fkAwqaDD-wH_Y2rg1oNWCrJMmRtOni2tkpwBde-5ITFzEX_5bYEi9M1SjFKxJPBqmJOgC4oMO6GZJl5a15P1Ig9gcKFcK5rMfipsZFkaB0a1sknDU0Wt00X8rt1FfZF2DqAnTSTAm2Ht9aA_ZSVGP5t9N03hCluFlsoRH2sBzRKW-DooYf7GFaRHPm37-zOH8sDWIMB_QwYMjUm9sFyLBwaxpntHWaFiXQqqg5LR8eJ4sTDMAXOR1GWVqn7yl2KkGq7pR3uOwio-Dwm5cN6T02pMOFJENzaOFULismC14lR3cM5JHfUuZ9vsZmm7g0g8U_RgkKJSXQ"
    },
    {
      "kty": "EC",
      "kid": "2026-10-es256-a",
      "use": "sig",
      "alg": "ES256",
      "crv": "P-256",
      "x": "AYdF7bfyNIhaHKrqWVssbtAr5H11vtQmVO1D0bO-OtE",
      "y": "o2vb6HN95aXasz3rIhC8xM_K9-hbpf0JGp8Py9Lq6GM"
    }
  ]
}
```

The JWKS contains **only public keys**. Publishing `d`, `p`, `q` (RSA private parts) or the `d` of an EC key would be a catastrophic leak; test for it.

### 12.2 Verifier caching rules

- Cache the JWKS (honor `Cache-Control`; 5 minutes to 24 hours is typical).
- On an **unknown `kid`**, refetch once, then fail. **Rate-limit** refetches (for example at most once per 30-60 seconds) so an attacker spraying random `kid` values cannot turn your API into a DoS amplifier against the issuer.
- On fetch failure, keep using the cached keys rather than failing every request.
- The JWKS URL comes from **your configuration** (or the configured issuer's discovery document), never from the token's `jku` or `x5u`.

### 12.3 Rotation without downtime

```mermaid
sequenceDiagram
    autonumber
    participant KMS as Key store (KMS or HSM)
    participant AS as Authorization server
    participant J as JWKS endpoint
    participant RS as Resource servers
    AS->>KMS: Generate key K2
    AS->>J: Publish K1 and K2, still signing with K1
    Note over J,RS: Wait at least one JWKS cache lifetime so every verifier has K2
    AS->>AS: Start signing new tokens with K2 (kid K2)
    Note over AS,RS: Tokens signed with K1 remain valid until they expire
    Note over J,RS: Wait the longest token lifetime plus clock skew
    AS->>J: Remove K1 from the JWKS
    AS->>KMS: Destroy or archive K1
```

- **Scheduled rotation**: for example every 90 days. It keeps the process exercised so an emergency rotation is routine.
- **Emergency rotation** (key compromise): remove the compromised key from the JWKS immediately and accept that tokens signed with it will fail; clients will refresh or re-login. Verifiers pick up the change on their next fetch or unknown-`kid` refetch.
- **Private keys** live in a KMS or HSM, or at minimum a secret manager. Never in the repository, container image or plain environment files.
- **`kid` values** are opaque identifiers. A JWK thumbprint (RFC 7638) or a date-based name both work. Spring's `NimbusJwtEncoder` builders default to the thumbprint.

---

## 13. Sender-constrained tokens and token sidejacking

**Token sidejacking** means stealing a bearer token (from a log, a proxy, a compromised device, browser storage) and replaying it from the attacker's machine. Bearer tokens have no defense against it except lifetime and audience.

**Sender-constrained** (proof-of-possession) tokens fix this by binding the token to a key the client holds:

| Mechanism | How the binding works | Where it fits |
|---|---|---|
| **mTLS** (RFC 8705) | The token carries `cnf.x5t#S256`, the hash of the client's TLS certificate; the API checks it matches the certificate on the connection | Service-to-service, banking (FAPI), anywhere you control client certificates |
| **DPoP** (RFC 9449, 2023) | The client signs a fresh, short-lived proof JWT (`typ: dpop+jwt`) per request with its private key; the token carries `cnf.jkt`, the thumbprint of that key | Public clients (SPAs, mobile), APIs where mTLS is impractical |

A stolen DPoP-bound token is useless without the private key, which the client keeps non-extractable (for example a WebCrypto key or a key in the device keystore). DPoP requests use `Authorization: DPoP <token>` plus a `DPoP: <proof>` header. Details and raw requests are in [modern OAuth](09-modern-oauth-2.1-and-extensions.md).

If you cannot use DPoP or mTLS, the OWASP JWT cheat sheet describes a **fingerprint** mitigation: put a random value in a hardened cookie (`HttpOnly; Secure; SameSite=Strict`, with a `__Secure-` or `__Host-` name prefix) and its SHA-256 hash in the token; the API requires both to match. It only helps when the token and cookie travel separately, and it is weaker than real proof-of-possession. The BFF pattern is usually the simpler answer for browsers.

---

## 14. Production best practices (2026)

**Format and algorithms**

- Asymmetric signatures whenever more than one service verifies: **ES256** or **RS256** (RSA 2048 bits minimum, 3072 for keys expected to be in use after 2030), **PS256** for FAPI-style profiles, **EdDSA (Ed25519)** where every verifier supports it.
- HS256 only when the issuer is the only verifier, with a **256-bit random key** from a CSPRNG, stored in a secret manager. Never a human-chosen string.
- **Allowlist algorithms per issuer** in configuration. Never accept `none`.
- Use **explicit typing**: `typ: at+jwt` for access tokens (RFC 9068), and validate it.

**Lifetimes**

| Token | Lifetime |
|---|---|
| Access token | 5-15 minutes (10 is a common default) |
| ID token | 5-10 minutes; validated once at login |
| Refresh token | Rotated on every use; idle 1-7 days, absolute 7-30 days; shorter for privileged users |
| Clock skew tolerance | At most 60 seconds (Spring's default is 60 s) |
| JWKS cache | 5 minutes to 24 hours, refetch on unknown `kid` (rate-limited) |
| Signing key rotation | Scheduled (for example every 90 days) and immediately on suspicion |

**Validation**

- Always validate signature, `iss`, `aud`, `exp`, `nbf`, and `typ`. Libraries often skip `aud` unless you configure it.
- Use one validator configuration per issuer and per token type, with mutually exclusive rules.
- Map scopes and roles to authorities, then **still** check object-level ownership in the API.

**Storage and transport**

- Browsers: **BFF** or server-side sessions; no tokens in `localStorage` or `sessionStorage` ([chapter 04](04-sessions-cookies-and-csrf.md)).
- Mobile: tokens in the Keychain or Android Keystore-backed storage; refresh tokens bound to the device where possible (DPoP).
- Send tokens only in the `Authorization` header over TLS. **Never in URLs** (they leak into logs, browser history and `Referer` headers).
- Token responses carry `Cache-Control: no-store`.
- Never log full tokens. Log `jti`, `sub`, `client_id` and the validation result.

**Size**

- Keep access tokens well under 1-2 KB. Many servers limit total request header size (Tomcat and Spring Boot default to 8 KB), and cookies are limited to about 4 KB each.

**Refresh and revocation**

- Refresh tokens: opaque, 256-bit, stored as SHA-256 hashes, rotated with family-wide reuse detection, bound to the client, revoked on logout and credential changes.
- Add a `jti` denylist or per-user token version for APIs that need immediate revocation.
- Sender-constrain tokens (DPoP or mTLS) for high-value APIs and public clients with refresh tokens.

**Keys**

- Private keys in a KMS or HSM; JWKS exposes public keys only; pre-publish new keys before signing with them; automate rotation; alert on signing-key access anomalies.

---

## 15. Common attacks and mistakes

| Attack / mistake | What goes wrong | Mitigation |
|---|---|---|
| **`alg: none`** | Library honors the header and skips signature verification; attacker forges any claims | Algorithm allowlist; reject `none` always; use a library that requires an expected algorithm |
| **Algorithm confusion (RS256 to HS256)** | Verifier is configured with an RSA public key but trusts the token's `alg`; attacker signs an HS256 token using the **public key bytes** as the HMAC secret, and the library verifies it with the same bytes | Bind each key to one algorithm; select the algorithm from configuration, never from the header; use typed key objects (an RSA key cannot be used for HMAC) |
| **`kid` injection** | `kid` used unsafely: in a file path (`../../dev/null` gives an empty, predictable key), in SQL (`' UNION SELECT 'known-secret' --`), or in a shell command | Treat `kid` as an opaque lookup key into an in-memory map of trusted keys; no file, SQL or command use |
| **`jku` / `x5u` injection** | Verifier downloads keys from the URL in the token header, so the attacker hosts their own JWKS and signs with their own key; also an SSRF vector | Ignore `jku`/`x5u`; fetch keys only from the configured issuer's JWKS URL (or a strict exact-match allowlist) |
| **Embedded `jwk` / `x5c` trust** | Library verifies with the key embedded in the token itself (for example CVE-2018-0114 in node-jose) | Never verify with a key supplied by the token, except DPoP proofs where the key is then checked against the token's `cnf.jkt` |
| **Weak HMAC secret** | `secret`, `changeme` or a short password; an attacker with one token brute-forces it offline (hashcat supports JWT cracking) and then mints tokens | 256-bit random key from a CSPRNG; store in a secret manager; prefer asymmetric keys |
| **Missing `aud` check** | A token issued for API A (or for another client) is accepted by API B from the same issuer | Configure and enforce the expected audience on every resource server; use distinct audiences per API |
| **Missing `exp` check or very long lifetimes** | A stolen token works for days or forever | Require `exp`; 5-15 minute access tokens; refresh with rotation |
| **Missing `iss` check** | Tokens from another tenant or issuer that shares infrastructure are accepted | Exact-match the issuer; one validator per issuer |
| **Cross-JWT confusion** | An ID token, logout token or token for another purpose is accepted as an access token | Explicit `typ` (`at+jwt`), distinct audiences, mutually exclusive validation rules (RFC 8725) |
| **ECDSA verification bugs** | "Psychic signatures" (CVE-2022-21449): Java 15-18 accepted an ECDSA signature of all zeros, letting anyone forge ES256 tokens | Patch the JDK promptly; use maintained libraries; include negative test vectors (for example Project Wycheproof) |
| **Token sidejacking** | Stolen bearer token replayed from the attacker's machine | Short TTL; sender-constrained tokens (DPoP or mTLS); BFF for browsers |
| **Tokens in `localStorage`** | Any XSS or compromised third-party script exfiltrates long-lived tokens | BFF or `HttpOnly` cookies; strict CSP; no refresh tokens in the browser |
| **Decoding without verifying** | Code calls a `decode()` helper (no signature check) and uses the claims for decisions | Only use claims returned by the verifying API; code review rule and lint |
| **Sensitive data in the payload** | Personal data or internal details readable by anyone with the token, and copied into logs | Minimal claims; opaque tokens or JWE if claims must be secret |
| **Tokens in URLs** | Leaked via server logs, browser history, `Referer`, analytics | `Authorization` header only; the implicit grant is deprecated for this reason |
| **No rotation path for keys** | A leaked key cannot be replaced without an outage | `kid` + JWKS, pre-publication, automated rotation drills |
| **Unbounded JWKS refetch on unknown `kid`** | Attacker sprays random `kid` values and the API hammers the issuer | Rate-limit refetches; cache negative results briefly |
| **Large clock skew allowance** | Expired tokens stay usable for minutes or hours | At most 60 s skew; NTP on all hosts |

### 15.1 What the classic attacks look like

**`alg: none`.** The attacker writes their own header and payload and leaves the signature empty:

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImF1ZCI6Imh0dHBzOi8vYXBpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzkxNDUwNjAwfQ.
```

Header: `{"alg":"none","typ":"JWT"}`. Payload: `{"sub":"admin","aud":"https://api.example.com","exp":1791450600}`. A library that honors `alg` from the token accepts it as "validly unsigned". This affected several libraries when it was publicized in 2015.

**Algorithm confusion.** The vulnerable pattern is a generic "verify with this key" call where the library picks the algorithm from the header:

```java
// VULNERABLE pseudo-code: the token decides how the key is used
Claims claims = verify(token, publicKeyPemBytes);   // header says HS256, so HMAC(publicKeyPemBytes)
```

The public key is public, so the attacker computes `HMAC-SHA256(publicKeyPemBytes, signingInput)` and the verifier agrees. The fix is structural: the verifier decides the algorithm per key. In Spring, `NimbusJwtDecoder` builds a key selector from the configured algorithm set, so an HS256 token never reaches an RSA key.

---

## 16. PASETO and other alternatives

JWT's flexibility (many algorithms, a header that names them) is the source of most of its attacks. Alternatives remove the choice:

- **PASETO** (Platform-Agnostic Security Tokens), created by Scott Arciszewski at Paragon Initiative Enterprises in 2018. Each **version** fixes the cryptography, so there is no `alg` header to tamper with. Current versions are **v4** (modern: Ed25519 signatures; XChaCha20 with BLAKE2b for encryption) and **v3** (NIST-friendly: P-384 ECDSA; AES-256-CTR with HMAC-SHA384); v1 and v2 are deprecated. Each version has two **purposes**: `local` (symmetric authenticated encryption, claims hidden) and `public` (signatures, claims readable). A token looks like `v4.public.<payload>.<optional footer>`. PASETO is **not an IETF standard** (its Internet-Draft expired), and OAuth and OIDC are built on JWT, so it fits best inside a system you control end to end.
- **Macaroons** (Google research, 2014) and **Biscuit**: tokens that the holder can **attenuate** (add restrictions) offline before passing them on. Useful for delegation chains; niche in mainstream web stacks.
- **Opaque tokens with introspection**: still the simplest secure choice when you do not need local verification.

For standards-based OAuth and OIDC, use JWT, follow RFC 8725 and RFC 9068, and let a well-configured library enforce the rules.

---

## 17. Spring Boot 4 / Spring Security 7

Stack: Java 21, Spring Boot 4.1.1, Spring Security 7.1.1, lambda DSL. The runnable version, with a JWKS endpoint and rotating refresh tokens, is in [../examples/02-jwt-auth/](../examples/02-jwt-auth/).

Dependency: `org.springframework.boot:spring-boot-starter-security-oauth2-resource-server`. Boot 4 renamed the security starters; the old `spring-boot-starter-oauth2-resource-server` name still resolves but is deprecated.

### 17.1 Resource server: validate JWT access tokens

```java
@Configuration
@EnableWebSecurity
class ResourceServerSecurityConfig {

    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/api/orders/**").hasAuthority("SCOPE_orders:read")
                .requestMatchers(HttpMethod.POST, "/api/orders/**").hasAuthority("SCOPE_orders:write")
                .anyRequest().authenticated())
            .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // Safe only because this API authenticates with the Authorization header, never cookies.
            .csrf(csrf -> csrf.disable());
        return http.build();
    }

    @Bean
    JwtDecoder jwtDecoder(@Value("${app.security.jwt.issuer}") String issuer,
                          @Value("${app.security.jwt.jwk-set-uri}") String jwkSetUri,
                          @Value("${app.security.jwt.audience}") String audience) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
                .jwsAlgorithm(SignatureAlgorithm.RS256)   // the allowlist: nothing else is accepted
                .jwsAlgorithm(SignatureAlgorithm.ES256)
                .build();
        // RFC 9068 profile: typ at+jwt, iss, aud, exp, iat, sub, jti, client_id
        decoder.setJwtValidator(JwtValidators.createAtJwtValidator()
                .issuer(issuer)
                .audience(audience)
                .build());
        return decoder;
    }
}
```

What this gives you:

- `jwsAlgorithm(...)` builds Nimbus's key selector from **your** algorithm set, so `none`, HS256 confusion and unexpected algorithms are rejected before any claim is read.
- Keys come only from the configured JWKS URL. Spring caches the key set in memory for 5 minutes by default (adjustable with `.cache(...)`), and the underlying Nimbus key source reloads it when a token arrives with a `kid` it does not know. Spring turns off Nimbus's own refetch rate limiter for this source, so if unknown-`kid` spraying is a concern, rate-limit at the gateway or in the `RestOperations` you pass in. Header `jku`, `x5u` and `jwk` values are never used to find verification keys.
- `JwtValidators.createAtJwtValidator()` (since 6.5) enforces RFC 9068: `typ` must be `at+jwt`, required claims must be present, `iss` and `aud` must match, and timestamps are checked with a 60-second default skew.
- If your tokens do not follow RFC 9068, use `JwtValidators.createDefaultWithValidators(new JwtIssuerValidator(issuer), new JwtAudienceValidator(audience))`. In Spring Security 7, the default validators also require `typ` to be `JWT` or absent, so they **reject** `at+jwt` tokens; use the RFC 9068 validator for those.
- The default authentication converter maps the `scope` (or `scp`) claim to `SCOPE_` authorities; customize it with `rs.jwt(jwt -> jwt.jwtAuthenticationConverter(...))` for roles.
- Spring Security's `SignatureAlgorithm` enum covers the RS, PS and ES families; EdDSA needs a custom Nimbus processor via `jwtProcessorCustomizer(...)`.

The minimal property-based alternative, if you prefer Boot auto-configuration:

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://auth.example.com
          audiences: https://api.example.com
          jws-algorithms: RS256, ES256
```

### 17.2 Issuing tokens: NimbusJwtEncoder with kid and at+jwt

In a full OAuth setup, Spring Authorization Server (now part of Spring Security 7) issues tokens for you ([OAuth 2](08-oauth-2.md), [../examples/03-oauth2-oidc/](../examples/03-oauth2-oidc/)). When a service issues its own access tokens, as in [../examples/02-jwt-auth/](../examples/02-jwt-auth/):

```java
@Configuration
class TokenIssuerConfig {

    // SigningKeyStore is an application interface (see the example project): it returns the
    // Nimbus JWKs to publish and verify with, and the kid of the key currently used for signing.
    @Bean
    JWKSource<SecurityContext> jwkSource(SigningKeyStore keys) {
        // Current key plus any keys still published for verification during rotation.
        // Private keys are loaded from a KMS, HSM or secret manager, never from the repository.
        return new ImmutableJWKSet<>(new JWKSet(keys.allSigningKeys()));
    }

    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }
}

@Service
class AccessTokenService {

    private final JwtEncoder encoder;
    private final SigningKeyStore keys;
    private final Clock clock;

    AccessTokenService(JwtEncoder encoder, SigningKeyStore keys, Clock clock) {
        this.encoder = encoder;
        this.keys = keys;
        this.clock = clock;
    }

    String issue(String userId, String clientId, Set<String> scopes) {
        Instant now = clock.instant();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(keys.activeKeyId())   // selects the signing key and tells verifiers which public key to use
                .type("at+jwt")              // RFC 9068 explicit typing
                .build();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("https://auth.example.com")
                .subject(userId)
                .audience(List.of("https://api.example.com"))
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(now.plus(Duration.ofMinutes(10)))
                .id(UUID.randomUUID().toString())
                .claim("client_id", clientId)
                .claim("scope", String.join(" ", scopes))
                .build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
```

`NimbusJwtEncoder` selects the JWK whose `kid` and algorithm match the header, so rotation is a matter of adding the new key to the set, switching `activeKeyId()`, and later removing the old key. For a single key, the shortcut `NimbusJwtEncoder.withKeyPair(rsaPublicKey, rsaPrivateKey).build()` sets `kid` to the key's RFC 7638 thumbprint.

### 17.3 Publishing the JWKS

```java
@RestController
class JwksController {

    private final SigningKeyStore keys;

    JwksController(SigningKeyStore keys) {
        this.keys = keys;
    }

    @GetMapping(value = "/oauth2/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<Map<String, Object>> jwks() {
        // toPublicJWKSet() strips private parameters: never publish private key material.
        JWKSet publicSet = new JWKSet(keys.allSigningKeys()).toPublicJWKSet();
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofHours(1)).cachePublic())
                .body(publicSet.toJSONObject());
    }
}
```

Remember to permit `/oauth2/jwks` without authentication in the issuer's filter chain.

---

## Interview questions

**1. What is the difference between an opaque token and a JWT?**
An opaque token is a random reference the issuer must look up (introspection), so revocation is instant but every check needs a call. A JWT carries signed claims that any service can verify locally with the issuer's public key, which scales well but makes revocation hard until `exp`.

**2. Is a JWT encrypted?**
No. A signed JWT (JWS) is only Base64URL-encoded; anyone holding it can read the claims. Signing gives integrity and authenticity. For confidentiality, use JWE (five-part, encrypted) or an opaque token.

**3. When would you use HS256 vs RS256 or ES256?**
HS256 only when the same service issues and verifies, with a 256-bit random secret, because every holder of an HMAC key can also forge tokens. When more than one service verifies, use asymmetric signatures (RS256 for compatibility, ES256 for compact tokens, EdDSA where supported) so verifiers hold only public keys.

**4. Explain the `alg: none` and algorithm-confusion attacks.**
Both exploit verifiers that let the token header choose the algorithm. With `none`, the library skips verification. With confusion, a verifier configured with an RSA public key accepts an HS256 token whose HMAC was computed with the public key bytes. The fix is an algorithm allowlist bound to each key, chosen by configuration, never by the token.

**5. List the checks a resource server must perform on a JWT access token.**
Size and format, `alg` in the allowlist, key selected by `kid` from the trusted JWKS, signature, `typ` (`at+jwt`), `iss` exact match, `aud` contains this API, `exp` and `nbf` with at most 60 s skew, then scopes and object-level authorization. Optionally a revocation check.

**6. How do you revoke a JWT before it expires?**
You cannot delete it, so you limit and check: short lifetimes (5-15 min) plus revocable refresh tokens, a `jti` denylist with TTL equal to the remaining lifetime, a per-user "tokens valid after" timestamp for "log out everywhere", or introspection for high-risk calls. Removing the signing key revokes everything and is reserved for key compromise.

**7. How does refresh token rotation with reuse detection work?**
Each refresh returns a new refresh token and marks the old one used. If a used token is presented again, the server knows two parties hold copies, cannot tell which is legitimate, and revokes the entire token family, forcing re-login. Tokens are stored hashed and the check runs under a row lock.

**8. Where should a browser app store tokens?**
Preferably nowhere: use a BFF that keeps tokens server-side and gives the browser an `HttpOnly; Secure; SameSite` session cookie with CSRF protection (RFC 10017). Never `localStorage` or `sessionStorage`, since any XSS can exfiltrate them. In-memory storage is a fallback for low-risk apps with short-lived tokens.

**9. Why should an API reject an ID token sent as a bearer token?**
The ID token's audience is the client, not the API, and it proves a login event, not an authorization grant. Accepting it enables cross-JWT confusion. APIs check `typ: at+jwt` and their own `aud` to reject it.

**10. How do you rotate signing keys without breaking clients?**
Publish the new key in the JWKS first, wait at least one verifier cache lifetime, start signing with the new `kid`, keep the old public key published until the longest-lived token signed with it expires, then remove it. Verifiers cache the JWKS and refetch (rate-limited) on an unknown `kid`.

---

## References

- RFC 7515 — JSON Web Signature (JWS): https://www.rfc-editor.org/rfc/rfc7515
- RFC 7516 — JSON Web Encryption (JWE): https://www.rfc-editor.org/rfc/rfc7516
- RFC 7517 — JSON Web Key (JWK): https://www.rfc-editor.org/rfc/rfc7517
- RFC 7518 — JSON Web Algorithms (JWA): https://www.rfc-editor.org/rfc/rfc7518
- RFC 7519 — JSON Web Token (JWT): https://www.rfc-editor.org/rfc/rfc7519
- RFC 7638 — JSON Web Key (JWK) Thumbprint: https://www.rfc-editor.org/rfc/rfc7638
- RFC 8037 — CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE (EdDSA): https://www.rfc-editor.org/rfc/rfc8037
- RFC 8725 — JSON Web Token Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725
- draft-ietf-oauth-rfc8725bis — JWT Best Current Practices update (Internet-Draft): https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc8725bis/
- RFC 9068 — JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens: https://www.rfc-editor.org/rfc/rfc9068
- RFC 9864 — Fully-Specified Algorithms for JOSE and COSE: https://www.rfc-editor.org/rfc/rfc9864
- RFC 4648 — The Base16, Base32, and Base64 Data Encodings (Base64URL, Section 5): https://www.rfc-editor.org/rfc/rfc4648
- RFC 6749 — The OAuth 2.0 Authorization Framework: https://www.rfc-editor.org/rfc/rfc6749
- RFC 6750 — OAuth 2.0 Bearer Token Usage: https://www.rfc-editor.org/rfc/rfc6750
- RFC 7009 — OAuth 2.0 Token Revocation: https://www.rfc-editor.org/rfc/rfc7009
- RFC 7662 — OAuth 2.0 Token Introspection: https://www.rfc-editor.org/rfc/rfc7662
- RFC 9701 — JSON Web Token (JWT) Response for OAuth Token Introspection: https://www.rfc-editor.org/rfc/rfc9701
- RFC 8414 — OAuth 2.0 Authorization Server Metadata: https://www.rfc-editor.org/rfc/rfc8414
- RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens: https://www.rfc-editor.org/rfc/rfc8705
- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP): https://www.rfc-editor.org/rfc/rfc9449
- RFC 9700 — Best Current Practice for OAuth 2.0 Security: https://www.rfc-editor.org/rfc/rfc9700
- RFC 10017 — OAuth 2.0 for Browser-Based Applications: https://www.rfc-editor.org/rfc/rfc10017
- OpenID Connect Core 1.0 (ID Token): https://openid.net/specs/openid-connect-core-1_0.html
- FAPI 2.0 Security Profile: https://openid.net/specs/fapi-security-profile-2_0-final.html
- OWASP JSON Web Token for Java Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- OWASP HTML5 Security Cheat Sheet (local storage): https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
- NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management: https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- CVE-2022-21449 — Java ECDSA signature verification ("psychic signatures"): https://nvd.nist.gov/vuln/detail/CVE-2022-21449
- CVE-2018-0114 — node-jose embedded JWK verification bypass: https://nvd.nist.gov/vuln/detail/CVE-2018-0114
- PASETO specification: https://github.com/paseto-standard/paseto-spec
- Spring Security reference — OAuth 2.0 Resource Server JWT: https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html
- Spring Security reference — Spring Authorization Server: https://docs.spring.io/spring-security/reference/servlet/oauth2/authorization-server/index.html
