# 03 — HTTP Authentication: Basic, Digest, Bearer, API Keys and HMAC Signing

HTTP has a small, built-in framework for authentication: the server sends a challenge, the client sends credentials in a header. Every scheme in this chapter, from 1996's Basic to today's Bearer tokens and signed requests, plugs into that same framework. This chapter explains the framework, the classic schemes and why they faded, and then how to design the two credentials most backend teams still build by hand in 2026: **API keys** and **HMAC-signed requests and webhooks**.

> **Where this fits in the evolution**
>
> - **Before:** Early web servers protected directories with Basic auth (HTTP/1.0, RFC 1945, 1996). The password was sent with every request, only base64-encoded.
> - **What it solved:** A standard way, built into every browser and HTTP library, to say "you must authenticate" (`401` + `WWW-Authenticate`) and "here are my credentials" (`Authorization`).
> - **What came next:** Digest (1997/1999, revised as RFC 7616 in 2015) tried to avoid sending the password but was overtaken by TLS. Browser apps moved to form login and [cookie sessions](04-sessions-cookies-and-csrf.md). APIs moved to **Bearer** tokens ([JWT](06-tokens-and-jwt.md), [OAuth 2](08-oauth-2.md)), static **API keys**, and **HMAC request signing** (AWS SigV4). Today the framework is extended by sender-constrained tokens ([DPoP, mTLS](09-modern-oauth-2.1-and-extensions.md)) and the standard HTTP Message Signatures (RFC 9421).

---

## Table of contents

1. [The HTTP authentication framework (RFC 9110)](#1-the-http-authentication-framework-rfc-9110)
2. [Basic authentication (RFC 7617)](#2-basic-authentication-rfc-7617)
3. [Digest authentication (RFC 7616) and why it faded](#3-digest-authentication-rfc-7616-and-why-it-faded)
4. [Bearer tokens (RFC 6750)](#4-bearer-tokens-rfc-6750)
5. [API keys done right](#5-api-keys-done-right)
6. [HMAC request signing](#6-hmac-request-signing)
7. [Webhook signature verification](#7-webhook-signature-verification)
8. [Constant-time comparison](#8-constant-time-comparison)
9. [Production best practices (2026)](#9-production-best-practices-2026)
10. [Common attacks and mistakes](#10-common-attacks-and-mistakes)
11. [Spring Boot 4 / Spring Security 7 snippets](#11-spring-boot-4--spring-security-7-snippets)
12. [Interview questions](#interview-questions)
13. [References](#references)

---

## 1. The HTTP authentication framework (RFC 9110)

### 1.1 Challenge and response

HTTP authentication is a **challenge-response** pattern defined in RFC 9110 (HTTP Semantics, 2022), section 11. It replaced RFC 7235 (2014), which in turn replaced the auth parts of RFC 2617 (1999).

| Piece | Direction | Purpose |
|---|---|---|
| `401 Unauthorized` | server to client | "This request lacks valid credentials." |
| `WWW-Authenticate` | server to client | The challenge: which scheme(s) the server accepts and their parameters. A `401` response **must** include it. |
| `Authorization` | client to server | The credentials: `Authorization: <scheme> <credentials>`. |
| `407 Proxy Authentication Required` | proxy to client | Same idea for a proxy. |
| `Proxy-Authenticate` / `Proxy-Authorization` | both | Proxy equivalents of the two headers above. |
| `Authentication-Info` | server to client | Optional extra data after successful authentication (used by Digest for mutual auth). |

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server
    C->>S: GET /reports (no credentials)
    S-->>C: 401 Unauthorized + WWW-Authenticate challenge
    Note over C: Pick a supported scheme and build credentials
    C->>S: GET /reports + Authorization header
    alt credentials valid and access allowed
        S-->>C: 200 OK
    else credentials valid but not allowed
        S-->>C: 403 Forbidden
    else credentials invalid or expired
        S-->>C: 401 Unauthorized + WWW-Authenticate
    end
```

A raw exchange looks like this:

```http
GET /reports/2026-q3 HTTP/1.1
Host: api.example.com
Accept: application/json
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="reports", scope="reports:read"
WWW-Authenticate: Basic realm="reports", charset="UTF-8"
Content-Type: application/problem+json
Cache-Control: no-store

{"type":"about:blank","title":"Unauthorized","status":401}
```

A server may offer several challenges, either in multiple `WWW-Authenticate` headers or comma-separated in one. The client typically picks the strongest scheme it supports. The `realm` parameter names a "protection space": credentials that work for one realm are not assumed to work for another.

### 1.2 401 versus 403 (and 404)

This distinction is a classic interview question and a frequent API bug.

| Status | Meaning (RFC 9110) | Will re-authenticating help? | Must include |
|---|---|---|---|
| **401 Unauthorized** | The request has no valid credentials for the target resource. Despite the name, this is about **authentication**. | Yes — send (better) credentials. | `WWW-Authenticate` |
| **403 Forbidden** | The server understood the request and refuses to fulfill it. If credentials were sent, they are considered insufficient. This is about **authorization**. | No (the same identity will be refused again). | Nothing special |
| **404 Not Found** | Can be used instead of 403 to **hide the existence** of a resource from a caller who must not even know it exists (for example another tenant's invoice). | — | — |
| **407** | Like 401, but for a proxy. | Yes, with proxy credentials. | `Proxy-Authenticate` |

Rules of thumb:

- No token, malformed token, expired token, bad signature → **401**.
- Valid token, but the user lacks the role or scope → **403** (Bearer adds `error="insufficient_scope"`).
- Valid token, resource belongs to another tenant → usually **404**, so you do not leak which IDs exist.

### 1.3 The scheme registry

Schemes are registered with IANA ("HTTP Authentication Scheme Registry"). The ones a backend developer meets:

| Scheme | Spec | Status in 2026 | Typical use |
|---|---|---|---|
| `Basic` | RFC 7617 | Alive, only over TLS | Machine credentials, OAuth `client_secret_basic`, internal tools |
| `Digest` | RFC 7616 | Legacy | SIP/VoIP, some embedded devices |
| `Bearer` | RFC 6750 | Dominant for APIs | OAuth access tokens, JWTs, opaque tokens, API keys |
| `DPoP` | RFC 9449 | Growing | Sender-constrained OAuth tokens ([chapter 09](09-modern-oauth-2.1-and-extensions.md)) |
| `Negotiate` | RFC 4559 | Enterprise intranets | Kerberos/SPNEGO single sign-on ([chapter 05](05-enterprise-sso-ldap-kerberos-saml.md)) |
| `HOBA`, `SCRAM-SHA-256`, `Mutual` | RFC 7486, RFC 7804, RFC 8120 | Experimental, rarely deployed | Research and niche uses |
| `AWS4-HMAC-SHA256` | AWS documentation (vendor-specific, not IANA-registered) | Very widely used | AWS SigV4 request signing |

### 1.4 Browser behavior worth knowing

- When a browser receives `401` with `WWW-Authenticate: Basic` (or Digest, or Negotiate), it shows its **native login dialog** and then caches and auto-sends the credentials for that origin and realm. There is no reliable way to "log out" of Basic auth in a browser.
- For a JSON API called from JavaScript, sending `WWW-Authenticate: Basic` on failures pops that dialog in front of your users. Return a `401` with a non-browser scheme (`Bearer`) or a custom entry point instead.
- Because the browser auto-attaches cached Basic/Digest/Negotiate credentials and cookies, these are **ambient credentials**, so cookie-style [CSRF](04-sessions-cookies-and-csrf.md#7-csrf-in-depth) applies to them too. Credentials that the client code must explicitly add to each request (Bearer tokens, API keys in headers) are not ambient, so CSRF does not apply.

---

## 2. Basic authentication (RFC 7617)

### 2.1 How it works

Basic sends `user-id:password`, base64-encoded, in every request.

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="ops-dashboard", charset="UTF-8"
```

```http
GET /metrics HTTP/1.1
Host: ops.example.com
Authorization: Basic YWxpY2U6Y29ycmVjdCBob3JzZSBiYXR0ZXJ5IHN0YXBsZQ==
```

Decoding is trivial:

```text
base64decode("YWxpY2U6Y29ycmVjdCBob3JzZSBiYXR0ZXJ5IHN0YXBsZQ==")
  = "alice:correct horse battery staple"
```

Key details from RFC 7617 (2015, which replaced RFC 2617):

- The user-id **cannot contain a colon**; the password can (split on the first colon).
- The optional `charset="UTF-8"` parameter tells the client to encode non-ASCII characters as UTF-8 before base64. Without it, encoding was historically undefined and inconsistent between clients.
- Base64 is an **encoding, not encryption**. Anyone who sees the header has the password.

### 2.2 Why Basic needs TLS — and still has problems with it

| Weakness | Why it matters | Mitigation |
|---|---|---|
| Password sent in a reversible form on **every** request | Any on-path observer, TLS-terminating proxy log, or debug log captures a reusable password. | TLS 1.2+ (prefer 1.3) everywhere, HSTS, never log `Authorization`. |
| No expiry, no session, no logout | A leaked credential works until the password changes. | Use high-entropy, rotatable machine secrets instead of human passwords. |
| Slow password hashing on every request | If the server stores Argon2id hashes (as it should, see [chapter 02](02-passwords-and-credential-storage.md)), each request costs tens of milliseconds of CPU and memory — an easy denial-of-service amplifier. | Use Basic only for low-volume calls, or exchange credentials once for a session or token. |
| No built-in brute-force protection | Attackers can retry passwords at network speed. | Rate limiting per account and per IP, breached-password checks, lockout with care. |
| Browser caches credentials | No way to sign out; ambient credentials are CSRF-able. | Do not use Basic for browser user login. Use [sessions](04-sessions-cookies-and-csrf.md) or the BFF pattern. |
| No MFA | A password alone is a single factor. | Use real login flows ([OIDC](10-openid-connect.md), [MFA](11-mfa-passwordless-and-passkeys.md)). |

### 2.3 Where Basic is still a reasonable choice in 2026

Basic is fine when the "password" is actually a **long random machine secret** and the channel is TLS:

- **OAuth client authentication**: `client_secret_basic` (RFC 6749 section 2.3.1) sends `client_id:client_secret` with Basic to the token endpoint. (Stronger options exist: `private_key_jwt` and mTLS — see [chapter 08](08-oauth-2.md) and [chapter 12](12-service-to-service-and-zero-trust.md).)
- **Package registries and Git over HTTPS**, where the "password" is a personal access token.
- **Internal tools and scrape endpoints** (for example a metrics endpoint behind a private network), as long as secrets are rotated and never shared between environments.

It is **not** a good choice for end-user login in browsers or mobile apps.

---

## 3. Digest authentication (RFC 7616) and why it faded

### 3.1 The idea

Digest (first RFC 2069 in 1997, then RFC 2617 in 1999, revised as RFC 7616 in 2015) was designed for a world **without TLS**. Instead of sending the password, the client proves it knows the password by hashing it together with a server-supplied **nonce**.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server
    C->>S: GET /dir/index.html
    S-->>C: 401 with WWW-Authenticate Digest realm, nonce, qop, algorithm, opaque
    Note over C: HA1 = H(username:realm:password)
    Note over C: HA2 = H(method:uri)
    Note over C: response = H(HA1:nonce:nc:cnonce:qop:HA2)
    C->>S: GET /dir/index.html + Authorization Digest with response
    Note over S: Recompute response from stored HA1 and compare
    S-->>C: 200 OK + optional Authentication-Info
```

### 3.2 A real exchange (values from RFC 7616 section 3.9.1)

Username `Mufasa`, password `Circle of Life`.

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest
    realm="http-auth@example.org",
    qop="auth, auth-int",
    algorithm=SHA-256,
    nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
    opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"
WWW-Authenticate: Digest
    realm="http-auth@example.org",
    qop="auth, auth-int",
    algorithm=MD5,
    nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
    opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"
```

```http
GET /dir/index.html HTTP/1.1
Host: example.org
Authorization: Digest username="Mufasa",
    realm="http-auth@example.org",
    uri="/dir/index.html",
    algorithm=SHA-256,
    nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
    nc=00000001,
    cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
    qop=auth,
    response="753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1",
    opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"
```

The computation (SHA-256 variant):

```text
HA1      = SHA256("Mufasa:http-auth@example.org:Circle of Life")
         = 7987c64c30e25f1b74be53f966b49b90f2808aa92faf9a00262392d7b4794232
HA2      = SHA256("GET:/dir/index.html")
response = SHA256(HA1 + ":" + nonce + ":" + "00000001" + ":" + cnonce + ":" + "auth" + ":" + HA2)
         = 753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1
```

RFC 7616 added SHA-256 and SHA-512/256 (MD5 is kept only for backward compatibility), a `userhash` option to hide the username, and a `charset` parameter for UTF-8 credentials. `qop=auth-int`, which also hashes the body, already existed in RFC 2617.

### 3.3 Why Digest faded

| Problem | Explanation |
|---|---|
| **Password-equivalent storage** | The server must store `HA1 = H(user:realm:password)` (or the plaintext). Anyone who steals HA1 can authenticate — no cracking needed. Worse, HA1 is a single fast hash, so it cannot be a salted, slow Argon2id/bcrypt hash. This directly conflicts with modern [password storage](02-passwords-and-credential-storage.md). |
| **Weak hash in practice** | For two decades only MD5 was widely implemented. SHA-256 support in clients arrived late and unevenly. |
| **Downgrade attacks** | An active attacker can strip the Digest challenge and offer Basic instead, then read the password. |
| **Partial protection** | `qop=auth` protects only the method and URI, not headers or body. `auth-int` was rarely implemented. |
| **TLS made it pointless** | Once HTTPS became universal, the main benefit (not sending the password in clear) was already provided by TLS — with confidentiality and integrity for the whole request. |
| **Poor UX and no MFA** | Same native browser dialog problem as Basic. No logout, no MFA, no federation. |

You will still meet Digest in **SIP (VoIP)** and in some IP cameras and embedded devices. Do not choose it for new systems.

> **Lesson that carried forward:** "Prove knowledge of a secret without sending it, bound to a server nonce" is exactly what HMAC request signing (section 6), SCRAM, and — with public-key cryptography instead of shared secrets — [WebAuthn/passkeys](11-mfa-passwordless-and-passkeys.md) do today.

---

## 4. Bearer tokens (RFC 6750)

### 4.1 What "bearer" means

RFC 6750 (2012) defines how to send an OAuth 2.0 access token. "Bearer" means: **whoever holds (bears) the token can use it**, like cash or a concert ticket. The server does not check who is presenting it. The token itself can be an opaque random string, a [JWT](06-tokens-and-jwt.md), or even an API key — Bearer only describes how it is sent and what errors look like.

### 4.2 Three ways to send it — only one is recommended

| Method | Example | RFC 6750 position | Use? |
|---|---|---|---|
| `Authorization` header | `Authorization: Bearer mF_9.B5f-4.1JqM` | The method resource servers **MUST** support | **Yes** |
| Form-encoded body | `access_token=mF_9.B5f-4.1JqM` in a `application/x-www-form-urlencoded` POST | Allowed with restrictions | Avoid |
| URI query parameter | `GET /resource?access_token=mF_9.B5f-4.1JqM` | **SHOULD NOT** be used unless nothing else is possible | **No** — ends up in logs, browser history, `Referer` headers, and proxy caches |

### 4.3 Error responses

```http
GET /api/invoices HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMjYtMTAifQ.eyJzdWIiOi...
```

Expired or invalid token:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="api",
    error="invalid_token",
    error_description="The access token expired"
Cache-Control: no-store
```

Valid token, missing scope:

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer realm="api",
    error="insufficient_scope",
    scope="invoices:write"
```

| `error` value | HTTP status | Meaning |
|---|---|---|
| `invalid_request` | 400 | Missing or duplicated parameter, more than one method used, malformed request |
| `invalid_token` | 401 | Expired, revoked, malformed, or failed signature/audience checks |
| `insufficient_scope` | 403 | The token is valid but lacks the required scope |

If the request had **no** credentials at all, the server should return `401` with a bare challenge (`WWW-Authenticate: Bearer realm="api"`) and no error code.

### 4.4 The bearer problem and its fix

Because a bearer token works for anyone who holds it, a stolen token (from logs, a compromised proxy, malware, or a misconfigured client) can be **replayed** from anywhere until it expires. The mitigations, in order of how often you will use them:

1. **Short lifetimes**: access tokens of 5–15 minutes, with rotated refresh tokens ([chapter 06](06-tokens-and-jwt.md)).
2. **Audience restriction**: a token minted for `orders-api` must be rejected by `billing-api` (`aud` check).
3. **Sender-constrained tokens**: bind the token to a key the client holds — **DPoP** (RFC 9449, `Authorization: DPoP ...` plus a signed `DPoP` proof header) or **mutual TLS** (RFC 8705). A stolen token is then useless without the private key. See [chapter 09](09-modern-oauth-2.1-and-extensions.md).

---

## 5. API keys done right

### 5.1 What an API key is (and is not)

An **API key** is a long-lived, random secret that identifies a **calling application, project, or integration** — not a human. It is the simplest credential for server-to-server access by third-party developers: "here is your key, put it in a header."

| Good fit | Bad fit |
|---|---|
| A customer's backend calling your public API | Logging in a human user (use [sessions](04-sessions-cookies-and-csrf.md) or [OIDC](10-openid-connect.md)) |
| CLI tools and CI jobs (with secret storage) | JavaScript in a browser or a mobile app — any key shipped to a client is **public** |
| Simple metered access, usage tracking, quotas | Delegated access on behalf of a user (use [OAuth 2](08-oauth-2.md)) |
| Internal tooling where OAuth is overkill | Your own microservices talking to each other (prefer client credentials, mTLS, or workload identity — [chapter 12](12-service-to-service-and-zero-trust.md)) |

> Publishable "keys" embedded in front-end code (map tiles, analytics, payment forms) are **identifiers**, not secrets. Protect them with origin restrictions and quotas, never with secrecy.

### 5.2 Anatomy of a well-designed key

```text
acme_live_8Hk2pQ7xW1nZ4rT9vB3mY6cF0dJ5sL2gA7eK1uN4qR8_02fh9kc
\_______/ \___________________________________________/ \_____/
  prefix               random secret (>= 128 bits)           checksum
```

| Part | Purpose |
|---|---|
| **Recognizable prefix** (`acme_live_`, `acme_test_`) | Humans and **secret scanners** can identify the key type and environment. GitHub (`ghp_`, `github_pat_`), Stripe (`sk_live_`, `sk_test_`), Slack (`xoxb-`) all do this. A `test` vs `live` prefix prevents using production keys in development by accident. |
| **Random secret** | At least **128 bits** from a CSPRNG (`SecureRandom`); 256 bits (32 bytes) is a common, cheap default. Encode as base62 or base64url so it is copy-paste and URL safe. |
| **Checksum** (optional) | A short CRC32 or similar over the rest lets scanners and your own API reject typos and random strings **without a database lookup**, reducing false positives. GitHub added checksummed token formats in 2021 for this reason. |
| **Lookup ID** (optional) | Some designs embed a short non-secret ID (`acme_live_k7Qp2_<secret>`) so you can find the row by ID and show it in dashboards ("key ending in ...k7Qp2"). |

Generating one in Java 21:

```java
import java.security.SecureRandom;
import java.util.Base64;
import java.util.zip.CRC32;

public final class ApiKeyGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    /** Returns e.g. acme_live_<43 chars of base64url>_<7 chars base36 CRC32 checksum>. */
    public static String newKey(String environment) {
        byte[] secret = new byte[32];                 // 256 bits of entropy
        RANDOM.nextBytes(secret);
        String body = "acme_" + environment + "_" + B64URL.encodeToString(secret);
        CRC32 crc = new CRC32();
        crc.update(body.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        String checksum = Long.toString(crc.getValue(), 36);
        return body + "_" + "0".repeat(Math.max(0, 7 - checksum.length())) + checksum;
    }
}
```

### 5.3 Store only a hash — and why a fast hash is fine here

**Never store API keys in plaintext.** A database dump, a backup, or a read-only SQL injection would hand an attacker every customer's credentials.

But unlike passwords, you do **not** need Argon2id:

- Passwords are low-entropy and guessable, so they need a **slow, salted** hash to resist offline cracking ([chapter 02](02-passwords-and-credential-storage.md)).
- A 256-bit random key cannot be brute-forced regardless of hash speed.
- API keys are verified on **every request**; a 50 ms Argon2id per call would be a self-inflicted denial of service.

Use **HMAC-SHA-256 with a server-side secret ("pepper")** kept in a KMS or secret manager, or at minimum SHA-256. The pepper means a stolen database alone is not even enough to test candidate keys.

```sql
CREATE TABLE api_key (
    id             UUID         PRIMARY KEY,
    owner_id       UUID         NOT NULL REFERENCES account(id),
    name           VARCHAR(100) NOT NULL,          -- "CI deploy key"
    prefix         VARCHAR(20)  NOT NULL,          -- "acme_live"
    last_four      CHAR(4)      NOT NULL,          -- shown in the UI
    key_hash       BYTEA        NOT NULL UNIQUE,   -- HMAC-SHA256(pepper, full key)
    pepper_version SMALLINT     NOT NULL,          -- allows pepper rotation
    scopes         TEXT[]       NOT NULL,          -- {"invoices:read"}
    allowed_cidrs  CIDR[],                         -- optional IP allowlist
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ,                    -- NULL only if policy allows
    revoked_at     TIMESTAMPTZ,
    last_used_at   TIMESTAMPTZ,
    last_used_ip   INET
);
```

Lookup by `key_hash` through a unique index is safe: the attacker would need to know the full key to produce a matching hash, so index timing reveals nothing useful.

### 5.4 Lifecycle: show once, rotate with overlap, revoke fast

```mermaid
flowchart LR
    A["Create: generate key, store HMAC hash"] --> B["Show full key ONCE to the user"]
    B --> C["Active: scoped, rate limited, last-used tracked"]
    C --> D["Rotation: new key issued, both valid during overlap"]
    D --> E["Old key revoked after overlap window"]
    C --> F["Leak detected by secret scanning"]
    F --> G["Immediate revocation and owner notified"]
    C --> H["Expired at expires_at"]
```

Concrete policy that works well for most SaaS APIs:

| Property | Recommendation |
|---|---|
| Entropy | >= 128 bits; 256 bits by default |
| Display | Show the full key **once** at creation. Afterwards show only prefix + last four characters. If it is lost, issue a new one. |
| Storage | HMAC-SHA-256 (pepper in KMS) or SHA-256; never plaintext, never reversible encryption unless you truly must re-display it (you should not) |
| Scopes | Least privilege per key (`invoices:read`, not "full access"). Separate read and write keys. |
| Expiry | Default 90 days to 1 year; enforce a maximum for high-privilege keys. Warn owners by email 14 and 3 days before expiry. |
| Rotation | Allow **at least two active keys** per integration so clients can deploy the new key, verify it, then revoke the old one (overlap of hours to a few days). |
| Revocation | Effective within seconds. If you cache key lookups, cache for at most 30–60 seconds or use an invalidation event. |
| Last-used tracking | Record `last_used_at` and IP (batched/async to avoid a write per request). Show it in the dashboard; flag and auto-expire keys unused for 90+ days. |
| Rate limits | Per key and per owner (for example 100 requests/second burst, plus daily quota). Return `429 Too Many Requests` with `Retry-After`. |
| Transport | Always TLS. Send in a **header**: `Authorization: Bearer <key>` or `X-API-Key: <key>`. **Never in the query string.** |
| Audit | Log key ID (never the key), owner, action, IP, user agent. Alert on use from new countries or ASNs for sensitive keys. |
| Optional hardening | IP allowlists (CIDR), per-key allowed origins, HMAC signing (section 6) for high-value APIs |

### 5.5 Verification flow

```mermaid
sequenceDiagram
    autonumber
    participant Client
    participant GW as API gateway or filter
    participant Store as Key store (DB plus cache)
    participant API as Business API
    Client->>GW: GET /v1/invoices + Authorization Bearer acme_live_...
    GW->>GW: Check prefix and checksum (reject garbage without DB hit)
    GW->>GW: hash = HMAC-SHA256(pepper, presented key)
    GW->>Store: find key by hash
    Store-->>GW: record with owner, scopes, expiry, revoked flag
    GW->>GW: Reject if missing, revoked, expired, or IP not allowed
    GW->>GW: Rate limit check for this key
    GW->>API: Forward with principal = owner, authorities = scopes
    API-->>Client: 200 OK
    GW-)Store: async update of last_used_at and last_used_ip
```

The HTTP side:

```http
GET /v1/invoices?status=open HTTP/1.1
Host: api.acme.example
Authorization: Bearer acme_live_8Hk2pQ7xW1nZ4rT9vB3mY6cF0dJ5sL2gA7eK1uN4qR8_02fh9kc
Accept: application/json
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
RateLimit-Policy: "default";q=100;w=1
RateLimit: "default";r=97;t=1

{"data":[{"id":"inv_123","amount":4200,"currency":"EUR"}]}
```

Revoked or unknown key:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="acme-api", error="invalid_token"
Content-Type: application/problem+json

{"title":"Invalid API key","status":401,"detail":"The API key is invalid, expired or revoked."}
```

Over quota:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 30
Content-Type: application/problem+json

{"title":"Rate limit exceeded","status":429}
```

> The `RateLimit` / `RateLimit-Policy` header fields come from an IETF HTTPAPI working group **draft**; many APIs still use vendor headers such as `X-RateLimit-Remaining`. `Retry-After` is standard (RFC 9110).

Give the same error message for "unknown", "revoked", and "expired" keys to avoid helping attackers enumerate; tell the owner the real reason in the dashboard.

### 5.6 Secret scanning and leak response

Keys leak — into Git repositories, CI logs, screenshots, support tickets, and LLM chat transcripts. Plan for it:

1. **Make keys detectable**: unique prefix + checksum gives near-zero false positives.
2. **Join provider scanning programs**: GitHub's secret scanning partner program lets a provider register token patterns; when a matching key is pushed to a public repository, GitHub notifies the provider's endpoint so it can revoke the key automatically. GitHub push protection can also block the push before it lands.
3. **Scan your own code and logs**: run tools such as gitleaks or trufflehog in CI; mask `Authorization` and `X-API-Key` in logging and APM agents.
4. **Have a revoke endpoint and a runbook**: revoke immediately, notify the owner, review `last_used_ip` and audit logs for abuse in the exposure window.

---

## 6. HMAC request signing

### 6.1 Why sign requests?

An API key or Bearer token is sent **as-is** with each request. Request signing instead sends a **proof** computed from a shared secret and the request contents:

| Property | API key / Bearer | HMAC-signed request |
|---|---|---|
| Secret travels over the network | Yes, every request | **No** — only a signature |
| Request integrity (method, path, body) | Only via TLS | **Yes**, end-to-end, even through proxies that terminate TLS |
| Replay protection | No (until expiry) | **Yes**, with timestamp + nonce |
| Complexity for clients | Trivial | Moderate (canonicalization must match exactly) |
| Typical users | Most SaaS APIs | AWS (SigV4), payment and banking APIs, webhooks |

HMAC (RFC 2104) with SHA-256 is the standard primitive: `signature = HMAC-SHA256(secret, string_to_sign)`. Only someone who knows the secret can compute it, and any change to the signed data changes the signature.

### 6.2 The building blocks

1. **Canonical request**: a deterministic, byte-exact representation of the parts you sign. Both sides must produce the **same bytes**, so define precisely: HTTP method in upper case, path with a fixed percent-encoding rule, query parameters sorted by name, a chosen set of headers lower-cased and trimmed, and a hash of the raw body.
2. **Timestamp**: when the request was signed. The server rejects anything outside a window (commonly ±5 minutes; AWS allows 15 minutes).
3. **Nonce**: a unique random value per request. The server remembers nonces it has seen **for the length of the window** and rejects duplicates. Timestamp alone limits replay to the window; timestamp + nonce prevents it entirely.
4. **Key ID**: tells the server which secret to use, which makes rotation possible.
5. **Signature**: HMAC over the string-to-sign, sent in a header.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (holds key id and secret)
    participant S as Server (holds same secret)
    participant N as Nonce cache (Redis)
    Note over C: Build canonical request: method, path, sorted query, signed headers, SHA-256 of body
    Note over C: string-to-sign = algorithm, timestamp, hash of canonical request (nonce is a signed header)
    Note over C: signature = HMAC-SHA256(secret, string-to-sign)
    C->>S: POST /v1/transfers + key id, timestamp, nonce, signature headers
    S->>S: Reject if timestamp outside plus or minus 5 minutes
    S->>S: Load secret by key id, rebuild canonical request from received bytes
    S->>S: Recompute signature and compare in constant time
    S->>N: SET nonce NX with TTL 10 minutes
    alt nonce was new
        N-->>S: OK
        S-->>C: 201 Created
    else nonce already seen
        N-->>S: exists
        S-->>C: 401 replay detected
    end
```

### 6.3 A simple, explicit scheme

A custom scheme many teams implement (shown here so every step is visible):

```http
POST /v1/transfers?dry_run=false HTTP/1.1
Host: api.bank.example
Content-Type: application/json
X-Acme-Key-Id: key_2026_10_ops
X-Acme-Timestamp: 2026-10-08T12:00:00Z
X-Acme-Nonce: 3f9c1a7e-5b2d-4c8e-9a61-0d7f2b4e8c13
X-Acme-Content-SHA256: 4c7a0e...e91b
Authorization: ACME-HMAC-SHA256 KeyId=key_2026_10_ops, SignedHeaders=content-type;host;x-acme-content-sha256;x-acme-nonce;x-acme-timestamp, Signature=9a1f6c...0be2

{"from":"acc_1","to":"acc_2","amount":"125.00","currency":"EUR"}
```

Canonical request (each line separated by `\n`):

```text
POST
/v1/transfers
dry_run=false
content-type:application/json
host:api.bank.example
x-acme-content-sha256:4c7a0e...e91b
x-acme-nonce:3f9c1a7e-5b2d-4c8e-9a61-0d7f2b4e8c13
x-acme-timestamp:2026-10-08T12:00:00Z

content-type;host;x-acme-content-sha256;x-acme-nonce;x-acme-timestamp
4c7a0e...e91b
```

String to sign and signature:

```text
ACME-HMAC-SHA256
2026-10-08T12:00:00Z
<hex SHA-256 of the canonical request>

signature = hex(HMAC-SHA256(secret, string_to_sign))
```

Server-side verification order (cheap checks first, state change last):

1. Parse headers; reject if any required header is missing (`401`).
2. Check the timestamp window (±300 seconds). Reject early — no DB lookup needed.
3. Look up the secret by key ID (reject unknown, revoked, expired keys).
4. Hash the **raw body bytes as received** and compare with `X-Acme-Content-SHA256`.
5. Rebuild the canonical request from the received request and compute the expected signature.
6. Compare signatures with a **constant-time** function (section 8).
7. Only after the signature is valid, record the nonce with `SET nonce:<keyId>:<nonce> 1 NX EX 600`. If it already existed, reject as a replay. (Recording before validation would let attackers fill your cache with junk.)

### 6.4 AWS Signature Version 4 — the classic example

AWS SigV4 is the most widely deployed HMAC signing scheme. Every AWS SDK call uses it.

**Step 1 — canonical request**

```text
GET
/
Action=ListUsers&Version=2010-05-08
content-type:application/x-www-form-urlencoded; charset=utf-8
host:iam.amazonaws.com
x-amz-date:20261008T120000Z

content-type;host;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

The last line is the hex SHA-256 of the (empty) payload.

**Step 2 — string to sign**

```text
AWS4-HMAC-SHA256
20261008T120000Z
20261008/us-east-1/iam/aws4_request
<hex SHA-256 of the canonical request>
```

The third line is the **credential scope**: date / region / service / `aws4_request`.

**Step 3 — derive a scoped signing key** (the long-term secret never signs requests directly)

```text
kDate    = HMAC-SHA256("AWS4" + SecretAccessKey, "20261008")
kRegion  = HMAC-SHA256(kDate, "us-east-1")
kService = HMAC-SHA256(kRegion, "iam")
kSigning = HMAC-SHA256(kService, "aws4_request")
signature = hex(HMAC-SHA256(kSigning, StringToSign))
```

**Step 4 — send it**

```http
GET /?Action=ListUsers&Version=2010-05-08 HTTP/1.1
Host: iam.amazonaws.com
Content-Type: application/x-www-form-urlencoded; charset=utf-8
X-Amz-Date: 20261008T120000Z
Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261008/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=<64 hex chars>
```

Design ideas worth copying:

- **Key derivation per day, region, and service** limits the blast radius of a derived key and lets AWS cache derived keys.
- **Timestamp window**: AWS documents that signed portions of a request are valid within 15 minutes of the request timestamp.
- **Signed payload hash** (`x-amz-content-sha256` for S3) protects the body.
- **Presigned URLs** put the same signature in query parameters (`X-Amz-Signature`, `X-Amz-Expires`, maximum 7 days) so a browser can upload or download one object without holding credentials. This is the one acceptable "credential in the URL" pattern: the URL is narrowly scoped, short-lived, and signed — not a reusable secret.
- **Temporary credentials**: modern AWS workloads sign with short-lived STS credentials from IAM roles (plus `X-Amz-Security-Token`), not long-lived access keys — the same "avoid long-lived shared secrets" principle as [chapter 12](12-service-to-service-and-zero-trust.md).

### 6.5 HTTP Message Signatures (RFC 9421) — the standard way

Every vendor inventing its own canonicalization led to RFC 9421, **HTTP Message Signatures** (February 2024). It defines how to select request components (`@method`, `@target-uri`, `@authority`, headers such as `content-digest`), serialize them into a signature base, and carry the result in two headers. It supports HMAC-SHA256 as well as asymmetric algorithms (RSA-PSS, ECDSA P-256, Ed25519). It pairs with RFC 9530 (Digest Fields, 2024) for the `Content-Digest` header.

```http
POST /v1/transfers HTTP/1.1
Host: api.bank.example
Content-Type: application/json
Content-Digest: sha-256=:<base64 SHA-256 of body>:
Signature-Input: sig1=("@method" "@target-uri" "content-digest" "content-type");created=1791460800;keyid="key_2026_10_ops";nonce="b3k2pp5k7z";alg="hmac-sha256"
Signature: sig1=:<base64 HMAC>:

{"from":"acc_1","to":"acc_2","amount":"125.00","currency":"EUR"}
```

If you are designing a new signing scheme in 2026, use RFC 9421 and an existing library rather than inventing one. Prefer **asymmetric** signatures (Ed25519 or ECDSA) when many verifiers exist, so verifiers never hold a secret that could also sign.

---

## 7. Webhook signature verification

### 7.1 The problem

A webhook endpoint (`POST /webhooks/payments`) is a **public URL**. Anyone who discovers it can send fake events ("invoice paid!"). The provider therefore signs each delivery with a secret shared only with you, and you must verify it before trusting anything in the body.

```mermaid
sequenceDiagram
    autonumber
    participant P as Provider (Stripe, GitHub, ...)
    participant W as Your webhook endpoint
    participant Q as Queue or job worker
    P->>W: POST /webhooks/payments + signature header + raw JSON body
    W->>W: Read RAW body bytes (do not parse first)
    W->>W: Check timestamp tolerance (if the scheme has one)
    W->>W: expected = HMAC-SHA256(endpoint secret, signed content)
    W->>W: Constant-time compare with every signature in the header
    alt valid and event id not seen before
        W->>Q: enqueue event
        W-->>P: 200 OK quickly
    else invalid signature or stale timestamp
        W-->>P: 400 or 401, nothing processed
    else duplicate event id
        W-->>P: 200 OK (idempotent, ignore)
    end
```

### 7.2 Stripe style: timestamp inside the signature

Stripe sends one header:

```http
POST /webhooks/stripe HTTP/1.1
Host: shop.example.com
Content-Type: application/json; charset=utf-8
Stripe-Signature: t=1791460800,v1=b98bafc4c74dc1fef3596bd54ce51df3992dcfbf4d9ccbe621036193226fffb5

{"id":"evt_1Q2","type":"invoice.paid"}
```

- `t` is a Unix timestamp; `v1` is `hex(HMAC-SHA256(endpoint_secret, t + "." + raw_body))`. (The example above uses the demo secret `whsec_demo_only_not_a_real_secret`.)
- Because the timestamp is **inside** the signed content, an attacker cannot change it. Stripe's libraries reject events older than a default tolerance of **5 minutes (300 seconds)**.
- During secret rotation the header can contain **multiple `v1` values**; accept the event if **any** matches.

### 7.3 GitHub style: body-only HMAC

```http
POST /webhooks/github HTTP/1.1
Host: ci.example.com
Content-Type: application/json
X-GitHub-Event: push
X-GitHub-Delivery: 72d3162e-cc78-11e3-81ab-4c9367dc0958
X-Hub-Signature-256: sha256=4079a02010abfb979c19ca57483cefe3a246330e9511bb7322d88e98c4017bfb

Hello, World!
```

- `X-Hub-Signature-256` is `sha256=` + hex HMAC-SHA256 of the raw body. (Example computed with the secret `It is a secret to everybody` and body `Hello, World!`.) The older `X-Hub-Signature` header uses SHA-1 and should be ignored.
- There is **no timestamp in the signature**, so replay protection must come from **deduplicating on `X-GitHub-Delivery`** (a unique ID per delivery) and making handlers idempotent.

### 7.4 Standard Webhooks

The **Standard Webhooks** specification (an industry effort, not an IETF RFC) unifies the pattern:

```http
webhook-id: msg_2KWPBgLlAfxdpx2AI54pPJ85f4W
webhook-timestamp: 1791460800
webhook-signature: v1,uBS6y6/ttLUomfkfsnQ53Qab1JKd4Msh5r1uaHZJiR8=
```

Signed content is `webhook-id + "." + webhook-timestamp + "." + raw_body`; the signature is base64 HMAC-SHA256. The header can list several space-separated signatures (rotation), and the spec also defines an asymmetric (Ed25519) variant.

### 7.5 Comparison

| | Stripe | GitHub | Standard Webhooks |
|---|---|---|---|
| Header | `Stripe-Signature` | `X-Hub-Signature-256` | `webhook-signature` (+ `webhook-id`, `webhook-timestamp`) |
| Algorithm | HMAC-SHA256, hex | HMAC-SHA256, hex | HMAC-SHA256, base64 (or Ed25519) |
| Signed content | `t.body` | `body` | `id.timestamp.body` |
| Replay protection | Timestamp tolerance (5 min) + event ID dedupe | Delivery ID dedupe only | Timestamp tolerance + message ID dedupe |
| Rotation | Multiple `v1` values | Change secret (brief overlap is your problem) | Multiple signatures |

### 7.6 Verifying a Stripe-style signature in Java 21

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;

public final class WebhookVerifier {

    private static final Duration TOLERANCE = Duration.ofMinutes(5);
    private final byte[] secret;
    private final Clock clock;

    public WebhookVerifier(byte[] secret, Clock clock) {
        this.secret = secret.clone();
        this.clock = clock;
    }

    /** rawBody must be the exact bytes received, before any JSON parsing. */
    public boolean verify(String signatureHeader, byte[] rawBody) {
        long timestamp = -1;
        var candidates = new java.util.ArrayList<byte[]>();
        for (String part : signatureHeader.split(",")) {
            String[] kv = part.trim().split("=", 2);
            if (kv.length != 2) continue;
            switch (kv[0]) {
                case "t" -> timestamp = parseLongOrMinusOne(kv[1]);
                case "v1" -> { try { candidates.add(HexFormat.of().parseHex(kv[1])); }
                               catch (IllegalArgumentException ignored) { } }
                default -> { } // ignore unknown schemes (for example v0)
            }
        }
        if (timestamp < 0 || candidates.isEmpty()) return false;

        long now = clock.instant().getEpochSecond();
        if (Math.abs(now - timestamp) > TOLERANCE.toSeconds()) return false;

        byte[] expected = hmacSha256(secret, concat((timestamp + ".").getBytes(StandardCharsets.US_ASCII), rawBody));
        boolean match = false;
        for (byte[] candidate : candidates) {
            match |= MessageDigest.isEqual(expected, candidate); // constant time, check all
        }
        return match;
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static long parseLongOrMinusOne(String s) {
        try { return Long.parseLong(s); } catch (NumberFormatException e) { return -1; }
    }
}
```

In a Spring MVC controller, accept the body as `@RequestBody byte[] body` (not a deserialized object) so you verify exactly what was sent.

### 7.7 Checklists

**Consumer (receiving webhooks):**

- Verify the signature over the **raw bytes** before parsing. Re-serialized JSON will not match (whitespace, key order, Unicode escaping).
- Enforce the timestamp tolerance (5 minutes is typical) when the scheme has one.
- Deduplicate on the event or delivery ID (store IDs for at least the provider's retry period, often 24–72 hours) and make handlers **idempotent** — providers retry.
- Respond `2xx` fast and do the work asynchronously; slow endpoints cause retries and duplicates.
- For critical state changes, **re-fetch the object from the provider's API** instead of trusting the event payload alone.
- Keep the endpoint secret in a secret manager; support two secrets during rotation.
- Do not exempt the webhook endpoint from authentication "because it is called by a machine". The signature **is** the authentication. (Do exempt it from cookie CSRF protection: it carries no cookies.)

**Provider (sending webhooks):**

- Sign every delivery; include a timestamp and a unique ID in the signed content.
- Generate per-endpoint secrets (>= 256 bits), show once, support rotation with overlapping signatures.
- Protect against **SSRF**: customers choose the URL, so block private, loopback, link-local and cloud metadata addresses (for example `169.254.169.254`), re-check after DNS resolution to defeat DNS rebinding, and send from an egress proxy.
- Consider asymmetric signatures (Ed25519) so consumers verify with a public key and you never share signing material.

---

## 8. Constant-time comparison

### 8.1 Why ordinary equality leaks secrets

`String.equals`, `Arrays.equals`, and a hand-written loop with `return false` on the first mismatch all **stop at the first differing byte**. The time taken depends on how many leading bytes are correct. With enough measurements (local network, statistics over many requests), an attacker can guess a MAC or token one byte at a time instead of all at once — turning a 2^256 search into roughly 256 × 32 guesses.

```java
// WRONG: early exit leaks how many leading bytes matched
if (expectedSignatureHex.equals(receivedSignatureHex)) { ... }

// RIGHT: time depends only on length, not content
if (MessageDigest.isEqual(expectedBytes, receivedBytes)) { ... }
```

`java.security.MessageDigest.isEqual(byte[], byte[])` has been constant-time with respect to the contents since Java 6u17. In current JDKs (including Java 21) its running time depends only on the length of the **first** argument, even when the lengths differ, so pass the expected value first. Length is not a secret here anyway: an HMAC-SHA256 output is always 32 bytes.

### 8.2 Rules

| Do | Don't |
|---|---|
| Compare **fixed-length digests** (HMAC outputs, SHA-256 of tokens) as bytes with `MessageDigest.isEqual` | Compare secrets with `equals`, `==`, `compareTo`, or `Arrays.equals` |
| Decode hex/base64 first, then compare bytes (or compare normalized lower-case hex consistently) | Compare case-insensitively with `equalsIgnoreCase` (also early-exit) |
| For variable-length secrets, hash both sides first (`SHA-256(a)` vs `SHA-256(b)`), then compare digests | Return different error messages or status codes for "wrong length" vs "wrong value" |
| Check **all** candidate signatures (rotation) without short-circuiting | Log the expected signature on failure |

Password hash verification (`Argon2PasswordEncoder.matches`, `BCryptPasswordEncoder.matches`) already compares in constant time internally — another reason never to roll your own.

---

## 9. Production best practices (2026)

| Area | Recommendation |
|---|---|
| Transport | TLS 1.3 preferred (1.2 minimum), HSTS with `max-age` of at least one year on public hosts. Plain HTTP must never carry any credential. |
| Status codes | `401` + `WWW-Authenticate` for missing/invalid credentials; `403` for authenticated-but-forbidden; `404` to hide cross-tenant resources. |
| Basic | Only over TLS, only with high-entropy machine secrets, low request volume. Never for browser user login. |
| Digest | Do not deploy for new systems. |
| Bearer | `Authorization` header only; never in URLs. Access tokens 5–15 min; validate signature, `iss`, `aud`, `exp` (and `nbf`); sender-constrain (DPoP/mTLS) for high-risk APIs. |
| API key entropy | >= 128 bits (256 bits default), CSPRNG, recognizable prefix, optional checksum. |
| API key storage | HMAC-SHA-256 with a pepper in KMS (or SHA-256). Show once. Never log. |
| API key lifecycle | Scopes, expiry (90 days to 1 year), two active keys for overlap rotation, instant revocation (cache TTL <= 60 s), last-used tracking, auto-expire after 90 days unused. |
| Rate limiting | Per key and per owner; `429` + `Retry-After`. |
| Request signing | HMAC-SHA256 (or Ed25519/ECDSA) over a canonical request incl. body hash; ±5 min timestamp window; nonce cache TTL >= 2 × window; key IDs for rotation. Prefer RFC 9421 for new designs. |
| Webhooks | Verify raw-body HMAC in constant time, 5 min tolerance, dedupe by event ID, idempotent async processing, SSRF controls on the sending side. |
| Logging | Redact `Authorization`, `Proxy-Authorization`, `Cookie`, `X-API-Key`, signature headers, and query strings that might contain tokens. |
| Secret scanning | Register key patterns with GitHub secret scanning; run gitleaks/trufflehog in CI; automate revocation. |
| Internal services | Prefer OAuth client credentials with short-lived tokens, mTLS, or workload identity federation over static API keys ([chapter 12](12-service-to-service-and-zero-trust.md)). |

---

## 10. Common attacks and mistakes

| Attack / mistake | What goes wrong | Mitigation |
|---|---|---|
| Basic auth over plain HTTP | Password readable by anyone on the path | TLS everywhere + HSTS; reject non-TLS at the edge |
| `WWW-Authenticate: Basic` on API 401s | Browser login popup in front of SPA users; cached ambient creds | Custom entry point returning `Bearer` challenge or problem JSON |
| Digest with stored HA1 | HA1 is a password equivalent; database theft = account takeover | Do not use Digest; store Argon2id hashes and use modern login |
| Token or key in the query string | Leaks via access logs, browser history, `Referer`, analytics, CDN logs | Headers only; strip and alert on `?api_key=` / `?access_token=` |
| API keys stored in plaintext | DB dump or backup leak exposes every customer | Store HMAC/SHA-256 hash only; show once |
| API key embedded in mobile app or JS bundle | Anyone can extract and abuse it | Keys stay server-side; use OAuth (PKCE) for apps; publishable keys only with origin limits and quotas |
| No rotation path (single key per integration) | Teams never rotate because it causes downtime | Two active keys, overlap window, expiry reminders |
| One "god key" with full access | Any leak is total compromise | Scoped keys, separate read/write, per-environment prefixes |
| Unbounded key validity | Forgotten keys in old repos still work years later | Expiry, auto-expire on inactivity, secret scanning |
| `String.equals` on signatures or keys | Timing side channel reveals the secret byte by byte | `MessageDigest.isEqual` on bytes; compare hashes |
| Verifying webhook signature on parsed JSON | Signature never matches, so developers "temporarily" disable checking | Verify raw bytes; read body as `byte[]` |
| No timestamp/nonce in signed requests | Captured request can be replayed (double payment) | Timestamp window + nonce cache + idempotency keys |
| Recording nonce before verifying signature | Attackers flood nonce cache; DoS | Verify signature first, then `SET NX` the nonce |
| Canonicalization ambiguity (encoding, header folding, duplicate params) | Signature valid for a different request than the one processed, or legit requests fail | Strict, documented canonical form; sign `Host`; reject duplicate params; use RFC 9421 libraries |
| Webhook sender without SSRF protection | Customer registers `http://169.254.169.254/...` and reads cloud credentials | Block private ranges after DNS resolution, egress proxy, no redirects |
| Same error leaking key state | Different messages for unknown/expired/revoked aid enumeration | Uniform `401` to callers; details only in the owner's dashboard |
| Logging `Authorization` headers | Secrets in log aggregation, visible to many staff and vendors | Redaction filters in logging and APM; scanning logs for prefixes |

---

## 11. Spring Boot 4 / Spring Security 7 snippets

### 11.1 HTTP Basic for a machine-only endpoint, without the browser popup

```java
@Configuration
@EnableWebSecurity
class OpsSecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain opsChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/ops/**")
            .authorizeHttpRequests(auth -> auth.anyRequest().hasRole("OPS"))
            .httpBasic(basic -> basic
                // Plain 401 without "WWW-Authenticate: Basic", so browsers do not pop a dialog
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // No cookies are used by this chain, so there is no ambient credential to forge
            .csrf(csrf -> csrf.disable());
        return http.build();
    }
}
```

(Strictly, RFC 9110 requires a `WWW-Authenticate` challenge on every `401`; an entry point that sends a non-Basic challenge, as suggested in section 1.4, stays compliant without triggering the popup. For clients that send credentials only after a challenge, such as Java's `HttpClient` with an `Authenticator` or `curl --anyauth`, keep the default entry point, which sends `WWW-Authenticate: Basic realm="Realm"`. Plain `curl -u` sends Basic credentials preemptively and does not need it.)

### 11.2 API key authentication with `AuthenticationFilter`

Spring Security has no built-in API key filter, but its generic `AuthenticationFilter` (an `AuthenticationConverter` that extracts credentials plus an `AuthenticationManager` that verifies them) is exactly the right shape.

```java
@Configuration
@EnableWebSecurity
class ApiKeySecurityConfig {

    @Bean
    @Order(2)
    SecurityFilterChain apiChain(HttpSecurity http, ApiKeyAuthenticationProvider apiKeyProvider) throws Exception {
        AuthenticationFilter apiKeyFilter = new AuthenticationFilter(
                new ProviderManager(apiKeyProvider),
                request -> {                                   // AuthenticationConverter
                    String header = request.getHeader(HttpHeaders.AUTHORIZATION);
                    if (header == null || !header.startsWith("Bearer acme_")) {
                        return null;                           // not an API key: let the chain continue
                    }
                    return ApiKeyAuthenticationToken.unauthenticated(header.substring("Bearer ".length()));
                });
        apiKeyFilter.setSuccessHandler((request, response, authentication) -> { }); // continue the chain
        apiKeyFilter.setFailureHandler(new AuthenticationEntryPointFailureHandler(
                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));

        http
            .securityMatcher("/v1/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/v1/invoices/**").hasAuthority("SCOPE_invoices:read")
                .requestMatchers(HttpMethod.POST, "/v1/invoices/**").hasAuthority("SCOPE_invoices:write")
                .anyRequest().authenticated())
            .addFilterBefore(apiKeyFilter, AuthorizationFilter.class)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
            .csrf(csrf -> csrf.disable());   // keys are sent explicitly in a header, never via cookies
        return http.build();
    }
}
```

The provider hashes the presented key, looks it up, and maps scopes to authorities:

```java
@Component
class ApiKeyAuthenticationProvider implements AuthenticationProvider {

    private final ApiKeyRepository keys;
    private final ApiKeyHasher hasher;       // HMAC-SHA256 with a pepper loaded from a secret manager
    private final Clock clock;

    ApiKeyAuthenticationProvider(ApiKeyRepository keys, ApiKeyHasher hasher, Clock clock) {
        this.keys = keys;
        this.hasher = hasher;
        this.clock = clock;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        String presented = (String) authentication.getCredentials();
        if (!ApiKeyFormat.hasValidChecksum(presented)) {
            throw new BadCredentialsException("Invalid API key");
        }
        ApiKeyRecord key = keys.findByHash(hasher.hash(presented))
                .filter(k -> k.revokedAt() == null)
                .filter(k -> k.expiresAt() == null || k.expiresAt().isAfter(clock.instant()))
                .orElseThrow(() -> new BadCredentialsException("Invalid API key")); // same message for all cases
        keys.recordUsageAsync(key.id(), clock.instant());
        var authorities = key.scopes().stream()
                .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                .toList();
        return ApiKeyAuthenticationToken.authenticated(key.ownerId(), key.id(), authorities);
    }

    @Override
    public boolean supports(Class<?> type) {
        return ApiKeyAuthenticationToken.class.isAssignableFrom(type);
    }
}
```

`ApiKeyAuthenticationToken`, `ApiKeyHasher`, `ApiKeyFormat`, and the repository are small classes you write yourself. A complete runnable version — hashed keys with scopes and rotation, plus HMAC-signed webhook verification with a timestamp window and nonce cache — is in [`../examples/05-api-keys-hmac/`](../examples/05-api-keys-hmac/).

---

## Interview questions

**1. What is the difference between 401 and 403?**
401 means the request lacks valid authentication credentials; the server must send a `WWW-Authenticate` challenge and the client can retry with credentials. 403 means the server knows (or does not care) who you are and refuses anyway — re-authenticating will not help. Use 404 when even revealing existence would leak information.

**2. Why is HTTP Basic considered insecure, and when is it acceptable?**
It sends a reusable password, only base64-encoded, on every request, with no expiry, logout, or MFA, and browsers cache it as an ambient credential. It is acceptable over TLS for machine-to-machine calls where the "password" is a high-entropy, rotatable secret — for example OAuth `client_secret_basic`.

**3. Digest avoids sending the password. Why did it not win?**
The server must store `H(user:realm:password)`, which is a password-equivalent and cannot be a slow salted hash; implementations used MD5 for years; it is vulnerable to downgrade to Basic; it only protected method and URI. TLS solved the cleartext problem more completely, so Digest's main advantage disappeared.

**4. What does "bearer" mean, and how do you reduce bearer-token risk?**
Whoever holds the token can use it. Reduce risk with short lifetimes (5–15 minutes), audience restriction, sending only in the `Authorization` header, and sender-constraining with DPoP (RFC 9449) or mTLS (RFC 8705).

**5. How should API keys be stored, and why not with bcrypt or Argon2?**
Store only a hash — HMAC-SHA-256 with a server-side pepper, or SHA-256. Slow hashes exist to protect low-entropy passwords from offline guessing; a 256-bit random key cannot be guessed, and keys are checked on every request, so a slow hash would only add latency and DoS risk.

**6. Why give API keys a recognizable prefix?**
So secret scanners (GitHub secret scanning, gitleaks) can detect leaked keys with almost no false positives and trigger automatic revocation, and so humans can tell key types and environments (`live` vs `test`) apart. A checksum lets you reject typos and random strings without a database lookup.

**7. How do you rotate an API key without downtime?**
Allow two active keys per integration. Issue a new key, let the client deploy it, confirm via `last_used_at` that traffic moved, then revoke the old key. Expiry reminders push owners to do this regularly.

**8. Walk through HMAC request signing and how it prevents replay.**
Client and server share a secret. The client builds a canonical request (method, path, sorted query, chosen headers, body hash), adds a timestamp and nonce, and sends `HMAC-SHA256(secret, string_to_sign)`. The server rebuilds the same bytes, recomputes, compares in constant time, rejects timestamps outside ±5 minutes, and rejects nonces it has already seen within that window.

**9. Why must you verify webhook signatures on the raw body?**
The HMAC was computed over exact bytes. Parsing and re-serializing JSON changes whitespace, key order, and escaping, so the signature will not match — or worse, developers disable the check. Read the body as bytes, verify, then parse.

**10. What is a timing attack on token comparison, and how do you prevent it in Java?**
Normal equality stops at the first different byte, so response time reveals how many leading bytes were correct, letting an attacker recover a MAC byte by byte. Use `MessageDigest.isEqual` on fixed-length byte arrays (or compare hashes of both values).

---

## References

- RFC 9110 — HTTP Semantics (section 11: HTTP Authentication; 401, 403, 407): https://www.rfc-editor.org/rfc/rfc9110
- RFC 7235 — HTTP/1.1 Authentication (obsoleted by RFC 9110, historical): https://www.rfc-editor.org/rfc/rfc7235
- RFC 7617 — The 'Basic' HTTP Authentication Scheme: https://www.rfc-editor.org/rfc/rfc7617
- RFC 7616 — HTTP Digest Access Authentication: https://www.rfc-editor.org/rfc/rfc7616
- RFC 2617 — HTTP Authentication: Basic and Digest Access Authentication (historical): https://www.rfc-editor.org/rfc/rfc2617
- RFC 6750 — The OAuth 2.0 Authorization Framework: Bearer Token Usage: https://www.rfc-editor.org/rfc/rfc6750
- RFC 6749 — The OAuth 2.0 Authorization Framework (section 2.3.1, client password authentication): https://www.rfc-editor.org/rfc/rfc6749
- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP): https://www.rfc-editor.org/rfc/rfc9449
- RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens: https://www.rfc-editor.org/rfc/rfc8705
- RFC 4559 — SPNEGO-based Kerberos and NTLM HTTP Authentication in Microsoft Windows: https://www.rfc-editor.org/rfc/rfc4559
- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication: https://www.rfc-editor.org/rfc/rfc2104
- RFC 9421 — HTTP Message Signatures: https://www.rfc-editor.org/rfc/rfc9421
- RFC 9530 — Digest Fields (`Content-Digest`): https://www.rfc-editor.org/rfc/rfc9530
- IANA HTTP Authentication Scheme Registry: https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml
- IETF HTTPAPI — RateLimit header fields for HTTP (draft): https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/
- AWS — Signature Version 4 for API requests: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html
- Stripe — Check webhook signatures: https://docs.stripe.com/webhooks#verify-events
- GitHub — Validating webhook deliveries: https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
- GitHub — Secret scanning partner program: https://docs.github.com/en/code-security/secret-scanning/secret-scanning-partnership-program/secret-scanning-partner-program
- Standard Webhooks specification: https://www.standardwebhooks.com/
- OWASP REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- OWASP Server-Side Request Forgery Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- Spring Security reference — Servlet authentication architecture (`AuthenticationFilter`, `AuthenticationEntryPoint`): https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html
