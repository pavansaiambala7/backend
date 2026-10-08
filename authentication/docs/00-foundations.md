# 00 — Foundations: Identity, Factors, State, Cryptography and Threats

Every authentication system, from a 1960s password file to a 2026 passkey, answers the same question: *is this request really coming from who it claims to be?* This chapter builds the vocabulary and mental models that the rest of the guide relies on: the difference between identifying, authenticating and authorizing; the three factor categories; why HTTP's statelessness shapes every web login design; the cryptographic building blocks (and which one to use when); what TLS does and does not give you; and the threats you are designing against. Read it first, and come back to the glossary whenever a later chapter uses a term you are not sure about.

> **Where this fits in the evolution**
>
> - **Before:** Nothing. This chapter is the toolbox, not an era. But every era in [the evolution chapter](01-evolution-of-authentication.md) is a different combination of the same pieces: a secret or key, a way to prove you hold it, a way to remember the result between requests, and a channel that protects all of it.
> - **What it solves:** It gives you the concepts to judge any mechanism on its own merits: what is the credential, where does it travel, who can replay it, how long does it live, how is it revoked?
> - **What comes next:** [Passwords and credential storage](02-passwords-and-credential-storage.md), then the protocols built on top of these ideas: [HTTP auth](03-http-basic-digest-and-api-keys.md), [sessions](04-sessions-cookies-and-csrf.md), [JWT](06-tokens-and-jwt.md), [OAuth 2](08-oauth-2.md), [OpenID Connect](10-openid-connect.md) and [passkeys](11-mfa-passwordless-and-passkeys.md).

---

## Table of contents

1. [Identification, authentication, authorization, accounting](#1-identification-authentication-authorization-accounting)
2. [Authentication factors and context signals](#2-authentication-factors-and-context-signals)
3. [HTTP is stateless, and why that matters](#3-http-is-stateless-and-why-that-matters)
4. [Stateful vs stateless authentication](#4-stateful-vs-stateless-authentication)
5. [Encoding, hashing, MAC, encryption, signatures](#5-encoding-hashing-mac-encryption-signatures)
6. [Symmetric vs asymmetric cryptography](#6-symmetric-vs-asymmetric-cryptography)
7. [The role of TLS](#7-the-role-of-tls)
8. [Threat model basics](#8-threat-model-basics)
9. [Never roll your own crypto (or your own protocol)](#9-never-roll-your-own-crypto-or-your-own-protocol)
10. [Production best practices (2026)](#10-production-best-practices-2026)
11. [Common attacks and mistakes](#11-common-attacks-and-mistakes)
12. [Spring Boot 4 / Spring Security 7 snippets](#12-spring-boot-4--spring-security-7-snippets)
13. [Glossary](#13-glossary)
14. [Interview questions](#interview-questions)
15. [References](#references)

---

## 1. Identification, authentication, authorization, accounting

### 1.1 Four different questions

People say "auth" for all of these, which causes real bugs. Keep them separate:

| Step | Question it answers | Example | Typical HTTP failure |
|---|---|---|---|
| **Identification** | *Who do you claim to be?* | Typing `alice@example.com` in a login form; the `sub` claim in a token; a client ID | None by itself. A claim of identity proves nothing. |
| **Authentication** (AuthN) | *Can you prove it?* | Password check, passkey signature, TOTP code, client certificate | `401 Unauthorized` (the name is historical; it means "unauthenticated") |
| **Authorization** (AuthZ) | *Are you allowed to do this?* | "Alice may read invoice 42 but not delete it" | `403 Forbidden` (or `404` to hide that the resource exists) |
| **Accounting** (auditing) | *What did you do, and when?* | Audit log: "alice deleted invoice 42 at 10:02 from 203.0.113.7" | None; it happens after the fact |

The classic acronym is **AAA** (Authentication, Authorization, Accounting), which comes from network access protocols such as RADIUS (see [enterprise SSO](05-enterprise-sso-ldap-kerberos-saml.md)). Identification is the step that comes before them.

```mermaid
flowchart LR
    A["Identification<br/>I am alice"] --> B["Authentication<br/>prove it"]
    B -->|"proof fails"| X["401 Unauthorized"]
    B -->|"proof ok"| C["Authorization<br/>may alice do this?"]
    C -->|"no"| Y["403 Forbidden"]
    C -->|"yes"| D["Perform action"]
    D --> E["Accounting<br/>audit log entry"]
    X --> E
    Y --> E
```

### 1.2 Why the separation matters in practice

- **Authentication without authorization is a common breach pattern.** An API that checks "is the token valid?" but never checks "does this token's user own invoice 42?" is vulnerable to Broken Object Level Authorization (BOLA), which sits at the top of the OWASP API Security Top 10. A valid login is not permission. See [authorization](13-authorization-rbac-abac-rebac.md).
- **Authorization protocols are not authentication protocols.** OAuth 2.0 issues *access tokens* that say "the bearer may call this API". It does not tell a client *who the user is*. OpenID Connect adds that layer with the ID token. Using a plain OAuth access token as proof of login leads to token-substitution attacks. See [OAuth 2](08-oauth-2.md) and [OpenID Connect](10-openid-connect.md).
- **Accounting is how you detect what authentication missed.** Failed logins, new devices, password resets and token refreshes should all produce structured audit events. Without them you cannot spot credential stuffing or investigate an account takeover.

### 1.3 Authentication is a moment; sessions carry it forward

Authentication happens once, at a point in time (the "authentication event"). Everything after that is the application *remembering* the result: a session cookie, an access token, a ticket. A lot of security work is about that memory:

- How long it lasts (session timeouts, token lifetimes).
- Whether it can be stolen and replayed (cookies, bearer tokens).
- How you force a fresh authentication for sensitive actions (re-authentication, step-up).

NIST SP 800-63B-4 makes this concrete. For example, at assurance level AAL2 it says the overall session timeout *SHOULD* be no more than 24 hours and the inactivity timeout *SHOULD* be no more than 1 hour; at AAL3 the limits are 12 hours (*SHALL*) and 15 minutes (*SHOULD*).

---

## 2. Authentication factors and context signals

### 2.1 The three factor categories

| Factor | "Something you..." | Examples | Main weaknesses |
|---|---|---|---|
| **Knowledge** | know | Password, PIN, passphrase, security question | Phishable, guessable, reused across sites, leaked in breaches |
| **Possession** | have | Phone with an authenticator app, hardware security key, passkey on a device, smart card, client certificate | Lost or stolen device; some forms (SMS, TOTP) can still be phished |
| **Inherence** | are | Fingerprint, face, voice | Probabilistic, cannot be changed if leaked, usually only unlocks a local key |

**Multi-factor authentication (MFA)** means proving *two or more different categories*. A password plus a security question is two knowledge factors, so it is **not** MFA. NIST also notes that a biometric on its own is not a sufficient authenticator; in modern systems a fingerprint or face usually *unlocks* a private key stored on the device (a possession factor), which is how passkeys work.

### 2.2 Phishing resistance is a separate property

Counting factors is not enough. An attacker-in-the-middle (AiTM) phishing site can relay a password *and* a TOTP code to the real site in real time, or trigger a push prompt that the victim approves because they believe they are logging in. What stops it is **origin binding**: the credential refuses to work for the wrong website.

| Method | Factors | Phishing-resistant? | Why |
|---|---|---|---|
| Password | 1 (know) | No | User can type it anywhere. NIST: "Passwords are not phishing-resistant." |
| Password + SMS code | 2 | No | Code can be relayed; SMS also vulnerable to SIM swap. NIST lists PSTN delivery as a *restricted* authenticator. |
| Password + TOTP app | 2 | No | Code can be relayed within its 30-second window |
| Password + push approval | 2 | No | Relay plus "MFA fatigue" (spamming prompts until the user taps approve) |
| Passkey / WebAuthn | 1 or 2 (have, plus user verification) | **Yes** | The browser binds the signature to the real origin; a look-alike domain gets nothing usable |
| Client certificate (mTLS) | 1 (have) | **Yes** | The private key never leaves the client and the TLS session is bound to the real server |

NIST SP 800-63B-4 requires verifiers to *offer* at least one phishing-resistant option at AAL2 and requires phishing resistance at AAL3. Details in [MFA and passkeys](11-mfa-passwordless-and-passkeys.md).

### 2.3 Context signals (risk-based authentication)

Modern systems also look at **signals** that are not factors but change how much proof they ask for:

| Signal | Example use |
|---|---|
| Device | Known device (long-lived device cookie, platform attestation) vs never seen before |
| Network | Residential IP vs hosting provider, VPN or anonymizer; IP reputation |
| Location and time | Impossible travel (London then Sydney ten minutes later), unusual hours |
| Behavior | Typing cadence, navigation patterns, request rate, bot detection |
| Transaction risk | Viewing a dashboard vs changing the payout bank account |

Signals feed **adaptive** or **step-up** authentication: allow, ask for another factor, slow down, or block. They are probabilistic and spoofable, so use them to *add* friction, never as the only proof of identity.

### 2.4 Assurance levels in one table

NIST SP 800-63B-4 grades the strength of an authentication event as an **Authenticator Assurance Level (AAL)**:

| Level | Requires | Typical use |
|---|---|---|
| AAL1 | Single factor (e.g. password) | Low-risk consumer apps |
| AAL2 | Two factors; verifiers must offer a phishing-resistant option | Most business and consumer apps with personal data |
| AAL3 | Phishing-resistant, hardware-backed, non-exportable private key | High-value admin, government, finance back-office |

---

## 3. HTTP is stateless, and why that matters

### 3.1 What "stateless" means

HTTP treats every request as independent. The server does not remember, at the protocol level, that the request it just received came from the same person who logged in a second ago. Connections are reused and pooled, load balancers spread requests across servers, and nothing in HTTP itself says "this is still Alice".

So after authenticating once, the client must send *something* with every subsequent request that lets the server recognize it. There are only three basic options, and every web authentication design is one of them or a mix:

| Option | What the client sends every time | Example | Chapter |
|---|---|---|---|
| Re-send the credential | The password or API key itself | HTTP Basic, static API keys | [03](03-http-basic-digest-and-api-keys.md) |
| Send a reference | An opaque, random **session ID** the server looks up | `Cookie: SESSION=...` | [04](04-sessions-cookies-and-csrf.md) |
| Send a self-contained token | A signed **token** carrying the claims | `Authorization: Bearer eyJ...` (JWT) | [06](06-tokens-and-jwt.md) |

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant S as Server
    B->>S: POST /login with username and password
    S->>S: Verify password hash
    S-->>B: 303 See Other plus Set-Cookie SESSION
    Note over B,S: HTTP forgets everything between requests
    B->>S: GET /orders plus Cookie SESSION
    S->>S: Look up session, find user alice
    S-->>B: 200 OK with alice's orders
    B->>S: GET /orders without a cookie
    S-->>B: 401 or redirect to /login
```

### 3.2 The raw HTTP

The first request has no credentials; the server says so with `401` and a challenge (for APIs) or a redirect to a login page (for browser apps):

```http
GET /api/orders HTTP/1.1
Host: api.example.com
Accept: application/json
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="api"
Content-Type: application/problem+json

{"type":"about:blank","title":"Unauthorized","status":401}
```

(RFC 6750 says the challenge should not include an `error` code when the request carried no credentials at all; `error="invalid_token"` is for expired, revoked or malformed tokens.)

After login, a browser app receives a session cookie:

```http
HTTP/1.1 303 See Other
Location: /dashboard
Set-Cookie: SESSION=3q2-7wE_vS1x...; Path=/; Secure; HttpOnly; SameSite=Lax
Cache-Control: no-store
```

And sends it back automatically on every request to that site:

```http
GET /dashboard HTTP/1.1
Host: app.example.com
Cookie: SESSION=3q2-7wE_vS1x...
```

An API client sends a token in the `Authorization` header instead:

```http
GET /api/orders HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMjYtMTAiLCJ0eXAiOiJhdCtqd3QifQ...
```

### 3.3 Consequences that drive the rest of this guide

1. **Whatever the client re-sends is a bearer credential.** Anyone who steals the session cookie or the token can replay it until it expires. That is why cookies get `HttpOnly`, `Secure` and `SameSite`, why access tokens are short-lived, and why modern OAuth adds sender-constrained tokens (DPoP, mTLS) that only work for the client holding a private key.
2. **Browsers attach cookies automatically.** That convenience is the root cause of **CSRF**: another site can make the browser send a request *with* your cookies. Header-based tokens are not sent automatically, so they do not have this problem, but they must be stored somewhere JavaScript can read, which brings **XSS** token theft. See [sessions, cookies and CSRF](04-sessions-cookies-and-csrf.md).
3. **Something must be checked on every request.** That check has a cost (a session store lookup, or a signature verification), and its design decides how you scale and how fast you can revoke access.

---

## 4. Stateful vs stateless authentication

"Stateful" and "stateless" describe *where the authentication state lives*: on the server, or inside the credential the client carries.

| Aspect | Stateful (server-side session) | Stateless (self-contained token, e.g. JWT) |
|---|---|---|
| What the client holds | Opaque random ID (no meaning) | Signed claims (user, scopes, expiry) |
| Server per-request work | Look up the ID in a session store | Verify signature and claims, no lookup |
| Revocation | Delete the session: instant | Hard: token is valid until `exp` unless you add a denylist or introspection |
| Horizontal scaling | Needs a shared store (Redis, database) or sticky sessions | Any instance with the public key can verify |
| Size on the wire | ~20-40 bytes | Often 500 bytes to several KB |
| Data freshness | Always current (roles read from store) | Claims are a snapshot from issuance time |
| Typical home | Browser apps (with cookies) | APIs, service-to-service calls, cross-domain |

```mermaid
flowchart LR
    subgraph Stateful
        C1["Client<br/>SESSION=abc123"] --> S1["App instance"]
        S1 --> R1[("Session store<br/>abc123 to alice, roles")]
    end
    subgraph Stateless
        C2["Client<br/>signed JWT"] --> S2["App instance"]
        S2 --> K2["Public key from JWKS<br/>cached locally"]
    end
```

### 4.1 It is a spectrum, not a choice

Real production systems mix the two:

- **Short-lived stateless access tokens + stateful refresh tokens.** Access tokens live 5-15 minutes and are verified locally. Refresh tokens are stored (hashed) on the authorization server, rotated on every use and revocable instantly. Revocation latency becomes "at most one access-token lifetime". See [JWT](06-tokens-and-jwt.md) and [../examples/02-jwt-auth/](../examples/02-jwt-auth/).
- **The BFF (Backend for Frontend) pattern.** The browser holds only an `HttpOnly` session cookie (stateful). The BFF holds the OAuth tokens server-side and attaches them when calling APIs (stateless). This keeps tokens out of JavaScript. See [../examples/03-oauth2-oidc/](../examples/03-oauth2-oidc/).
- **Token introspection.** Opaque access tokens that resource servers check with the authorization server (RFC 7662): stateful, but centralized.

Rule of thumb: **for browser apps, prefer server-side sessions or a BFF; for APIs and services, use short-lived signed tokens.** Do not choose JWTs for a single monolith just because they are fashionable; you would be trading easy revocation for nothing.

---

## 5. Encoding, hashing, MAC, encryption, signatures

These five are constantly confused, and the confusion causes real vulnerabilities (Base64 "encryption", fast hashes for passwords, encrypted-but-reversible password stores).

### 5.1 The comparison table

| Primitive | Key? | Reversible? | Protects | Example algorithms | Used in authentication for |
|---|---|---|---|---|---|
| **Encoding** | No | Yes, by anyone | Nothing. It changes representation only. | Base64, Base64URL, hex, URL encoding | Basic auth header format, JWT segments |
| **Hashing** | No | No (one-way) | Integrity against accidents; fingerprinting | SHA-256, SHA-3, BLAKE2 | Hashing high-entropy tokens before storage, PKCE `S256`, HIBP lookups |
| **Password hashing (KDF)** | No (salt is public) | No, and deliberately *slow* | Stored passwords against offline guessing | Argon2id, scrypt, bcrypt, PBKDF2 | Password storage ([chapter 02](02-passwords-and-credential-storage.md)) |
| **MAC** | Shared secret | No | Integrity + authenticity between parties sharing a key | HMAC-SHA256, KMAC | Signed cookies, webhook signatures, HS256 JWTs, TOTP |
| **Encryption** | Shared secret (symmetric) or public key | Yes, with the key | Confidentiality (AEAD modes add integrity) | AES-GCM, ChaCha20-Poly1305, RSA-OAEP, HPKE | TLS, encrypted cookies, JWE, secrets at rest |
| **Digital signature** | Private key signs, public key verifies | No | Integrity + authenticity + non-repudiation; anyone can verify | RSA-PSS / RS256, ECDSA P-256 (ES256), Ed25519 | JWTs (RS256/ES256/EdDSA), SAML assertions, WebAuthn, certificates |

```mermaid
flowchart TD
    Q1{"What do you need?"} -->|"Just a safe text format"| E["Encoding<br/>Base64URL"]
    Q1 -->|"Store a password"| P["Password hash<br/>Argon2id"]
    Q1 -->|"Store a random token or API key"| H["Fast hash<br/>SHA-256"]
    Q1 -->|"Detect tampering, both sides share a key"| M["MAC<br/>HMAC-SHA256"]
    Q1 -->|"Detect tampering, many verifiers"| S["Signature<br/>ES256 or RS256 or Ed25519"]
    Q1 -->|"Hide the content"| C["Encryption<br/>AES-256-GCM"]
```

### 5.2 Encoding is not security

```text
alice:correct horse battery staple
      --Base64-->
YWxpY2U6Y29ycmVjdCBob3JzZSBiYXR0ZXJ5IHN0YXBsZQ==
```

Anyone can reverse that in one line. HTTP Basic sends exactly this, which is why it is only acceptable over TLS. A JWT payload is also just Base64URL-encoded JSON: **anyone holding a JWT can read its claims**. Never put secrets or sensitive personal data in a signed-only JWT.

### 5.3 Hashing: one-way fingerprints

A cryptographic hash maps any input to a fixed-size digest with three properties: you cannot find an input from a digest (preimage resistance), you cannot find a second input with the same digest as a given one (second-preimage resistance), and you cannot find any two inputs with the same digest (collision resistance). MD5 and SHA-1 have practical collision attacks (MD5 since 2004, SHA-1 publicly since the 2017 "SHAttered" collision) and must not be used where collisions matter.

Two different jobs need two different hashes:

- **High-entropy secrets** (random 256-bit session IDs, API keys, refresh tokens, reset tokens): a fast hash like SHA-256 is fine, because there is nothing to guess. Brute-forcing 2^256 possibilities is impossible at any speed.
- **Low-entropy secrets** (human-chosen passwords): a fast hash is a disaster, because attackers can try billions of guesses per second on GPUs. Use a slow, memory-hard password hashing function with a unique salt. See [chapter 02](02-passwords-and-credential-storage.md).

### 5.4 MAC: proving a message came from a key holder

A Message Authentication Code is a keyed checksum: `tag = HMAC(key, message)`. Only someone with the key can produce a valid tag, and any change to the message breaks it. It does not hide the message.

Typical uses: webhook signatures (`X-Signature: sha256=...`), signed session cookies, TOTP codes (RFC 6238 is HMAC over a time counter), and HS256 JWTs.

The catch: **every verifier also has the key and can therefore forge tags.** That is fine between two parties, but if five microservices verify HS256 JWTs, any one of them can mint tokens for all the others. When more than one service verifies, use signatures.

Always compare MACs in **constant time** (`MessageDigest.isEqual` in Java). A normal `equals` returns early at the first differing byte, and the timing difference can leak the correct tag byte by byte.

### 5.5 Encryption: hiding content

Use **authenticated encryption (AEAD)** such as AES-GCM or ChaCha20-Poly1305: it provides confidentiality *and* detects tampering. Unauthenticated modes (ECB, raw CBC) leak patterns or allow tampering; Adobe's 2013 breach exposed passwords encrypted with 3DES in ECB mode, where identical passwords produced identical ciphertexts. With AES-GCM, never reuse a nonce with the same key; reuse breaks both confidentiality and integrity.

Passwords should almost never be *encrypted* for storage, because encryption is reversible: whoever gets the key gets every password. Hash them instead.

### 5.6 Digital signatures: anyone can verify, only one can sign

The signer holds a private key; verifiers need only the public key. This is what makes federation work: an identity provider signs an ID token or SAML assertion, and any number of relying parties verify it with the provider's published public key (for OAuth/OIDC, a JWKS document) without being able to forge new ones.

Signatures are the reason JWTs can be verified locally, the reason passkeys resist server breaches (the server stores only public keys), and the reason TLS certificates work.

---

## 6. Symmetric vs asymmetric cryptography

| Aspect | Symmetric | Asymmetric (public-key) |
|---|---|---|
| Keys | One shared secret | Key pair: private (secret) + public (shareable) |
| Speed | Very fast | Much slower |
| Key distribution | Hard: every pair of parties needs a secret delivered safely | Easy: publish the public key |
| Primitives | AES-GCM, ChaCha20-Poly1305, HMAC | RSA, ECDSA, EdDSA (Ed25519), ECDH/X25519, ML-KEM, ML-DSA |
| Auth uses | Session cookie MACs, HS256, TOTP seeds, Kerberos tickets | JWT RS256/ES256/EdDSA, WebAuthn, mTLS, SAML, TLS certificates |
| If the verifier is breached | Attacker can impersonate users (has the shared secret) | Attacker learns only public keys |

In practice the two are combined (hybrid cryptography): TLS uses asymmetric key exchange and certificates to agree on fresh symmetric keys, then encrypts traffic symmetrically.

### 6.1 Key sizes and algorithms for 2026

| Purpose | Recommended | Acceptable minimum | Avoid |
|---|---|---|---|
| Symmetric encryption | AES-256-GCM, ChaCha20-Poly1305 | AES-128-GCM | DES, 3DES, RC4, ECB mode |
| MAC | HMAC-SHA256 with a 256-bit random key | HMAC-SHA256 | HMAC with short or human-chosen keys |
| Signatures (tokens) | ES256 (P-256) or EdDSA (Ed25519) | RS256 with RSA 2048 bits (3072 for keys meant to live past 2030) | RSA below 2048, `none`, MD5/SHA-1 based |
| Key exchange | X25519 or P-256 ECDHE; hybrid X25519 + ML-KEM-768 where supported | P-256 ECDHE | Static RSA key exchange, finite-field DH below 2048 |
| Hash | SHA-256, SHA-384, SHA-3 | SHA-256 | MD5, SHA-1 |

RSA 2048 and P-256 both give at least the 112-bit security strength that NIST SP 800-57 sets as the current minimum (P-256 gives 128).

**Post-quantum note.** NIST published its first post-quantum standards in August 2024: FIPS 203 (ML-KEM, key encapsulation), FIPS 204 (ML-DSA, signatures) and FIPS 205 (SLH-DSA, hash-based signatures). Key exchange is being migrated first, because "harvest now, decrypt later" threatens recorded traffic today; major browsers and CDNs have started negotiating hybrid key exchange (classical X25519 combined with ML-KEM) in TLS 1.3. Post-quantum *signatures* for JWTs and certificates are still being standardized and deployed. For an application developer in 2026 the practical advice is: use your platform's TLS defaults, keep algorithms configurable (allowlists, `kid`-based key rotation) so you can migrate later, and never hard-code a single algorithm deep in business logic.

---

## 7. The role of TLS

### 7.1 What TLS gives you

TLS (Transport Layer Security; TLS 1.3 was published as RFC 8446 in 2018 and revised as RFC 9846 in July 2026) provides three things for the connection:

1. **Confidentiality.** Passwords, cookies and tokens cannot be read by anyone on the network path (Wi-Fi, ISP, proxies).
2. **Integrity.** Requests and responses cannot be modified in transit.
3. **Server authentication.** The certificate proves the client is talking to the real `app.example.com`, not an impostor. Optionally, **mutual TLS (mTLS)** also authenticates the client with its own certificate.

### 7.2 What TLS does not give you

- **It does not authenticate the user.** TLS protects the channel that carries the password; it does not check the password. (mTLS authenticates a client *key*, which identifies a device or service, not necessarily a person.)
- **It does not protect data at the endpoints.** XSS in the browser, a compromised server, or logs that record tokens all bypass TLS.
- **It does not stop phishing.** A phishing site at `examp1e.com` can have a perfectly valid certificate. Only origin-bound credentials (passkeys) solve that.
- **It usually ends at the edge.** TLS is often terminated at a load balancer or API gateway. Traffic behind it is plain HTTP unless you re-encrypt (or use a service mesh with mTLS). In a zero-trust design, internal hops are encrypted and authenticated too. See [service-to-service and zero trust](12-service-to-service-and-zero-trust.md).

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server
    C->>S: ClientHello with supported versions, ciphers, key share
    S-->>C: ServerHello with key share
    S-->>C: Certificate, CertificateVerify, Finished (encrypted)
    C->>C: Validate certificate chain, hostname, expiry
    C->>S: Finished
    Note over C,S: Encrypted channel established. TLS has authenticated the SERVER only.
    C->>S: POST /login with password, inside TLS
    S-->>C: Set-Cookie SESSION, inside TLS
    Note over C,S: Application-level authentication runs on top of TLS
```

### 7.3 TLS rules for authentication systems

| Rule | Why |
|---|---|
| HTTPS everywhere, including "internal" pages and redirects | One plain-HTTP request can leak a cookie. Firesheep (2010) hijacked Facebook and Twitter sessions on open Wi-Fi this way. |
| TLS 1.2 minimum, TLS 1.3 preferred; TLS 1.0/1.1 disabled | RFC 8996 (2021) formally deprecated TLS 1.0 and 1.1 |
| HSTS: `Strict-Transport-Security: max-age=31536000; includeSubDomains` (add `preload` when ready) | Stops SSL-stripping downgrade attacks after the first visit (RFC 6797) |
| `Secure` attribute on every auth cookie | Browser never sends the cookie over plain HTTP |
| Never disable certificate validation in clients (no "trust all" `TrustManager`) | Disabling it turns every HTTPS call into a MITM opportunity |
| Automate certificate renewal (ACME) | Public TLS certificate lifetimes are shrinking: 200 days from March 2026, scheduled to fall to 100 days in 2027 and 47 days in 2029 (CA/Browser Forum ballot SC-081) |
| Re-encrypt or use mTLS behind the load balancer for sensitive traffic | "Internal network" is not a security boundary |

---

## 8. Threat model basics

### 8.1 Think like the attacker

A threat model asks four questions: *What are we building? What can go wrong? What are we doing about it? Did we do a good job?* For authentication, the "S" in Microsoft's STRIDE model, **Spoofing** (pretending to be someone else), is the core threat, but tampering, information disclosure and elevation of privilege all show up too.

Attackers target four places: the **user**, the **channel**, the **client** (browser, mobile app), and the **server** (including its databases and its identity provider).

```mermaid
flowchart LR
    U["User"] -->|"credentials"| CL["Browser or app"]
    CL -->|"HTTPS"| SV["Server and IdP"]
    SV --> DB[("User store and sessions")]
    A1["Phishing, AiTM proxy,<br/>MFA fatigue, SIM swap"] -.-> U
    A2["XSS, malware,<br/>token theft from storage"] -.-> CL
    A3["MITM, SSL stripping,<br/>replay"] -.-> SV
    A4["Credential stuffing, brute force,<br/>password spraying, enumeration"] -.-> SV
    A5["Database breach,<br/>offline cracking"] -.-> DB
    A6["CSRF via the victim's browser"] -.-> CL
```

### 8.2 The threats you must know

| Threat | What happens | Primary defenses |
|---|---|---|
| **Phishing** | User enters credentials on a fake site. Modern kits run as a reverse proxy (AiTM) and capture the session cookie *after* MFA. | Passkeys/WebAuthn (origin-bound), FIDO security keys; short session lifetimes; detect new devices |
| **Credential stuffing** | Attacker replays username/password pairs leaked from *other* sites, relying on password reuse | MFA, breached-password checks, bot detection, rate limits per IP and per account, anomaly detection |
| **Brute force / password spraying** | Many guesses against one account, or one common password against many accounts | Throttling with increasing delays, NIST blocklist of common passwords, MFA, monitoring of failures across accounts |
| **Offline cracking** | After a database breach, attacker guesses passwords against stolen hashes at GPU speed | Argon2id/scrypt/bcrypt with unique salts, optional pepper in an HSM or KMS, breach detection |
| **Man-in-the-middle (MITM)** | Attacker on the network reads or alters traffic | TLS everywhere, HSTS, certificate validation, mTLS internally |
| **XSS (cross-site scripting)** | Injected script runs in your origin: reads tokens from `localStorage`, makes authenticated calls | Output encoding, Content Security Policy, `HttpOnly` cookies, never store tokens in `localStorage` |
| **CSRF (cross-site request forgery)** | Another site makes the victim's browser send a state-changing request with the victim's cookies | `SameSite` cookies, synchronizer or double-submit CSRF tokens, checking `Origin` / `Sec-Fetch-Site` |
| **Replay** | A captured valid message (token, signed request, OTP) is sent again | Short lifetimes, nonces, timestamps, one-time use, sender-constrained tokens (DPoP, mTLS) |
| **Session hijacking** | Attacker obtains a valid session ID (sniffing, XSS, malware, logs) | `Secure`/`HttpOnly`, TLS, rotation on login, idle and absolute timeouts, device binding where available |
| **Session fixation** | Attacker plants a known session ID before login; it stays valid after login | Issue a new session ID on every privilege change (Spring Security does this by default) |
| **Token theft** | Bearer token stolen from storage, logs, URLs or a compromised dependency | Short-lived access tokens, refresh rotation with reuse detection, DPoP/mTLS binding, never put tokens in URLs |
| **User enumeration** | Different responses or timings reveal which usernames exist | Generic messages, consistent status codes and timing, rate limits |
| **Account recovery abuse** | Attacker resets the password via a weak recovery channel (email takeover, help desk social engineering, SIM swap) | Strong, rate-limited, single-use recovery; notify on every recovery; require existing factors where possible |
| **Insider / IdP compromise** | Admin or attacker with IdP signing keys mints valid tokens for anyone ("golden SAML") | HSM-held keys, key rotation, least privilege, monitoring token issuance |

### 8.3 Assume breach

Design as if each layer will eventually fail: the database *will* leak (so hash passwords properly), a token *will* be stolen (so it expires quickly and is bound to its sender), a user *will* be phished (so offer passkeys and detect anomalies). This "defense in depth" mindset is the thread running through the [production checklist](14-production-architecture-and-checklist.md).

---

## 9. Never roll your own crypto (or your own protocol)

### 9.1 What the rule means

"Don't roll your own crypto" does not only mean "don't invent a cipher". It covers three levels:

1. **Primitives:** never invent hash functions, ciphers or random number generators.
2. **Constructions:** never combine primitives yourself (your own "encrypt then hash with a secret", your own token format, your own password scheme like `sha256(salt + password)`).
3. **Protocols:** never design your own login, SSO or token-exchange protocol when OAuth 2, OpenID Connect, WebAuthn or SAML already exists and has been attacked and fixed for years.

Security protocols fail in subtle ways that tests do not catch: timing leaks, nonce reuse, missing audience checks, algorithm confusion, replay windows. Published standards have been formally analyzed and battle-tested; your weekend design has not.

### 9.2 Real failures caused by homemade designs

| Homemade choice | What went wrong |
|---|---|
| Passwords "protected" with reversible 3DES in ECB mode (Adobe, 2013) | Identical passwords had identical ciphertexts; combined with plaintext hints, many were recovered |
| Unsalted SHA-1 password hashes (LinkedIn, 2012) | Millions of hashes cracked quickly with precomputed tables and GPUs |
| JWT libraries trusting the token's `alg` header | `alg: none` accepted, or an RSA public key used as an HMAC secret (algorithm confusion) |
| `token.equals(expected)` for secrets | Timing side channel leaks the secret byte by byte |
| `Math.random()` or `java.util.Random` for session IDs or reset tokens | Predictable output; attacker can guess valid tokens |
| Custom "remember me" cookie containing `username + md5(password)` | Offline cracking of the password from a stolen cookie |

### 9.3 What to use instead (Java 21 / Spring)

| Need | Use |
|---|---|
| Password hashing | Spring Security `Argon2PasswordEncoder` inside a `DelegatingPasswordEncoder` ([chapter 02](02-passwords-and-credential-storage.md)) |
| Random tokens, session IDs | `java.security.SecureRandom`, at least 128 bits (256 bits for long-lived secrets) |
| Constant-time comparison | `java.security.MessageDigest.isEqual(a, b)` |
| JWT creation and validation | Spring Security OAuth2 Resource Server / Nimbus JOSE + JWT with an algorithm allowlist |
| Login, sessions, CSRF | Spring Security defaults (`formLogin`, session fixation protection, CSRF filter) |
| SSO and delegated access | OpenID Connect and OAuth 2 via Spring Security (`oauth2Login`, `oauth2ResourceServer`, Spring Authorization Server, now part of Spring Security 7) |
| Passkeys | Spring Security WebAuthn support (`http.webAuthn(...)`, plus the `spring-security-webauthn` module) |
| Encryption at rest, envelope encryption | A cloud KMS or a vetted library such as Google Tink |

---

## 10. Production best practices (2026)

| Area | Practice | Concrete numbers |
|---|---|---|
| Transport | TLS 1.3 preferred, 1.2 minimum, HSTS | `max-age=31536000; includeSubDomains` |
| Randomness | CSPRNG for every secret | Session IDs and tokens: at least 128 bits of entropy; API keys and refresh tokens: 256 bits |
| Passwords | Argon2id, NIST SP 800-63B-4 rules | m=19 MiB, t=2, p=1 minimum; 15+ characters for password-only accounts, 8+ when MFA is always required |
| MFA | Offer passkeys; accept TOTP; avoid SMS | NIST: PSTN/SMS is a *restricted* authenticator |
| Sessions | Server-side, rotated on login, `HttpOnly; Secure; SameSite` | Idle timeout 15-60 min; absolute 8-24 h depending on risk (NIST AAL2: SHOULD be ≤ 1 h idle, ≤ 24 h overall) |
| Access tokens | Short-lived, signed asymmetrically when multiple services verify | 5-15 min lifetime; ES256/EdDSA or RS256 with 2048+ bit RSA |
| Refresh tokens | Rotated every use, reuse detection, stored hashed | Absolute lifetime e.g. 7-30 days, idle e.g. 1-7 days |
| Keys | Rotate signing keys, publish via JWKS with `kid` | Rotate at least every 90 days to 1 year; keep the old public key published for at least the max token lifetime |
| Logging | Log authentication events, never log secrets | Never log passwords, tokens, cookies, `Authorization` headers or reset links |
| Browser storage | No tokens in `localStorage` or `sessionStorage` | Use `HttpOnly` cookies via sessions or a BFF |

---

## 11. Common attacks and mistakes

| Attack / mistake | What goes wrong | Mitigation |
|---|---|---|
| Treating authentication as authorization | Any logged-in user can read anyone's data (BOLA/IDOR) | Check ownership/permissions on every object access ([chapter 13](13-authorization-rbac-abac-rebac.md)) |
| Using an OAuth access token as proof of login | A token issued to another app can be replayed to log in as the victim | Use OpenID Connect and validate the ID token (`iss`, `aud`, `nonce`) |
| Base64 treated as encryption | Credentials or PII readable by anyone who sees the header or token | Use TLS for transport; JWE or don't include sensitive data at all |
| Fast hash (MD5/SHA-x) for passwords | GPU cracking recovers most passwords after a breach | Argon2id/scrypt/bcrypt with salt ([chapter 02](02-passwords-and-credential-storage.md)) |
| Sharing one HMAC key across many services | Any service can forge tokens for all others | Asymmetric signatures (RS256/ES256/EdDSA) with JWKS |
| Non-constant-time secret comparison | Timing attack reveals MACs or API keys | `MessageDigest.isEqual` |
| Predictable random numbers | Attackers guess session IDs or reset tokens | `SecureRandom`, at least 128 bits |
| Tokens in `localStorage` | Any XSS steals long-lived credentials | `HttpOnly` cookie sessions or BFF |
| Tokens or session IDs in URLs | Leak via browser history, logs, `Referer` header | Send in headers or cookies only; `Referrer-Policy: no-referrer` on sensitive pages |
| TLS only on the login page | Session cookie stolen on the next plain-HTTP request | HTTPS everywhere + HSTS + `Secure` cookies |
| Disabling certificate validation "temporarily" | MITM of every outbound call | Proper trust stores; fix the certificate instead |
| Logging `Authorization` headers or request bodies | Credentials end up in log storage with weak access control | Redact at the logging layer; review log configuration |
| Designing a custom token or SSO protocol | Subtle flaws (replay, audience confusion) go unnoticed | Use OAuth 2 / OIDC / WebAuthn / SAML via mature libraries |

---

## 12. Spring Boot 4 / Spring Security 7 snippets

### 12.1 Authentication vs authorization in one filter chain

The lambda DSL below shows the separation clearly: `formLogin` *authenticates*; `authorizeHttpRequests` *authorizes*; `exceptionHandling` decides between 401 and 403.

```java
package com.example.auth.foundations;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

@Configuration
class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // AUTHORIZATION: who may do what (evaluated after authentication)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/css/**", "/error").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            // AUTHENTICATION: how users prove who they are
            .formLogin(Customizer.withDefaults())
            // Unauthenticated API calls get 401 instead of a redirect to /login.
            // Authenticated-but-forbidden calls still get 403 from the AccessDeniedHandler.
            .exceptionHandling(ex -> ex
                .defaultAuthenticationEntryPointFor(
                    new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                    PathPatternRequestMatcher.withDefaults().matcher("/api/**")));
        return http.build();
    }
}
```

### 12.2 Secure random tokens and constant-time comparison

```java
package com.example.auth.foundations;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

final class Tokens {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private Tokens() {}

    /** 32 random bytes = 256 bits of entropy, URL-safe (43 characters). */
    static String newOpaqueToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return B64URL.encodeToString(bytes);
    }

    /** Store only this hash. A fast hash is fine because the token is high-entropy. */
    static byte[] sha256(String token) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", e);
        }
    }

    /** Constant-time comparison: does not return early on the first different byte. */
    static boolean matches(String presentedToken, byte[] storedHash) {
        return MessageDigest.isEqual(sha256(presentedToken), storedHash);
    }
}
```

Runnable examples that build on these foundations:

- Form login, server-side sessions, Argon2id, CSRF: [../examples/01-session-auth/](../examples/01-session-auth/)
- Signed access tokens, rotating refresh tokens, JWKS: [../examples/02-jwt-auth/](../examples/02-jwt-auth/)
- OAuth 2 / OpenID Connect with an authorization server, resource server and BFF client: [../examples/03-oauth2-oidc/](../examples/03-oauth2-oidc/)
- TOTP second factor: [../examples/04-mfa-totp/](../examples/04-mfa-totp/)
- Hashed API keys and HMAC webhooks: [../examples/05-api-keys-hmac/](../examples/05-api-keys-hmac/)

---

## 13. Glossary

| Term | Meaning |
|---|---|
| **Principal** | The authenticated entity a system acts on behalf of: a user, a service, a device. In Spring Security, `Authentication.getPrincipal()`. |
| **Subject** | The entity a token or assertion is *about*. In JWT/OIDC the `sub` claim: a stable, unique identifier for the user at that issuer (not an email address, which can change). |
| **Credential** | The thing used to prove identity: password, private key, OTP seed, client secret, certificate. |
| **Authenticator** | NIST term for something the user possesses and controls to authenticate (a password, a security key, a phone app). |
| **Claimant / verifier** | NIST terms: the party trying to prove identity, and the party checking the proof. |
| **Claim** | A statement about the subject, e.g. `"email": "alice@example.com"` or `"scope": "orders:read"`. Claims are only as trustworthy as whoever signed them. |
| **Assertion** | A signed package of claims issued by an identity provider about an authentication event, e.g. a SAML assertion or an OIDC ID token. |
| **Token** | A string that represents an authentication or authorization result. *Bearer* tokens work for whoever holds them; *sender-constrained* tokens (DPoP, mTLS) only work with proof of a private key. |
| **Access token** | OAuth token a client presents to an API (resource server). It represents delegated permission, not user identity. |
| **Refresh token** | Long-lived OAuth credential used only at the authorization server to get new access tokens. |
| **ID token** | OIDC JWT that tells the *client* who the user is and how they authenticated. Never send it to APIs as an access token. |
| **Scope** | A named permission requested by an OAuth client, e.g. `orders:read`. Scopes limit what a token may do; they are not user roles. |
| **IdP (identity provider)** | The system that authenticates users and issues assertions or tokens: Okta, Entra ID, Keycloak, Google, your own authorization server. Also called OpenID Provider (OP) in OIDC. |
| **RP / SP** | Relying Party (OIDC, WebAuthn) or Service Provider (SAML): the application that trusts the IdP's assertion to log the user in. |
| **Client** | In OAuth, the application requesting tokens. *Confidential* clients can keep a secret (server-side apps); *public* clients cannot (SPAs, mobile apps). |
| **Resource server** | The API that receives access tokens and serves protected resources. |
| **Authorization server** | The OAuth server that authenticates the resource owner (user), obtains consent and issues tokens. |
| **Resource owner** | OAuth term for the user (or entity) who can grant access to their protected resources. |
| **Nonce** | "Number used once": a random value that makes a message unique to prevent replay. In OIDC, the client's `nonce` must come back inside the ID token. |
| **Audience (`aud`)** | Who a token is intended for. A resource server must reject tokens whose `aud` is not itself, otherwise a token for API A could be replayed to API B. |
| **Issuer (`iss`)** | Who created and signed a token. Validators must check it against the exact expected value. |
| **Expiry (`exp`) / not-before (`nbf`) / issued-at (`iat`)** | Token validity time window claims, checked with a small clock-skew allowance (typically ≤ 60 seconds). |
| **JWKS** | JSON Web Key Set: a published list of public keys (each with a `kid`) that verifiers use to check token signatures. |
| **Session** | Server-side record of an authenticated user, referenced by an opaque ID usually stored in a cookie. |
| **CSRF token** | A secret, per-session (or per-request) value that a page must include in state-changing requests, proving the request came from your own UI. |
| **PKCE** | Proof Key for Code Exchange (RFC 7636): binds an OAuth authorization code to the client instance that started the flow. |
| **Salt** | A unique, random, non-secret value mixed into each password hash so identical passwords hash differently. |
| **Pepper** | A secret key, stored separately from the database, applied to password hashes so a database-only leak is not enough to crack them. |
| **Federation** | Trusting authentication performed by another domain's IdP (SAML, OIDC). |
| **SSO** | Single Sign-On: authenticate once at an IdP, then access many applications without logging in again. |

---

## Interview questions

1. **What is the difference between authentication and authorization? Which HTTP status codes go with each?**
   Authentication proves who you are (failure: `401 Unauthorized`, which really means unauthenticated). Authorization decides what you may do (failure: `403 Forbidden`, or `404` to hide existence). A valid login says nothing about permission on a specific object.

2. **Is a password plus a security question multi-factor authentication?**
   No. Both are knowledge factors. MFA requires factors from different categories: know, have, are.

3. **Why is TOTP not phishing-resistant while a passkey is?**
   A TOTP code is just a number the user can type into any site, so a real-time phishing proxy can relay it. A passkey's signature is bound by the browser to the real origin, so a look-alike domain cannot obtain a usable assertion.

4. **Why does HTTP's statelessness matter for authentication design?**
   The server does not remember previous requests, so the client must send a credential every time: the password itself, a session ID, or a self-contained token. Whatever is sent is a bearer credential that can be stolen and replayed, which drives cookie flags, token lifetimes and sender-constraining.

5. **Compare server-side sessions with JWT access tokens.**
   Sessions: tiny opaque ID, server lookup per request, instant revocation, need a shared store to scale. JWTs: self-contained, verified locally without lookup, scale easily, but are hard to revoke before `exp` and carry a snapshot of claims. Production systems combine them: short-lived JWTs plus revocable refresh tokens, or a BFF holding tokens behind a session cookie.

6. **When is it acceptable to store a SHA-256 hash of a secret instead of using Argon2id?**
   When the secret is high-entropy and machine-generated (random 256-bit API keys, refresh tokens, reset tokens). Guessing is impossible regardless of hash speed. Human-chosen passwords are low-entropy and need a slow, salted, memory-hard function.

7. **What is the difference between a MAC and a digital signature, and why does it matter for JWTs?**
   A MAC uses one shared key, so every verifier can also create valid tags. A signature uses a private key to sign and a public key to verify, so verifiers cannot forge. If several services verify tokens, use asymmetric signatures (RS256, ES256, EdDSA) so a compromise of one service does not let it mint tokens.

8. **What does TLS protect, and what does it not protect?**
   It protects confidentiality and integrity in transit and authenticates the server (and the client with mTLS). It does not authenticate the user, does not stop phishing on look-alike domains, and does not protect data at the endpoints (XSS, compromised servers, logs).

9. **What is credential stuffing and how is it different from brute force?**
   Credential stuffing replays real username/password pairs leaked from other sites, relying on password reuse; each account sees only one or two attempts. Brute force guesses many passwords for one account. Defenses differ: stuffing needs MFA, breached-password checks and bot/IP-reputation detection, not just per-account lockout.

10. **What does "never roll your own crypto" cover beyond inventing ciphers?**
    Also combining primitives yourself (your own password scheme or token format) and designing your own authentication protocols. Use vetted libraries and published standards (Argon2id, JOSE libraries, OAuth 2/OIDC, WebAuthn) because subtle flaws like timing leaks, nonce reuse and missing audience checks are not caught by functional tests.

---

## References

- NIST SP 800-63-4, *Digital Identity Guidelines* (2025): https://pages.nist.gov/800-63-4/
- NIST SP 800-63B-4, *Authentication and Authenticator Management*: https://pages.nist.gov/800-63-4/sp800-63b/
- NIST SP 800-57 Part 1 Rev. 5, *Recommendation for Key Management*: https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), August 2024: https://csrc.nist.gov/projects/post-quantum-cryptography
- RFC 9110, *HTTP Semantics* (authentication framework, section 11): https://www.rfc-editor.org/rfc/rfc9110
- RFC 6265, *HTTP State Management Mechanism* (cookies): https://www.rfc-editor.org/rfc/rfc6265
- RFC 8446, *TLS 1.3* (2018): https://www.rfc-editor.org/rfc/rfc8446
- RFC 9846, *TLS 1.3* (revision, July 2026, obsoletes RFC 8446): https://www.rfc-editor.org/rfc/rfc9846
- RFC 8996, *Deprecating TLS 1.0 and TLS 1.1*: https://www.rfc-editor.org/rfc/rfc8996
- RFC 6797, *HTTP Strict Transport Security (HSTS)*: https://www.rfc-editor.org/rfc/rfc6797
- RFC 2104, *HMAC*: https://www.rfc-editor.org/rfc/rfc2104
- RFC 4648, *Base16, Base32 and Base64 Encodings*: https://www.rfc-editor.org/rfc/rfc4648
- RFC 7519, *JSON Web Token (JWT)*: https://www.rfc-editor.org/rfc/rfc7519
- RFC 8032, *Edwards-Curve Digital Signature Algorithm (EdDSA)*: https://www.rfc-editor.org/rfc/rfc8032
- RFC 7662, *OAuth 2.0 Token Introspection*: https://www.rfc-editor.org/rfc/rfc7662
- RFC 9106, *Argon2*: https://www.rfc-editor.org/rfc/rfc9106
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- OWASP Transport Layer Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
- OWASP API Security Top 10: https://owasp.org/API-Security/
- Spring Security reference documentation: https://docs.spring.io/spring-security/reference/
