# 01 — The Evolution of Authentication: From CTSS Passwords to Passkeys

Authentication has been reinvented roughly once a decade, and each reinvention was a reaction to a specific failure of the one before: plaintext password files leaked, so we hashed them; passwords crossed networks in the clear, so we built tickets and TLS; every site wanted your password, so we built federation and delegation; passwords got phished at scale, so we bound credentials to the website itself. This chapter tells that story era by era: what each technology solved, what broke it, and what replaced it. If you understand *why* each step happened, today's "best practices" stop being a checklist and become obvious.

> **Where this fits in the evolution**
>
> - **Before:** [Foundations](00-foundations.md) gave you the building blocks (factors, hashing, MACs, signatures, TLS, threats).
> - **What it solves:** This chapter is the map. Every later chapter zooms into one region of it, and every era below links to its chapter.
> - **What comes next:** Start with the oldest credential that is still everywhere: [passwords and credential storage](02-passwords-and-credential-storage.md).

---

## Table of contents

1. [The big picture](#1-the-big-picture)
2. [Era-by-era summary table](#2-era-by-era-summary-table)
3. [Era 1: Shared computers and the first passwords (1960s-1970s)](#3-era-1-shared-computers-and-the-first-passwords-1960s-1970s)
4. [Era 2: Hashed and salted password files (1979-2015)](#4-era-2-hashed-and-salted-password-files-1979-2015)
5. [Era 3: Network authentication: Kerberos, LDAP, RADIUS (1980s-1990s)](#5-era-3-network-authentication-kerberos-ldap-radius-1980s-1990s)
6. [Era 4: The early web: Basic, Digest, cookies, sessions, SSL/TLS (1994-2011)](#6-era-4-the-early-web-basic-digest-cookies-sessions-ssltls-1994-2011)
7. [Era 5: Enterprise federation and SAML (1999-2005)](#7-era-5-enterprise-federation-and-saml-1999-2005)
8. [Era 6: User-centric identity and delegation: OpenID and OAuth 1.0 (2005-2010)](#8-era-6-user-centric-identity-and-delegation-openid-and-oauth-10-2005-2010)
9. [Era 7: The token era: OAuth 2.0, OpenID Connect, JWT, PKCE (2012-2015)](#9-era-7-the-token-era-oauth-20-openid-connect-jwt-pkce-2012-2015)
10. [Era 8: Hardening OAuth: BCP, sender-constrained tokens, OAuth 2.1, GNAP (2017-2026)](#10-era-8-hardening-oauth-bcp-sender-constrained-tokens-oauth-21-gnap-2017-2026)
11. [Era 9: Beyond passwords: OTP, FIDO, WebAuthn, passkeys (2005-2026)](#11-era-9-beyond-passwords-otp-fido-webauthn-passkeys-2005-2026)
12. [Era 10: Zero trust and workload identity (2014-2026)](#12-era-10-zero-trust-and-workload-identity-2014-2026)
13. [Era 11: The browser as identity mediator: FedCM and beyond (2022-2026)](#13-era-11-the-browser-as-identity-mediator-fedcm-and-beyond-2022-2026)
14. [How the wire changed: one request per era](#14-how-the-wire-changed-one-request-per-era)
15. [Lessons learned: the recurring themes](#15-lessons-learned-the-recurring-themes)
16. [Production best practices (2026): what history tells you to do](#16-production-best-practices-2026-what-history-tells-you-to-do)
17. [Common attacks and mistakes: repeating history](#17-common-attacks-and-mistakes-repeating-history)
18. [Spring Boot 4 / Spring Security 7: the eras in one framework](#18-spring-boot-4--spring-security-7-the-eras-in-one-framework)
19. [Interview questions](#interview-questions)
20. [References](#references)

---

## 1. The big picture

Four forces pushed authentication forward:

1. **Scale.** One machine with a few hundred users, then campus networks, then the public web with billions of users, then thousands of microservices and devices per company.
2. **Attackers.** Curious insiders, then network sniffers, then offline crackers with GPUs, then phishing at industrial scale, credential stuffing with billions of leaked passwords, and real-time attacker-in-the-middle proxies.
3. **Usability.** Every mechanism that was too painful (complex password rules, hardware tokens for everyone, URL-based identifiers) was bypassed or abandoned. Mechanisms that are *easier* than passwords (single sign-on, passkeys) win.
4. **Standards and regulation.** NIST guidelines, payment and banking regulations, and the IETF/OpenID/W3C standards process turned lessons into defaults.

```mermaid
timeline
    title From shared computers to federation, 1960s to 2009
    section Shared computers
        early 1960s : CTSS at MIT, passwords in a plaintext file
        1967 : One-way password storage on Cambridge Titan
        1979 : Unix crypt with salt and iterated DES
    section Networks and directories
        late 1980s : Kerberos v4 from MIT Project Athena : Shadow password files
        1993 : Kerberos v5 RFC 1510 : LDAP RFC 1487
        1997 : RADIUS RFC 2058 : LDAPv3 RFC 2251
    section Early web
        1994 : Netscape cookies
        1995 : SSL 2.0 : SSH
        1996 : HTTP Basic in HTTP 1.0 RFC 1945
        1997 : HTTP Digest RFC 2069 : Cookie spec RFC 2109
        1999 : TLS 1.0 RFC 2246 : bcrypt
    section Federation and delegation
        2002 : SAML 1.0
        2005 : SAML 2.0 : OpenID 1.0
        2007 : OpenID 2.0 : OAuth 1.0
        2009 : OAuth 1.0a : scrypt
```

```mermaid
timeline
    title From tokens to passkeys, 2012 to 2026
    section Token era
        2012 : OAuth 2.0 RFC 6749 and RFC 6750
        2014 : OpenID Connect Core 1.0 : FIDO U2F
        2015 : JWT RFC 7519 : PKCE RFC 7636 : Argon2 wins PHC
    section Hardening and phishing resistance
        2017 : NIST SP 800-63-3 drops composition and rotation rules
        2019 : WebAuthn Level 1 : Device flow RFC 8628
        2020 : mTLS tokens RFC 8705 : JWT BCP RFC 8725
        2022 : Passkeys commitment : FedCM in Chrome
        2023 : DPoP RFC 9449
        2024 : GNAP RFC 9635
        2025 : OAuth Security BCP RFC 9700 : NIST SP 800-63-4
        2026 : Browser-Based Apps RFC 10017 : WebAuthn Level 3 : OAuth 2.1 still a draft
```

---

## 2. Era-by-era summary table

| Era | Years | Key technologies | Problem solved | What broke it | Replaced or extended by | Chapter |
|---|---|---|---|---|---|---|
| Shared computers | 1960s-1970s | CTSS passwords | Separate users on one time-sharing machine | Plaintext password file leaked (1962, 1966) | One-way hashed password storage | [02](02-passwords-and-credential-storage.md) |
| Hashed password files | 1967-2015 | Titan one-way storage, Unix `crypt`, salts, shadow files, md5crypt, bcrypt, PBKDF2, scrypt, Argon2 | File theft no longer reveals passwords directly | Fast hashes cracked offline; GPUs and ASICs; precomputed tables | Slow, salted, memory-hard KDFs (Argon2id) | [02](02-passwords-and-credential-storage.md) |
| Network authentication | 1978-2006 | Needham-Schroeder, Kerberos, LDAP, RADIUS, SSH | Passwords off the wire (Kerberos, SSH); one central user directory (LDAP); remote access (RADIUS) | Intranet-only design; offline ticket cracking; LDAP binds expose passwords to every app; MD5 in RADIUS | Web SSO (SAML, OIDC), RADIUS over TLS, zero trust | [05](05-enterprise-sso-ldap-kerberos-saml.md) |
| Early web | 1994-2011 | HTTP Basic, Digest, cookies, server-side sessions, SSL/TLS | Logins for a stateless protocol; encrypted channel | Session hijacking, CSRF, XSS, fixation; every site has its own password, so reuse | `HttpOnly`/`Secure`/`SameSite`, CSRF tokens, HTTPS everywhere, federation | [03](03-http-basic-digest-and-api-keys.md), [04](04-sessions-cookies-and-csrf.md) |
| Enterprise federation | 1999-2005 | Microsoft Passport, Liberty Alliance, SAML 1.x/2.0 | Cross-domain single sign-on, one corporate identity | XML signature wrapping, complexity, browser-only, unfit for APIs and mobile | OpenID Connect (still coexists with SAML in enterprises) | [05](05-enterprise-sso-ldap-kerberos-saml.md) |
| User-centric identity and delegation | 2005-2010 | OpenID 1.0/2.0, OAuth 1.0/1.0a | Log in with an existing account; let apps act for you without your password | Confusing URL identifiers; OAuth 1.0 session fixation; complex signatures | OAuth 2.0 and OpenID Connect | [07](07-oauth-1.md) |
| Token era | 2012-2015 | OAuth 2.0, bearer tokens, OIDC, JWT, PKCE | Simple delegation for web, mobile and APIs; standard login on top | Implicit grant leaks, redirect abuse, bearer token theft, OAuth misused for login | Security BCP, PKCE everywhere, sender-constrained tokens | [06](06-tokens-and-jwt.md), [08](08-oauth-2.md), [10](10-openid-connect.md) |
| Hardening OAuth | 2017-2026 | RFC 8252, device flow, mTLS, DPoP, PAR, RAR, RFC 9700, OAuth 2.1 (draft), GNAP | Close the attack classes found in OAuth 2.0 deployments | Still evolving; bearer tokens remain the default | OAuth 2.1 consolidation (in progress) | [09](09-modern-oauth-2.1-and-extensions.md) |
| Beyond passwords | 2005-2026 | HOTP/TOTP, SMS OTP, FIDO U2F, FIDO2/WebAuthn, passkeys | Second factor; then phishing-resistant, passwordless login | SMS: SIM swap, interception; OTP and push: real-time phishing relay | Passkeys (origin-bound public keys) | [11](11-mfa-passwordless-and-passkeys.md) |
| Zero trust and workloads | 2014-2026 | BeyondCorp, NIST SP 800-207, mTLS meshes, SPIFFE, workload identity federation, CAEP | Stop trusting the network; authenticate every service call | Long-lived shared secrets leak; perimeter breaches | Short-lived, attested workload credentials | [12](12-service-to-service-and-zero-trust.md) |
| Browser as mediator | 2022-2026 | FedCM, storage partitioning, digital credentials | Federation without third-party cookies and with less tracking | Browser support uneven (Chromium only for FedCM as of 2026) | Still emerging | [10](10-openid-connect.md) |

---

## 3. Era 1: Shared computers and the first passwords (1960s-1970s)

### 3.1 The problem: many people, one computer

MIT's Compatible Time-Sharing System (CTSS), demonstrated in 1961, let many people use one expensive computer at the same time. Each user had private files and a limited allotment of machine time, so the system needed to know who was who. Fernando Corbató's team is generally credited with the first use of computer passwords for this purpose.

### 3.2 How it worked

Each user had a password; the system compared what the user typed with a master password file. The file was stored **in plaintext**.

### 3.3 What broke it

- **Insiders read the file.** By a widely reported account, in 1962 a PhD student, Allan Scherr, requested a printout of the password file through the system's offline print queue so he could use other people's time allotments. He confessed about 25 years later.
- **Software bugs exposed it.** In 1966 a bug swapped the system's message-of-the-day file with the password file, so everyone who logged in saw every password.

### 3.4 What replaced it

The fix was to **never store the password itself**. At Cambridge, the Titan time-sharing system used a one-way transformation of passwords by 1967; the technique is credited to Roger Needham (Morris and Thompson later cited Maurice Wilkes's 1968 book as the source of the idea). If the stored value cannot be turned back into the password, reading the file is not enough.

> **Lesson:** Assume the credential store will be read by someone who should not read it. Store something that is useless to them. This is still the first rule of [password storage](02-passwords-and-credential-storage.md).

---

## 4. Era 2: Hashed and salted password files (1979-2015)

### 4.1 Unix `crypt` and the 1979 paper

Robert Morris and Ken Thompson's paper *Password Security: A Case History* (Communications of the ACM, November 1979) described how Unix password storage evolved in response to real break-in attempts:

- An early Unix implementation mimicked the M-209 cipher machine and was **too fast**, so likely passwords could be enumerated quickly.
- Seventh Edition Unix switched to a modified **DES**, iterated **25 times**, to slow guessing down, and modified so that off-the-shelf DES hardware could not be used directly.
- It added a **12-bit salt** (4,096 possible values), so the same password produced different stored values for different users, and an attacker could not precompute one dictionary of hashes for everyone.

### 4.2 What broke it

- **The hashes were world-readable.** `/etc/passwd` had to be readable by all programs (to map user IDs to names), so anyone with a shell could copy the hashes and guess offline. The Morris worm of 1988 included password guessing among its spreading techniques.
- **Hardware got faster** while `crypt` stayed fixed at 25 DES rounds, and passwords were truncated to 8 characters.
- **Fast general-purpose hashes** were adopted on the web in the 1990s and 2000s (MD5, SHA-1), often **unsalted**. Precomputed lookup tables and then rainbow tables (Philippe Oechslin, 2003, building on Martin Hellman's 1980 time-memory trade-off) made unsalted hashes trivial to reverse.
- **Breaches at web scale** showed the consequences: RockYou (2009) stored about 32 million passwords in plaintext; LinkedIn (2012) used unsalted SHA-1; Adobe (2013) *encrypted* passwords with 3DES in ECB mode instead of hashing them.

### 4.3 What replaced it, step by step

| Year | Step | What it fixed |
|---|---|---|
| 1988 | Shadow password files (System V Release 3.2; BSD 4.3 Reno in 1990) | Hashes moved to a root-only file |
| 1994 | md5crypt (FreeBSD) | Longer passwords, bigger salt, 1,000 iterations |
| 1999 | bcrypt (Provos and Mazières, USENIX) | **Adaptive cost**: the work factor can be raised as hardware improves |
| 2000 | PBKDF2 (PKCS #5 v2.0, RFC 2898) | Standardized iterated, salted key derivation; still the FIPS-approved choice |
| 2007-2008 | sha256crypt / sha512crypt | Configurable rounds for Unix systems |
| 2009 | scrypt (Colin Percival) | **Memory-hard**: GPUs and ASICs cannot cheaply run millions of guesses in parallel |
| 2015 | Argon2 wins the Password Hashing Competition; RFC 9106 in 2021 | Tunable memory, time and parallelism; Argon2id resists both GPU and side-channel attacks |

> **Lesson:** The attacker's cost per guess is the only thing you control after a breach. Every step in this table made each guess more expensive. Details and parameters: [chapter 02](02-passwords-and-credential-storage.md).

---

## 5. Era 3: Network authentication: Kerberos, LDAP, RADIUS (1980s-1990s)

### 5.1 The problem: passwords crossing the network

Once computers were networked, people logged in remotely with Telnet, `rlogin` and FTP, which sent passwords **in cleartext**. Anyone on the same network segment could sniff them. And each server had its own user list.

### 5.2 Kerberos: never send the password

Kerberos came out of MIT's Project Athena (started 1983). Version 4 was released publicly in the late 1980s (sources give 1988 or 1989); version 5 was published as RFC 1510 in 1993 and revised as RFC 4120 in 2005. It builds on the Needham-Schroeder protocol (1978) and uses only symmetric cryptography.

The key ideas:

- The password never crosses the network. The client proves knowledge of it by decrypting a reply from the Key Distribution Center (KDC).
- After one login, the client holds a **Ticket-Granting Ticket (TGT)** and gets **service tickets** for each service without typing the password again: single sign-on inside a network.
- Tickets are time-limited (typically 10 hours) and include timestamps to stop replay.

```mermaid
sequenceDiagram
    autonumber
    participant U as User workstation
    participant AS as KDC Authentication Service
    participant TGS as KDC Ticket Granting Service
    participant S as File server
    U->>AS: AS-REQ, I am alice, timestamp encrypted with key from password
    AS-->>U: AS-REP, TGT plus session key encrypted with alice's key
    Note over U: Password used locally only, never sent
    U->>TGS: TGS-REQ, TGT plus authenticator, I want the file server
    TGS-->>U: Service ticket for the file server
    U->>S: AP-REQ, service ticket plus authenticator
    S-->>U: Access granted
```

**What broke it (or limited it):** Kerberos was designed for a trusted, managed network. It needs clock synchronization and direct reachability of the KDC, which does not fit the open internet. Tickets encrypted with keys derived from passwords can be cracked offline (the "Kerberoasting" and "AS-REP roasting" attacks against Active Directory). If the KDC's master key is stolen, attackers can forge any ticket ("golden ticket"). It is still the backbone of Windows domain authentication (Active Directory adopted it as the default with Windows 2000) and reaches intranet websites through SPNEGO (RFC 4559, 2006).

### 5.3 LDAP: one directory for everyone

The Lightweight Directory Access Protocol (RFC 1487 in 1993; LDAPv3 in RFC 2251, 1997; current spec RFC 4511, 2006) gave organizations a single, central directory of users and groups that every application could query.

**What broke it:** applications typically authenticate users with an LDAP "bind" that sends the user's password to the directory, so **every application sees every password**, and without LDAPS or StartTLS the password crosses the network in the clear. Each application also implements its own login page. Centralizing *identity data* was a step forward; centralizing *authentication* required SSO protocols. See [enterprise SSO](05-enterprise-sso-ldap-kerberos-saml.md).

### 5.4 RADIUS: authentication for network access

RADIUS (RFC 2058 in January 1997, revised by RFC 2138 the same year and RFC 2865 in 2000) authenticates users for dial-up, VPN, Wi-Fi (802.1X) and network devices, and became the classic example of the AAA model (authentication, authorization, accounting) still used today.

**What broke it:** its integrity protection relies on MD5 and a shared secret. In July 2024 the **Blast-RADIUS** attack (CVE-2024-3596) showed that a network attacker could use an MD5 chosen-prefix collision to turn an `Access-Reject` into an `Access-Accept` for deployments over UDP without the Message-Authenticator attribute. The fix is to require Message-Authenticator and move to RADIUS over TLS.

### 5.5 SSH: public keys for remote login

SSH (first released in 1995) replaced Telnet and `rlogin` with an encrypted channel and, crucially, **public-key user authentication**: the server stores the user's public key and the private key never leaves the client. This is the same idea that passkeys brought to the web 25 years later.

> **Lesson:** Move secrets off the wire. Kerberos did it with symmetric tickets, SSH with public keys and an encrypted channel. Centralize identity, but do not hand passwords to every application.

---

## 6. Era 4: The early web: Basic, Digest, cookies, sessions, SSL/TLS (1994-2011)

### 6.1 The problem: logins for a stateless protocol

HTTP has no memory between requests (see [foundations](00-foundations.md#3-http-is-stateless-and-why-that-matters)). The early web needed a way to log in once and stay logged in, and a way to protect passwords on the wire.

### 6.2 HTTP Basic and Digest

- **HTTP Basic** (documented in HTTP/1.0, RFC 1945, 1996; current spec RFC 7617, 2015): the browser sends `Authorization: Basic base64(user:password)` **on every request**. Simple, universally supported, and only safe over TLS. There is no real logout and no place for MFA.
- **HTTP Digest** (RFC 2069, 1997; RFC 2617, 1999; RFC 7616, 2015): a challenge-response scheme that sends an MD5 hash of the password, a server nonce and the request instead of the password. It avoided cleartext passwords, but required the server to store password-equivalent values, was complex, and became pointless once TLS was everywhere.

Both are covered in [chapter 03](03-http-basic-digest-and-api-keys.md).

### 6.3 Cookies and server-side sessions

Lou Montulli at Netscape came up with HTTP cookies in 1994 (supported in the Mosaic Netscape 0.9 beta released in October 1994). The IETF documented them in RFC 2109 (1997) and RFC 2965 (2000), and finally described how they actually work in RFC 6265 (2011); an update known as "6265bis" (which adds `SameSite`) is still an Internet-Draft as of October 2026.

The pattern that every web framework adopted:

1. The user submits a **login form** over HTTPS.
2. The server verifies the password and creates a **server-side session**.
3. The server sends `Set-Cookie: SESSIONID=<random>`.
4. The browser sends the cookie on every request; the server looks up the session.

This is still the recommended design for browser applications in 2026 (directly, or as a BFF in front of OAuth). See [sessions, cookies and CSRF](04-sessions-cookies-and-csrf.md).

### 6.4 SSL and TLS

Netscape shipped SSL 2.0 in 1995 and SSL 3.0 in 1996; the IETF standardized TLS 1.0 in 1999 (RFC 2246). TLS 1.2 followed in 2008 and TLS 1.3 in 2018 (RFC 8446, revised as RFC 9846 in 2026). TLS 1.0 and 1.1 were formally deprecated in 2021 (RFC 8996).

### 6.5 What broke this era

| Problem | What happened | Fix that followed |
|---|---|---|
| TLS only on the login page | Session cookies sent over plain HTTP. **Firesheep** (2010) let anyone on public Wi-Fi hijack Facebook and Twitter sessions with one click. | HTTPS everywhere, HSTS, `Secure` cookies, free certificates (Let's Encrypt, public beta from December 2015) |
| XSS | Injected script read `document.cookie` and stole sessions | `HttpOnly` cookies, output encoding, Content Security Policy |
| CSRF | Other sites triggered state-changing requests with the victim's cookies | Synchronizer tokens, `SameSite` cookies (Chrome has treated cookies without the attribute as `Lax` since 2020) |
| Session fixation | Attacker planted a session ID before login | Rotate the session ID on login |
| One password per site | Users reused passwords; one breach unlocked many accounts (**credential stuffing**) | Breached-password checks, MFA, federation, passkeys |

> **Lesson:** A login is only as strong as the session it creates. Protect the session identifier as carefully as the password.

---

## 7. Era 5: Enterprise federation and SAML (1999-2005)

### 7.1 The problem: one identity across many domains

Companies bought SaaS applications and partnered with other companies. Users had separate passwords for each, and IT could not centrally disable a departing employee. Kerberos did not cross organizational or internet boundaries.

### 7.2 What appeared

- **Microsoft Passport** (1999): a single Microsoft-run login for many sites. Centralized in one company, which partners and privacy advocates resisted.
- **Liberty Alliance** (founded 2001): an industry federation effort whose ID-FF specification fed into SAML 2.0.
- **SAML** (OASIS): SAML 1.0 ratified in November 2002, 1.1 in 2003, and **SAML 2.0 in March 2005**. The identity provider (IdP) signs an XML **assertion** saying "this user authenticated at this time", and the service provider (SP) validates the signature and logs the user in. Usually transported through the browser via redirects and auto-submitted forms.

**Problem solved:** true cross-domain single sign-on, centralized account control, and a clean separation of the IdP (who authenticates) from the SP (who trusts the result).

### 7.3 What broke it (or limited it)

- **XML Signature is hard to verify correctly.** The 2012 paper *On Breaking SAML: Be Whoever You Want to Be* (USENIX Security) found critical XML Signature Wrapping vulnerabilities in 11 of 14 SAML frameworks it analyzed: the attacker moves the signed element and inserts an unsigned one that the application reads instead.
- **Stolen IdP signing keys are catastrophic.** With them, attackers can forge assertions for any user ("golden SAML").
- **Designed for browsers, not APIs or mobile apps.** Large XML payloads, POST bindings and no notion of delegated API access.

SAML is far from dead: it remains the most widely supported protocol for enterprise SaaS SSO in 2026. New designs prefer OpenID Connect. See [enterprise SSO](05-enterprise-sso-ldap-kerberos-saml.md).

> **Lesson:** Separate the party that authenticates from the party that relies on it, and make the relying party verify a signed, audience-restricted, short-lived assertion. That idea survived; the XML did not.

---

## 8. Era 6: User-centric identity and delegation: OpenID and OAuth 1.0 (2005-2010)

### 8.1 OpenID 1.0 and 2.0: log in with an account you already have

Brad Fitzpatrick created OpenID at LiveJournal in 2005. Users identified themselves with a URL (`https://alice.example.org/`), and the site redirected them to their OpenID provider to log in. **OpenID 2.0** was finalized in December 2007, and the OpenID Foundation was formed the same year.

**What broke it:** URLs as usernames confused ordinary users; a malicious relying party could redirect users to a look-alike of their provider and phish the password; and it did not help applications call APIs on the user's behalf. Its successor, OpenID Connect (2014), kept the name and the goal but rebuilt the protocol on OAuth 2.0.

### 8.2 The password anti-pattern

Around 2006-2007, web applications wanted to import your contacts from webmail or post to your social network account. The common solution was to **ask for your password to the other service** and log in as you. The app got full, unlimited, unrevocable access, and the practice trained users to type passwords into third-party sites.

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant A as Third-party app
    participant M as Webmail
    rect rgb(255, 235, 235)
    Note over U,M: Before OAuth, the password anti-pattern
    U->>A: Here is my webmail password
    A->>M: Log in as the user with the password
    M-->>A: Full access to everything, forever
    end
    rect rgb(235, 255, 235)
    Note over U,M: With OAuth, delegated access
    A->>U: Redirect to webmail to approve read contacts
    U->>M: Log in at webmail itself and approve
    M-->>A: Limited, revocable token for contacts only
    end
```

### 8.3 OAuth 1.0 and 1.0a: delegation without the password

OAuth 1.0 was stabilized in October 2007 and its final specification published in December 2007. The user approves access at the service itself, and the app receives a **token** limited in scope and revocable. Every API request is signed with HMAC-SHA1 (or RSA-SHA1) using the client's secret and the token secret, which protected requests even without TLS.

**What broke it:** on April 23, 2009, a **session fixation** flaw in the authorization step was disclosed: an attacker could start a flow, trick a victim into approving it, and then use the resulting token. **OAuth 1.0a** (June 24, 2009) fixed it with a callback confirmation and verifier. The IETF later published it as RFC 5849 (April 2010). The deeper problem was **complexity**: building the exact signature base string (parameter normalization, encoding rules) was a constant source of interoperability bugs. See [OAuth 1](07-oauth-1.md).

> **Lesson:** Separate authorization from authentication. A user should be able to grant an application narrow, revocable access without giving it their credentials.

---

## 9. Era 7: The token era: OAuth 2.0, OpenID Connect, JWT, PKCE (2012-2015)

### 9.1 OAuth 2.0 (2012)

RFC 6749 (the framework) and RFC 6750 (bearer token usage) were published in October 2012. The big design changes from OAuth 1.0:

- **Rely on TLS instead of per-request signatures.** Requests carry a simple **bearer token**: whoever holds it can use it.
- **Separate roles:** client, resource owner, authorization server, resource server.
- **Multiple grant types** for different clients: authorization code, implicit (for browsers, at a time when cross-origin requests were hard), resource owner password credentials, client credentials, plus extension grants.
- **Short-lived access tokens with refresh tokens.**

It was a framework, not a single protocol, and its lead editor at the time, Eran Hammer, publicly withdrew from the effort in 2012, criticizing its complexity and security trade-offs. Many of the later fixes addressed exactly those concerns. The threat model followed in RFC 6819 (2013).

### 9.2 What broke in OAuth 2.0 deployments

| Attack class | What happened | Eventual fix |
|---|---|---|
| Implicit grant token leakage | Access tokens returned in the URL fragment leaked via history, `Referer`, open redirectors | Implicit deprecated; authorization code + PKCE for browser apps (RFC 9700) |
| Authorization code interception | On mobile, a malicious app registered the same custom URL scheme and stole codes | PKCE (RFC 7636, 2015); claimed HTTPS redirects (RFC 8252) |
| Redirect URI manipulation | Loose pattern matching let attackers redirect codes to their own pages | Exact redirect URI matching |
| CSRF on the callback | Attacker logged the victim into the attacker's account | `state` parameter, PKCE |
| Mix-up attacks | A client using several authorization servers was tricked into sending a code to the wrong one | `iss` in the authorization response (RFC 9207, 2022) |
| Password grant | Clients collected user passwords directly, preventing MFA and federation | Password grant "MUST NOT be used" (RFC 9700) |
| Bearer token theft | Stolen tokens replayed from anywhere | Short lifetimes; sender-constrained tokens (mTLS RFC 8705, DPoP RFC 9449) |
| OAuth used as login | Apps accepted any valid access token as proof of identity, so a token issued to a malicious app could log in to another | OpenID Connect ID tokens with audience and nonce |

### 9.3 OpenID Connect (2014): authentication on top of OAuth

OpenID Connect Core 1.0 was finalized in February 2014 (and published as ISO/IEC 26131 in 2024). It adds what OAuth deliberately left out:

- An **ID token** (a signed JWT) issued *to the client* that says who the user is (`sub`), who issued it (`iss`), who it is for (`aud`), when and how the user authenticated (`auth_time`, `acr`, `amr`) and a `nonce` against replay.
- A standard **UserInfo** endpoint, standard scopes (`openid`, `profile`, `email`) and **discovery** (`/.well-known/openid-configuration`) with a JWKS for key rotation.

It replaced OpenID 2.0 for consumer login ("Sign in with Google") and became the default for new enterprise SSO. See [OpenID Connect](10-openid-connect.md).

### 9.4 JWT and JOSE (2015)

In May 2015 the IETF published JWT (RFC 7519) together with JWS, JWE, JWK and JWA (RFCs 7515-7518). A compact, URL-safe, signed JSON format made tokens **self-contained**: an API can verify a token locally with a public key, without calling the authorization server.

**What broke:** libraries that trusted the token header's `alg` (accepting `none`, or using an RSA public key as an HMAC secret), missing `aud`/`iss` checks, sensitive data in readable payloads, and the inability to revoke a token before it expires. The fixes came in the JWT Best Current Practices (RFC 8725, 2020): algorithm allowlists, explicit typing, full claim validation. See [tokens and JWT](06-tokens-and-jwt.md).

### 9.5 PKCE (2015)

Proof Key for Code Exchange (RFC 7636, September 2015) makes the client create a random `code_verifier`, send its SHA-256 hash (`code_challenge`) in the authorization request and the verifier itself when redeeming the code. A stolen code is useless without the verifier. Designed for mobile apps, it is now recommended for **every** client type.

> **Lesson:** Bearer tokens trade security for simplicity. Every later improvement in OAuth (PKCE, short lifetimes, DPoP, mTLS) is about binding a token or code to the party that is supposed to use it.

---

## 10. Era 8: Hardening OAuth: BCP, sender-constrained tokens, OAuth 2.1, GNAP (2017-2026)

### 10.1 A decade of extensions

| Year | Specification | What it added |
|---|---|---|
| 2017 | RFC 8252, OAuth 2.0 for Native Apps (BCP 212) | Use the system browser, not embedded web views; PKCE; claimed HTTPS redirect URIs |
| 2019 | RFC 8628, Device Authorization Grant | Login for TVs, CLIs and devices without a keyboard: show a code, approve on a phone |
| 2020 | RFC 8705, mutual TLS client authentication and certificate-bound tokens | Tokens usable only over a TLS connection with the right client certificate |
| 2020 | RFC 8693, Token Exchange | Swap one token for another (delegation, impersonation, downscoping) |
| 2020 | RFC 8725, JWT Best Current Practices | Algorithm allowlists, typing, validation rules |
| 2021 | RFC 9126, Pushed Authorization Requests (PAR) | Send authorization parameters over a back channel instead of the URL |
| 2021 | RFC 9068, JWT profile for access tokens | Standard claims and `typ: at+jwt` for JWT access tokens |
| 2022 | RFC 9207, Authorization Server Issuer Identification | `iss` in the authorization response against mix-up attacks |
| 2023 | RFC 9396, Rich Authorization Requests (RAR) | Fine-grained `authorization_details` instead of coarse scopes |
| 2023 | RFC 9449, DPoP | Application-layer proof of possession: each request carries a fresh signed proof |
| 2023 | RFC 9470, Step-Up Authentication Challenge | APIs can demand a stronger or more recent login (`acr_values`, `max_age`) |
| 2025 | **RFC 9700, OAuth 2.0 Security Best Current Practice** (BCP 240, January) | The consolidated security rules: PKCE, exact redirect matching, no implicit, no password grant, refresh token protection |
| 2025 | FAPI 2.0 Security Profile (OpenID Foundation, final in February) | High-security profile for open banking and similar APIs |
| 2025 | RFC 9728, Protected Resource Metadata | APIs advertise which authorization servers they trust |
| 2026 | RFC 10017, OAuth 2.0 for Browser-Based Applications (BCP 212, August) | Compares SPA architectures (BFF, token-mediating backend, browser-only client) and their threats; the BFF keeps tokens out of the browser entirely |

### 10.2 OAuth 2.1: consolidation, still a draft

OAuth 2.1 folds OAuth 2.0, PKCE, bearer token usage, native-app and browser-app guidance and the Security BCP into one document, removing the implicit and password grants and requiring PKCE and exact redirect URI matching. **As of October 2026 it is still an IETF Internet-Draft** (draft-ietf-oauth-v2-1, revision 16, September 2026), not an RFC. Treat it as the direction of travel; cite RFC 6749 plus RFC 9700 as the published baseline. See [modern OAuth](09-modern-oauth-2.1-and-extensions.md).

### 10.3 GNAP: a clean-slate alternative

The Grant Negotiation and Authorization Protocol (RFC 9635, October 2024) is a new protocol, not an OAuth extension: JSON requests to a single endpoint, keys bound to every client by default, and flexible interaction modes. It is a published standard but, as of 2026, sees little adoption compared with OAuth 2.x. It is worth knowing as a sign of where the ideas are heading (sender-constrained by default, no client secrets).

> **Lesson:** Security improvements are added as extensions, then consolidated, and only then become defaults. Deprecations (implicit grant, password grant, TLS 1.0, SHA-1) are as important as new features.

---

## 11. Era 9: Beyond passwords: OTP, FIDO, WebAuthn, passkeys (2005-2026)

### 11.1 One-time passwords

- **HOTP** (RFC 4226, 2005) and **TOTP** (RFC 6238, 2011): an app or token computes an HMAC of a shared secret and a counter or the current time, truncated to six digits. Stealing yesterday's code is useless. See [../examples/04-mfa-totp/](../examples/04-mfa-totp/).
- **SMS codes** became the most widespread second factor because every phone can receive them.

**What broke:** SMS codes can be stolen via **SIM swapping** (social-engineering the carrier into moving a number), SS7 interception and malware; NIST's SP 800-63-3 (2017) restricted them, and SP 800-63B-4 (2025) still lists PSTN delivery as the one *restricted* authenticator. Worse, **all** code- and push-based methods can be relayed by a real-time phishing proxy, and push prompts can be spammed until a tired user approves ("MFA fatigue").

### 11.2 The 2017 password policy reset

NIST SP 800-63-3 (June 2017) reversed decades of folk wisdom: no more mandatory composition rules ("one uppercase, one digit, one symbol") and no forced periodic rotation, because both pushed users toward predictable patterns. Instead: longer passwords, blocklists of common and breached passwords, and rate limiting. SP 800-63B-4 (2025) kept this and raised the minimum length to 15 characters when a password is the only factor (8 when used only with MFA). See [chapter 02](02-passwords-and-credential-storage.md).

### 11.3 FIDO U2F, FIDO2 and WebAuthn

- **FIDO U2F** (final 1.0 specifications published December 2014): a USB/NFC security key as a second factor. The key signs a challenge together with the **origin** the browser is actually talking to, so a phishing site gets a signature that is useless for the real site.
- **FIDO2** = **WebAuthn** (W3C) + **CTAP** (FIDO Alliance). WebAuthn Level 1 became a W3C Recommendation in March 2019, Level 2 in 2021 and **Level 3 in August 2026**. Websites can register a public key per user and authenticate with a signature, optionally with user verification (PIN or biometric on the device), which can replace the password entirely.

### 11.4 Passkeys

Device-bound FIDO credentials had one big usability problem: lose the device, lose the credential. On May 5, 2022, Apple, Google and Microsoft jointly committed to **passkeys**: FIDO credentials that can be **synced** across a user's devices by the platform's credential manager, and used across devices (phone as authenticator for a laptop). Apple shipped them in iOS 16 later that year.

NIST SP 800-63B-4 (2025) recognizes **syncable authenticators**: synced passkeys can be used up to AAL2, while AAL3 still requires a non-exportable key (a device-bound passkey or hardware security key).

```mermaid
flowchart LR
    P["Password only"] -->|"phished, stuffed, cracked"| P2["Password plus SMS OTP"]
    P2 -->|"SIM swap, relay"| P3["Password plus TOTP or push"]
    P3 -->|"real-time relay, MFA fatigue"| F["FIDO U2F security key<br/>second factor, origin-bound"]
    F -->|"needs extra hardware"| W["FIDO2 WebAuthn<br/>passwordless possible"]
    W -->|"lost device problem"| K["Passkeys<br/>synced, phishing-resistant"]
```

> **Lesson:** Bind the credential to the origin. Phishing resistance comes from the browser checking where the user really is, not from adding more codes for the user to type. See [MFA, passwordless and passkeys](11-mfa-passwordless-and-passkeys.md).

---

## 12. Era 10: Zero trust and workload identity (2014-2026)

### 12.1 The end of the perimeter

The traditional model trusted anything inside the corporate network ("castle and moat"). Phishing, VPN compromises and lateral movement showed that an attacker inside the network was the normal case. Google's **BeyondCorp** papers (from 2014) described granting access based on device and user identity rather than network location; **NIST SP 800-207** (*Zero Trust Architecture*, 2020) generalized the idea: authenticate and authorize every request, continuously.

### 12.2 Services need identities too

With microservices, most authentication traffic is machine to machine. Early systems used long-lived shared secrets and API keys copied into configuration files and CI systems, where they leaked. The modern toolbox:

- **OAuth client credentials** with short-lived tokens, preferably with private-key JWT or mTLS client authentication instead of shared client secrets.
- **Mutual TLS** between services, often automated by a service mesh, with workload identities such as **SPIFFE** IDs.
- **Workload identity federation**: a platform (Kubernetes, a cloud provider, a CI system such as GitHub Actions) issues a short-lived signed OIDC token for the workload, which is exchanged for cloud credentials. No stored secret at all.
- **Continuous access evaluation**: the OpenID Foundation finalized the **Shared Signals Framework**, **CAEP** and **RISC** 1.0 in September 2025, so an IdP can tell applications in near real time that a session was revoked or a credential compromised.

See [service-to-service and zero trust](12-service-to-service-and-zero-trust.md).

> **Lesson:** Shorten lifetimes. A credential that expires in minutes and is minted on demand is worth little to a thief; a static secret in a config file is worth everything.

---

## 13. Era 11: The browser as identity mediator: FedCM and beyond (2022-2026)

### 13.1 Why browsers got involved

Classic federation relies on redirects, iframes and cookies shared across sites. The same mechanisms enable cross-site tracking, so browsers started restricting **third-party cookies** and partitioning storage (Safari blocks them by default; Firefox partitions them per site by default). That broke some identity features, such as silent token renewal in hidden iframes and some front-channel logout designs. Chrome ultimately decided not to remove third-party cookies (announced in 2024 and confirmed in April 2025), but the work produced new identity-specific browser APIs.

### 13.2 FedCM

The **Federated Credential Management API** (FedCM) lets the *browser* mediate "Sign in with an IdP" with its own account chooser, without third-party cookies and without the IdP learning which sites you visit until you choose to sign in. It shipped in Chrome 108 (late 2022) and is used by major IdPs, with a fallback to classic redirect-based OAuth/OIDC. It is a W3C Working Draft in the Federated Identity Working Group (first published August 2024) and, as of October 2026, is supported in Chromium-based browsers but **not** in Firefox or Safari.

### 13.3 What else is emerging

- **Digital credentials and wallets.** Standards such as OpenID for Verifiable Presentations and browser APIs for presenting credentials from a wallet are maturing; NIST SP 800-63C-4 (2025) already describes subscriber-controlled wallets in its federation model. Expect this to matter for identity proofing (age, driver's license) more than for everyday login at first.
- **AI agents acting for users.** Agent protocols are adopting OAuth (authorization code + PKCE, Protected Resource Metadata) to get delegated, scoped, revocable access instead of user passwords: the password anti-pattern of 2007 being solved again with the same tool.

> **Lesson:** When the platform changes, identity protocols adapt; the principles (delegation, audience restriction, user consent, origin binding) stay the same.

---

## 14. How the wire changed: one request per era

The same "show me my photos" request, as it would look in each era. Values are illustrative.

**1996, HTTP Basic: the password on every request.**

```http
GET /photos HTTP/1.1
Host: photos.example.net
Authorization: Basic YWxpY2U6cGFzc3dvcmQxMjM=
```

**Late 1990s to today, form login then a session cookie.**

```http
GET /photos HTTP/1.1
Host: photos.example.net
Cookie: JSESSIONID=5A1F3C0B2E9D4F6A8B7C
```

**2009, OAuth 1.0a: a signed request (format from RFC 5849).**

```http
GET /photos?file=vacation.jpg&size=original HTTP/1.1
Host: photos.example.net
Authorization: OAuth realm="Photos",
    oauth_consumer_key="dpf43f3p2l4k3l03",
    oauth_token="nnch734d00sl2jdk",
    oauth_signature_method="HMAC-SHA1",
    oauth_timestamp="137131202",
    oauth_nonce="chapoH",
    oauth_signature="MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D"
```

**2012 onward, OAuth 2.0: a bearer token over TLS.**

```http
GET /photos HTTP/1.1
Host: photos.example.net
Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6IjIwMjYtMDkiLCJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOi...
```

**2023 onward, DPoP: a token bound to a key, plus a fresh proof per request.**

```http
GET /photos HTTP/1.1
Host: photos.example.net
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6IjIwMjYtMDkiLCJ0eXAiOiJhdCtqd3QifQ.eyJjbmYiOnsiamt0Ij...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYi...
```

Read top to bottom, the trend is clear: the long-term secret leaves the request, the credential gets scoped and short-lived, and finally it becomes useless without a private key the attacker does not have.

---

## 15. Lessons learned: the recurring themes

### 15.1 Move secrets off the wire, then out of the server

| Era | How the secret moved |
|---|---|
| Unix crypt (1979) | Server stores a one-way hash, not the password |
| Kerberos (1980s) | Password never sent; tickets instead |
| SSH (1995) | Public-key login: private key never leaves the client |
| Digest (1997) | Hash of password and nonce instead of the password (later superseded by TLS) |
| OAuth (2007, 2012) | Third-party apps never see the user's password |
| PKCE (2015) | Code redeemable only with a verifier that never travels in the front channel |
| WebAuthn / passkeys (2019, 2022) | Server stores only a public key; a database breach leaks nothing usable |

The end state is **public-key authentication everywhere**: nothing the server stores, and nothing that crosses the network, lets an attacker impersonate the user.

### 15.2 Bind credentials to the origin and to the sender

Bearer credentials (passwords, cookies, bearer tokens, OTP codes) work for *anyone* who holds them. The fixes bind them:

- **To the origin:** FIDO/WebAuthn signatures include the origin; `SameSite` cookies are not sent on cross-site requests; OIDC `aud` and SAML audience restrictions stop tokens from being replayed to other applications.
- **To the sender:** PKCE binds a code to the client instance; mTLS (RFC 8705) and DPoP (RFC 9449) bind tokens to a private key; the 2016 OAuth mix-up attacks were about a client accepting a response from (or sending a code to) the wrong authorization server, which the `iss` response parameter (RFC 9207) now prevents.

### 15.3 Separate authentication from authorization

OAuth 1.0 and 2.0 deliberately did **delegation**, not login. Treating access tokens as proof of identity caused years of vulnerabilities until OpenID Connect added a separate, audience-restricted ID token. The same separation shows up as IdP vs SP in SAML, as scopes vs claims in OAuth/OIDC, and as authentication vs [authorization](13-authorization-rbac-abac-rebac.md) in application code.

### 15.4 Shorten lifetimes and make revocation possible

Kerberos tickets expire in hours. Sessions get idle and absolute timeouts. Access tokens dropped from long-lived to 5-15 minutes, refresh tokens are rotated on every use, workload credentials are minted on demand, and even public TLS certificates are scheduled to shrink to 47 days by 2029. Short lifetimes turn "permanent compromise" into "brief window".

### 15.5 Centralize, but protect the center

Kerberos KDCs, LDAP directories, SAML IdPs and OIDC providers all centralize authentication, which makes MFA, auditing and offboarding possible in one place. It also creates a single target: golden tickets and golden SAML are what happens when the center's keys are stolen. Protect signing keys in HSMs or KMSs, rotate them, and monitor token issuance.

### 15.6 Usability is a security property

Composition rules and forced rotation produced `Password1!`, `Password2!`. OpenID 2.0's URL identifiers confused users. Hardware tokens for everyone never happened. Passkeys are succeeding partly because they are *easier* than passwords. If the secure path is harder than the insecure one, users and developers will find the insecure one.

### 15.7 Attackers go to the weakest link

When passwords got hashed, attackers phished. When MFA arrived, they relayed codes and spammed push prompts. When MFA became phishing-resistant, they went after **account recovery**, help desks and session cookies after login. Every new defense moves the attack, so recovery flows, session handling and token storage deserve the same rigor as the login screen.

### 15.8 Deprecate aggressively

The implicit grant, the password grant, SHA-1, RC4, TLS 1.0, SMS OTP: each lived on years after its weakness was known, because removing things is hard. Build systems that can change algorithms and flows (algorithm allowlists, `kid`-based key rotation, `DelegatingPasswordEncoder` hash prefixes) so you can deprecate quickly when the next weakness appears.

---

## 16. Production best practices (2026): what history tells you to do

| Theme | 2026 practice | Concrete settings |
|---|---|---|
| Password storage | Argon2id with unique salts, upgrade old hashes on login | m=19 MiB, t=2, p=1 minimum ([chapter 02](02-passwords-and-credential-storage.md)) |
| Password policy | NIST SP 800-63B-4: length and blocklists, no composition rules, no forced rotation | 15+ characters if password-only, 8+ with mandatory MFA; accept at least 64 |
| MFA | Passkeys first, TOTP acceptable, SMS only as a restricted fallback | Offer at least one phishing-resistant option (NIST AAL2) |
| Browser apps | Server-side session or BFF; no tokens in JavaScript-readable storage | `HttpOnly; Secure; SameSite=Lax` (or `Strict`), CSRF protection |
| OAuth | Authorization code + PKCE for every client; exact redirect URIs; no implicit or password grant | Follow RFC 9700; track OAuth 2.1 (draft) |
| Login for apps | OpenID Connect, validating ID token `iss`, `aud`, `exp`, `nonce` | Never use a plain access token as proof of identity |
| Tokens | Short-lived access tokens, rotated refresh tokens with reuse detection, sender-constrained where justified | Access 5-15 min; refresh rotation on every use; DPoP or mTLS for high-risk APIs |
| JWT | Algorithm allowlist, asymmetric keys when multiple verifiers, JWKS with `kid` and rotation | ES256/EdDSA or RS256 (2048+ bit); validate `iss`, `aud`, `exp`, `nbf` |
| Services | Client credentials with private-key JWT or mTLS; workload identity federation | No long-lived shared secrets in config or CI |
| Transport | TLS 1.3 preferred, HSTS, automated certificates | Plan for 47-day certificates by 2029 |

---

## 17. Common attacks and mistakes: repeating history

| Attack / mistake | What goes wrong | Mitigation |
|---|---|---|
| Storing passwords with MD5/SHA-1/SHA-256 (the 2000s mistake) | Offline cracking at billions of guesses per second after a breach | Argon2id/scrypt/bcrypt with salt; rehash on login |
| Encrypting passwords instead of hashing (Adobe 2013) | Whoever gets the key gets every password | One-way password hashing; never reversible storage |
| Password rules that force complexity and rotation (pre-2017) | Predictable patterns, sticky notes, `Spring2026!` | NIST SP 800-63B-4 length + blocklist approach |
| TLS only on the login page (pre-Firesheep) | Session cookies sniffed on public networks | HTTPS everywhere, HSTS, `Secure` cookies |
| Asking users for their password to another service (2007 anti-pattern) | Full, unrevocable access; trains users to be phished | OAuth authorization code + PKCE with narrow scopes |
| Using the implicit grant in a new SPA | Tokens leak through URLs and browser history | Authorization code + PKCE, ideally behind a BFF |
| Using the password grant "because it's simple" | App handles passwords; MFA and federation impossible | Redirect-based authorization code flow |
| Treating an OAuth access token as login | Token substitution: tokens issued to other apps accepted | OpenID Connect ID token validation |
| Trusting the JWT `alg` header (2015-era library bug) | `alg: none` or algorithm confusion forges tokens | Server-side algorithm allowlist and key selection |
| Long-lived bearer tokens | A single leak gives months of access | 5-15 min access tokens; rotated refresh tokens; DPoP/mTLS |
| SMS OTP for high-value accounts | SIM swap and real-time phishing | Passkeys or security keys; SMS only as a restricted fallback |
| Weak account recovery behind strong MFA | Attackers skip MFA by "recovering" the account | Recovery codes, notifications, waiting periods, require existing factors |
| Long-lived service secrets in repositories | Leaked keys used for months | Workload identity federation, short-lived tokens, secret scanning |
| Building a custom SSO or token protocol | Rediscovering signature wrapping, mix-up and replay bugs | Use OIDC, SAML or OAuth via mature libraries |

---

## 18. Spring Boot 4 / Spring Security 7: the eras in one framework

Spring Security has accumulated support for most of this history, which makes it a good map from concepts to code. Since Spring Security 7, each built-in authentication mechanism also adds a **factor authority** to the `Authentication` that records *how* the user authenticated (for example `FACTOR_PASSWORD`, `FACTOR_WEBAUTHN`, `FACTOR_X509`, `FACTOR_OTT`, `FACTOR_SAML_RESPONSE`, `FACTOR_AUTHORIZATION_CODE`, `FACTOR_BEARER`), and `@EnableMultiFactorAuthentication` can require more than one of them.

| Era | Mechanism | Spring Security 7 DSL (lambda style) |
|---|---|---|
| Early web (1996) | HTTP Basic | `http.httpBasic(Customizer.withDefaults())` |
| Early web (1990s) | Form login + server-side session + CSRF | `http.formLogin(...)`, `sessionManagement(...)`, `csrf(...)` (CSRF on by default) |
| Network / PKI | Client certificates (mTLS) | `http.x509(...)` |
| Enterprise federation (2005) | SAML 2.0 SSO | `http.saml2Login(...)`, `saml2Logout(...)`, `saml2Metadata(...)` |
| Token era (2014) | OpenID Connect login | `http.oauth2Login(...)`, `oidcLogout(...)` |
| Token era (2015) | JWT bearer tokens for APIs | `http.oauth2ResourceServer(rs -> rs.jwt(...))` |
| OAuth authorization server | Issue tokens (Spring Authorization Server, now part of Spring Security 7) | `http.oauth2AuthorizationServer(...)` |
| Passwordless (email links) | One-time tokens | `http.oneTimeTokenLogin(...)` |
| Phishing-resistant (2019+) | WebAuthn / passkeys | `http.webAuthn(...)` |

A modern browser-app login that offers both a password form and passkeys:

```java
package com.example.auth.evolution;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
class ModernLoginConfig {

    @Bean
    SecurityFilterChain web(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/error", "/css/**").permitAll()
                .anyRequest().authenticated())
            // 1990s idea, still right for browsers: form login + server-side session.
            // Spring rotates the session ID on login and enables CSRF protection by default.
            .formLogin(Customizer.withDefaults())
            // 2019+ idea: origin-bound public-key credentials (passkeys).
            .webAuthn(webAuthn -> webAuthn
                .rpName("Example App")
                .rpId("example.com")
                .allowedOrigins("https://example.com"));
        return http.build();
    }
}
```

This assumes a `UserDetailsService` and a `PasswordEncoder` bean (see [chapter 02](02-passwords-and-credential-storage.md)) and the `org.springframework.security:spring-security-webauthn` dependency (version managed by Spring Boot); without configured repositories, Spring keeps WebAuthn credentials in memory, which is only suitable for demos. Runnable, era-specific examples:

- Form login, sessions, Argon2id, CSRF, fixation, throttling: [../examples/01-session-auth/](../examples/01-session-auth/)
- JWT access tokens, rotating refresh tokens, JWKS: [../examples/02-jwt-auth/](../examples/02-jwt-auth/)
- OAuth 2 / OIDC authorization server, resource server and BFF: [../examples/03-oauth2-oidc/](../examples/03-oauth2-oidc/)
- TOTP second factor with recovery codes: [../examples/04-mfa-totp/](../examples/04-mfa-totp/)
- Hashed API keys and HMAC webhooks: [../examples/05-api-keys-hmac/](../examples/05-api-keys-hmac/)

---

## Interview questions

1. **Why did systems stop storing passwords in plaintext, and what was the first fix?**
   Plaintext files leaked through insiders and bugs (CTSS in 1962 and 1966). The fix, used at Cambridge by 1967 and in Unix by the 1970s, was storing a one-way transformation so the file alone does not reveal passwords. Salts (Unix, 1979) and slow, memory-hard functions (bcrypt 1999, scrypt 2009, Argon2 2015) followed as attackers got faster.

2. **What problem did Kerberos solve, and why didn't it become the authentication protocol of the web?**
   It kept passwords off the network and gave single sign-on within an organization using tickets. It assumes a managed network, reachable KDCs and synchronized clocks, uses password-derived symmetric keys that can be cracked offline, and does not cross organizational boundaries, so the web adopted SAML and later OpenID Connect.

3. **Why did OAuth 2.0 drop OAuth 1.0's request signatures, and what did that cost?**
   Signatures were complex and caused interoperability bugs; OAuth 2.0 relied on TLS and simple bearer tokens instead. The cost was that stolen tokens can be replayed by anyone, which later led to sender-constrained tokens (mTLS RFC 8705, DPoP RFC 9449).

4. **Why is OpenID Connect needed if we already have OAuth 2.0?**
   OAuth 2.0 is for delegated authorization; an access token says what the bearer may do at an API, not who the user is or which client it was issued to. OIDC adds an ID token for the client with `iss`, `aud`, `sub`, `nonce` and authentication time, which prevents token-substitution login attacks.

5. **What is the OAuth 2.0 Security BCP and what did it change?**
   RFC 9700 (January 2025, BCP 240) consolidates years of attack research: PKCE for all clients, exact redirect URI matching, the implicit grant discouraged, the password grant forbidden, refresh token rotation or sender-constraining for public clients, and more. OAuth 2.1, still a draft in 2026, folds these rules into the core spec.

6. **What made FIDO/WebAuthn phishing-resistant when TOTP and SMS were not?**
   The browser includes the real origin in what the authenticator signs, and credentials are scoped to the relying party ID. A phishing domain cannot get a signature valid for the real site, whereas OTP codes are just numbers a user can type into any page.

7. **What are passkeys, and what trade-off do synced passkeys make?**
   Passkeys are FIDO2/WebAuthn credentials that platforms can sync across a user's devices. Syncing solves device loss and makes passwordless login practical, but the private key is exportable to the sync fabric, so NIST SP 800-63B-4 allows synced passkeys up to AAL2 while AAL3 needs non-exportable keys.

8. **Name three recurring themes in the evolution of authentication.**
   Move secrets off the wire (hashes, Kerberos, OAuth, public keys); bind credentials to origin and sender (WebAuthn, PKCE, DPoP, audience restriction); shorten lifetimes (short access tokens, rotated refresh tokens, ephemeral workload credentials); and separate authentication from authorization (OIDC vs OAuth).

9. **What is FedCM and why does it exist?**
   A browser API for federated sign-in that lets the browser show the account chooser and mediate the exchange without third-party cookies, limiting tracking. It shipped in Chrome in 2022 and is a W3C Working Draft; in 2026 it works in Chromium-based browsers only, so IdPs keep redirect-based OIDC as a fallback.

10. **Is OAuth 2.1 a published standard?**
    No. As of October 2026 it is still an IETF Internet-Draft (revision 16, September 2026). The published baseline is RFC 6749 and RFC 6750 plus RFC 9700 and the related extension RFCs.

---

## References

**Passwords and early systems**

- Morris, R. and Thompson, K., *Password Security: A Case History*, Communications of the ACM 22(11), November 1979
- Provos, N. and Mazières, D., *A Future-Adaptable Password Scheme*, USENIX Annual Technical Conference, 1999: https://www.usenix.org/legacy/event/usenix99/provos/provos.pdf
- RFC 2898, *PKCS #5 v2.0* (PBKDF2), 2000: https://www.rfc-editor.org/rfc/rfc2898 (current version RFC 8018: https://www.rfc-editor.org/rfc/rfc8018)
- RFC 7914, *The scrypt Password-Based Key Derivation Function*, 2016: https://www.rfc-editor.org/rfc/rfc7914
- RFC 9106, *Argon2*, 2021: https://www.rfc-editor.org/rfc/rfc9106

**Network authentication**

- RFC 1510, *Kerberos V5*, 1993: https://www.rfc-editor.org/rfc/rfc1510
- RFC 4120, *Kerberos V5*, 2005: https://www.rfc-editor.org/rfc/rfc4120
- RFC 4559, *SPNEGO-based Kerberos and NTLM HTTP Authentication*, 2006: https://www.rfc-editor.org/rfc/rfc4559
- RFC 1487, *X.500 Lightweight Directory Access Protocol*, 1993: https://www.rfc-editor.org/rfc/rfc1487
- RFC 4511, *LDAP: The Protocol*, 2006: https://www.rfc-editor.org/rfc/rfc4511
- RFC 2058, *RADIUS*, 1997: https://www.rfc-editor.org/rfc/rfc2058
- RFC 2865, *RADIUS*, 2000: https://www.rfc-editor.org/rfc/rfc2865
- Blast-RADIUS, CVE-2024-3596: https://www.blastradius.fail/

**Early web**

- RFC 1945, *HTTP/1.0*, 1996: https://www.rfc-editor.org/rfc/rfc1945
- RFC 2069, *HTTP Digest Access Authentication*, 1997: https://www.rfc-editor.org/rfc/rfc2069
- RFC 7616, *HTTP Digest Access Authentication*, 2015: https://www.rfc-editor.org/rfc/rfc7616
- RFC 7617, *The 'Basic' HTTP Authentication Scheme*, 2015: https://www.rfc-editor.org/rfc/rfc7617
- RFC 2109, *HTTP State Management Mechanism*, 1997: https://www.rfc-editor.org/rfc/rfc2109
- RFC 6265, *HTTP State Management Mechanism*, 2011: https://www.rfc-editor.org/rfc/rfc6265
- draft-ietf-httpbis-rfc6265bis (Internet-Draft): https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/
- RFC 2246, *TLS 1.0*, 1999: https://www.rfc-editor.org/rfc/rfc2246
- RFC 8446, *TLS 1.3*, 2018: https://www.rfc-editor.org/rfc/rfc8446
- RFC 9846, *TLS 1.3*, 2026: https://www.rfc-editor.org/rfc/rfc9846
- RFC 8996, *Deprecating TLS 1.0 and TLS 1.1*, 2021: https://www.rfc-editor.org/rfc/rfc8996

**Federation and delegation**

- OASIS SAML 2.0 specifications, 2005: https://docs.oasis-open.org/security/saml/v2.0/
- Somorovsky et al., *On Breaking SAML: Be Whoever You Want to Be*, USENIX Security 2012: https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky
- OpenID Authentication 2.0, 2007: https://openid.net/specs/openid-authentication-2_0.html
- OAuth Core 1.0 Revision A, 2009, and OAuth Security Advisory 2009.1: https://oauth.net/core/1.0a/ and https://oauth.net/advisories/2009-1/
- RFC 5849, *The OAuth 1.0 Protocol*, 2010: https://www.rfc-editor.org/rfc/rfc5849
- RFC 6749, *The OAuth 2.0 Authorization Framework*, 2012: https://www.rfc-editor.org/rfc/rfc6749
- RFC 6750, *Bearer Token Usage*, 2012: https://www.rfc-editor.org/rfc/rfc6750
- RFC 6819, *OAuth 2.0 Threat Model and Security Considerations*, 2013: https://www.rfc-editor.org/rfc/rfc6819
- OpenID Connect Core 1.0 (incorporating errata set 2): https://openid.net/specs/openid-connect-core-1_0.html
- RFC 7519, *JSON Web Token*, 2015: https://www.rfc-editor.org/rfc/rfc7519
- RFC 7636, *PKCE*, 2015: https://www.rfc-editor.org/rfc/rfc7636
- RFC 8252, *OAuth 2.0 for Native Apps*, 2017: https://www.rfc-editor.org/rfc/rfc8252
- RFC 8628, *OAuth 2.0 Device Authorization Grant*, 2019: https://www.rfc-editor.org/rfc/rfc8628
- RFC 8693, *OAuth 2.0 Token Exchange*, 2020: https://www.rfc-editor.org/rfc/rfc8693
- RFC 8705, *OAuth 2.0 Mutual-TLS*, 2020: https://www.rfc-editor.org/rfc/rfc8705
- RFC 8725, *JSON Web Token Best Current Practices*, 2020: https://www.rfc-editor.org/rfc/rfc8725
- RFC 9068, *JWT Profile for OAuth 2.0 Access Tokens*, 2021: https://www.rfc-editor.org/rfc/rfc9068
- RFC 9126, *Pushed Authorization Requests*, 2021: https://www.rfc-editor.org/rfc/rfc9126
- RFC 9207, *Authorization Server Issuer Identification*, 2022: https://www.rfc-editor.org/rfc/rfc9207
- RFC 9396, *Rich Authorization Requests*, 2023: https://www.rfc-editor.org/rfc/rfc9396
- RFC 9449, *DPoP*, 2023: https://www.rfc-editor.org/rfc/rfc9449
- RFC 9470, *Step Up Authentication Challenge Protocol*, 2023: https://www.rfc-editor.org/rfc/rfc9470
- RFC 9635, *GNAP*, 2024: https://www.rfc-editor.org/rfc/rfc9635
- RFC 9700, *OAuth 2.0 Security Best Current Practice*, 2025: https://www.rfc-editor.org/rfc/rfc9700
- RFC 9728, *OAuth 2.0 Protected Resource Metadata*, 2025: https://www.rfc-editor.org/rfc/rfc9728
- RFC 10017, *OAuth 2.0 for Browser-Based Applications*, 2026: https://www.rfc-editor.org/rfc/rfc10017
- draft-ietf-oauth-v2-1, *The OAuth 2.1 Authorization Framework* (Internet-Draft): https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/
- FAPI 2.0 Security Profile (final): https://openid.net/specs/fapi-security-profile-2_0-final.html

**Beyond passwords**

- RFC 4226, *HOTP*, 2005: https://www.rfc-editor.org/rfc/rfc4226
- RFC 6238, *TOTP*, 2011: https://www.rfc-editor.org/rfc/rfc6238
- W3C, *Web Authentication Level 3*: https://www.w3.org/TR/webauthn-3/
- FIDO Alliance specifications (U2F, CTAP): https://fidoalliance.org/specifications/
- NIST SP 800-63-3 (2017, superseded): https://pages.nist.gov/800-63-3/
- NIST SP 800-63-4 (2025): https://pages.nist.gov/800-63-4/
- NIST SP 800-63B-4: https://pages.nist.gov/800-63-4/sp800-63b/

**Zero trust, workloads and the browser**

- NIST SP 800-207, *Zero Trust Architecture*, 2020: https://csrc.nist.gov/pubs/sp/800/207/final
- Ward, R. and Beyer, B., *BeyondCorp: A New Approach to Enterprise Security*, ;login:, 2014: https://research.google/pubs/beyondcorp-a-new-approach-to-enterprise-security/
- SPIFFE: https://spiffe.io/
- OpenID Shared Signals Framework, CAEP and RISC: https://openid.net/wg/sharedsignals/
- W3C, *Federated Credential Management API*: https://www.w3.org/TR/fedcm/
- CA/Browser Forum Ballot SC-081 (certificate validity reduction): https://cabforum.org/
