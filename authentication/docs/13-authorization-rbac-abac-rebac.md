# 13 — Authorization: ACLs, RBAC, ABAC and ReBAC

Authentication answers **"who are you?"**. Authorization answers **"what are you allowed to do, to which thing, right now?"**. Every earlier chapter ends at the moment the system knows who the caller is. This chapter covers what happens next: access control lists, role-based, attribute-based and relationship-based access control (Google Zanzibar, OpenFGA, SpiceDB), OAuth scopes versus real permissions, policy engines (OPA/Rego, Cedar), where to enforce decisions, multi-tenant isolation, and the bugs that dominate real-world breaches: BOLA/IDOR, broken function-level authorization and mass assignment. It ends with Spring Security 7 method security.

> **Where this fits in the evolution**
>
> - **Before:** Access control predates the web. Lampson's access matrix (1971), mandatory access control for military systems (Bell-LaPadula, 1973) and per-file access control lists (Multics, Unix permission bits) protected shared computers. Business software then adopted **roles** (RBAC, formalized by NIST in 1992 and standardized as ANSI INCITS 359 in 2004).
> - **What it solved and what broke:** Roles were easy to audit but exploded in number once rules depended on region, department, project or time. **ABAC** (XACML, NIST SP 800-162) added attributes and context. Collaboration apps (documents shared with users, groups and folders) needed permissions that follow **relationships**, which led to Google's **Zanzibar** paper (2019) and open-source **ReBAC** systems.
> - **What extends it:** Policy-as-code engines (OPA, Cedar), the OpenID **AuthZEN Authorization API 1.0** (final January 2026) that standardizes how an application asks a policy decision point for a decision, and continuous evaluation driven by security signals (see [production architecture](14-production-architecture-and-checklist.md)). OAuth ([chapter 08](08-oauth-2.md)) is related but different: it delegates access from a user to a *client*, it does not decide what the *user* may do.

---

## Table of contents

1. [Authentication vs authorization](#1-authentication-vs-authorization)
2. [Vocabulary: subjects, resources, PEP and PDP](#2-vocabulary-subjects-resources-pep-and-pdp)
3. [How access control models evolved](#3-how-access-control-models-evolved)
4. [Access control lists (ACLs)](#4-access-control-lists-acls)
5. [Role-based access control (RBAC)](#5-role-based-access-control-rbac)
6. [Attribute-based access control (ABAC)](#6-attribute-based-access-control-abac)
7. [Relationship-based access control (ReBAC) and Zanzibar](#7-relationship-based-access-control-rebac-and-zanzibar)
8. [Choosing a model](#8-choosing-a-model)
9. [OAuth scopes vs fine-grained permissions](#9-oauth-scopes-vs-fine-grained-permissions)
10. [Policy engines: OPA, Cedar and AuthZEN](#10-policy-engines-opa-cedar-and-authzen)
11. [Where to enforce: gateway, service, data](#11-where-to-enforce-gateway-service-data)
12. [Multi-tenancy and tenant isolation](#12-multi-tenancy-and-tenant-isolation)
13. [The bugs that cause breaches: BOLA, BFLA, mass assignment](#13-the-bugs-that-cause-breaches-bola-bfla-mass-assignment)
14. [Least privilege and access governance](#14-least-privilege-and-access-governance)
15. [Production best practices (2026)](#15-production-best-practices-2026)
16. [Common attacks and mistakes](#16-common-attacks-and-mistakes)
17. [Spring Boot 4 / Spring Security 7](#17-spring-boot-4--spring-security-7)
18. [Interview questions](#interview-questions)
19. [References](#references)

---

## 1. Authentication vs authorization

| | Authentication (authn) | Authorization (authz) |
|---|---|---|
| Question | Who is calling? | May this caller perform this action on this resource now? |
| Input | Credentials: password, passkey, token, certificate | The authenticated principal, the action, the resource, the context |
| Output | A principal plus *how* it was proven (method, time, assurance level) | Permit or deny, sometimes with obligations ("log this", "mask field X") |
| Frequency | Once per login or token validation | On **every** request, often several times per request |
| Typical failure | Account takeover | Data leak or privilege escalation by a legitimate, logged-in user |
| OWASP Top 10:2025 | A07 Authentication Failures | **A01 Broken Access Control** (number one in 2021 and 2025) |

The two are separate steps, but they are connected. Authorization often depends on **how** the user authenticated: "approve a payment only if the user authenticated with a phishing-resistant factor in the last 5 minutes". OpenID Connect carries this as `acr`, `amr` and `auth_time` ([chapter 10](10-openid-connect.md)), and RFC 9470 defines how an API asks for a stronger login ([chapter 09](09-modern-oauth-2.1-and-extensions.md)).

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant G as API gateway
    participant S as Orders service
    participant P as Policy decision point
    participant D as Database
    C->>G: GET /orders/8812 with Bearer token
    G->>G: Authenticate - verify signature, iss, aud, exp
    G->>G: Coarse authorization - scope orders:read present
    G->>S: Forward request with verified identity
    S->>P: May user alice read order 8812
    P-->>S: Permit
    S->>D: SELECT order WHERE id and tenant match
    D-->>S: Row
    S-->>C: 200 OK
```

### 1.1 The HTTP status codes

RFC 9110 names are confusing: **401 Unauthorized means "not authenticated"**, and **403 Forbidden means "authenticated, but not allowed"**.

A request with an expired token gets a 401 and a challenge:

```http
GET /api/orders/8812 HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6IjIwMjYtMTAtYSJ9...
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="api", error="invalid_token", error_description="The access token expired"
Cache-Control: no-store
```

A valid token without the needed scope gets a 403 with `insufficient_scope` (RFC 6750 section 3.1):

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer realm="api", error="insufficient_scope", scope="orders:write"
Content-Type: application/problem+json

{"type":"about:blank","title":"Forbidden","status":403,"detail":"Scope orders:write is required"}
```

For **objects the caller may not even know exist** (someone else's order), return **404 Not Found** instead of 403. A 403 confirms that order 8813 exists, which helps an attacker enumerate. Many APIs therefore load objects through a query that already filters by owner or tenant, so "not yours" and "does not exist" become the same answer.

---

## 2. Vocabulary: subjects, resources, PEP and PDP

| Term | Meaning | Example |
|---|---|---|
| **Subject / principal** | Who is acting: a user, a service, a device | `user:alice`, `client:billing-service` |
| **Action / operation** | What they want to do | `read`, `approve`, `DELETE /orders/{id}` |
| **Resource / object** | What they want to act on | `order:8812`, `folder:finance` |
| **Context / environment** | Facts about the request | time, IP, device posture, `acr`, tenant |
| **Permission** | A right to perform an action on a resource type | `invoice:approve` |
| **Policy** | A rule that combines the above into permit or deny | "Managers may approve invoices under 10,000 EUR in their own cost center" |

The XACML standard and NIST SP 800-162 split an authorization system into four roles. The names are worth knowing because policy engines, AuthZEN and most vendor documentation use them:

| Component | Job | In a typical Spring service |
|---|---|---|
| **PEP** (Policy Enforcement Point) | Intercepts the request, asks for a decision, enforces it | The Spring Security filter chain, `@PreAuthorize`, a gateway filter |
| **PDP** (Policy Decision Point) | Evaluates policies and returns permit or deny | An `AuthorizationManager`, an OPA sidecar, OpenFGA, Cedar |
| **PIP** (Policy Information Point) | Supplies attributes the PDP needs | The user directory, the orders database, an HR system |
| **PAP** (Policy Administration Point) | Where policies are written and managed | A Git repository of Rego or Cedar files, an admin UI for roles |

```mermaid
flowchart LR
    U["Caller"] --> PEP["PEP: filter, gateway, annotation"]
    PEP -->|"subject, action, resource, context"| PDP["PDP: policy engine"]
    PDP -->|"needs attributes"| PIP["PIP: directory, database, HR"]
    PAP["PAP: policies in Git or admin UI"] -->|"publishes policies"| PDP
    PDP -->|"permit or deny"| PEP
    PEP -->|"if permitted"| R["Protected resource"]
```

The main design rule: **the PEP must fail closed**. If the PDP is unreachable, times out or returns something unexpected, the answer is deny.

---

## 3. How access control models evolved

| Era | Model | Origin | Core idea | What pushed the next step |
|---|---|---|---|---|
| 1970s | Access matrix, DAC | Lampson, "Protection" (1971) | A matrix of subjects × objects; owners grant rights at their discretion | The matrix is huge and sparse; nobody manages it directly |
| 1970s | MAC | Bell-LaPadula (1973) | System-enforced labels (Secret, Top Secret); "no read up, no write down" | Too rigid for business software |
| 1960s-1990s | ACLs | Multics, Unix `rwx`, Windows NTFS | Store the matrix by column: each object lists who may do what | Hard to answer "what can Alice access?"; hard to manage at scale |
| 1992-2004 | **RBAC** | Ferraiolo and Kuhn (NIST, 1992), RBAC96 (Sandhu et al., 1996), ANSI INCITS 359-2004 | Permissions go to roles; users get roles | Role explosion when rules depend on context |
| 2000s-2014 | **ABAC** | XACML 1.0 (2003) and 3.0 (2013), NIST SP 800-162 (2014) | Decisions from attributes of subject, resource, action and environment | Policies hard to audit; XML policy languages were painful |
| 2012 | OAuth scopes | RFC 6749 | Limit what a *client* may do on a user's behalf | Not a model for what the *user* may do |
| 2016-2023 | **Policy as code** | OPA/Rego (CNCF graduated 2021), Cedar (AWS, open-sourced 2023) | Policies as versioned, tested code, evaluated by a general engine | Graph-shaped permissions are awkward to express as rules |
| 2019 | **ReBAC** | Google Zanzibar paper (USENIX ATC 2019); SpiceDB, OpenFGA, Ory Keto | Permissions follow relationships in a graph | Operating a consistent relationship store |
| 2026 | Standard decision API | OpenID AuthZEN Authorization API 1.0 (final, January 2026) | One JSON API between any PEP and any PDP | Adoption is just starting |

None of these replaced the previous model completely. A 2026 SaaS product typically uses **RBAC** for coarse admin permissions, **ownership or ReBAC** for objects, **ABAC conditions** for context (tenant, region, authentication strength) and **scopes** for third-party clients.

---

## 4. Access control lists (ACLs)

### 4.1 How they work

An ACL is attached to a **resource** and lists entries of (principal, permissions):

```text
document:q3-forecast
  user:alice      read, write, share
  group:finance   read
  user:bob        read
```

Unix permission bits are a compact ACL (owner, group, other × read, write, execute). Google Drive sharing, S3 object ACLs and Windows NTFS are fuller ACL implementations.

### 4.2 Strengths and weaknesses

| Strengths | Weaknesses |
|---|---|
| Natural for user-owned, shared resources | **Reverse lookup** ("everything Alice can read") requires scanning every ACL |
| Easy to explain to users ("shared with") | Thousands of entries to keep consistent when people change teams |
| Decision is a single lookup | No inheritance unless you build it (folder to document) |
| | Revoking a user means touching every ACL that names them |

AWS illustrates the trend away from raw ACLs: since April 2023, new S3 buckets have ACLs **disabled by default** ("bucket owner enforced"), and AWS recommends policies instead.

### 4.3 ACLs in Spring

Spring Security still ships the `spring-security-acl` module (tables `acl_sid`, `acl_class`, `acl_object_identity`, `acl_entry`, plus `AclPermissionEvaluator` for `hasPermission(...)` expressions). It works, but it stores one row per grant per object, is hard to query for list endpoints, and has no notion of group nesting or folder inheritance. For new systems with sharing requirements, a ReBAC store ([section 7](#7-relationship-based-access-control-rebac-and-zanzibar)) or a simple ownership column plus a `shares` table is usually easier.

---

## 5. Role-based access control (RBAC)

### 5.1 The model

RBAC adds an indirection: **users get roles, roles get permissions**. When Carol joins finance, you assign one role instead of editing a thousand ACLs.

```mermaid
flowchart LR
    subgraph Users
        A["alice"]
        B["bob"]
        C["carol"]
    end
    subgraph Roles
        R1["ADMIN"]
        R2["ACCOUNTANT"]
        R3["VIEWER"]
    end
    subgraph Permissions
        P1["invoice:read"]
        P2["invoice:create"]
        P3["invoice:approve"]
        P4["user:manage"]
    end
    A --> R1
    B --> R2
    C --> R3
    R1 --> P4
    R1 --> R2
    R2 --> P2
    R2 --> P3
    R2 --> R3
    R3 --> P1
```

The ANSI/INCITS 359-2004 standard (based on the NIST model) defines building blocks:

| Component | Adds | Example |
|---|---|---|
| **Core RBAC** | Users, roles, permissions, sessions (a user activates a subset of roles) | `ACCOUNTANT` has `invoice:create` |
| **Hierarchical RBAC** | Roles inherit permissions from junior roles | `ADMIN` > `ACCOUNTANT` > `VIEWER` |
| **Static separation of duty (SSD)** | Some roles can never be held together | Nobody is both `PAYMENT_CREATOR` and `PAYMENT_APPROVER` |
| **Dynamic separation of duty (DSD)** | Some roles cannot be *active in the same session* | A user holding both roles must choose one per session |

### 5.2 Check permissions, not role names

Code that says `if (user.hasRole("MANAGER"))` hard-wires an organizational decision into the program. When the business decides that team leads may also approve invoices, you must change and redeploy code.

Code that says `hasAuthority("invoice:approve")` leaves the role-to-permission mapping as **data**. Roles become bundles of permissions managed by administrators.

| Approach | Example check | Change "team leads can approve" |
|---|---|---|
| Role check | `hasRole('MANAGER')` | Code change and deploy |
| Permission check | `hasAuthority('invoice:approve')` | Add the permission to the `TEAM_LEAD` role in the database |

### 5.3 Role explosion

Pure RBAC breaks when rules depend on context. "Accountants may approve invoices in their own region, under 10,000 EUR, for their own cost center" leads to roles such as `ACCOUNTANT_EMEA_CC4711_SMALL`. With 5 regions, 200 cost centers and 3 limits you have 3,000 roles that nobody can audit.

Three fixes, often combined:

1. **Scoped roles** (role bindings): a role is granted *on a resource*: "Alice is `editor` of project 42". Kubernetes `RoleBinding`, GitHub repository roles and cloud IAM role assignments all work this way. This is a step toward ReBAC.
2. **Attributes** for the conditions: keep one `ACCOUNTANT` role and express "own region, under the limit" as an ABAC condition.
3. **Relationships** for ownership and sharing (ReBAC).

### 5.4 Roles in tokens

Putting a few coarse roles or groups in an access token or ID token is fine: `"roles": ["ACCOUNTANT"]`. Putting **every permission** or **per-object grants** in tokens is not:

- Tokens grow beyond header limits (many servers cap request headers at 8 KB).
- Permissions in a token are **stale** until the token expires. Removing a role does not take effect for up to one access-token lifetime, which is one reason access tokens should live 5-15 minutes.
- Identity providers cap group claims. Microsoft Entra ID, for example, emits at most 200 groups in a JWT and switches to an "overage" indicator beyond that, which the API must handle by querying Microsoft Graph.

A good split: **coarse roles and scopes in the token, fine-grained and object-level decisions in the service or PDP**.

---

## 6. Attribute-based access control (ABAC)

### 6.1 The model

ABAC decides from **attributes**, evaluated by **policies**:

| Attribute category | Examples |
|---|---|
| Subject | department, job title, clearance, employment type, tenant, `acr` (authentication strength), risk score |
| Resource | owner, classification (public, internal, confidential), region, status (draft, approved), amount |
| Action | read, update, approve, export |
| Environment | time of day, IP range or country, device compliance, current incident mode |

A policy in plain English:

> A clinician may read a patient record if the clinician is assigned to the patient's ward **and** the request happens during the clinician's shift, **or** the clinician declares an emergency (break-glass), in which case access is granted, logged and reviewed within 24 hours.

RBAC is a special case of ABAC in which the only subject attribute is `role`.

```mermaid
sequenceDiagram
    autonumber
    participant PEP as Records API PEP
    participant PDP as Policy engine
    participant HR as HR system PIP
    participant DB as Records DB PIP
    PEP->>PDP: subject dr-lee, action read, resource record-77, context time and device
    PDP->>HR: Get ward assignment and shift for dr-lee
    HR-->>PDP: ward 4B, shift 07:00 to 19:00
    PDP->>DB: Get ward of record-77
    DB-->>PDP: ward 4B
    PDP-->>PEP: Permit with obligation log-access
    PEP->>PEP: Write audit event, then return the record
```

### 6.2 Strengths and weaknesses

| Strengths | Weaknesses |
|---|---|
| Very fine-grained; no role explosion | Harder to answer "who can access record 77?" (you must evaluate policies for every subject) |
| Context-aware: time, location, device, authentication strength | Attributes must be **trustworthy and fresh**: a stale "department" attribute is a wrong decision |
| Policies can change without code changes | Each attribute lookup adds latency |
| Natural fit for regulations ("EU data stays with EU staff") | Policies need their own tests, review and versioning |

**Attribute trust is the main risk.** An attribute that comes from the client (`X-User-Department: finance`) is worthless. Attributes must come from the token issued by your identity provider, from your own database, or from another authoritative system.

### 6.3 XACML and its successors

XACML (OASIS, version 3.0 in 2013) is the original ABAC standard: an XML policy language plus the PEP/PDP/PIP/PAP architecture. The architecture lives on; the XML language has largely been replaced by **policy-as-code** languages such as Rego and Cedar ([section 10](#10-policy-engines-opa-cedar-and-authzen)).

---

## 7. Relationship-based access control (ReBAC) and Zanzibar

### 7.1 The idea

In collaboration products, permissions follow **relationships**:

- Alice is a **member** of team Engineering.
- Team Engineering is an **editor** of folder Roadmaps.
- Folder Roadmaps is the **parent** of document Q3-Plan.
- Therefore Alice can **edit** Q3-Plan.

Expressing this with roles needs a role per folder; with ABAC it needs recursive attribute lookups. ReBAC stores the relationships as a graph and answers questions by walking it.

```mermaid
flowchart LR
    alice["user alice"] -->|"member"| eng["team engineering"]
    eng -->|"editor"| folder["folder roadmaps"]
    folder -->|"parent of"| doc["document q3-plan"]
    bob["user bob"] -->|"viewer"| doc
    doc -.->|"can edit: alice via team and folder"| alice
```

### 7.2 Google Zanzibar (2019)

Google described its global authorization system in *Zanzibar: Google's Consistent, Global Authorization System* (Pang et al., USENIX ATC 2019). It serves Calendar, Cloud, Drive, Maps, Photos, YouTube and hundreds of other services. The paper's abstract reports trillions of access control lists, millions of authorization requests per second, 95th-percentile latency below 10 milliseconds and availability above 99.999% over three years of production use.

Key concepts:

| Concept | Meaning |
|---|---|
| **Relation tuple** | `object#relation@user`, for example `doc:readme#owner@user:10`. The "user" can itself be a **userset**: `doc:readme#viewer@group:eng#member` ("members of group eng are viewers") |
| **Namespace configuration** | Per object type: which relations exist and how they derive from each other (**userset rewrites**): `viewer` includes `editor`, `editor` includes `owner`, and a document's `viewer` includes the parent folder's `viewer` |
| **APIs** | `Check` (may U do R on O?), `Read` (list tuples), `Write`, `Expand` (show the effective userset tree), `Watch` (stream changes) |
| **Zookies** | Consistency tokens. A client stores a zookie with the content version; later checks are evaluated at a snapshot at least that new |
| **The "new enemy" problem** | Without ordering, two failures happen: (1) Alice removes Bob from a folder, then adds a secret document, and a stale check still lets Bob see it; (2) Alice removes Bob's access to a document, then edits the content, and the new content is shown to Bob because the ACL check used an old snapshot. Zookies solve both |
| **Leopard** | A specialized index that flattens deeply nested group memberships for fast checks |

### 7.3 Open-source Zanzibar-style systems

| System | Origin | Notes |
|---|---|---|
| **OpenFGA** | Created by Auth0/Okta, open-sourced 2022, **CNCF incubating since October 2025** | DSL for authorization models, HTTP and gRPC APIs, conditional tuples (CEL) for ABAC-style conditions, AuthZEN endpoint |
| **SpiceDB** | AuthZed, open source | Schema language with `relation` and `permission`, consistency tokens (ZedTokens), caveats (CEL) for conditions |
| **Ory Keto** | Ory | Zanzibar-inspired permission server in the Ory stack |
| **Permify, Warrant** and others | Various | Similar models with different storage and hosting choices |

### 7.4 An OpenFGA model

```text
model
  schema 1.1

type user

type team
  relations
    define member: [user]

type folder
  relations
    define owner: [user]
    define editor: [user, team#member] or owner
    define viewer: [user, team#member] or editor

type document
  relations
    define parent: [folder]
    define owner: [user]
    define editor: [user, team#member] or owner or editor from parent
    define viewer: [user, team#member, user:*] or editor or viewer from parent
```

`editor from parent` means "anyone who is an editor of this document's parent folder". `user:*` allows public sharing.

Relationships are written as tuples:

```http
POST /stores/01JAZ3T8T9Q0WPE7K4X5N9RB2M/write HTTP/1.1
Host: fga.internal.example.com
Authorization: Bearer eyJhbGciOiJFUzI1NiJ9...
Content-Type: application/json

{
  "writes": {
    "tuple_keys": [
      { "user": "user:alice", "relation": "member", "object": "team:engineering" },
      { "user": "team:engineering#member", "relation": "editor", "object": "folder:roadmaps" },
      { "user": "folder:roadmaps", "relation": "parent", "object": "document:q3-plan" }
    ]
  }
}
```

A check walks the graph:

```http
POST /stores/01JAZ3T8T9Q0WPE7K4X5N9RB2M/check HTTP/1.1
Host: fga.internal.example.com
Authorization: Bearer eyJhbGciOiJFUzI1NiJ9...
Content-Type: application/json

{
  "authorization_model_id": "01JAZ40C1V6S8Q7NZ0V9W3E1TQ",
  "tuple_key": { "user": "user:alice", "relation": "editor", "object": "document:q3-plan" }
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{ "allowed": true, "resolution": "" }
```

For list pages, `ListObjects` answers "which documents can Alice view?" so the service can filter its query (see [section 11.3](#113-data-level-filtering)).

### 7.5 The same idea in SpiceDB

```text
definition user {}

definition team {
    relation member: user
}

definition document {
    relation owner: user
    relation editor: user | team#member
    relation viewer: user | team#member

    permission edit = owner + editor
    permission view = edit + viewer
}
```

### 7.6 Operating ReBAC: the hard parts

| Problem | What goes wrong | Practical answer |
|---|---|---|
| **Dual writes** | The app commits "document created" to its database but the tuple write to the ReBAC store fails, so the owner cannot open their own document (or a deletion leaves stale grants) | Transactional outbox: write the tuple change to an outbox table in the same transaction, deliver it asynchronously with retries; or make the ReBAC store the source of truth for sharing |
| **Consistency** | A check right after a permission change sees the old state (new enemy problem) | Use consistency tokens (ZedTokens, zookies) or "fully consistent" reads for sensitive operations; accept small staleness for low-risk reads |
| **List filtering** | Checking each of 10,000 rows one by one is slow | Use `ListObjects` or `LookupResources` and filter in SQL with `id IN (...)`, or keep a materialized index |
| **Modeling** | Relations drift from product semantics | Treat the model as code: review, version, test with fixtures of tuples and expected checks |
| **Latency and availability** | Every request depends on another network service | Co-locate, cache with short TTLs, set timeouts and fail closed; monitor p99 |

---

## 8. Choosing a model

| Model | Best for | Weak at | Typical implementation |
|---|---|---|---|
| **ACL** | Small numbers of user-owned shared objects | Reverse lookups, inheritance, scale | Owner column plus `shares` table; `spring-security-acl` |
| **RBAC** | Admin consoles, internal tools, coarse API permissions | Context, ownership, per-object sharing | Roles and permissions tables; roles in tokens; `hasAuthority` |
| **ABAC** | Context and regulation: region, classification, time, device, authentication strength | Auditing "who can access X"; attribute freshness | Policy engine (OPA, Cedar) or code with clear rules |
| **ReBAC** | Collaboration: documents, folders, organizations, teams, nested groups | Operational complexity; another system to run | OpenFGA, SpiceDB, Keto |

A decision path that works for most backends:

1. Start with **authenticated + RBAC permissions** for functions (`invoice:approve`).
2. Add **ownership and tenant checks** for every object, in the query itself.
3. Add **ABAC conditions** when rules depend on context (region, amount, `acr`).
4. Move to **ReBAC** when sharing, nested groups or hierarchy inheritance appear, or when several services need the same relationship data.
5. Move policies to an **engine** when several services or languages must enforce the same rules, or when auditors want policies separate from code.

---

## 9. OAuth scopes vs fine-grained permissions

### 9.1 What a scope is

A scope (RFC 6749 section 3.3) limits what a **client application** may do **on behalf of** the user. The user (or an administrator) consents to the scope. It is a **ceiling for delegation**, not a statement of what the user is allowed to do.

The effective access for a request is the **intersection**:

```mermaid
flowchart LR
    U["What the user may do: roles, ownership, relationships"] --> E{"Effective access"}
    S["What the client was granted: scopes"] --> E
    P["Resource policy and context: tenant, acr, time"] --> E
    E --> D["Permit only if all three allow it"]
```

Example: a reporting app holds a token for Alice with scope `orders:read`.

| Request | Scope allows? | Alice allowed? | Result |
|---|---|---|---|
| Read Alice's own order | Yes | Yes | **Permit** |
| Read Bob's order in another tenant | Yes | No | **Deny** (404) |
| Cancel Alice's own order | No (`orders:write` missing) | Yes | **Deny** (403 `insufficient_scope`) |

### 9.2 Common mistakes with scopes

| Mistake | Why it is wrong | Better |
|---|---|---|
| Treating `orders:read` as "may read all orders" | Scope says what the client may do, not which objects | Check ownership and tenant on every object |
| Scopes per object (`order:8812:read`) | Token bloat, consent screens nobody understands | Coarse scopes plus object checks; RAR for transactions |
| Using scopes as user roles for first-party apps | Mixes delegation with entitlement; every user gets the same scopes | Roles or permissions for users; scopes for clients |
| Assuming client-credentials tokens are all-powerful | A service token with `orders:read` can read every tenant's orders | Bind service clients to tenants or audiences; check tenant anyway |
| Accepting tokens without checking `aud` | A token for API A works at API B | Validate audience ([chapter 06](06-tokens-and-jwt.md)) |

### 9.3 When scopes are too coarse: RAR

For transaction-level consent ("pay 45.00 EUR to IBAN DE89..."), **Rich Authorization Requests** (RFC 9396) replace a scope string with a structured `authorization_details` object that the user approves and the API enforces. See [chapter 09](09-modern-oauth-2.1-and-extensions.md).

### 9.4 Mapping scopes in Spring

Spring Security's resource server turns each scope into an authority with the `SCOPE_` prefix: scope `orders:read` becomes `SCOPE_orders:read`. Roles from a custom claim can be mapped with a second converter (see [section 17.1](#171-request-level-rules-scopes-roles-and-tenant)).

---

## 10. Policy engines: OPA, Cedar and AuthZEN

### 10.1 Why externalize policy

Authorization rules scattered across `if` statements in 40 services drift apart, are hard to audit and change only with deployments. **Policy as code** moves rules into a dedicated language, stored in Git, reviewed, unit-tested and evaluated by an engine that the application calls.

You do not always need an engine. For one service with a few rules, clear Java code in one `AuthorizationService` class is easier to read and test. Engines pay off with many services, several languages, frequent rule changes or audit requirements.

### 10.2 Open Policy Agent (OPA) and Rego

OPA is a general-purpose policy engine (CNCF graduated project). Policies are written in **Rego**, a declarative, Datalog-inspired language. OPA runs as a sidecar, a central service, or an embedded library (Go, or compiled to WebAssembly), and it is widely used for Kubernetes admission control (Gatekeeper) and Envoy external authorization.

A Rego policy (OPA 1.0 syntax, where `if` and `contains` are required):

```rego
package httpapi.authz

default allow := false

# Accountants may read invoices in their own tenant.
allow if {
    input.action == "read"
    input.resource.type == "invoice"
    "ACCOUNTANT" in input.subject.roles
    input.subject.tenant == input.resource.tenant
}

# Approvers may approve invoices below their limit, never their own.
allow if {
    input.action == "approve"
    input.resource.type == "invoice"
    "invoice:approve" in input.subject.permissions
    input.subject.tenant == input.resource.tenant
    input.resource.amount <= input.subject.approval_limit
    input.resource.created_by != input.subject.id
}

reasons contains "self-approval is not allowed" if {
    input.action == "approve"
    input.resource.created_by == input.subject.id
}
```

The service asks OPA through its Data API:

```http
POST /v1/data/httpapi/authz HTTP/1.1
Host: localhost:8181
Content-Type: application/json

{
  "input": {
    "subject":  { "id": "u-17", "tenant": "t-acme", "roles": ["ACCOUNTANT"],
                  "permissions": ["invoice:approve"], "approval_limit": 10000 },
    "action":   "approve",
    "resource": { "type": "invoice", "id": "inv-311", "tenant": "t-acme",
                  "amount": 4200, "created_by": "u-17" }
  }
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{ "result": { "allow": false, "reasons": ["self-approval is not allowed"] } }
```

OPA also writes **decision logs** (input, result, policy version) that make audits much easier.

### 10.3 Cedar

Cedar is a policy language created by AWS, open-sourced in 2023 and accepted as a **CNCF sandbox project in October 2025**. It powers Amazon Verified Permissions. Its design goals are readability, speed and **formal analyzability**: the language semantics have been formally verified, a schema validator catches typos and type errors, and analysis tools can prove that a policy change does not grant new access.

Key semantics:

- **Default deny.** Nothing is allowed unless a `permit` matches.
- **`forbid` always wins** over `permit`.
- Entities have types and hierarchy: `User::"alice" in Group::"finance"`.

```cedar
// Owners and editors may edit documents.
permit (
    principal,
    action == Action::"edit",
    resource is Document
)
when { resource.owner == principal || principal in resource.editors };

// Anyone in the document's organization may view it.
permit (
    principal,
    action == Action::"view",
    resource is Document
)
when { principal.org == resource.org };

// Nobody edits a locked document, whatever else allows it.
forbid (
    principal,
    action == Action::"edit",
    resource is Document
)
when { resource.locked };

// Confidential documents require a phishing-resistant login.
forbid (
    principal,
    action,
    resource is Document
)
when { resource.classification == "confidential" }
unless { context.amr.contains("hwk") };
```

### 10.4 AuthZEN: a standard API between PEP and PDP

Every engine had its own request format, so switching engines meant rewriting every enforcement point. The OpenID Foundation's **AuthZEN Authorization API 1.0** (final specification, January 2026) defines a common JSON API. A PEP sends subject, action, resource and context; the PDP answers with a decision:

```http
POST /access/v1/evaluation HTTP/1.1
Host: pdp.internal.example.com
Authorization: Bearer eyJhbGciOiJFUzI1NiJ9...
Content-Type: application/json

{
  "subject":  { "type": "user", "id": "alice@example.com" },
  "action":   { "name": "can_read" },
  "resource": { "type": "document", "id": "q3-plan" },
  "context":  { "time": "2026-10-08T09:30:00Z" }
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{ "decision": true }
```

The specification also defines batch evaluations and search endpoints (which subjects, resources or actions are allowed). OpenFGA and several commercial and open-source PDPs expose AuthZEN endpoints; treat support as new and check each product's documentation.

### 10.5 Engine comparison

| | In-code (Java) | OPA / Rego | Cedar | OpenFGA / SpiceDB |
|---|---|---|---|---|
| Model | Anything | ABAC and general rules | RBAC + ABAC (+ entity hierarchy) | ReBAC (+ conditions) |
| Data | Your DB | Pushed in `input` or loaded as data bundles | Entities passed with the request | Relationship tuples stored in the engine |
| Strength | Simple, fast, type-safe | Very flexible, huge ecosystem, decision logs | Readable, validated, analyzable | Sharing, hierarchies, "who can see X" |
| Weakness | Scattered and hard to audit at scale | Rego learning curve; you must supply data | Less suited to deep graphs | Operating a consistent store; dual writes |
| Latency (co-located) | Microseconds | Typically sub-millisecond to a few ms locally | Typically sub-millisecond | A few ms; depends on graph depth and consistency |

---

## 11. Where to enforce: gateway, service, data

### 11.1 Defense in depth

```mermaid
flowchart TB
    C["Client"] --> E["Edge or API gateway"]
    E -->|"token valid, audience, scope per route, tenant routing, rate limits"| S["Service: controller and method security"]
    S -->|"function-level: may call approve. object-level: may approve inv-311"| Q["Repository and queries"]
    Q -->|"every query filtered by tenant and owner"| DB[("Database with row-level security")]
    S --> P["PDP: OPA, Cedar, OpenFGA"]
    UI["UI hides buttons"] -.->|"UX only, never security"| C
```

| Layer | Enforce here | Do not rely on it for |
|---|---|---|
| **UI** | Hiding buttons and menu items for usability | Anything; the API must enforce everything |
| **Gateway** | Authentication, token audience, coarse scope per route, tenant routing, rate limits, blocking admin paths from the internet | Object-level decisions (the gateway does not have the data) |
| **Service** | Function-level (may call this operation) and object-level (may touch this record) checks; field-level filtering | Being the only line if queries are unscoped |
| **Data layer** | Tenant and owner predicates in every query; row-level security as a backstop | Business rules that need application context |
| **Async paths** | Message consumers, scheduled jobs, exports, webhooks must carry the original principal and tenant and re-check | Assuming "internal" means "authorized" |

Zero-trust networks ([chapter 12](12-service-to-service-and-zero-trust.md)) apply the same idea between services: an internal call still carries an identity and is still authorized.

### 11.2 Coarse at the gateway, fine in the service

A gateway can say "only tokens with `orders:write` may call `POST /orders/**`". It cannot say "only the buyer may cancel order 8812", because that needs the order row. Putting fine-grained rules in the gateway either duplicates the service's data access or produces wrong answers. Keep the gateway coarse and stateless; keep the fine rules next to the data.

### 11.3 Data-level filtering

Single-object endpoints can check after loading. **List and search endpoints** cannot: you must filter **in the query**, or pagination and counts leak and performance collapses.

| Technique | How | When |
|---|---|---|
| **Query predicates** | `WHERE tenant_id = :tenant AND (owner_id = :user OR visibility = 'TENANT')` | Default for ownership and tenancy |
| **Join to a grants table** | `JOIN document_grants g ON g.document_id = d.id AND g.principal_id IN (:user, :groups)` | ACL-style sharing |
| **ReBAC list API** | `ListObjects` / `LookupResources`, then `WHERE id IN (...)` | ReBAC systems with bounded result sizes |
| **Partial evaluation** | OPA's compile API turns a policy into conditions that you translate to SQL | Policy engines and large data sets |
| **Row-level security (RLS)** | The database enforces a predicate on every query | Defense in depth for multi-tenant tables |
| **Post-filtering** | Load, then drop rows the user may not see | Only for small, bounded sets; breaks pagination and counts |

PostgreSQL row-level security as a tenant backstop:

```sql
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;   -- applies to the table owner too

CREATE POLICY tenant_isolation ON invoices
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- Per transaction, from the application (parameterized, local to the transaction):
SELECT set_config('app.tenant_id', '6f1c2a9e-1b7d-4c55-9a59-2f4d3c1e8b10', true);
```

Notes: superusers and roles with `BYPASSRLS` always bypass RLS, so the application's database role must have neither. Set the tenant per transaction (`set_config(..., true)`), never per pooled connection, or one tenant's setting leaks to the next request that borrows the connection.

---

## 12. Multi-tenancy and tenant isolation

In a B2B SaaS product, a **cross-tenant data leak** is the worst authorization bug: one customer sees another customer's data. Tenant isolation must be designed in, not added per endpoint.

### 12.1 Isolation models

| Model | Data layout | Isolation | Cost and operations | Typical use |
|---|---|---|---|---|
| **Silo** | Database (or account) per tenant | Strongest; a missing `WHERE` cannot leak | Highest cost; many databases to migrate | Regulated or very large customers |
| **Bridge** | Schema per tenant in a shared database | Strong; connection selects schema | Medium; schema migrations per tenant | Mid-size tenant counts |
| **Pool** | Shared tables with a `tenant_id` column | Depends on every query being correct (plus RLS) | Lowest cost, easiest operations | Most SaaS products |

Many products mix them: pooled for most customers, silo for enterprise customers that pay for it.

### 12.2 Resolving the tenant

The tenant must come from something **the client cannot forge**:

| Source | Trustworthy? | Notes |
|---|---|---|
| Claim in a validated access token (`tenant_id`, `org_id`) | Yes | Issued by your IdP after it checked membership |
| Issuer of the token (`iss`) with one IdP per tenant | Yes | Map `iss` to tenant from your own configuration |
| Subdomain (`acme.app.example.com`) or path (`/tenants/acme/...`) | Only as a **selector** | Must be checked against the token's tenant or a server-side membership lookup |
| `X-Tenant-ID` header sent by the client | **No** | Fine only when set by your own gateway after validation, and stripped from external requests |

Users who belong to several tenants should either get a token per tenant (an "organization switch" re-issues the token) or have their membership checked server-side on every request.

### 12.3 Enforcement checklist for pooled tenancy

```mermaid
flowchart LR
    T["Validated token: tenant_id t-acme"] --> G["Gateway: path tenant equals token tenant"]
    G --> S["Service: TenantContext set once per request"]
    S --> R["Repositories: every query includes tenant_id"]
    R --> DB[("RLS policy on tenant_id")]
    S --> K["Cache keys prefixed with tenant"]
    S --> O["Object storage prefix per tenant"]
    S --> M["Messages carry tenant_id and are re-checked"]
```

- Set the tenant **once per request** from the validated token, in a request-scoped context; never accept it from the request body.
- Every repository method takes the tenant implicitly (Hibernate `@TenantId`, Spring Data query derivation with tenant, or a base repository) or explicitly; code review rejects unscoped queries.
- **Row-level security** as a backstop.
- **Caches, search indexes, object storage, queues and logs** are tenant-aware: cache key `t-acme:invoice:311`, S3 prefix `tenants/t-acme/`, search filter on tenant.
- **Background jobs** run with an explicit tenant and a service identity, never "all tenants" by accident.
- **Per-tenant encryption keys** (KMS key per tenant) for silo-like guarantees in pooled storage, and crypto-shredding on tenant deletion.
- **Enterprise SSO per tenant:** a tenant's IdP may only assert users for that tenant. Before letting a tenant claim an email domain for SSO routing or just-in-time provisioning, **verify domain ownership** (DNS TXT record). Otherwise tenant A configures an IdP that asserts `ceo@tenant-b.com`.
- **Support access** to customer tenants goes through a separate admin plane with just-in-time approval, time limits, customer-visible audit logs and impersonation tokens that record the real actor (the `act` claim from RFC 8693).
- **Automated cross-tenant tests:** for every endpoint, a test that a tenant B user gets 404 for a tenant A object.

---

## 13. The bugs that cause breaches: BOLA, BFLA, mass assignment

The **OWASP API Security Top 10 (2023)** puts three authorization bugs among the top five risks: **API1 Broken Object Level Authorization**, **API3 Broken Object Property Level Authorization** and **API5 Broken Function Level Authorization**.

### 13.1 BOLA / IDOR (API1:2023)

**Broken Object Level Authorization**, also called **Insecure Direct Object Reference (IDOR)**: the API checks that the caller is logged in, then loads whatever object ID the caller supplies.

Alice reads her own invoice, then changes the ID:

```http
GET /api/v1/invoices/1043 HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhbGljZSIsInRlbmFudF9pZCI6InQtYWNtZSJ9...
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{ "id": 1043, "tenantId": "t-globex", "customer": "Bob Smith", "iban": "DE89370400440532013000", "amount": 18250.00 }
```

The vulnerable code:

```java
@GetMapping("/api/v1/invoices/{id}")
InvoiceView get(@PathVariable long id) {
    return invoices.findById(id).map(InvoiceView::from).orElseThrow(NotFound::new);   // no ownership check
}
```

The fix scopes the query by the caller's tenant (and owner, if relevant), so another tenant's invoice is simply "not found":

```java
@GetMapping("/api/v1/invoices/{id}")
InvoiceView get(@PathVariable long id, @AuthenticationPrincipal Jwt jwt) {
    String tenant = jwt.getClaimAsString("tenant_id");
    return invoices.findByIdAndTenantId(id, tenant).map(InvoiceView::from).orElseThrow(NotFound::new);
}
```

```http
HTTP/1.1 404 Not Found
Content-Type: application/problem+json

{ "type": "about:blank", "title": "Not Found", "status": 404 }
```

**Random UUIDs do not fix BOLA.** They make guessing harder, but IDs leak through URLs, logs, emails, shared links and other API responses. The fix is always an authorization check.

BOLA hides in places reviewers forget: nested routes (`/accounts/{a}/cards/{c}` where `c` is not checked to belong to `a`), batch endpoints (`ids=1,2,3`), GraphQL resolvers, file downloads by key, export jobs, websocket subscriptions and "find by email" lookups.

### 13.2 Broken Function Level Authorization (API5:2023)

The caller may not use an **operation at all**, but the endpoint does not check:

```http
POST /api/v1/admin/users/77/roles HTTP/1.1
Host: api.example.com
Authorization: Bearer <token of an ordinary user>
Content-Type: application/json

{ "role": "ADMIN" }
```

```http
HTTP/1.1 204 No Content
```

Typical causes: admin endpoints "hidden" in the UI but exposed by the API; a new endpoint added without a rule; checks on `GET` but not on `PUT` or `DELETE` for the same path; internal endpoints reachable from outside; path-matching mismatches between the security layer and the router.

Fixes:

- **Deny by default.** End the rule list with `anyRequest().denyAll()` (or `authenticated()` plus mandatory method-level rules) so a forgotten endpoint fails closed.
- Function-level checks on **every** method and HTTP verb (`@PreAuthorize("hasAuthority('user:manage')")`).
- Admin APIs on a separate host, port or network, not reachable from the internet.
- Users may only grant roles and permissions **they hold themselves** (no self-escalation via role management).
- An automated **authorization matrix** test: every endpoint × every role, expected status.

### 13.3 Broken Object Property Level Authorization and mass assignment (API3:2023)

OWASP's 2023 list merged two older items into API3: **excessive data exposure** (reading properties you should not see) and **mass assignment** (writing properties you should not set).

Mass assignment: the framework binds the whole JSON body onto the entity.

```http
PATCH /api/v1/users/me HTTP/1.1
Host: api.example.com
Authorization: Bearer <alice's token>
Content-Type: application/json

{ "displayName": "Alice", "role": "ADMIN", "emailVerified": true, "tenantId": "t-globex" }
```

Vulnerable code binds request JSON directly to the JPA entity:

```java
@PatchMapping("/api/v1/users/me")
User update(@RequestBody User body, @AuthenticationPrincipal Jwt jwt) {   // entity as request body
    User user = users.findBySubject(jwt.getSubject()).orElseThrow();
    BeanUtils.copyProperties(body, user, "id");                            // copies role, tenantId, ...
    return users.save(user);                                               // and returns every field
}
```

The fix uses explicit request and response **DTOs** that contain only the allowed fields:

```java
record UpdateProfileRequest(@Size(max = 80) String displayName, @Size(max = 500) String bio) {}

record ProfileView(String displayName, String bio, String email) {
    static ProfileView from(User user) {
        return new ProfileView(user.getDisplayName(), user.getBio(), user.getEmail());   // no role, no hash, no tenant
    }
}

@PatchMapping("/api/v1/users/me")
ProfileView update(@Valid @RequestBody UpdateProfileRequest body, @AuthenticationPrincipal Jwt jwt) {
    User user = users.findBySubject(jwt.getSubject()).orElseThrow();
    user.changeProfile(body.displayName(), body.bio());     // role, tenant and verification are not reachable
    return ProfileView.from(users.save(user));
}
```

Also consider making the JSON mapper reject unknown properties (Jackson's `FAIL_ON_UNKNOWN_PROPERTIES`) so that a client sending `role` gets a 400 instead of silent success, and use separate DTOs per role when admins may edit more fields than users.

**Excessive data exposure** is the read-side twin: returning the entity (with `passwordHash`, `mfaSecret`, `internalNotes`, other users' emails) and expecting the client to hide fields. Return DTOs built for each audience.

### 13.4 Other recurring authorization bugs

| Bug | Example | Fix |
|---|---|---|
| **Path normalization mismatch** | Security rule on `/admin/**`, request to `/admin/../admin/x`, `/ADMIN/x`, `/admin;x=y/users` or with encoded slashes reaches the controller | Use the framework's matchers (Spring's `PathPatternRequestMatcher`) and keep the strict firewall (`StrictHttpFirewall` rejects `;`, encoded `/`, `..`); deny by default |
| **Confused deputy** | A service with broad permissions performs an action requested by a caller who lacks them | Propagate the end-user identity (token exchange, RFC 8693) and authorize the end user, not just the calling service |
| **Stale permissions** | Removed admin keeps admin rights in a 24-hour token | 5-15 minute access tokens; check sensitive permissions server-side; revoke sessions on role changes |
| **Client-side authorization** | `isAdmin: true` stored in `localStorage` or decided in JavaScript | All decisions on the server |
| **Shared cache leaks** | A CDN caches `/api/me` for the first user and serves it to others | `Cache-Control: private, no-store` on personalized responses; vary cache keys correctly |
| **TOCTOU** | Check "may approve" then approve later after the invoice changed | Check and act in one transaction, with the condition in the `UPDATE ... WHERE` |
| **Signed URL over-sharing** | Pre-signed download URL valid for 7 days, forwarded to anyone | Short expiry (minutes), bound to one object, issued only after an authorization check |

---

## 14. Least privilege and access governance

**Least privilege**: every user, service and process gets only the permissions it needs, for only as long as it needs them.

| Practice | Concrete form |
|---|---|
| **Default deny** | Unmatched requests are denied; new endpoints have no access until a rule is written |
| **Narrow scopes and audiences** | One audience per API; services request only the scopes they use |
| **Just-in-time (JIT) elevation** | Admin rights granted for 1-8 hours after approval, then removed automatically |
| **Separation of duty** | Creator and approver of a payment must differ; enforced in policy, not by convention |
| **Access reviews** | Managers re-certify their team's privileged roles, for example quarterly; unused permissions are removed |
| **Fast deprovisioning** | Leavers lose access within minutes: SCIM (RFC 7643/7644) from the HR system or IdP, plus session and refresh-token revocation |
| **Break-glass accounts** | Few, strongly protected (hardware keys), monitored, alerting on every use |
| **Service accounts** | Per-service identities with minimal permissions; no shared "integration" super-user; short-lived credentials ([chapter 12](12-service-to-service-and-zero-trust.md)) |
| **Database least privilege** | The app's DB role cannot `DROP`, cannot bypass RLS, and is separate from the migration role |
| **Audit every decision that matters** | Log denies and every privileged action with subject, action, resource, decision, policy version |

---

## 15. Production best practices (2026)

**Model and rules**

- Default deny at every layer. A request that matches no rule is denied.
- Check **permissions** (`invoice:approve`), not role names, in code. Keep role-to-permission mapping as data.
- Authorize **every object access** on the server, in the query when possible. Return 404 for objects outside the caller's scope.
- Use DTOs for every request and response body; never bind or serialize entities directly.
- Put coarse roles and scopes in tokens; keep object-level and frequently changing permissions out of tokens.
- Keep access tokens at **5-15 minutes** so role removals take effect quickly; revoke sessions and refresh tokens on privilege changes.

**Multi-tenancy**

- Tenant from a validated token claim or issuer, set once per request; path or subdomain tenant must match it.
- Every query tenant-scoped, plus **row-level security** on pooled tables, plus tenant-prefixed cache and storage keys.
- Domain verification before a tenant can claim an email domain for SSO.

**Policy engines and ReBAC**

- Co-locate the PDP (sidecar or library) when possible; budget **p99 under 5-10 ms** per decision and set a hard timeout (for example 50-100 ms) that **fails closed**.
- Cache decisions only briefly (seconds, at most about a minute) and include every input in the cache key; do not cache denies for long, and never cache across tenants.
- Version policies in Git with unit tests and a CI gate; record the policy version in decision logs.
- For ReBAC, use the outbox pattern for tuple writes and consistency tokens for checks that follow a permission change.

**Testing and monitoring**

- Maintain an **authorization matrix test** (endpoints × roles × tenants) that runs in CI.
- Add negative tests for BOLA (another user's ID), BFLA (ordinary user on admin endpoints) and mass assignment (extra fields).
- Alert on spikes of 403/404 per user (enumeration), privilege grants, break-glass use, and cross-tenant access by support staff.
- Verify against **OWASP ASVS 5.0 chapter V8 (Authorization)** ([chapter 14](14-production-architecture-and-checklist.md#14-owasp-asvs-50)).

---

## 16. Common attacks and mistakes

| Attack / mistake | What goes wrong | Mitigation |
|---|---|---|
| **BOLA / IDOR** | Logged-in user changes an ID and reads or modifies another user's or tenant's object | Object-level checks on every access; tenant- and owner-scoped queries; 404 for foreign objects; automated negative tests |
| **Broken function level authorization** | Ordinary user calls admin or internal operations | Deny by default; per-method and per-verb checks; separate admin plane; authorization matrix tests |
| **Mass assignment** | Client sets `role`, `tenantId`, `emailVerified`, `price` through a generic update | Request DTOs with only allowed fields; reject unknown properties; per-role DTOs |
| **Excessive data exposure** | API returns full entities and relies on the client to hide fields | Response DTOs per audience; field-level authorization |
| **Trusting client-supplied tenant or role** | `X-Tenant-ID` or a body field decides whose data is used | Tenant and roles only from validated tokens or server-side lookups; strip internal headers at the edge |
| **Scopes treated as permissions** | `orders:read` lets a client read every tenant's orders | Effective access = scopes ∩ user permissions ∩ policy; always check objects |
| **Role explosion** | Thousands of roles nobody understands; reviews become rubber stamps | Scoped roles, ABAC conditions, ReBAC; periodic role mining and cleanup |
| **Stale permissions in tokens** | Revoked admin keeps access until a long-lived token expires | 5-15 min access tokens; server-side checks for sensitive operations; revoke on role change |
| **Path-matching bypass** | Encoded or unusual paths skip a URL rule but still reach the controller | Framework path matchers, strict firewall, deny by default, method security as a second layer |
| **Authorization only in the UI** | Hidden buttons, but the API accepts the call | Every decision on the server |
| **Fail-open PDP** | Policy engine timeout treated as permit | Fail closed; alert on PDP errors; circuit breaker returns deny |
| **Unscoped background jobs** | Batch job or consumer processes all tenants' data or acts without a principal | Explicit tenant and service identity on every job and message; re-check on consumption |
| **Self-escalation** | A user with "manage users" grants themselves `ADMIN` | Only grant roles you hold; SoD for role management; alerts on privilege grants |
| **Unverified domain claims in multi-tenant SSO** | Tenant A's IdP asserts users with tenant B's email domain | DNS-verified domains per tenant; map users by (`iss`, `sub`), never by email alone |
| **Post-filtering large lists** | Load 10,000 rows, drop forbidden ones: slow, broken pagination, count leaks | Filter in the query (predicates, joins, ListObjects, partial evaluation) |

---

## 17. Spring Boot 4 / Spring Security 7

Spring Security 7 builds all authorization on one interface, `AuthorizationManager<T>`, used for HTTP requests (`T` = `RequestAuthorizationContext`) and for methods (`T` = `MethodInvocation` or `MethodInvocationResult`). In 7.0 the old `check` method was removed; implementations provide `authorize(...)`, which returns an `AuthorizationResult` (for example `AuthorizationDecision`). The legacy `AccessDecisionManager`/voter API moved to the separate `spring-security-access` module and is deprecated. Spring Security 7 also added `hasAllAuthorities`/`hasAllRoles` and an `AuthorizationManagerFactory` that you can publish as a bean to customize how the built-in rules (`hasRole`, `authenticated`, ...) are created.

The runnable resource server in [../examples/03-oauth2-oidc/](../examples/03-oauth2-oidc/) shows scope-based request authorization, and [../examples/05-api-keys-hmac/](../examples/05-api-keys-hmac/) shows scope checks for API keys.

### 17.1 Request-level rules: scopes, roles and tenant

```java
import java.util.Objects;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.DelegatingJwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasAuthority;
import static org.springframework.security.authorization.AuthorizationManagers.allOf;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity            // enables @PreAuthorize, @PostAuthorize, @PreFilter, @PostFilter
class ApiSecurityConfig {

    @Bean
    SecurityFilterChain api(HttpSecurity http) {
        AuthorizationManager<RequestAuthorizationContext> sameTenant = sameTenantAsToken();

        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health").permitAll()
                // coarse rules: scope per route AND path tenant must equal token tenant
                .requestMatchers(HttpMethod.GET, "/api/v1/tenants/{tenantId}/invoices/**")
                    .access(allOf(hasAuthority("SCOPE_invoices:read"), sameTenant))
                .requestMatchers(HttpMethod.POST, "/api/v1/tenants/{tenantId}/invoices/**")
                    .access(allOf(hasAuthority("SCOPE_invoices:write"), sameTenant))
                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                // default deny: anything not listed above is refused
                .anyRequest().denyAll())
            .oauth2ResourceServer(rs -> rs
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())));
        return http.build();
    }

    /** The {tenantId} path variable must match the tenant_id claim of the validated token. */
    private static AuthorizationManager<RequestAuthorizationContext> sameTenantAsToken() {
        return (authentication, context) -> {
            String pathTenant = context.getVariables().get("tenantId");
            boolean granted = authentication.get() instanceof JwtAuthenticationToken token
                    && pathTenant != null
                    && Objects.equals(pathTenant, token.getToken().getClaimAsString("tenant_id"));
            return new AuthorizationDecision(granted);
        };
    }

    /** scope claim -> SCOPE_x authorities, roles claim -> ROLE_x authorities. */
    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter scopes = new JwtGrantedAuthoritiesConverter();   // "scope"/"scp" -> SCOPE_
        JwtGrantedAuthoritiesConverter roles = new JwtGrantedAuthoritiesConverter();
        roles.setAuthoritiesClaimName("roles");
        roles.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new DelegatingJwtGrantedAuthoritiesConverter(scopes, roles));
        return converter;
    }

    /** ADMIN implies ACCOUNTANT implies VIEWER; picked up by request and method security. */
    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.withDefaultRolePrefix()
                .role("ADMIN").implies("ACCOUNTANT")
                .role("ACCOUNTANT").implies("VIEWER")
                .build();
    }
}
```

Points to notice:

- `anyRequest().denyAll()` makes a forgotten endpoint fail closed.
- The tenant rule is a plain lambda: `AuthorizationManager` is a functional interface.
- The `RoleHierarchy` bean is detected automatically by `authorizeHttpRequests` and by method security.

### 17.2 Method security with `@PreAuthorize` and `@PostAuthorize`

Method security is the right place for function-level and object-level rules because it sits next to the business logic and protects the method no matter which controller, consumer or job calls it.

```java
import java.util.List;
import java.util.UUID;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class InvoiceService {

    private final InvoiceRepository invoices;
    private final TenantContext tenant;

    InvoiceService(InvoiceRepository invoices, TenantContext tenant) {
        this.invoices = invoices;
        this.tenant = tenant;
    }

    // Function-level permission, data-level filtering in the query.
    @PreAuthorize("hasAuthority('SCOPE_invoices:read') and hasRole('VIEWER')")
    @Transactional(readOnly = true)
    public List<InvoiceView> list() {
        return invoices.findAllByTenantId(tenant.id()).stream().map(InvoiceView::from).toList();
    }

    // Object-level rule delegated to a bean: @invoiceAuthz.canApprove(...)
    @PreAuthorize("hasAuthority('invoice:approve') and @invoiceAuthz.canApprove(#invoiceId, authentication)")
    @Transactional
    public void approve(UUID invoiceId) {
        invoices.approve(invoiceId, tenant.id());
    }

    // Check the returned object after loading it.
    @PostAuthorize("returnObject.ownerId() == authentication.name or hasRole('ACCOUNTANT')")
    @Transactional(readOnly = true)
    public InvoiceView get(UUID invoiceId) {
        return invoices.findByIdAndTenantId(invoiceId, tenant.id())
                .map(InvoiceView::from)
                .orElseThrow(InvoiceNotFoundException::new);
    }
}
```

The bean referenced from SpEL keeps complex logic in plain, testable Java:

```java
import java.util.UUID;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component("invoiceAuthz")
class InvoiceAuthorization {

    private final InvoiceRepository invoices;
    private final TenantContext tenant;

    InvoiceAuthorization(InvoiceRepository invoices, TenantContext tenant) {
        this.invoices = invoices;
        this.tenant = tenant;
    }

    /** Same tenant, within the approver's limit, and never your own invoice (separation of duty). */
    public boolean canApprove(UUID invoiceId, Authentication authentication) {
        return invoices.findByIdAndTenantId(invoiceId, tenant.id())
                .map(inv -> !inv.createdBy().equals(authentication.getName())
                        && inv.amount().compareTo(ApprovalLimits.of(authentication)) <= 0)
                .orElse(false);   // unknown or foreign invoice: deny
    }
}
```

Method parameter names such as `#invoiceId` require compiling with `-parameters`, which the Spring Boot Maven and Gradle plugins configure by default. Keep secured methods `public` and call them through the Spring bean (a call from another method of the same class bypasses the proxy and therefore the check).

### 17.3 A custom `PermissionEvaluator` for `hasPermission(...)`

`hasPermission(#id, 'Project', 'edit')` delegates to a `PermissionEvaluator`. This is a good fit for scoped roles ("Alice is `MAINTAINER` of project 42"):

```java
import java.io.Serializable;
import java.util.UUID;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
class ProjectPermissionEvaluator implements PermissionEvaluator {

    private final ProjectMembershipRepository memberships;

    ProjectPermissionEvaluator(ProjectMembershipRepository memberships) {
        this.memberships = memberships;
    }

    @Override
    public boolean hasPermission(Authentication auth, Object target, Object permission) {
        return target instanceof Project project && check(auth, project.id(), permission);
    }

    @Override
    public boolean hasPermission(Authentication auth, Serializable targetId, String targetType, Object permission) {
        return "Project".equals(targetType) && targetId instanceof UUID id && check(auth, id, permission);
    }

    private boolean check(Authentication auth, UUID projectId, Object permission) {
        return memberships.findRole(auth.getName(), projectId)            // e.g. VIEWER, MAINTAINER, OWNER
                .map(role -> role.grants(ProjectPermission.from(permission.toString())))
                .orElse(false);                                           // not a member: deny
    }
}
```

Register it on the expression handler. The method is `static` so Spring publishes it before method security initializes; `@Lazy` defers creating the evaluator (and its repository) until first use:

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;

@Configuration
class MethodSecurityConfig {

    @Bean
    static MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            @Lazy PermissionEvaluator permissionEvaluator, RoleHierarchy roleHierarchy) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(permissionEvaluator);
        handler.setRoleHierarchy(roleHierarchy);
        return handler;
    }
}
```

Usage, including a reusable meta-annotation:

```java
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.UUID;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasPermission(#projectId, 'Project', 'edit')")
@interface CanEditProject {}

@Service
class ProjectService {

    @CanEditProject
    public void rename(UUID projectId, String newName) { /* ... */ }

    @PreAuthorize("hasPermission(#projectId, 'Project', 'delete')")
    public void delete(UUID projectId) { /* ... */ }
}
```

Spring Security can also template meta-annotations (publish an `AnnotationTemplateExpressionDefaults` bean and use placeholders such as `{value}` in the expression) when one annotation should take parameters.

### 17.4 A custom `AuthorizationManager` that calls an external PDP

When decisions live in OPA, Cedar, OpenFGA or any AuthZEN PDP, wrap the call in an `AuthorizationManager`. Note the Spring Security 7 signature: `authorize(Supplier<? extends Authentication>, T)`.

```java
import java.util.function.Supplier;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

@Component
class PdpAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final PdpClient pdp;   // your HTTP client for the AuthZEN or OPA endpoint, 100 ms timeout

    PdpAuthorizationManager(PdpClient pdp) {
        this.pdp = pdp;
    }

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
                                         RequestAuthorizationContext context) {
        Authentication auth = authentication.get();
        if (auth == null || !auth.isAuthenticated()) {
            return new AuthorizationDecision(false);
        }
        try {
            boolean allowed = pdp.evaluate(
                    auth.getName(),
                    context.getRequest().getMethod(),
                    context.getRequest().getRequestURI(),
                    context.getVariables());
            return new AuthorizationDecision(allowed);
        } catch (RuntimeException pdpUnavailable) {
            return new AuthorizationDecision(false);   // fail closed
        }
    }
}
```

Plug it in with `.requestMatchers("/api/v1/reports/**").access(pdpAuthorizationManager)`. For methods, implement `AuthorizationManager<MethodInvocation>` and register it with `AuthorizationManagerBeforeMethodInterceptor`.

### 17.5 Testing authorization

Every rule deserves a negative test. With `spring-security-test` and MockMvc:

```java
// Another tenant's invoice must look like it does not exist.
mvc.perform(get("/api/v1/tenants/t-acme/invoices/{id}", globexInvoiceId)
        .with(jwt().jwt(j -> j.subject("alice").claim("tenant_id", "t-acme"))
                   .authorities(new SimpleGrantedAuthority("SCOPE_invoices:read"))))
   .andExpect(status().isNotFound());

// Path tenant different from token tenant is refused by the request rule.
mvc.perform(get("/api/v1/tenants/t-globex/invoices")
        .with(jwt().jwt(j -> j.subject("alice").claim("tenant_id", "t-acme"))
                   .authorities(new SimpleGrantedAuthority("SCOPE_invoices:read"))))
   .andExpect(status().isForbidden());

// Ordinary user on an admin endpoint. csrf() is added so the 403 really comes from
// the authorization rule: MockMvc's jwt() sets no Authorization header, so the
// resource server's "ignore CSRF for bearer requests" rule does not apply here.
mvc.perform(post("/api/v1/admin/users/77/roles").with(jwt()).with(csrf()))
   .andExpect(status().isForbidden());
```

---

## Interview questions

**1. What is the difference between authentication and authorization?**
Authentication verifies who the caller is and produces a principal. Authorization decides, on every request, whether that principal may perform a specific action on a specific resource in the current context. Authorization can depend on how the user authenticated (`acr`, `amr`, `auth_time`).

**2. 401 or 403? And when 404?**
401 means not authenticated (missing, invalid or expired credentials) and comes with `WWW-Authenticate`. 403 means authenticated but not allowed. Use 404 for objects outside the caller's scope so the API does not reveal that they exist.

**3. Compare RBAC, ABAC and ReBAC.**
RBAC grants permissions to roles; simple and auditable, but roles explode when rules depend on context. ABAC evaluates attributes of subject, resource, action and environment; flexible and context-aware, but harder to audit and dependent on trustworthy, fresh attributes. ReBAC derives permissions from relationships in a graph (member of team, team edits folder, folder contains document); ideal for sharing and hierarchies, but you must operate a consistent relationship store.

**4. What is BOLA and how do you prevent it?**
Broken Object Level Authorization (IDOR), API1 in the OWASP API Security Top 10 2023: the API loads whatever object ID the caller supplies without checking ownership. Prevent it by authorizing every object access server-side, ideally by scoping the query (`findByIdAndTenantId`), returning 404 for foreign objects, and testing with other users' IDs. UUIDs alone do not fix it.

**5. What is the difference between BOLA and BFLA?**
BOLA is about a specific **object** (may Alice read invoice 1043?). BFLA (API5) is about a **function** (may Alice call the admin role-assignment endpoint at all?). BFLA is prevented by deny-by-default and per-operation checks; BOLA needs per-object checks.

**6. What is mass assignment?**
The framework binds every field of the request body onto an internal object, so a client can set fields such as `role`, `tenantId` or `emailVerified`. Prevent it with request DTOs that contain only allowed fields, per-role DTOs, and optionally rejecting unknown properties. OWASP 2023 groups it with excessive data exposure as API3, Broken Object Property Level Authorization.

**7. Are OAuth scopes permissions?**
No. A scope limits what a client may do on behalf of a user. Effective access is the intersection of the client's scopes, the user's own permissions and resource policy. A token with `orders:read` must still only read orders the user may see.

**8. Why should you check permissions rather than roles in code?**
Role-to-permission mapping is an organizational decision that changes. `hasAuthority('invoice:approve')` lets administrators change which roles grant approval without code changes; `hasRole('MANAGER')` hard-codes it.

**9. What problem do Zanzibar's zookies solve?**
The "new enemy" problem: a permission check evaluated against stale data can show new content to someone whose access was just removed. A zookie (consistency token) records the version at which content changed, and later checks are evaluated at a snapshot at least that new.

**10. Where should authorization be enforced in a microservice architecture?**
In layers: coarse checks at the gateway (valid token, audience, scope per route, tenant routing), function- and object-level checks in each service next to the data, tenant and owner filters in every query with row-level security as a backstop, and re-checks in asynchronous consumers. The UI only hides controls for usability. Policy decision points must fail closed.

**11. How do you isolate tenants in a pooled multi-tenant database?**
Take the tenant from the validated token (not from a client header), set it once per request, scope every query by `tenant_id`, add PostgreSQL row-level security (set per transaction, app role without `BYPASSRLS`), prefix caches and storage keys with the tenant, carry the tenant in messages, and run cross-tenant negative tests for every endpoint.

---

## References

**Standards and papers**

- [RFC 9110 — HTTP Semantics (401, 403, 404)](https://www.rfc-editor.org/rfc/rfc9110)
- [RFC 6749 — The OAuth 2.0 Authorization Framework (section 3.3, scopes)](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 6750 — Bearer Token Usage (`insufficient_scope`)](https://www.rfc-editor.org/rfc/rfc6750)
- [RFC 9396 — OAuth 2.0 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396)
- [RFC 8693 — OAuth 2.0 Token Exchange (`act` claim)](https://www.rfc-editor.org/rfc/rfc8693)
- [RFC 9470 — OAuth 2.0 Step Up Authentication Challenge Protocol](https://www.rfc-editor.org/rfc/rfc9470)
- [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643) and [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644) — SCIM 2.0
- [NIST RBAC project and the ANSI INCITS 359 standard](https://csrc.nist.gov/projects/role-based-access-control)
- [NIST SP 800-162 — Guide to Attribute Based Access Control (ABAC) Definition and Considerations](https://csrc.nist.gov/pubs/sp/800/162/upd2/final)
- [OASIS XACML 3.0](https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html)
- [Zanzibar: Google's Consistent, Global Authorization System (USENIX ATC 2019)](https://www.usenix.org/conference/atc19/presentation/pang)
- [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)

**Engines and tools**

- [Open Policy Agent documentation](https://www.openpolicyagent.org/docs/latest/)
- [Cedar policy language](https://www.cedarpolicy.com/)
- [OpenFGA documentation](https://openfga.dev/docs)
- [SpiceDB documentation](https://authzed.com/docs)
- [PostgreSQL row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [Spring Security reference: Authorization architecture](https://docs.spring.io/spring-security/reference/servlet/authorization/architecture.html)
- [Spring Security reference: Method security](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)

**OWASP**

- [OWASP Top 10:2025 — A01 Broken Access Control](https://owasp.org/Top10/2025/)
- [OWASP API Security Top 10 2023 — API1 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP API Security Top 10 2023 — API3 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [OWASP API Security Top 10 2023 — API5 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [OWASP Authorization Testing Automation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html)
- [OWASP ASVS 5.0 (chapter V8 Authorization)](https://owasp.org/www-project-application-security-verification-standard/)
