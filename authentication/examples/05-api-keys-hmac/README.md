# 05 — API keys and HMAC-signed webhooks

A Spring Boot API that does the two credentials most backend teams still build by hand in 2026:

1. **API keys** for third-party integrations: generated from a CSPRNG with a recognizable `ak_live_` prefix
   and a checksum, **shown once**, stored only as a **prefix plus a peppered HMAC-SHA256 hash**, limited by
   **scopes** and an **expiry**, **rotated with an overlap window**, **revoked instantly**, and verified by
   a custom Spring Security filter with a **constant-time** comparison.
2. **Webhook verification** for events a payment provider pushes to you: a Stripe-style
   `t=<unix>,v1=<hex HMAC-SHA256>` signature over the **raw body**, a **5-minute timestamp tolerance**, a
   **replay cache**, and **idempotency by event id** for provider retries.

**Read with:**

- [Chapter 03 — HTTP Basic, Digest and API keys](../../docs/03-http-basic-digest-and-api-keys.md): sections
  [5 (API keys done right)](../../docs/03-http-basic-digest-and-api-keys.md#5-api-keys-done-right),
  [7 (webhook signature verification)](../../docs/03-http-basic-digest-and-api-keys.md#7-webhook-signature-verification),
  [8 (constant-time comparison)](../../docs/03-http-basic-digest-and-api-keys.md#8-constant-time-comparison) and
  [11.2 (API keys with `AuthenticationFilter`)](../../docs/03-http-basic-digest-and-api-keys.md#112-api-key-authentication-with-authenticationfilter)
  are implemented here
- [Chapter 12 — Service-to-service and zero trust, section 2](../../docs/12-service-to-service-and-zero-trust.md#2-the-options-compared):
  when an API key is the right machine credential and when client credentials, mTLS or workload identity are better
- [Chapter 13 — Authorization](../../docs/13-authorization-rbac-abac-rebac.md):
  [9 (scopes vs fine-grained permissions)](../../docs/13-authorization-rbac-abac-rebac.md#9-oauth-scopes-vs-fine-grained-permissions) and
  [12 (tenant isolation)](../../docs/13-authorization-rbac-abac-rebac.md#12-multi-tenancy-and-tenant-isolation)
- [Chapter 14 — Production architecture](../../docs/14-production-architecture-and-checklist.md):
  [5 (key management and rotation)](../../docs/14-production-architecture-and-checklist.md#5-key-management-and-rotation),
  [10 (rate limiting)](../../docs/14-production-architecture-and-checklist.md#10-rate-limiting-and-bot-protection) and
  [11 (logging and auditing)](../../docs/14-production-architecture-and-checklist.md#11-logging-and-auditing)

Stack: Java 21, Spring Boot 4.1.1 (Spring Framework 7.0, Spring Security 7.1.1), Spring JDBC (`JdbcClient`), H2.

> **When to use API keys.** They suit third-party developers calling your public API from *their* servers,
> CLIs and CI jobs. They are the wrong tool for logging in humans (use sessions or OpenID Connect,
> examples [01](../01-session-auth/) and [03](../03-oauth2-oidc/)), for anything shipped inside a browser or
> mobile app (a key in a client is public), and for your own microservices, which should use OAuth client
> credentials, mTLS or workload identity instead of long-lived shared secrets.

---

## What it demonstrates

| Security property | How | Where |
|---|---|---|
| High-entropy, recognizable keys | `ak_live_` + 32 bytes from `SecureRandom` as 43 base62 characters + 6-character CRC32 checksum (57 characters); `ak_test_` for non-production; secret scanners can match `ak_live_[0-9A-Za-z]{49}` | [`ApiKeyFormat`](src/main/java/com/backend/auth/apikeys/apikey/ApiKeyFormat.java) |
| Garbage rejected without I/O | Wrong prefix, length, alphabet or checksum fails before any hash or database query (also catches every single-character typo) | `ApiKeyFormat.lookupPrefix` |
| Show once, store a hash | The full key appears only in the `201` response (`Cache-Control: no-store`); the table holds the 16-character `prefix` (lookup and display) and `HMAC-SHA256(pepper, key)`; `toString()` of every object holding a key is redacted | [`ApiKeyService`](src/main/java/com/backend/auth/apikeys/apikey/ApiKeyService.java), [`ApiKeyHasher`](src/main/java/com/backend/auth/apikeys/apikey/ApiKeyHasher.java), [`schema.sql`](src/main/resources/schema.sql) |
| Fast keyed hash, not Argon2id | A 256-bit random key cannot be guessed, keys are checked on every request, and the pepper (outside the database) means a stolen table cannot even test candidates | `ApiKeyHasher` |
| Constant-time comparison | Look up candidates by prefix, then `MessageDigest.isEqual(storedHash, HMAC(presented))` | [`ApiKeyVerifier`](src/main/java/com/backend/auth/apikeys/apikey/ApiKeyVerifier.java) |
| Header only, never the URL | `Authorization: Bearer <key>` or `X-API-Key: <key>`; the query string is never read, and a key found there gets a 401 explaining why plus a log warning; two keys in one request is a `400 invalid_request` | [`ApiKeyAuthenticationConverter`](src/main/java/com/backend/auth/apikeys/security/ApiKeyAuthenticationConverter.java), [`ApiKeyAuthenticationEntryPoint`](src/main/java/com/backend/auth/apikeys/security/ApiKeyAuthenticationEntryPoint.java) |
| Spring Security integration | Generic `AuthenticationFilter` + custom `AuthenticationConverter` + `AuthenticationProvider`; stateless (no session, no cookie); no CSRF needed because nothing is ambient | [`SecurityConfig`](src/main/java/com/backend/auth/apikeys/security/SecurityConfig.java), [`ApiKeyAuthenticationProvider`](src/main/java/com/backend/auth/apikeys/security/ApiKeyAuthenticationProvider.java) |
| One answer for every bad key | Unknown, malformed, revoked and expired keys all get `401` + `WWW-Authenticate: Bearer error="invalid_token"` and the same body; the real reason is logged with the key prefix only | `ApiKeyVerifier`, `ApiKeyAuthenticationEntryPoint` |
| Scopes as authorities | `orders:read` becomes `SCOPE_orders:read`; missing scope is `403` + `error="insufficient_scope"`; unlisted endpoints are denied; scopes outside the catalog are refused at creation | `SecurityConfig`, [`InsufficientScopeHandler`](src/main/java/com/backend/auth/apikeys/security/InsufficientScopeHandler.java) |
| Expiry and last-used tracking | Every key expires (default 90 days, maximum 365); `last_used_at` written at most once a minute per key | `ApiKeyService`, `ApiKeyVerifier` |
| Rotation with overlap | `POST /admin/api-keys/{id}/rotate` issues a successor with the same name, scopes and lifetime and shortens the old key to 24 hours (never extends it); one successor per key, enforced by a conditional `UPDATE` | `ApiKeyService.rotate`, [`ApiKeyRepository`](src/main/java/com/backend/auth/apikeys/apikey/ApiKeyRepository.java) |
| Instant revocation | `POST /admin/api-keys/{id}/revoke`; no lookup cache, so the next request fails; idempotent; the row is kept for audit | `ApiKeyService.revoke` |
| Keys cannot mint keys, tenants stay apart | `/admin/**` accepts only administrator credentials (Argon2id), never an API key; each administrator sees only their account's keys, and another account's key id is a `404` | `SecurityConfig`, [`ApiKeyAdminController`](src/main/java/com/backend/auth/apikeys/admin/ApiKeyAdminController.java) |
| Webhook signature over raw bytes | Verified in a security filter before MVC parses anything; the controller then reads the *same* bytes | [`WebhookSignatureFilter`](src/main/java/com/backend/auth/apikeys/webhook/WebhookSignatureFilter.java), [`CachedBodyRequest`](src/main/java/com/backend/auth/apikeys/webhook/CachedBodyRequest.java) |
| Timestamp tolerance | `t` is inside the signed content; more than 5 minutes off in either direction is rejected | [`WebhookSignatureVerifier`](src/main/java/com/backend/auth/apikeys/webhook/WebhookSignatureVerifier.java) |
| Replay protection | After the HMAC succeeds (never before), SHA-256 of the signed content goes into a replay cache until its timestamp leaves the window | `WebhookSignatureVerifier`, [`InMemoryReplayCache`](src/main/java/com/backend/auth/apikeys/webhook/InMemoryReplayCache.java) |
| Secret rotation | Several `v1` values in the header and several configured secrets; every pair is compared without short-circuiting | `WebhookSignatureVerifier`, [`SignatureHeader`](src/main/java/com/backend/auth/apikeys/webhook/SignatureHeader.java) |
| Idempotent processing | Provider retries are freshly signed, so they pass the replay cache; the primary key on `event_id` acknowledges them with `200 duplicate: true` without processing twice | [`ProcessedWebhookEvents`](src/main/java/com/backend/auth/apikeys/webhook/ProcessedWebhookEvents.java) |
| Bounded input | Webhook bodies over 64 KB get `413` without being buffered beyond the limit or hashed; signature headers over 2 KB are rejected | `WebhookSignatureFilter`, `SignatureHeader` |

## The flow

**API keys**

```mermaid
sequenceDiagram
    autonumber
    participant A as Administrator
    participant C as Integration (partner backend, CI job)
    participant S as API (Spring Security filters)
    participant DB as api_key table

    A->>S: POST /admin/api-keys with Basic credentials, name, scopes
    S->>S: key = ak_live_ + 32 random bytes in base62 + CRC32 checksum
    S->>DB: INSERT prefix, HMAC-SHA256(pepper, key), scopes, expires_at
    S-->>A: 201 with the full key, shown this one time only
    A->>C: Put the key in the integration's secret manager

    C->>S: GET /v1/orders, Authorization: Bearer ak_live_...
    S->>S: Prefix, length, alphabet and checksum check (no I/O)
    S->>DB: SELECT candidates WHERE prefix = ak_live_XXXXXXXX
    S->>S: MessageDigest.isEqual(stored hash, HMAC of presented key)
    S->>S: Revoked or expired? Same 401 as an unknown key
    S->>S: Authorities = SCOPE_orders:read, SCOPE_orders:write
    S-->>C: 200, or 403 insufficient_scope

    A->>S: POST /admin/api-keys/{id}/rotate
    S->>DB: INSERT successor, set old expires_at = now + 24 h, rotated_to = successor
    S-->>A: 201 with the new key, both keys work during the overlap
    A->>S: POST /admin/api-keys/{id}/revoke (once traffic has moved)
    S->>DB: SET revoked_at, effective on the next request
```

**Webhooks**

```mermaid
sequenceDiagram
    autonumber
    participant P as Payment provider
    participant W as WebhookSignatureFilter
    participant R as Replay cache
    participant H as PaymentWebhookController
    participant DB as processed_webhook_event

    P->>W: POST /webhooks/payments, Payments-Signature t and v1, raw JSON body
    W->>W: Body larger than 64 KB? 413
    W->>W: Parse header, timestamp within 5 minutes of now?
    W->>W: HMAC-SHA256(secret, t.rawBody), constant-time compare with each v1
    W->>R: First time this signed content is seen?
    alt missing, invalid, stale or replayed
        W-->>P: 401, nothing reaches the controller
    else authentic and new
        W->>H: Same raw bytes, authority WEBHOOK_PAYMENTS
        H->>DB: INSERT event_id (primary key)
        H-->>P: 200 received, duplicate false (or true for a provider retry)
    end
```

## Project layout

```text
src/main/java/com/backend/auth/apikeys/
├── ApiKeysApplication.java       Boot entry point, Clock bean
├── apikey/                       key format, peppered hashing, repository (SQL), management service, verifier
├── security/                     three filter chains, API key converter/provider/token, 401/403 problem responses
├── admin/                        /admin/api-keys endpoints and DEMO administrator accounts
├── api/                          /v1/me and /v1/orders (the protected business API)
├── webhook/                      signature header parsing, verifier, replay cache, filter, event idempotency
└── crypto/                       HMAC-SHA256 and SHA-256 helpers
src/main/resources/
├── application.yml               key policy, DEMO pepper, DEMO webhook secret, DEMO administrators
└── schema.sql                    api_key and processed_webhook_event tables
```

## Run it

```bash
./mvnw spring-boot:run          # http://localhost:8085
./mvnw test                     # 72 tests, no network needed once dependencies are downloaded
```

The database is an in-memory H2 instance, so a restart forgets every key. DEMO administrators (Argon2id
hashes in `application.yml`; they stand in for your real dashboard login):

| Administrator | Password | Manages keys of account |
|---|---|---|
| `acme-admin` | `acme-admin-demo-passphrase` | `acme` |
| `globex-admin` | `globex-admin-demo-passphrase` | `globex` |

The webhook secret is the DEMO value `whsec_demo_only_not_a_real_secret`, the same one chapter 03 uses.

## curl walkthrough

The responses below are from a real run, trimmed to the relevant lines; keys, ids and times will differ.
`curl -u` sends Basic credentials without waiting for a challenge, which matters because `/admin` deliberately
sends none (see [design notes](#design-notes)).

```bash
BASE=http://localhost:8085
ADMIN='acme-admin:acme-admin-demo-passphrase'
```

**1. Create a key.** The response is the only place the full key ever appears.

```bash
CREATED=$(curl -s -u "$ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"CI deploy key","scopes":["orders:read","orders:write"]}' \
  "$BASE/admin/api-keys")
echo "$CREATED" | jq .
KEY=$(echo "$CREATED" | jq -r .key); KEY_ID=$(echo "$CREATED" | jq -r .id)
```

```json
{
  "id": "35cb7ae5-a70e-4f41-9c60-8a5896f71f21",
  "name": "CI deploy key",
  "key": "ak_live_V4WDfT2e7TSGesmg3L3H15DGKmJnWMzeWqEyApWL5zy0DkmaS",
  "prefix": "ak_live_V4WDfT2e",
  "scopes": ["orders:read", "orders:write"],
  "createdAt": "2026-10-08T09:00:34Z",
  "expiresAt": "2027-01-06T09:00:34Z",
  "notice": "Store this key in your secret manager now. It is shown only once and cannot be recovered."
}
```

**2. Use it.** Either header works; the owner and scopes come from the key.

```bash
curl -s -H "Authorization: Bearer $KEY" "$BASE/v1/me" | jq .
curl -s -i -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"item":"anvil","quantity":2}' "$BASE/v1/orders"
```

```json
{
  "owner": "acme",
  "keyId": "35cb7ae5-a70e-4f41-9c60-8a5896f71f21",
  "keyPrefix": "ak_live_V4WDfT2e",
  "authorities": ["SCOPE_orders:read", "SCOPE_orders:write"]
}
```

```http
HTTP/1.1 201
Location: /v1/orders/b6ff960f-13b7-4b9d-a584-9fde38ef5ace

{"id":"b6ff960f-13b7-4b9d-a584-9fde38ef5ace","owner":"acme","item":"anvil","quantity":2,"createdAt":"2026-10-08T09:00:34.580195045Z"}
```

**3. List keys.** Prefix, status and last use; never the key or its hash.

```bash
curl -s -u "$ADMIN" "$BASE/admin/api-keys" | jq .
```

```json
[
  {
    "id": "35cb7ae5-a70e-4f41-9c60-8a5896f71f21",
    "name": "CI deploy key",
    "prefix": "ak_live_V4WDfT2e",
    "scopes": ["orders:read", "orders:write"],
    "status": "ACTIVE",
    "createdAt": "2026-10-08T09:00:34Z",
    "expiresAt": "2027-01-06T09:00:34Z",
    "lastUsedAt": "2026-10-08T09:00:34Z",
    "revokedAt": null,
    "rotatedTo": null
  }
]
```

**4. What failures look like.**

```bash
curl -s -i "$BASE/v1/orders"                                                  # no key
curl -s -i -H "Authorization: Bearer ak_live_thisIsNotARealKeyButItHasTheRightLength0000000000" "$BASE/v1/orders"
curl -s -i "$BASE/v1/orders?api_key=$KEY"                                     # key in the URL
```

```http
HTTP/1.1 401
WWW-Authenticate: Bearer realm="api"
{"title":"Authentication required","status":401,"detail":"Send an API key in the Authorization header (Bearer) or the X-API-Key header."}

HTTP/1.1 401
WWW-Authenticate: Bearer realm="api", error="invalid_token"
{"title":"Invalid API key","status":401,"detail":"The API key is invalid, expired or revoked."}

HTTP/1.1 401
WWW-Authenticate: Bearer realm="api"
{"title":"Authentication required","status":401,"detail":"Credentials in the URL are ignored (they leak into logs). Send the API key in the Authorization header (Bearer) or the X-API-Key header, and rotate the key you just exposed."}
```

**5. Least privilege.** A read-only key cannot create orders: `403`, not `401`, because a different key would help.

```bash
READ_ONLY=$(curl -s -u "$ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"Reporting","scopes":["orders:read"],"expiresInDays":30}' "$BASE/admin/api-keys" | jq -r .key)
curl -s -i -H "X-API-Key: $READ_ONLY" -H 'Content-Type: application/json' \
  -d '{"item":"anvil","quantity":1}' "$BASE/v1/orders"
```

```http
HTTP/1.1 403
WWW-Authenticate: Bearer realm="api", error="insufficient_scope"
{"title":"Insufficient scope","status":403,"detail":"This API key does not have the scope required for this operation."}
```

**6. Rotate without downtime, then revoke the old key.**

```bash
ROTATED=$(curl -s -u "$ADMIN" -X POST "$BASE/admin/api-keys/$KEY_ID/rotate")
echo "$ROTATED" | jq -c '.replacement | {id, key, expiresAt}'
echo "$ROTATED" | jq -c '.previous | {id, status, expiresAt, rotatedTo}'
NEW_KEY=$(echo "$ROTATED" | jq -r .replacement.key)
curl -s -o /dev/null -w "old key: %{http_code}\n" -H "X-API-Key: $KEY" "$BASE/v1/orders"
curl -s -o /dev/null -w "new key: %{http_code}\n" -H "X-API-Key: $NEW_KEY" "$BASE/v1/orders"
```

```text
{"id":"13ac7946-56d1-4528-8906-e01a0bf6c16d","key":"ak_live_i5o8s3MhL8fMKPcoHPSeztkIxxhag6u16YRxfLs10K32d4fUD","expiresAt":"2027-01-06T09:00:34Z"}
{"id":"35cb7ae5-a70e-4f41-9c60-8a5896f71f21","status":"ACTIVE","expiresAt":"2026-10-09T09:00:34Z","rotatedTo":"13ac7946-56d1-4528-8906-e01a0bf6c16d"}
old key: 200
new key: 200
```

The old key now expires 24 hours from the rotation, and `rotatedTo` links it to its successor.

Once the integration runs on the new key (check `lastUsedAt`), revoke the old one instead of waiting 24 hours:

```bash
curl -s -u "$ADMIN" -X POST "$BASE/admin/api-keys/$KEY_ID/revoke" | jq -c '{id, status, revokedAt}'
curl -s -o /dev/null -w "old key: %{http_code}\n" -H "X-API-Key: $KEY" "$BASE/v1/orders"
curl -s -o /dev/null -w "new key: %{http_code}\n" -H "X-API-Key: $NEW_KEY" "$BASE/v1/orders"
```

```text
{"id":"35cb7ae5-a70e-4f41-9c60-8a5896f71f21","status":"REVOKED","revokedAt":"2026-10-08T09:00:34Z"}
old key: 401
new key: 200
```

**7. Boundaries.** Another account cannot see the key (`404`, so it cannot even learn the id exists), and an
API key cannot manage keys.

```bash
curl -s -i -u 'globex-admin:globex-admin-demo-passphrase' "$BASE/admin/api-keys/$KEY_ID"
curl -s -i -H "Authorization: Bearer $NEW_KEY" "$BASE/admin/api-keys"
```

```http
HTTP/1.1 404
{"detail":"No such API key.","instance":"/admin/api-keys/35cb7ae5-a70e-4f41-9c60-8a5896f71f21","status":404,"title":"Not Found"}

HTTP/1.1 401
{"title":"Authentication required","status":401,"detail":"Administrator credentials are required."}
```

**8. A signed webhook.** Sign exactly the bytes you send, as the provider would:

```bash
SECRET=whsec_demo_only_not_a_real_secret                      # DEMO secret from application.yml
BODY='{"id":"evt_1001","type":"payment.succeeded","data":{"amount":4200,"currency":"EUR"}}'
T=$(date +%s)
SIG=$(printf '%s.%s' "$T" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')
curl -s -i -H "Payments-Signature: t=$T,v1=$SIG" -H 'Content-Type: application/json' \
  --data-raw "$BODY" "$BASE/webhooks/payments"
```

```http
HTTP/1.1 200
{"received":true,"duplicate":false}
```

**9. Replayed, tampered and stale deliveries.**

```bash
# the same request again (an attacker who captured it)
curl -s -i -H "Payments-Signature: t=$T,v1=$SIG" -H 'Content-Type: application/json' --data-raw "$BODY" "$BASE/webhooks/payments"
# the amount changed, signature reused
curl -s -i -H "Payments-Signature: t=$T,v1=$SIG" -H 'Content-Type: application/json' --data-raw "${BODY/4200/999999}" "$BASE/webhooks/payments"
# correctly signed, but 10 minutes old
OLD_T=$((T - 600)); OLD_SIG=$(printf '%s.%s' "$OLD_T" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')
curl -s -i -H "Payments-Signature: t=$OLD_T,v1=$OLD_SIG" -H 'Content-Type: application/json' --data-raw "$BODY" "$BASE/webhooks/payments"
```

All three get the same answer (the specific reason, `REPLAYED`, `SIGNATURE_MISMATCH` or
`TIMESTAMP_OUTSIDE_TOLERANCE`, is only logged):

```http
HTTP/1.1 401
{"title":"Webhook rejected","status":401,"detail":"Missing, invalid, expired or replayed Payments-Signature header."}
```

**10. A provider retry.** Retries are signed again with a new timestamp, so they are not replays; the event id
makes sure the event is processed once:

```bash
T2=$(date +%s); SIG2=$(printf '%s.%s' "$T2" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')
curl -s -i -H "Payments-Signature: t=$T2,v1=$SIG2" -H 'Content-Type: application/json' --data-raw "$BODY" "$BASE/webhooks/payments"
```

```http
HTTP/1.1 200
{"received":true,"duplicate":true}
```

(Run it at least a second after step 8, or `T2` equals `T` and it really is a replay.)

## How the tests prove each property

`./mvnw test` runs 72 tests: unit tests for the format, hasher, verifier and replay cache, and MockMvc tests
through the real filter chains. A test clock (`MutableClock`) replaces the application clock, so expiry,
overlap and tolerance are tested without sleeping.

| Property | Test |
|---|---|
| Created key works (Bearer and `X-API-Key`), no session cookie | `ApiKeyAuthenticationTests.newKeyWorksInTheAuthorizationHeaderWithoutCreatingASession`, `newKeyWorksInTheXApiKeyHeader` |
| Missing key: 401 with a bare Bearer challenge | `requestWithoutAKeyGets401WithABearerChallenge` |
| Wrong key: 401 (well-formed but unknown; typo, other environment, wrong length; all identical) | `wellFormedButUnknownKeyIs401`, `malformedAndMistypedKeysGetTheSameAnswerAsUnknownKeys` |
| Revoked key: 401 on the very next request | `revokedKeyIs401Immediately` |
| Expired key: 401 | `expiredKeyIs401` |
| Key in the query string ignored (`api_key`, `apiKey`, `access_token`, `key`) | `keyInTheQueryStringIsIgnored` |
| Missing scope: 403 `insufficient_scope`; scopes become `SCOPE_` authorities; owner scoping | `missingScopeIs403`, `writeScopeAllowsCreatingButNotReading`, `scopesBecomeScopeAuthorities`, `ordersBelongToTheKeysOwner` |
| Ambiguous credentials refused; unlisted endpoints denied; API keys rejected on `/admin` | `sendingTwoKeysIsABadRequest`, `endpointsNotExplicitlyAllowedAreDenied`, `apiKeysCannotManageApiKeys` |
| Last use recorded | `lastUsedIsRecorded` |
| Full key only in the create response, never in listings | `ApiKeyManagementTests.fullKeyIsReturnedOnlyByTheCreateResponse` |
| Database holds the prefix and `HMAC(pepper, key)`, not the key and not a plain SHA-256 | `databaseHoldsOnlyThePrefixAndAPepperedHash` |
| Admin needs administrator credentials, sends no Basic challenge | `adminEndpointsNeedAdministratorCredentials` |
| Unknown scopes, empty scopes, too-long lifetimes refused | `invalidCreateRequestsAreRejected` |
| Rotation: both keys during the overlap, old key dead after it; one successor per key; revoked keys not rotatable | `rotationKeepsTheOldKeyWorkingOnlyDuringTheOverlap`, `aKeyCanBeRotatedOnlyOnce`, `revokedKeysCannotBeRotated` |
| Revocation idempotent; tenants isolated (404) | `revokingTwiceKeepsTheFirstRevocation`, `administratorsOnlySeeTheirOwnAccountsKeys` |
| Key shape, uniqueness, fixed width, every single-character typo caught, environments separated | `ApiKeyFormatTests` |
| Hash is HMAC-SHA256 under the pepper; short peppers refused | `ApiKeyHasherTests` |
| Signer and verifier match an openssl-computed known answer (the chapter 03 example) | `WebhookSignatureVerifierTests.knownAnswerComputedWithOpenssl` |
| Valid webhook accepted | `PaymentWebhookTests.validSignatureIsAccepted` |
| Tampered body rejected (also reformatted JSON with the same meaning) | `PaymentWebhookTests.tamperedBodyIsRejected`, `WebhookSignatureVerifierTests.tamperedBodyIsRejected`, `reformattedJsonIsRejectedBecauseTheSignatureCoversRawBytes` |
| Old timestamp rejected (and future ones; 5 minutes exactly still accepted; a captured signature cannot be given a fresh `t`) | `PaymentWebhookTests.signatureOlderThanTheToleranceIsRejected`, `timestampsOlderThanFiveMinutesAreRejected`, `timestampsTooFarInTheFutureAreRejected`, `timestampsExactlyAtTheToleranceAreAccepted`, `refreshingAnOldTimestampBreaksTheSignature` |
| Replayed signature rejected (also at the last instant of the window, and when one of two signatures is dropped) | `PaymentWebhookTests.replayedDeliveryIsRejected`, `theSameDeliveryIsAcceptedOnlyOnce`, `replayAtTheVeryEndOfTheWindowIsStillCaught`, `droppingOneOfTwoSignaturesDoesNotDisguiseAReplay` |
| Only verified messages enter the replay cache; concurrent duplicates: exactly one wins | `onlyVerifiedMessagesAreRecordedInTheReplayCache`, `InMemoryReplayCacheTests` |
| Secret rotation on either side | `anyOfSeveralSignaturesMayMatchWhileTheSenderRotatesItsSecret`, `oldAndNewSecretsAreBothAcceptedDuringOurRotation` |
| Malformed or oversized headers, missing signature, API key instead of signature, oversized body | `malformedHeadersAreRejected` (10 cases), `oversizedHeadersAreRejectedBeforeParsing`, `missingSignatureIsRejected`, `anApiKeyIsNotAWebhookSignature`, `oversizedBodiesAreRefusedBeforeAnyHmacIsComputed` |
| Provider retry acknowledged but processed once | `providerRetryIsAcknowledgedButProcessedOnlyOnce` |

## Design notes

- **Why a prefix lookup plus `MessageDigest.isEqual`, rather than `WHERE key_hash = ?`.** Both are safe: an
  index lookup by a keyed hash leaks nothing useful, because nobody without the pepper can compute a hash to
  probe with. The prefix lookup is used here because the prefix is needed anyway (dashboards, logs, support),
  and it makes the constant-time comparison visible. The 8 random characters in the stored prefix are treated as
  public, which leaves about 208 secret bits.
- **Why the admin API sends no `WWW-Authenticate: Basic` challenge.** Browsers cache Basic credentials and attach
  them to every request, which makes them an ambient credential like a cookie, and CSRF would apply. Without a
  challenge, a browser never prompts for or caches them, while `curl -u` and HTTP clients send them anyway
  (chapter 03, section 11.1). HTTP Basic is only a stand-in for your real console login here.
- **Why webhook failures are `401` without a challenge.** There is no registered `WWW-Authenticate` scheme for
  webhook signatures. Stripe's documentation suggests `400`; any non-`2xx` makes the provider retry, so pick one
  and keep it consistent. This example uses `401` because the request failed *authentication*.
- **Why the replay cache key is the signed content, not the signature.** During a rotation the header carries two
  valid `v1` values. Keyed by the matching signature, an attacker could replay the request with one of them removed
  and it would look new. `SHA-256(t + "." + body)` identifies the message itself.
- **Why `last_used_at` is not written on every request.** One `UPDATE` per API call does not scale; one per key per
  minute is plenty for "unused for 90 days" reports. The SQL never moves the value backwards.

## What you would change for production

- **Secrets out of the repository.** Inject the pepper and the webhook secret from a secret manager or KMS
  (`API_KEYS_PEPPER`, `PAYMENTS_WEBHOOK_SECRET`) and delete the DEMO fallbacks from `application.yml`, or compute the HMAC inside a KMS/HSM so the application never
  holds the pepper. Add a `pepper_version` column so a new pepper can be introduced for new keys while old keys keep
  verifying until they rotate out.
- **A real database and schema migrations** (PostgreSQL with Flyway or Liquibase); `INSERT ... ON CONFLICT DO NOTHING`
  for event idempotency, and a cleanup job that drops processed event ids after the provider's retry period.
- **Shared replay cache.** With more than one instance, replace `InMemoryReplayCache` with Redis
  `SET <key> 1 NX EXAT <t + tolerance>`.
- **A real console login for administrators.** Session or BFF login with MFA (examples [01](../01-session-auth/),
  [03](../03-oauth2-oidc/), [04](../04-mfa-totp/)), step-up authentication before creating keys, a cap on active keys
  per account, and login throttling (Basic here has none).
- **Rate limiting and quotas** per key and per account (`429` with `Retry-After`), at the gateway or with a token bucket.
- **Lifecycle automation.** Expiry reminders (for example 14 and 3 days before), auto-expiry of keys unused for 90 days,
  `last_used_ip` and an audit trail of every create, rotate and revoke with the administrator's identity.
- **Leak response.** Register the `ak_live_` pattern with GitHub secret scanning and run gitleaks or trufflehog in CI;
  wire the partner-program callback to automatic revocation; consider revoking any key seen in a query string.
- **Optional caching with a short TTL.** Cache key lookups for at most 30 to 60 seconds, or invalidate on revocation;
  this example has no cache, so revocation is immediate.
- **Logging and transport.** TLS everywhere with HSTS; redact `Authorization`, `X-API-Key` and `Payments-Signature`
  in access logs and APM agents; configure forwarded headers correctly behind a proxy.
- **Webhook processing.** Enqueue the event (outbox or queue) and answer within the provider's timeout; for money
  movements, re-fetch the object from the provider's API instead of trusting the payload.
- **Choose the right credential.** For new signing schemes prefer HTTP Message Signatures (RFC 9421) or asymmetric
  webhook signatures (Ed25519, as in Standard Webhooks) so verifiers hold no signing secret, and for your own
  services prefer OAuth client credentials, mTLS or workload identity over static API keys.
