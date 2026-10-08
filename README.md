# backend

Backend engineering notes and runnable examples.

| Folder | What's inside |
|--------|---------------|
| [authentication/](authentication/) | Authentication from the basics to what production systems use today, told through its evolution: passwords and hashing, HTTP Basic/Digest and API keys, sessions and CSRF, enterprise SSO (LDAP, Kerberos, SAML), JWT, OAuth 1.0a, OAuth 2.0 and 2.1, OpenID Connect, MFA and passkeys, service-to-service and zero trust, authorization models, and a production checklist. Includes runnable Spring Boot 4 examples with tests. |

## Requirements for the examples

- Java 21
- No Maven install needed: each example ships the Maven wrapper (`./mvnw test`)
