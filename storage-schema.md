# OAuth KV Storage Schema

This document describes the schema used in the OAUTH_KV storage for the OAuth 2.0 provider library. The library uses Cloudflare Workers KV to store all OAuth-related data, including client registrations, authorization grants, and tokens.

## Overview

The OAUTH_KV namespace stores several types of objects, each with a distinct key prefix to identify the type of data. The storage leverages KV's built-in TTL (Time-To-Live) functionality for automatic expiration of short-lived data like tokens and authorization codes.

## Key Naming Conventions

All keys in the KV namespace follow a consistent pattern to make them easily identifiable:

| Prefix | Purpose | Example |
|--------|---------|---------|
| `client:` | Client registration data | `client:abc123` |
| `grant:{userId}:` | Authorization grant data | `grant:user123:xyz789` |
| `auth_code:` | Authorization codes | `auth_code:def456` |
| `token:` | Access and refresh tokens | `token:ghi789` |

## Data Structures

### Clients

Client records store OAuth client application information.

**Key format:** `client:{clientId}`

**Content Example:**
```json
{
  "clientId": "abc123",
  "clientSecret": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
  "redirectUris": ["https://app.example.com/callback"],
  "clientName": "Example App",
  "logoUri": "https://app.example.com/logo.png",
  "clientUri": "https://app.example.com",
  "policyUri": "https://app.example.com/privacy",
  "tosUri": "https://app.example.com/terms",
  "jwksUri": null,
  "contacts": ["dev@example.com"],
  "grantTypes": ["authorization_code", "refresh_token"],
  "responseTypes": ["code"],
  "registrationDate": 1644256123
}
```

> **Note:** The `clientSecret` is stored as a SHA-256 hash, not in plaintext. The actual secret is only returned to the client when initially created or updated, and never stored.

**TTL:** No expiration (persistent storage)

### Authorization Grants

Grant records store information about permissions a user has granted to an application, along with the refresh token for that grant.

**Key format:** `grant:{userId}:{grantId}`

**Content Example:**
```json
{
  "id": "xyz789",
  "clientId": "abc123",
  "userId": "user123",
  "scope": ["document.read", "document.write"],
  "metadata": {
    "label": "My Files Access",
    "deviceInfo": "Chrome on Windows"
  },
  "props": {
    "userId": 123,
    "username": "johndoe"
  },
  "createdAt": 1644256123,
  "refreshTokenId": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
}
```

**TTL:** No expiration (persistent until revoked)

> **Note:** The `userId` is included in the key, allowing efficient listing of all grants for a user using KV's `list()` function with a prefix. The `refreshTokenId` is the hash of the refresh token, which is stored directly in the grant record.

### Authorization Codes

Authorization codes are short-lived credentials issued during the authorization flow.

**Key format:** `auth_code:{codeHash}`

**Content Example:**
```json
{
  "grantId": "xyz789",
  "userId": "user123"
}
```

> **Note:** The authorization code is hashed using SHA-256 before being used as part of the key. Only the hash of the code is stored, not the code itself. The content includes both the grant ID and user ID to reconstruct the full grant key later.

**TTL:** 10 minutes (600 seconds)

### Tokens

Token records store metadata about issued access tokens.

**Key format:** `token:{tokenId}`

**Content Example:**
```json
{
  "id": "ghi789",
  "grantId": "xyz789",
  "userId": "user123",
  "createdAt": 1644256123,
  "expiresAt": 1644259723
}
```

> **Note:** The token format is `{userId}:{grantId}:{random-secret}` which embeds the identifiers needed for parallel lookups. Only access tokens are stored here; refresh tokens are stored in the grant records.

**TTL:** Access tokens typically have a 1 hour (3600 seconds) TTL by default

## Security Considerations

1. **Sensitive Value Storage**: No sensitive values are stored in plaintext in KV storage:
   - Access tokens and refresh tokens are stored as SHA-256 hashes
   - Client secrets are stored as SHA-256 hashes
   - Authorization codes are stored as SHA-256 hashes

   This ensures that even if the KV data is compromised, the actual sensitive values cannot be retrieved.

2. **Token Format**: Tokens use the format `{userId}:{grantId}:{random-secret}` which allows:
   - Parallel lookups of token and grant records for better performance
   - Verification that the token was issued for the specific grant and user
   - Enhanced security through proper validation checks

3. **TTL-based Expiration**: Access tokens automatically expire using KV's TTL feature, reducing the need for manual cleanup.

4. **Efficient Storage**: Refresh tokens are stored within the grant records, eliminating redundant storage and simplifying the data model.

5. **Cryptographic Hash Verification**: When validating credentials, the system hashes the provided value and compares it with the stored hash, rather than comparing plaintext values.

## Example Workflow

1. A client is registered, creating a `client:{clientId}` entry with a hashed client secret.
2. A user authorizes the client, creating a `grant:{userId}:{grantId}` entry (without a refresh token initially).
3. An authorization code is issued, a hash of the code is calculated, and a temporary `auth_code:{codeHash}` entry is created containing both the grant ID and user ID.
4. The client exchanges the code for tokens:
   - The code is hashed and looked up
   - After verification, the `auth_code:{codeHash}` entry is deleted
   - A new refresh token is generated and its hash is stored in the grant record
   - A new access token is generated and its hash is stored in a separate `token:{accessTokenId}` entry
   - Both tokens are returned to the client
5. Access tokens expire automatically after their TTL.
6. Refresh tokens do not expire and are stored directly in the grant; they remain valid until the grant is revoked.
7. When using a refresh token, the client provides it, and after verification, a new access token is issued.

## Implementation Notes

- For high-traffic applications, consider using a caching layer in front of KV to reduce read operations on frequently accessed data.
- Monitor KV usage metrics to ensure you stay within Cloudflare's limits for your plan.
- The design uses KV's `list()` capability with key prefixes to efficiently query related data like all grants for a user, eliminating the need for separate list indexes.
- If a grant is revoked, associated tokens are not immediately deleted from KV, but rely on TTL expiration. Add a cleanup process if immediate revocation is required.