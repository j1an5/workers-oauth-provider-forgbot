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

Grant records store information about permissions a user has granted to an application, along with the authorization code (initially) and refresh token (after code exchange).

**Key format:** `grant:{userId}:{grantId}`

**Content Example (during authorization):**
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
  "authCodeId": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
  "codeChallenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "codeChallengeMethod": "S256"
}
```

**Content Example (after code exchange):**
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

**TTL:**
- Initially 10 minutes (during authorization process)
- No expiration after the authorization code is exchanged for tokens

> **Note:** The grant record includes the hash of the authorization code initially, which is replaced by the hash of the refresh token after the code is exchanged. The record also has a TTL during the authorization process, which is removed when the code is exchanged for tokens to make the grant permanent.

### Tokens

Token records store metadata about issued access tokens, including denormalized grant information for faster access.

**Key format:** `token:{userId}:{grantId}:{tokenId}`

**Content Example:**
```json
{
  "id": "ghi789",
  "grantId": "xyz789",
  "userId": "user123",
  "createdAt": 1644256123,
  "expiresAt": 1644259723,
  "grant": {
    "clientId": "abc123",
    "scope": ["document.read", "document.write"],
    "props": {
      "userId": 123,
      "username": "johndoe"
    }
  }
}
```

> **Note:** The token format is `{userId}:{grantId}:{random-secret}` which embeds the identifiers needed for efficient lookups. The token key format includes the user ID and grant ID to enable efficient revocation of all tokens for a specific grant. The token record contains denormalized grant information to eliminate the need for a separate grant lookup during token validation.

**TTL:** Access tokens typically have a 1 hour (3600 seconds) TTL by default

## Security Considerations

1. **Sensitive Value Storage**: No sensitive values are stored in plaintext in KV storage:
   - Access tokens and refresh tokens are stored as SHA-256 hashes
   - Client secrets are stored as SHA-256 hashes
   - Authorization codes are stored as SHA-256 hashes
   - For PKCE, only the code challenge is stored, never the code verifier

   This ensures that even if the KV data is compromised, the actual sensitive values cannot be retrieved.

2. **Token Format**: Tokens use the format `{userId}:{grantId}:{random-secret}` which allows:
   - Direct access to token records without needing to look up grants separately
   - Verification that the token was issued for the specific grant and user
   - Enhanced security through proper validation checks

3. **TTL-based Expiration**: Access tokens automatically expire using KV's TTL feature, reducing the need for manual cleanup.

4. **Efficient Storage**:
   - Refresh tokens are stored within the grant records, eliminating redundant storage
   - Grant data is denormalized into token records for faster validation
   - Token keys include user ID and grant ID to enable efficient revocation

5. **Structured Key Design**: The key format `token:{userId}:{grantId}:{tokenId}` enables:
   - Efficient revocation of all tokens for a specific grant
   - Easy lookup of all tokens issued to a specific user
   - Clean organization of the key-value namespace

6. **Cryptographic Hash Verification**: When validating credentials, the system hashes the provided value and compares it with the stored hash, rather than comparing plaintext values.

## Example Workflow

1. A client is registered, creating a `client:{clientId}` entry with a hashed client secret.

2. A user authorizes the client, creating a `grant:{userId}:{grantId}` entry that includes:
   - The hashed authorization code in the `authCodeId` field
   - PKCE code challenge and method (if PKCE is used)
   - A 10-minute TTL on the grant record

3. The client exchanges the authorization code for tokens:
   - The code is validated by comparing its hash to the one stored in the grant
   - If PKCE was used, the code_verifier is validated against the stored code_challenge
   - The `authCodeId` and PKCE fields are removed from the grant
   - A refresh token is generated and its hash is stored in the grant's `refreshTokenId` field
   - The grant's TTL is removed, making it permanent
   - A new access token is generated and stored as `token:{userId}:{grantId}:{accessTokenId}` with denormalized grant data
   - Both tokens are returned to the client

4. When the client makes API requests with the access token:
   - The system looks up the token directly using the structured key format
   - Grant information is already available in the token record, eliminating need for a separate lookup
   - The API handler is called with the grant props from the token record

5. Access tokens expire automatically after their TTL.

6. Refresh tokens do not expire and are stored directly in the grant; they remain valid until the grant is revoked.
   - When the `strictOAuth21RefreshTokens` option is enabled, refresh tokens are one-time use, and a new refresh token is issued with each refresh grant.

7. When a grant is revoked:
   - All associated access tokens are found using the key prefix `token:{userId}:{grantId}:` and deleted
   - The grant record is deleted, which also effectively revokes the refresh token

## Implementation Notes

- For high-traffic applications, consider using a caching layer in front of KV to reduce read operations on frequently accessed data.
- Monitor KV usage metrics to ensure you stay within Cloudflare's limits for your plan.
- The design uses KV's `list()` capability with key prefixes to efficiently query related data like all grants for a user, eliminating the need for separate list indexes.
- If a grant is revoked, associated tokens are not immediately deleted from KV, but rely on TTL expiration. Add a cleanup process if immediate revocation is required.