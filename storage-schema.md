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

Grant records store information about permissions a user has granted to an application.

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
  "createdAt": 1644256123
}
```

**TTL:** No expiration (persistent until revoked)

> **Note:** The `userId` is included in the key, allowing efficient listing of all grants for a user using KV's `list()` function with a prefix.

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

Token records store metadata about issued access and refresh tokens.

**Key format:** `token:{tokenId}`

**Content Example:**
```json
{
  "id": "ghi789",
  "grantId": "xyz789",
  "userId": "user123",
  "type": "access",
  "createdAt": 1644256123,
  "expiresAt": 1644259723
}
```

> **Note:** The `userId` is included in the token data to allow reconstructing the full grant key.

**TTL:**
- Access tokens: Typically 1 hour (3600 seconds) by default
- Refresh tokens: Typically 30 days (2592000 seconds) by default

> **Important:** The actual token strings are never stored in the KV storage. Only the token IDs (SHA-256 hashes of the token strings) are stored.

## Security Considerations

1. **Sensitive Value Storage**: No sensitive values are stored in plaintext in KV storage:
   - Access and refresh tokens are stored as SHA-256 hashes
   - Client secrets are stored as SHA-256 hashes
   - Authorization codes are stored as SHA-256 hashes

   This ensures that even if the KV data is compromised, the actual sensitive values cannot be retrieved.

2. **TTL-based Expiration**: Tokens and authorization codes automatically expire using KV's TTL feature, reducing the need for manual cleanup.

3. **Cryptographic Hash Verification**: When validating client credentials or authorization codes, the system hashes the provided value and compares it with the stored hash, rather than comparing plaintext values.

4. **Efficient Key Design**: The key design leverages KV's list capabilities to efficiently query related data without maintaining separate indexes or lists.

## Example Workflow

1. A client is registered, creating a `client:{clientId}` entry with a hashed client secret.
2. A user authorizes the client, creating a `grant:{userId}:{grantId}` entry.
3. An authorization code is issued, a hash of the code is calculated, and a temporary `auth_code:{codeHash}` entry is created containing both the grant ID and user ID.
4. The client exchanges the code for tokens:
   - The code is hashed and looked up
   - After verification, the `auth_code:{codeHash}` entry is deleted
   - New tokens are generated and their hashes are stored as `token:{accessTokenId}` and `token:{refreshTokenId}` entries, including the user ID in the token data
5. Access tokens expire automatically after their TTL.
6. Refresh tokens can be used to obtain new access tokens until they expire.

## Implementation Notes

- For high-traffic applications, consider using a caching layer in front of KV to reduce read operations on frequently accessed data.
- Monitor KV usage metrics to ensure you stay within Cloudflare's limits for your plan.
- The design uses KV's `list()` capability with key prefixes to efficiently query related data like all grants for a user, eliminating the need for separate list indexes.
- If a grant is revoked, associated tokens are not immediately deleted from KV, but rely on TTL expiration. Add a cleanup process if immediate revocation is required.