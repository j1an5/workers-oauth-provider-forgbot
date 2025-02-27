Prompt: Could you write a document (text or markdown) explaining the schema of the OAUTH_KV storage? This should be appropriate to include in the repository to help developers understand the code.

Claude responded:

# OAuth KV Storage Schema

This document describes the schema used in the OAUTH_KV storage for the OAuth 2.0 provider library. The library uses Cloudflare Workers KV to store all OAuth-related data, including client registrations, authorization grants, and tokens.

## Overview

The OAUTH_KV namespace stores several types of objects, each with a distinct key prefix to identify the type of data. The storage leverages KV's built-in TTL (Time-To-Live) functionality for automatic expiration of short-lived data like tokens and authorization codes.

## Key Naming Conventions

All keys in the KV namespace follow a consistent pattern to make them easily identifiable:

| Prefix | Purpose | Example |
|--------|---------|---------|
| `client:` | Client registration data | `client:abc123` |
| `grant:` | Authorization grant data | `grant:xyz789` |
| `auth_code:` | Authorization codes | `auth_code:def456` |
| `token:` | Access and refresh tokens | `token:ghi789` |
| `user_grants:` | List of grants for a user | `user_grants:user123` |
| `clients_list` | List of all client IDs | `clients_list` |

## Data Structures

### Clients

Client records store OAuth client application information.

**Key format:** `client:{clientId}`

**Content Example:**
```json
{
  "clientId": "abc123",
  "clientSecret": "secureRandomSecret",
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

**TTL:** No expiration (persistent storage)

### Authorization Grants

Grant records store information about permissions a user has granted to an application.

**Key format:** `grant:{grantId}`

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

### Authorization Codes

Authorization codes are short-lived credentials issued during the authorization flow.

**Key format:** `auth_code:{code}`

**Content:** The grant ID associated with this authorization code (string value)

**TTL:** 10 minutes (600 seconds)

### Tokens

Token records store metadata about issued access and refresh tokens.

**Key format:** `token:{tokenId}`

**Content Example:**
```json
{
  "id": "ghi789",
  "grantId": "xyz789",
  "type": "access",
  "createdAt": 1644256123,
  "expiresAt": 1644259723
}
```

**TTL:**
- Access tokens: Typically 1 hour (3600 seconds) by default
- Refresh tokens: Typically 30 days (2592000 seconds) by default

> **Important:** The actual token strings are never stored in the KV storage. Only the token IDs (SHA-256 hashes of the token strings) are stored.

### User Grants List

A list of all grant IDs associated with a specific user.

**Key format:** `user_grants:{userId}`

**Content Example:**
```json
["xyz789", "mno456", "pqr789"]
```

**TTL:** No expiration (persistent)

### Clients List

A list of all client IDs registered in the system.

**Key format:** `clients_list`

**Content Example:**
```json
["abc123", "def456", "ghi789"]
```

**TTL:** No expiration (persistent)

## Relationships

The following diagram illustrates the relationships between the different data entities:

```
User (userId) 1:N Grants (grantId)
Grant (grantId) 1:N Tokens (tokenId)
Client (clientId) 1:N Grants (grantId)
AuthCode -> Grant (1:1 temporary relationship)
```

## Security Considerations

1. **Token Storage**: The actual token strings are never stored. Instead, we store the SHA-256 hash of the token string. This ensures that even if the KV data is compromised, the actual tokens cannot be retrieved.

2. **TTL-based Expiration**: Tokens and authorization codes automatically expire using KV's TTL feature, reducing the need for manual cleanup.

3. **Client Secrets**: Client secrets are stored in plaintext in the KV storage, under the assumption that the KV namespace is secure. In production environments with high-security requirements, consider implementing additional encryption for client secrets.

## Example Workflow

1. A client is registered, creating a `client:{clientId}` entry and updating `clients_list`.
2. A user authorizes the client, creating a `grant:{grantId}` entry and updating `user_grants:{userId}`.
3. An authorization code is issued, creating a temporary `auth_code:{code}` entry pointing to the grant.
4. The client exchanges the code for tokens, creating `token:{accessTokenId}` and `token:{refreshTokenId}` entries.
5. The authorization code is deleted after use.
6. Access tokens expire automatically after their TTL.
7. Refresh tokens can be used to obtain new access tokens until they expire.

## Implementation Notes

- For high-traffic applications, consider using a caching layer in front of KV to reduce read operations on frequently accessed data.
- Monitor KV usage metrics to ensure you stay within Cloudflare's limits for your plan.
- If a grant is revoked, associated tokens are not immediately deleted from KV, but rely on TTL expiration. Add a cleanup process if immediate revocation is required.