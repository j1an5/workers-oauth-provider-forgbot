// my-oauth.ts

// Types

/**
 * Configuration options for the OAuth Provider
 */
export interface OAuthProviderOptions {
  /**
   * Base URL for API routes. Requests with URLs starting with this prefix
   * will be treated as API requests and require a valid access token.
   */
  apiRoute: string;

  /**
   * Handler function for API requests that have a valid access token.
   * This function receives the authenticated user properties along with the request.
   */
  apiHandler: ApiHandler;

  /**
   * Handler function for all non-API requests or API requests without a valid token.
   */
  defaultHandler: DefaultHandler;

  /**
   * URL of the OAuth authorization endpoint where users can grant permissions.
   * This URL is used in OAuth metadata and is not handled by the provider itself.
   */
  authorizeEndpoint: string;

  /**
   * URL of the token endpoint which the provider will implement.
   * This endpoint handles token issuance, refresh, and revocation.
   */
  tokenEndpoint: string;

  /**
   * Optional URL for the client registration endpoint.
   * If provided, the provider will implement dynamic client registration.
   */
  clientRegistrationEndpoint?: string;

  /**
   * Time-to-live for access tokens in seconds.
   * Defaults to 1 hour (3600 seconds) if not specified.
   */
  accessTokenTTL?: number;
}

/**
 * Handler function type for authenticated API requests
 * @param request - The original HTTP request
 * @param env - Cloudflare Worker environment variables
 * @param ctx - Cloudflare Worker execution context with ctx.props for user properties
 * @param oauth - Helper methods for OAuth operations
 * @returns A Promise resolving to an HTTP Response
 */
export interface ApiHandler {
  (request: Request, env: any, ctx: ExecutionContext, oauth: OAuthHelpers): Promise<Response>;
}

/**
 * Handler function type for non-API or unauthenticated requests
 * @param request - The original HTTP request
 * @param env - Cloudflare Worker environment variables
 * @param ctx - Cloudflare Worker execution context
 * @param oauth - Helper methods for OAuth operations
 * @returns A Promise resolving to an HTTP Response
 */
export interface DefaultHandler {
  (request: Request, env: any, ctx: ExecutionContext, oauth: OAuthHelpers): Promise<Response>;
}

/**
 * Helper methods for OAuth operations provided to handler functions
 */
export interface OAuthHelpers {
  /**
   * Parses an OAuth authorization request from the HTTP request
   * @param request - The HTTP request containing OAuth parameters
   * @returns The parsed authorization request parameters
   */
  parseAuthRequest(request: Request): AuthRequest;

  /**
   * Looks up a client by its client ID
   * @param clientId - The client ID to look up
   * @returns A Promise resolving to the client info, or null if not found
   */
  lookupClient(clientId: string): Promise<ClientInfo | null>;

  /**
   * Completes an authorization request by creating a grant and authorization code
   * @param options - Options specifying the grant details
   * @returns A Promise resolving to an object containing the redirect URL
   */
  completeAuthorization(options: CompleteAuthorizationOptions): Promise<{ redirectTo: string }>;

  /**
   * Creates a new OAuth client
   * @param clientInfo - Partial client information to create the client with
   * @returns A Promise resolving to the created client info
   */
  createClient(clientInfo: Partial<ClientInfo>): Promise<ClientInfo>;

  /**
   * Lists all registered OAuth clients with pagination support
   * @param options - Optional pagination parameters (limit and cursor)
   * @returns A Promise resolving to the list result with items and optional cursor
   */
  listClients(options?: ListOptions): Promise<ListResult<ClientInfo>>;

  /**
   * Updates an existing OAuth client
   * @param clientId - The ID of the client to update
   * @param updates - Partial client information with fields to update
   * @returns A Promise resolving to the updated client info, or null if not found
   */
  updateClient(clientId: string, updates: Partial<ClientInfo>): Promise<ClientInfo | null>;

  /**
   * Deletes an OAuth client
   * @param clientId - The ID of the client to delete
   * @returns A Promise resolving when the deletion is confirmed.
   */
  deleteClient(clientId: string): Promise<void>;

  /**
   * Lists all authorization grants for a specific user with pagination support
   * @param userId - The ID of the user whose grants to list
   * @param options - Optional pagination parameters (limit and cursor)
   * @returns A Promise resolving to the list result with items and optional cursor
   */
  listUserGrants(userId: string, options?: ListOptions): Promise<ListResult<Grant>>;

  /**
   * Revokes an authorization grant
   * @param grantId - The ID of the grant to revoke
   * @param userId - The ID of the user who owns the grant
   * @returns A Promise resolving when the revocation is confirmed.
   */
  revokeGrant(grantId: string, userId: string): Promise<void>;
}

/**
 * Parsed OAuth authorization request parameters
 */
export interface AuthRequest {
  /**
   * OAuth response type (e.g., "code" for authorization code flow)
   */
  responseType: string;

  /**
   * Client identifier for the OAuth client
   */
  clientId: string;

  /**
   * URL to redirect to after authorization
   */
  redirectUri: string;

  /**
   * Array of requested permission scopes
   */
  scope: string[];

  /**
   * Client state value to be returned in the redirect
   */
  state: string;

  /**
   * PKCE code challenge (RFC 7636)
   */
  codeChallenge?: string;

  /**
   * PKCE code challenge method (plain or S256)
   */
  codeChallengeMethod?: string;
}

/**
 * OAuth client registration information
 */
export interface ClientInfo {
  /**
   * Unique identifier for the client
   */
  clientId: string;

  /**
   * Secret used to authenticate the client (stored as a hash)
   */
  clientSecret: string;

  /**
   * List of allowed redirect URIs for the client
   */
  redirectUris: string[];

  /**
   * Human-readable name of the client application
   */
  clientName?: string;

  /**
   * URL to the client's logo
   */
  logoUri?: string;

  /**
   * URL to the client's homepage
   */
  clientUri?: string;

  /**
   * URL to the client's privacy policy
   */
  policyUri?: string;

  /**
   * URL to the client's terms of service
   */
  tosUri?: string;

  /**
   * URL to the client's JSON Web Key Set for validating signatures
   */
  jwksUri?: string;

  /**
   * List of email addresses for contacting the client developers
   */
  contacts?: string[];

  /**
   * List of grant types the client supports
   */
  grantTypes?: string[];

  /**
   * List of response types the client supports
   */
  responseTypes?: string[];

  /**
   * Unix timestamp when the client was registered
   */
  registrationDate?: number;
}

/**
 * Options for completing an authorization request
 */
export interface CompleteAuthorizationOptions {
  /**
   * The original parsed authorization request
   */
  request: AuthRequest;

  /**
   * Identifier for the user granting the authorization
   */
  userId: string;

  /**
   * Application-specific metadata to associate with this grant
   */
  metadata: any;

  /**
   * List of scopes that were actually granted (may differ from requested scopes)
   */
  scope: string[];

  /**
   * Application-specific properties to include with API requests
   * authorized by this grant
   */
  props: any;

  /**
   * Optional custom expiration time in seconds for the tokens
   */
  expiresIn?: number;
}

/**
 * Authorization grant record
 */
export interface Grant {
  /**
   * Unique identifier for the grant
   */
  id: string;

  /**
   * Client that received this grant
   */
  clientId: string;

  /**
   * User who authorized this grant
   */
  userId: string;

  /**
   * List of scopes that were granted
   */
  scope: string[];

  /**
   * Application-specific metadata associated with this grant
   */
  metadata: any;

  /**
   * Application-specific properties included with API requests
   */
  props: any;

  /**
   * Unix timestamp when the grant was created
   */
  createdAt: number;

  /**
   * The hash of the current refresh token associated with this grant
   */
  refreshTokenId?: string;

  /**
   * The hash of the previous refresh token associated with this grant
   * This token is still valid until the new token is first used
   */
  previousRefreshTokenId?: string;

  /**
   * The hash of the authorization code associated with this grant
   * Only present during the authorization code exchange process
   */
  authCodeId?: string;

  /**
   * PKCE code challenge for this authorization
   * Only present during the authorization code exchange process
   */
  codeChallenge?: string;

  /**
   * PKCE code challenge method (plain or S256)
   * Only present during the authorization code exchange process
   */
  codeChallengeMethod?: string;
}

/**
 * Token record stored in KV
 * Note: The actual token format is "{userId}:{grantId}:{random-secret}"
 * but we still only store the hash of the full token string.
 * This contains only access tokens; refresh tokens are stored within the grant records.
 */
export interface Token {
  /**
   * Unique identifier for the token (hash of the actual token)
   */
  id: string;

  /**
   * Identifier of the grant this token is associated with
   */
  grantId: string;

  /**
   * User ID associated with this token
   */
  userId: string;

  /**
   * Unix timestamp when the token was created
   */
  createdAt: number;

  /**
   * Unix timestamp when the token expires
   */
  expiresAt: number;

  /**
   * Denormalized grant information for faster access
   */
  grant: {
    /**
     * Client that received this grant
     */
    clientId: string;

    /**
     * List of scopes that were granted
     */
    scope: string[];

    /**
     * Application-specific properties included with API requests
     */
    props: any;
  };
}

/**
 * Options for listing operations that support pagination
 */
export interface ListOptions {
  /**
   * Maximum number of items to return (max 1000)
   */
  limit?: number;

  /**
   * Cursor for pagination (from a previous listing operation)
   */
  cursor?: string;
}

/**
 * Result of a listing operation with pagination support
 */
export interface ListResult<T> {
  /**
   * The list of items
   */
  items: T[];

  /**
   * Cursor to get the next page of results, if there are more results
   */
  cursor?: string;
}

/**
 * OAuth 2.0 Provider implementation for Cloudflare Workers
 * Implements authorization code flow with support for refresh tokens
 * and dynamic client registration.
 */
export class OAuthProvider {
  /**
   * Configuration options for the provider
   */
  private options: OAuthProviderOptions;

  /**
   * Creates a new OAuth provider instance
   * @param options - Configuration options for the provider
   */
  constructor(options: OAuthProviderOptions) {
    this.options = {
      ...options,
      accessTokenTTL: options.accessTokenTTL || DEFAULT_ACCESS_TOKEN_TTL
    };
  }

  /**
   * Main fetch handler for the Worker
   * Routes requests to the appropriate handler based on the URL
   * @param request - The HTTP request
   * @param env - Cloudflare Worker environment variables
   * @param ctx - Cloudflare Worker execution context
   * @returns A Promise resolving to an HTTP Response
   */
  async fetch(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Handle .well-known/oauth-authorization-server
    if (url.pathname === '/.well-known/oauth-authorization-server') {
      return this.handleMetadataDiscovery();
    }

    // Handle token endpoint
    if (this.isTokenEndpoint(url)) {
      return this.handleTokenRequest(request, env);
    }

    // Handle client registration endpoint
    if (this.options.clientRegistrationEndpoint &&
        this.isClientRegistrationEndpoint(url)) {
      return this.handleClientRegistration(request, env);
    }

    // Check if it's an API request
    if (this.isApiRequest(url)) {
      return this.handleApiRequest(request, env, ctx);
    }

    // Default handler for all other requests
    return this.options.defaultHandler(request, env, ctx, this.createOAuthHelpers(env));
  }

  /**
   * Checks if a URL matches the configured token endpoint
   * @param url - The URL to check
   * @returns True if the URL matches the token endpoint
   */
  private isTokenEndpoint(url: URL): boolean {
    const tokenUrl = new URL(this.options.tokenEndpoint);
    return url.pathname === tokenUrl.pathname;
  }

  /**
   * Checks if a URL matches the configured client registration endpoint
   * @param url - The URL to check
   * @returns True if the URL matches the client registration endpoint
   */
  private isClientRegistrationEndpoint(url: URL): boolean {
    if (!this.options.clientRegistrationEndpoint) return false;
    const registrationUrl = new URL(this.options.clientRegistrationEndpoint);
    return url.pathname === registrationUrl.pathname;
  }

  /**
   * Checks if a URL is an API request based on the configured API route
   * @param url - The URL to check
   * @returns True if the URL is an API request
   */
  private isApiRequest(url: URL): boolean {
    const apiUrl = new URL(this.options.apiRoute);
    return url.href.startsWith(apiUrl.href);
  }

  /**
   * Handles the OAuth metadata discovery endpoint
   * Implements RFC 8414 for OAuth Server Metadata
   * @returns Response with OAuth server metadata
   */
  private async handleMetadataDiscovery(): Promise<Response> {
    const metadata = {
      issuer: new URL(this.options.tokenEndpoint).origin,
      authorization_endpoint: this.options.authorizeEndpoint,
      token_endpoint: this.options.tokenEndpoint,
      registration_endpoint: this.options.clientRegistrationEndpoint,
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      response_types_supported: ["code"],
      scopes_supported: [], // This could be configured in the future
      response_modes_supported: ["query"],
      revocation_endpoint: this.options.tokenEndpoint, // Reusing token endpoint for revocation
      code_challenge_methods_supported: ["plain", "S256"], // PKCE support
    };

    return new Response(JSON.stringify(metadata), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  /**
   * Handles client authentication and token issuance via the token endpoint
   * Supports authorization_code and refresh_token grant types
   * @param request - The HTTP request
   * @param env - Cloudflare Worker environment variables
   * @returns Response with token data or error
   */
  private async handleTokenRequest(request: Request, env: any): Promise<Response> {
    // Only accept POST requests
    if (request.method !== 'POST') {
      return createErrorResponse(
        'invalid_request',
        'Method not allowed',
        405
      );
    }

    let contentType = request.headers.get('Content-Type') || '';
    let body: any = {};

    if (contentType.includes('application/json')) {
      body = await request.json();
    } else {
      // Assume application/x-www-form-urlencoded
      const formData = await request.formData();
      for (const [key, value] of formData.entries()) {
        body[key] = value;
      }
    }

    // Authenticate client
    const authHeader = request.headers.get('Authorization');
    let clientId = '';
    let clientSecret = '';

    if (authHeader && authHeader.startsWith('Basic ')) {
      // Basic auth
      const credentials = atob(authHeader.substring(6));
      const [id, secret] = credentials.split(':');
      clientId = id;
      clientSecret = secret;
    } else {
      // Form parameters
      clientId = body.client_id;
      clientSecret = body.client_secret;
    }

    if (!clientId || !clientSecret) {
      return createErrorResponse(
        'invalid_client',
        'Client authentication failed',
        401
      );
    }

    // Verify client
    const clientInfo = await this.getClient(env, clientId);
    if (!clientInfo) {
      return createErrorResponse(
        'invalid_client',
        'Client not found',
        401
      );
    }

    // Hash the provided secret and compare with stored hash
    const providedSecretHash = await hashSecret(clientSecret);
    if (providedSecretHash !== clientInfo.clientSecret) {
      return createErrorResponse(
        'invalid_client',
        'Client authentication failed',
        401
      );
    }

    // Handle different grant types
    const grantType = body.grant_type;

    if (grantType === 'authorization_code') {
      return this.handleAuthorizationCodeGrant(body, clientInfo, env);
    } else if (grantType === 'refresh_token') {
      return this.handleRefreshTokenGrant(body, clientInfo, env);
    } else {
      return createErrorResponse(
        'unsupported_grant_type',
        'Grant type not supported'
      );
    }
  }

  /**
   * Handles the authorization code grant type
   * Exchanges an authorization code for access and refresh tokens
   * @param body - The parsed request body
   * @param clientInfo - The authenticated client information
   * @param env - Cloudflare Worker environment variables
   * @returns Response with token data or error
   */
  private async handleAuthorizationCodeGrant(
    body: any,
    clientInfo: ClientInfo,
    env: any
  ): Promise<Response> {
    const code = body.code;
    const redirectUri = body.redirect_uri;
    const codeVerifier = body.code_verifier;

    if (!code) {
      return createErrorResponse(
        'invalid_request',
        'Authorization code is required'
      );
    }

    // OAuth 2.1 requires redirect_uri parameter
    if (!redirectUri) {
      return createErrorResponse(
        'invalid_request',
        'redirect_uri is required'
      );
    }

    // OAuth 2.1 requires exact match for redirect URIs
    if (!clientInfo.redirectUris.includes(redirectUri)) {
      return createErrorResponse(
        'invalid_grant',
        'Invalid redirect URI'
      );
    }

    // Parse the authorization code to extract user ID and grant ID
    const codeParts = code.split(':');
    if (codeParts.length !== 3) {
      return createErrorResponse(
        'invalid_grant',
        'Invalid authorization code format'
      );
    }

    const [userId, grantId, _] = codeParts;

    // Get the grant
    const grantKey = `grant:${userId}:${grantId}`;
    const grantData = await env.OAUTH_KV.get(grantKey, { type: 'json' });

    if (!grantData) {
      return createErrorResponse(
        'invalid_grant',
        'Grant not found or authorization code expired'
      );
    }

    // Verify that the grant contains an auth code hash
    if (!grantData.authCodeId) {
      return createErrorResponse(
        'invalid_grant',
        'Authorization code already used'
      );
    }

    // Verify the authorization code by comparing its hash to the one in the grant
    const codeHash = await hashSecret(code);
    if (codeHash !== grantData.authCodeId) {
      return createErrorResponse(
        'invalid_grant',
        'Invalid authorization code'
      );
    }

    // Verify client ID matches
    if (grantData.clientId !== clientInfo.clientId) {
      return createErrorResponse(
        'invalid_grant',
        'Client ID mismatch'
      );
    }

    // Verify PKCE code_verifier if code_challenge was provided during authorization
    if (grantData.codeChallenge) {
      if (!codeVerifier) {
        return createErrorResponse(
          'invalid_request',
          'code_verifier is required for PKCE'
        );
      }

      // Verify the code verifier against the stored code challenge
      let calculatedChallenge: string;

      if (grantData.codeChallengeMethod === 'S256') {
        // SHA-256 transformation for S256 method
        const encoder = new TextEncoder();
        const data = encoder.encode(codeVerifier);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        calculatedChallenge = base64UrlEncode(String.fromCharCode(...hashArray));
      } else {
        // Plain method, direct comparison
        calculatedChallenge = codeVerifier;
      }

      if (calculatedChallenge !== grantData.codeChallenge) {
        return createErrorResponse(
          'invalid_grant',
          'Invalid PKCE code_verifier'
        );
      }
    }

    // Code is valid - generate tokens
    const accessTokenSecret = generateRandomString(TOKEN_LENGTH);
    const refreshTokenSecret = generateRandomString(TOKEN_LENGTH);

    const accessToken = `${userId}:${grantId}:${accessTokenSecret}`;
    const refreshToken = `${userId}:${grantId}:${refreshTokenSecret}`;

    // Use WebCrypto to generate token IDs from the full token strings
    const accessTokenId = await generateTokenId(accessToken);
    const refreshTokenId = await generateTokenId(refreshToken);

    const now = Math.floor(Date.now() / 1000);
    const accessTokenExpiresAt = now + this.options.accessTokenTTL!;

    // Store access token with denormalized grant information
    const accessTokenData: Token = {
      id: accessTokenId,
      grantId: grantId,
      userId: userId,
      createdAt: now,
      expiresAt: accessTokenExpiresAt,
      grant: {
        clientId: grantData.clientId,
        scope: grantData.scope,
        props: grantData.props
      }
    };

    // Update the grant:
    // - Remove the auth code hash (it's single-use)
    // - Remove PKCE-related fields (one-time use)
    // - Add the refresh token hash
    // - Make it permanent (no TTL)
    delete grantData.authCodeId;
    delete grantData.codeChallenge;
    delete grantData.codeChallengeMethod;
    grantData.refreshTokenId = refreshTokenId;
    grantData.previousRefreshTokenId = undefined; // No previous token for first use

    // Update the grant with the refresh token hash and no TTL
    await env.OAUTH_KV.put(grantKey, JSON.stringify(grantData));

    // Save access token with TTL
    await env.OAUTH_KV.put(
      `token:${userId}:${grantId}:${accessTokenId}`,
      JSON.stringify(accessTokenData),
      { expirationTtl: this.options.accessTokenTTL }
    );

    // Return the tokens
    return new Response(JSON.stringify({
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: this.options.accessTokenTTL,
      refresh_token: refreshToken,
      scope: grantData.scope.join(' ')
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  /**
   * Handles the refresh token grant type
   * Issues a new access token using a refresh token
   * @param body - The parsed request body
   * @param clientInfo - The authenticated client information
   * @param env - Cloudflare Worker environment variables
   * @returns Response with token data or error
   */
  private async handleRefreshTokenGrant(
    body: any,
    clientInfo: ClientInfo,
    env: any
  ): Promise<Response> {
    const refreshToken = body.refresh_token;

    if (!refreshToken) {
      return createErrorResponse(
        'invalid_request',
        'Refresh token is required'
      );
    }

    // Parse the token to extract user ID and grant ID
    const tokenParts = refreshToken.split(':');
    if (tokenParts.length !== 3) {
      return createErrorResponse(
        'invalid_grant',
        'Invalid token format'
      );
    }

    const [userId, grantId, _] = tokenParts;

    // Calculate the token hash
    const providedTokenHash = await generateTokenId(refreshToken);

    // Get the associated grant using userId in the key
    const grantKey = `grant:${userId}:${grantId}`;
    const grantData = await env.OAUTH_KV.get(grantKey, { type: 'json' });

    if (!grantData) {
      return createErrorResponse(
        'invalid_grant',
        'Grant not found'
      );
    }

    // Check if the provided token matches either the current or previous refresh token
    const isCurrentToken = grantData.refreshTokenId === providedTokenHash;
    const isPreviousToken = grantData.previousRefreshTokenId === providedTokenHash;

    if (!isCurrentToken && !isPreviousToken) {
      return createErrorResponse(
        'invalid_grant',
        'Invalid refresh token'
      );
    }

    // Verify client ID matches
    if (grantData.clientId !== clientInfo.clientId) {
      return createErrorResponse(
        'invalid_grant',
        'Client ID mismatch'
      );
    }

    // Generate new access token with embedded user and grant IDs
    const accessTokenSecret = generateRandomString(TOKEN_LENGTH);
    const newAccessToken = `${userId}:${grantId}:${accessTokenSecret}`;
    const accessTokenId = await generateTokenId(newAccessToken);

    // Always issue a new refresh token with each use
    const refreshTokenSecret = generateRandomString(TOKEN_LENGTH);
    const newRefreshToken = `${userId}:${grantId}:${refreshTokenSecret}`;
    const newRefreshTokenId = await generateTokenId(newRefreshToken);

    const now = Math.floor(Date.now() / 1000);
    const accessTokenExpiresAt = now + this.options.accessTokenTTL!;

    // Store new access token with denormalized grant information
    const accessTokenData: Token = {
      id: accessTokenId,
      grantId: grantId,
      userId: userId,
      createdAt: now,
      expiresAt: accessTokenExpiresAt,
      grant: {
        clientId: grantData.clientId,
        scope: grantData.scope,
        props: grantData.props
      }
    };

    // Update the grant with the token rotation information

    // The token which the client used this time becomes the "previous" token, so that the client
    // can always use the same token again next time. This might technically violate OAuth 2.1's
    // requirement that refresh tokens be single-use. However, this requirement violates the laws
    // of distributed systems. It's important that the client can always retry when a transient
    // failure occurs. Under the strict requirement, if the failure occurred after the server
    // rotated the token but before the client managed to store the updated token, then the client
    // no longer has any valid refresh token and has effectively lost its grant. That's bad! So
    // instead, we don't invalidate the old token until the client successfully uses a newer token.
    // This provides most of the security benefits (tokens still rotate naturally) but without
    // being inherently unreliable.
    grantData.previousRefreshTokenId = providedTokenHash;

    // The newly-generated token becomes the new "current" token.
    grantData.refreshTokenId = newRefreshTokenId;

    // Save the updated grant
    await env.OAUTH_KV.put(grantKey, JSON.stringify(grantData));

    // Save access token with TTL
    await env.OAUTH_KV.put(
      `token:${userId}:${grantId}:${accessTokenId}`,
      JSON.stringify(accessTokenData),
      { expirationTtl: this.options.accessTokenTTL }
    );

    // Return the new access token and refresh token
    return new Response(JSON.stringify({
      access_token: newAccessToken,
      token_type: 'bearer',
      expires_in: this.options.accessTokenTTL,
      refresh_token: newRefreshToken,
      scope: grantData.scope.join(' ')
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  /**
   * Handles the dynamic client registration endpoint (RFC 7591)
   * @param request - The HTTP request
   * @param env - Cloudflare Worker environment variables
   * @returns Response with client registration data or error
   */
  private async handleClientRegistration(request: Request, env: any): Promise<Response> {
    if (!this.options.clientRegistrationEndpoint) {
      return createErrorResponse(
        'not_implemented',
        'Client registration is not enabled',
        501
      );
    }

    // Check method
    if (request.method !== 'POST') {
      return createErrorResponse(
        'invalid_request',
        'Method not allowed',
        405
      );
    }

    // Parse client metadata
    const clientMetadata = await request.json();

    // Validate redirect URIs
    if (!clientMetadata.redirect_uris || !Array.isArray(clientMetadata.redirect_uris) || clientMetadata.redirect_uris.length === 0) {
      return createErrorResponse(
        'invalid_redirect_uri',
        'At least one redirect URI is required'
      );
    }

    // Create client
    const clientId = generateRandomString(16);
    const clientSecret = generateRandomString(32);

    // Hash the client secret before storing
    const hashedSecret = await hashSecret(clientSecret);

    const clientInfo: ClientInfo = {
      clientId,
      clientSecret: hashedSecret, // Store the hashed secret
      redirectUris: clientMetadata.redirect_uris,
      clientName: clientMetadata.client_name,
      logoUri: clientMetadata.logo_uri,
      clientUri: clientMetadata.client_uri,
      policyUri: clientMetadata.policy_uri,
      tosUri: clientMetadata.tos_uri,
      jwksUri: clientMetadata.jwks_uri,
      contacts: clientMetadata.contacts,
      grantTypes: clientMetadata.grant_types || ['authorization_code', 'refresh_token'],
      responseTypes: clientMetadata.response_types || ['code'],
      registrationDate: Math.floor(Date.now() / 1000)
    };

    // Store client info
    await env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(clientInfo));

    // Return client information with the original unhashed secret
    const response = {
      client_id: clientInfo.clientId,
      client_secret: clientSecret, // Return the original unhashed secret
      redirect_uris: clientInfo.redirectUris,
      client_name: clientInfo.clientName,
      logo_uri: clientInfo.logoUri,
      client_uri: clientInfo.clientUri,
      policy_uri: clientInfo.policyUri,
      tos_uri: clientInfo.tosUri,
      jwks_uri: clientInfo.jwksUri,
      contacts: clientInfo.contacts,
      grant_types: clientInfo.grantTypes,
      response_types: clientInfo.responseTypes,
      registration_client_uri: `${this.options.clientRegistrationEndpoint}/${clientId}`,
      client_id_issued_at: clientInfo.registrationDate,
    };

    return new Response(JSON.stringify(response), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  /**
   * Handles API requests by validating the access token and calling the API handler
   * @param request - The HTTP request
   * @param env - Cloudflare Worker environment variables
   * @param ctx - Cloudflare Worker execution context
   * @returns Response from the API handler or error
   */
  private async handleApiRequest(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
    // Get access token from Authorization header
    const authHeader = request.headers.get('Authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return createErrorResponse(
        'invalid_token',
        'Missing or invalid access token',
        401,
        { 'WWW-Authenticate': 'Bearer realm="OAuth", error="invalid_token", error_description="Missing or invalid access token"' }
      );
    }

    const accessToken = authHeader.substring(7);

    // Parse the token to extract user ID and grant ID for parallel lookups
    const tokenParts = accessToken.split(':');
    if (tokenParts.length !== 3) {
      return createErrorResponse(
        'invalid_token',
        'Invalid token format',
        401,
        { 'WWW-Authenticate': 'Bearer realm="OAuth", error="invalid_token"' }
      );
    }

    const [userId, grantId, _] = tokenParts;

    // Generate token ID from the full token
    const accessTokenId = await generateTokenId(accessToken);

    // Look up the token record, which now contains the denormalized grant information
    const tokenKey = `token:${userId}:${grantId}:${accessTokenId}`;
    const tokenData = await env.OAUTH_KV.get(tokenKey, { type: 'json' });

    // Verify token
    if (!tokenData) {
      return createErrorResponse(
        'invalid_token',
        'Invalid access token',
        401,
        { 'WWW-Authenticate': 'Bearer realm="OAuth", error="invalid_token"' }
      );
    }

    // Check if token is expired (should be auto-deleted by KV TTL, but double-check)
    const now = Math.floor(Date.now() / 1000);
    if (tokenData.expiresAt < now) {
      return createErrorResponse(
        'invalid_token',
        'Access token expired',
        401,
        { 'WWW-Authenticate': 'Bearer realm="OAuth", error="invalid_token"' }
      );
    }

    // Extract the denormalized grant data directly from the token
    const grantProps = tokenData.grant.props;

    // Set the grant props on the context object
    ctx.props = grantProps;
    
    // Call the API handler with the props in ctx
    return this.options.apiHandler(
      request,
      env,
      ctx,
      this.createOAuthHelpers(env)
    );
  }
  /**
   * Creates the helper methods object for OAuth operations
   * This is passed to the handler functions to allow them to interact with the OAuth system
   * @param env - Cloudflare Worker environment variables
   * @returns An instance of OAuthHelpers
   */
  private createOAuthHelpers(env: any): OAuthHelpers {
    return new OAuthHelpersImpl(env, this);
  }

  /**
   * Fetches client information from KV storage
   * @param env - Cloudflare Worker environment variables
   * @param clientId - The client ID to look up
   * @returns The client information, or null if not found
   */
  getClient(env: any, clientId: string): Promise<ClientInfo | null> {
    const clientKey = `client:${clientId}`;
    return env.OAUTH_KV.get(clientKey, { type: 'json' });
  }
}

// Constants
/**
 * Default expiration time for access tokens (1 hour in seconds)
 */
const DEFAULT_ACCESS_TOKEN_TTL = 60 * 60;

/**
 * Length of generated token strings
 */
const TOKEN_LENGTH = 32;

// Helper Functions
/**
 * Helper function to create OAuth error responses
 * @param code - OAuth error code (e.g., 'invalid_request', 'invalid_token')
 * @param description - Human-readable error description
 * @param status - HTTP status code (default: 400)
 * @param headers - Additional headers to include
 * @returns A Response object with the error
 */
function createErrorResponse(
  code: string,
  description: string,
  status: number = 400,
  headers: Record<string, string> = {}
): Response {
  const body = JSON.stringify({
    error: code,
    error_description: description
  });

  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...headers
    }
  });
}

/**
 * Hashes a secret value using SHA-256
 * @param secret - The secret value to hash
 * @returns A hex string representation of the hash
 */
async function hashSecret(secret: string): Promise<string> {
  // Use the same approach as generateTokenId for consistency
  return generateTokenId(secret);
}

/**
 * Generates a cryptographically secure random string
 * @param length - The length of the string to generate
 * @returns A random string of the specified length
 */
function generateRandomString(length: number): string {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const values = new Uint8Array(length);
  crypto.getRandomValues(values);
  for (let i = 0; i < length; i++) {
    result += characters.charAt(values[i] % characters.length);
  }
  return result;
}

/**
 * Generates a token ID by hashing the token value using SHA-256
 * @param token - The token to hash
 * @returns A hex string representation of the hash
 */
async function generateTokenId(token: string): Promise<string> {
  // Convert the token string to a Uint8Array
  const encoder = new TextEncoder();
  const data = encoder.encode(token);

  // Use the WebCrypto API to create a SHA-256 hash
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);

  // Convert the hash to a hex string
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  return hashHex;
}

/**
 * Encodes a string as base64url (URL-safe base64)
 * @param str - The string to encode
 * @returns The base64url encoded string
 */
function base64UrlEncode(str: string): string {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Class that implements the OAuth helper methods
 * Provides methods for OAuth operations needed by handlers
 */
class OAuthHelpersImpl implements OAuthHelpers {
  private env: any;
  private provider: OAuthProvider;

  /**
   * Creates a new OAuthHelpers instance
   * @param env - Cloudflare Worker environment variables
   * @param provider - Reference to the parent provider instance
   */
  constructor(env: any, provider: OAuthProvider) {
    this.env = env;
    this.provider = provider;
  }

  /**
   * Parses an OAuth authorization request from the HTTP request
   * @param request - The HTTP request containing OAuth parameters
   * @returns The parsed authorization request parameters
   */
  parseAuthRequest(request: Request): AuthRequest {
    const url = new URL(request.url);
    const responseType = url.searchParams.get('response_type') || '';
    const clientId = url.searchParams.get('client_id') || '';
    const redirectUri = url.searchParams.get('redirect_uri') || '';
    const scope = (url.searchParams.get('scope') || '').split(' ').filter(Boolean);
    const state = url.searchParams.get('state') || '';
    const codeChallenge = url.searchParams.get('code_challenge') || undefined;
    const codeChallengeMethod = url.searchParams.get('code_challenge_method') || 'plain';

    // OAuth 2.1 does not support the implicit flow ('token' response type)
    if (responseType === 'token') {
      throw new Error('The implicit grant flow is not supported in OAuth 2.1');
    }

    return {
      responseType,
      clientId,
      redirectUri,
      scope,
      state,
      codeChallenge,
      codeChallengeMethod
    };
  }

  /**
   * Looks up a client by its client ID
   * @param clientId - The client ID to look up
   * @returns A Promise resolving to the client info, or null if not found
   */
  async lookupClient(clientId: string): Promise<ClientInfo | null> {
    return await this.provider.getClient(this.env, clientId);
  }

  /**
   * Completes an authorization request by creating a grant and authorization code
   * @param options - Options specifying the grant details
   * @returns A Promise resolving to an object containing the redirect URL
   */
  async completeAuthorization(options: CompleteAuthorizationOptions): Promise<{ redirectTo: string }> {
    // Generate a unique grant ID
    const grantId = generateRandomString(16);

    // Generate an authorization code with embedded user and grant IDs
    const authCodeSecret = generateRandomString(32);
    const authCode = `${options.userId}:${grantId}:${authCodeSecret}`;

    // Hash the authorization code
    const authCodeId = await hashSecret(authCode);

    // Store the grant with the auth code hash
    const grant: Grant = {
      id: grantId,
      clientId: options.request.clientId,
      userId: options.userId,
      scope: options.scope,
      metadata: options.metadata,
      props: options.props,
      createdAt: Math.floor(Date.now() / 1000),
      authCodeId: authCodeId, // Store the auth code hash in the grant
      // Store PKCE parameters if provided
      codeChallenge: options.request.codeChallenge,
      codeChallengeMethod: options.request.codeChallengeMethod
    };

    // Store the grant with a key that includes the user ID
    const grantKey = `grant:${options.userId}:${grantId}`;

    // Set 10-minute TTL for the grant (will be extended when code is exchanged)
    const codeExpiresIn = 600; // 10 minutes
    await this.env.OAUTH_KV.put(grantKey, JSON.stringify(grant), { expirationTtl: codeExpiresIn });

    // Build the redirect URL
    const redirectUrl = new URL(options.request.redirectUri);
    redirectUrl.searchParams.set('code', authCode);
    if (options.request.state) {
      redirectUrl.searchParams.set('state', options.request.state);
    }

    return { redirectTo: redirectUrl.toString() };
  }

  /**
   * Creates a new OAuth client
   * @param clientInfo - Partial client information to create the client with
   * @returns A Promise resolving to the created client info
   */
  async createClient(clientInfo: Partial<ClientInfo>): Promise<ClientInfo> {
    const clientId = generateRandomString(16);
    const clientSecret = generateRandomString(32);

    // Hash the client secret
    const hashedSecret = await hashSecret(clientSecret);

    const newClient: ClientInfo = {
      clientId,
      clientSecret: hashedSecret, // Store hashed secret
      redirectUris: clientInfo.redirectUris || [],
      clientName: clientInfo.clientName,
      logoUri: clientInfo.logoUri,
      clientUri: clientInfo.clientUri,
      policyUri: clientInfo.policyUri,
      tosUri: clientInfo.tosUri,
      jwksUri: clientInfo.jwksUri,
      contacts: clientInfo.contacts,
      grantTypes: clientInfo.grantTypes || ['authorization_code', 'refresh_token'],
      responseTypes: clientInfo.responseTypes || ['code'],
      registrationDate: Math.floor(Date.now() / 1000)
    };

    await this.env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(newClient));

    // Return client with unhashed secret
    const clientResponse = {
      ...newClient,
      clientSecret // Return original unhashed secret
    };

    return clientResponse;
  }

  /**
   * Lists all registered OAuth clients with pagination support
   * @param options - Optional pagination parameters (limit and cursor)
   * @returns A Promise resolving to the list result with items and optional cursor
   */
  async listClients(options?: ListOptions): Promise<ListResult<ClientInfo>> {
    // Prepare list options for KV
    const listOptions: { limit?: number; cursor?: string; prefix: string } = {
      prefix: 'client:'
    };

    if (options?.limit !== undefined) {
      listOptions.limit = options.limit;
    }

    if (options?.cursor !== undefined) {
      listOptions.cursor = options.cursor;
    }

    // Use the KV list() function to get client keys with pagination
    const response = await this.env.OAUTH_KV.list(listOptions);

    // Fetch all clients in parallel
    const clients: ClientInfo[] = [];
    const promises = response.keys.map(async (key: { name: string }) => {
      const clientId = key.name.substring('client:'.length);
      const client = await this.provider.getClient(this.env, clientId);
      if (client) {
        clients.push(client);
      }
    });

    await Promise.all(promises);

    // Return result with cursor if there are more results
    return {
      items: clients,
      cursor: response.list_complete ? undefined : response.cursor
    };
  }

  /**
   * Updates an existing OAuth client
   * @param clientId - The ID of the client to update
   * @param updates - Partial client information with fields to update
   * @returns A Promise resolving to the updated client info, or null if not found
   */
  async updateClient(clientId: string, updates: Partial<ClientInfo>): Promise<ClientInfo | null> {
    const client = await this.provider.getClient(this.env, clientId);
    if (!client) {
      return null;
    }

    // Handle secret updates - if a new secret is provided, hash it
    let secretToStore = client.clientSecret;
    let originalSecret: string | undefined = undefined;

    if (updates.clientSecret) {
      originalSecret = updates.clientSecret;
      secretToStore = await hashSecret(updates.clientSecret);
    }

    const updatedClient: ClientInfo = {
      ...client,
      ...updates,
      clientId: client.clientId, // Ensure clientId doesn't change
      clientSecret: secretToStore // Use hashed secret
    };

    await this.env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(updatedClient));

    // Return client with unhashed secret if a new one was provided
    if (originalSecret) {
      return {
        ...updatedClient,
        clientSecret: originalSecret
      };
    }

    return updatedClient;
  }

  /**
   * Deletes an OAuth client
   * @param clientId - The ID of the client to delete
   * @returns A Promise resolving when the deletion is confirmed.
   */
  async deleteClient(clientId: string): Promise<void> {
    // Delete client
    await this.env.OAUTH_KV.delete(`client:${clientId}`);
  }

  /**
   * Lists all authorization grants for a specific user with pagination support
   * @param userId - The ID of the user whose grants to list
   * @param options - Optional pagination parameters (limit and cursor)
   * @returns A Promise resolving to the list result with items and optional cursor
   */
  async listUserGrants(userId: string, options?: ListOptions): Promise<ListResult<Grant>> {
    // Prepare list options for KV
    const listOptions: { limit?: number; cursor?: string; prefix: string } = {
      prefix: `grant:${userId}:`
    };

    if (options?.limit !== undefined) {
      listOptions.limit = options.limit;
    }

    if (options?.cursor !== undefined) {
      listOptions.cursor = options.cursor;
    }

    // Use the KV list() function to get grant keys with pagination
    const response = await this.env.OAUTH_KV.list(listOptions);

    // Fetch all grants in parallel
    const grants: Grant[] = [];
    const promises = response.keys.map(async (key: { name: string }) => {
      const grantData = await this.env.OAUTH_KV.get(key.name, { type: 'json' });
      if (grantData) {
        grants.push(grantData);
      }
    });

    await Promise.all(promises);

    // Return result with cursor if there are more results
    return {
      items: grants,
      cursor: response.list_complete ? undefined : response.cursor
    };
  }

  /**
   * Revokes an authorization grant and all its associated access tokens
   * @param grantId - The ID of the grant to revoke
   * @param userId - The ID of the user who owns the grant
   * @returns A Promise resolving when the revocation is confirmed.
   */
  async revokeGrant(grantId: string, userId: string): Promise<void> {
    // Construct the full grant key with user ID
    const grantKey = `grant:${userId}:${grantId}`;

    // Delete all access tokens associated with this grant
    const tokenPrefix = `token:${userId}:${grantId}:`;

    // Handle pagination to ensure we delete all tokens even if there are more than 1000
    let cursor: string | undefined;
    let allTokensDeleted = false;

    // Continue fetching and deleting tokens until we've processed all of them
    while (!allTokensDeleted) {
      const listOptions: { prefix: string; cursor?: string } = {
        prefix: tokenPrefix
      };

      if (cursor) {
        listOptions.cursor = cursor;
      }

      const result = await this.env.OAUTH_KV.list(listOptions);

      // Delete each token in this batch
      if (result.keys.length > 0) {
        await Promise.all(result.keys.map((key: { name: string }) => {
          return this.env.OAUTH_KV.delete(key.name);
        }));
      }

      // Check if we need to fetch more tokens
      if (result.list_complete) {
        allTokensDeleted = true;
      } else {
        cursor = result.cursor;
      }
    }

    // After all tokens are deleted, delete the grant itself
    await this.env.OAUTH_KV.delete(grantKey);
  }
}

/**
 * Default export of the OAuth provider
 * This allows users to import the library and use it directly as in the example
 */
export default OAuthProvider;