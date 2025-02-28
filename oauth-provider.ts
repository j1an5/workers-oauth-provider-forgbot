// my-oauth.ts

// Types

export interface OAuthProviderOptions {
  apiRoute: string;
  apiHandler: ApiHandler;
  defaultHandler: DefaultHandler;
  authorizeEndpoint: string;
  tokenEndpoint: string;
  clientRegistrationEndpoint?: string;
  accessTokenTTL?: number;  // in seconds, default 1 hour
  refreshTokenTTL?: number; // in seconds, default 30 days
}

export interface ApiHandler {
  (request: Request, env: any, ctx: ExecutionContext, oauth: OAuthHelpers, props: any): Promise<Response>;
}

export interface DefaultHandler {
  (request: Request, env: any, ctx: ExecutionContext, oauth: OAuthHelpers): Promise<Response>;
}

export interface OAuthHelpers {
  parseAuthRequest(request: Request): AuthRequest;
  lookupClient(clientId: string): Promise<ClientInfo | null>;
  completeAuthorization(options: CompleteAuthorizationOptions): { redirectTo: string };
  createClient(clientInfo: Partial<ClientInfo>): Promise<ClientInfo>;
  listClients(): Promise<ClientInfo[]>;
  updateClient(clientId: string, updates: Partial<ClientInfo>): Promise<ClientInfo | null>;
  deleteClient(clientId: string): Promise<boolean>;
  listUserGrants(userId: string): Promise<Grant[]>;
  revokeGrant(grantId: string): Promise<boolean>;
}

export interface AuthRequest {
  responseType: string;
  clientId: string;
  redirectUri: string;
  scope: string[];
  state: string;
}

export interface ClientInfo {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  clientName?: string;
  logoUri?: string;
  clientUri?: string;
  policyUri?: string;
  tosUri?: string;
  jwksUri?: string;
  contacts?: string[];
  grantTypes?: string[];
  responseTypes?: string[];
  registrationDate?: number;
}

export interface CompleteAuthorizationOptions {
  request: AuthRequest;
  userId: string;
  metadata: any;
  scope: string[];
  props: any;
  expiresIn?: number; // in seconds
}

export interface Grant {
  id: string;
  clientId: string;
  userId: string;
  scope: string[];
  metadata: any;
  props: any;
  createdAt: number;
}

export interface Token {
  id: string;
  grantId: string;
  type: 'access' | 'refresh';
  createdAt: number;
  expiresAt: number;
}

// Constants
const DEFAULT_ACCESS_TOKEN_TTL = 60 * 60; // 1 hour
const DEFAULT_REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60; // 30 days
const TOKEN_LENGTH = 32;

// Helper Functions
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

function base64UrlEncode(str: string): string {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Main OAuthProvider Class
export class OAuthProvider {
  private options: OAuthProviderOptions;

  constructor(options: OAuthProviderOptions) {
    this.options = {
      ...options,
      accessTokenTTL: options.accessTokenTTL || DEFAULT_ACCESS_TOKEN_TTL,
      refreshTokenTTL: options.refreshTokenTTL || DEFAULT_REFRESH_TOKEN_TTL
    };
  }

  // Main fetch handler
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

  private isTokenEndpoint(url: URL): boolean {
    const tokenUrl = new URL(this.options.tokenEndpoint);
    return url.pathname === tokenUrl.pathname;
  }

  private isClientRegistrationEndpoint(url: URL): boolean {
    if (!this.options.clientRegistrationEndpoint) return false;
    const registrationUrl = new URL(this.options.clientRegistrationEndpoint);
    return url.pathname === registrationUrl.pathname;
  }

  private isApiRequest(url: URL): boolean {
    const apiUrl = new URL(this.options.apiRoute);
    return url.href.startsWith(apiUrl.href);
  }

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
    };

    return new Response(JSON.stringify(metadata), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  private async handleTokenRequest(request: Request, env: any): Promise<Response> {
    // Only accept POST requests
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({
        error: 'invalid_request',
        error_description: 'Method not allowed'
      }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' }
      });
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
      return new Response(JSON.stringify({
        error: 'invalid_client',
        error_description: 'Client authentication failed'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Verify client
    const clientInfo = await this.getClient(env, clientId);
    if (!clientInfo || clientInfo.clientSecret !== clientSecret) {
      return new Response(JSON.stringify({
        error: 'invalid_client',
        error_description: 'Client authentication failed'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Handle different grant types
    const grantType = body.grant_type;

    if (grantType === 'authorization_code') {
      return this.handleAuthorizationCodeGrant(body, clientInfo, env);
    } else if (grantType === 'refresh_token') {
      return this.handleRefreshTokenGrant(body, clientInfo, env);
    } else {
      return new Response(JSON.stringify({
        error: 'unsupported_grant_type',
        error_description: 'Grant type not supported'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  private async handleAuthorizationCodeGrant(
    body: any,
    clientInfo: ClientInfo,
    env: any
  ): Promise<Response> {
    const code = body.code;
    const redirectUri = body.redirect_uri;

    if (!code) {
      return new Response(JSON.stringify({
        error: 'invalid_request',
        error_description: 'Authorization code is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Verify redirect URI is in the allowed list
    if (redirectUri && !clientInfo.redirectUris.includes(redirectUri)) {
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: 'Invalid redirect URI'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Verify the code and get the grant
    try {
      const codeKey = `auth_code:${code}`;
      const grantId = await env.OAUTH_KV.get(codeKey);

      if (!grantId) {
        throw new Error('Invalid or expired code');
      }

      // Delete the code so it can't be used again
      await env.OAUTH_KV.delete(codeKey);

      // Get the grant
      const grantKey = `grant:${grantId}`;
      const grantData = await env.OAUTH_KV.get(grantKey, { type: 'json' });

      if (!grantData) {
        throw new Error('Grant not found');
      }

      // Verify client ID matches
      if (grantData.clientId !== clientInfo.clientId) {
        throw new Error('Client ID mismatch');
      }

      // Generate tokens
      const accessToken = generateRandomString(TOKEN_LENGTH);
      const refreshToken = generateRandomString(TOKEN_LENGTH);

      // Use WebCrypto to generate token IDs
      const accessTokenId = await generateTokenId(accessToken);
      const refreshTokenId = await generateTokenId(refreshToken);

      const now = Math.floor(Date.now() / 1000);
      const accessTokenExpiresAt = now + this.options.accessTokenTTL!;
      const refreshTokenExpiresAt = now + this.options.refreshTokenTTL!;

      // Store access token
      const accessTokenData: Token = {
        id: accessTokenId,
        grantId: grantId,
        type: 'access',
        createdAt: now,
        expiresAt: accessTokenExpiresAt
      };

      // Store refresh token
      const refreshTokenData: Token = {
        id: refreshTokenId,
        grantId: grantId,
        type: 'refresh',
        createdAt: now,
        expiresAt: refreshTokenExpiresAt
      };

      // Save tokens with TTL
      await env.OAUTH_KV.put(
        `token:${accessTokenId}`,
        JSON.stringify(accessTokenData),
        { expirationTtl: this.options.accessTokenTTL }
      );

      await env.OAUTH_KV.put(
        `token:${refreshTokenId}`,
        JSON.stringify(refreshTokenData),
        { expirationTtl: this.options.refreshTokenTTL }
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
    } catch (error) {
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: error instanceof Error ? error.message : 'Invalid authorization code'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  private async handleRefreshTokenGrant(
    body: any,
    clientInfo: ClientInfo,
    env: any
  ): Promise<Response> {
    const refreshToken = body.refresh_token;

    if (!refreshToken) {
      return new Response(JSON.stringify({
        error: 'invalid_request',
        error_description: 'Refresh token is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      // Get refresh token from storage
      const refreshTokenId = await generateTokenId(refreshToken);
      const tokenKey = `token:${refreshTokenId}`;
      const tokenData = await env.OAUTH_KV.get(tokenKey, { type: 'json' });

      if (!tokenData || tokenData.type !== 'refresh') {
        throw new Error('Invalid refresh token');
      }

      // Get the associated grant
      const grantKey = `grant:${tokenData.grantId}`;
      const grantData = await env.OAUTH_KV.get(grantKey, { type: 'json' });

      if (!grantData) {
        throw new Error('Grant not found');
      }

      // Verify client ID matches
      if (grantData.clientId !== clientInfo.clientId) {
        throw new Error('Client ID mismatch');
      }

      // Generate new access token
      const newAccessToken = generateRandomString(TOKEN_LENGTH);
      const accessTokenId = await generateTokenId(newAccessToken);

      const now = Math.floor(Date.now() / 1000);
      const accessTokenExpiresAt = now + this.options.accessTokenTTL!;

      // Store new access token
      const accessTokenData: Token = {
        id: accessTokenId,
        grantId: tokenData.grantId,
        type: 'access',
        createdAt: now,
        expiresAt: accessTokenExpiresAt
      };

      await env.OAUTH_KV.put(
        `token:${accessTokenId}`,
        JSON.stringify(accessTokenData),
        { expirationTtl: this.options.accessTokenTTL }
      );

      // Return the new access token
      return new Response(JSON.stringify({
        access_token: newAccessToken,
        token_type: 'bearer',
        expires_in: this.options.accessTokenTTL,
        scope: grantData.scope.join(' ')
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: error instanceof Error ? error.message : 'Invalid refresh token'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  private async handleClientRegistration(request: Request, env: any): Promise<Response> {
    if (!this.options.clientRegistrationEndpoint) {
      return new Response(JSON.stringify({
        error: 'not_implemented',
        error_description: 'Client registration is not enabled'
      }), {
        status: 501,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check method
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({
        error: 'invalid_request',
        error_description: 'Method not allowed'
      }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      // Parse client metadata
      const clientMetadata = await request.json();

      // Validate redirect URIs
      if (!clientMetadata.redirect_uris || !Array.isArray(clientMetadata.redirect_uris) || clientMetadata.redirect_uris.length === 0) {
        return new Response(JSON.stringify({
          error: 'invalid_redirect_uri',
          error_description: 'At least one redirect URI is required'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // Create client
      const clientId = generateRandomString(16);
      const clientSecret = generateRandomString(32);

      const clientInfo: ClientInfo = {
        clientId,
        clientSecret,
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

      // Also store in clients list
      await this.updateClientsList(env, clientId);

      // Return client information
      const response = {
        client_id: clientInfo.clientId,
        client_secret: clientInfo.clientSecret,
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
    } catch (error) {
      return new Response(JSON.stringify({
        error: 'invalid_request',
        error_description: 'Invalid client metadata'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  private async handleApiRequest(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
    // Get access token from Authorization header
    const authHeader = request.headers.get('Authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({
        error: 'invalid_token',
        error_description: 'Missing or invalid access token'
      }), {
        status: 401,
        headers: {
          'Content-Type': 'application/json',
          'WWW-Authenticate': 'Bearer realm="OAuth", error="invalid_token", error_description="Missing or invalid access token"'
        }
      });
    }

    const accessToken = authHeader.substring(7);

    try {
      // Verify token and get associated grant
      const accessTokenId = await generateTokenId(accessToken);
      const tokenKey = `token:${accessTokenId}`;
      const tokenData = await env.OAUTH_KV.get(tokenKey, { type: 'json' });

      if (!tokenData || tokenData.type !== 'access') {
        throw new Error('Invalid access token');
      }

      // Check if token is expired (should be auto-deleted by KV TTL, but double-check)
      const now = Math.floor(Date.now() / 1000);
      if (tokenData.expiresAt < now) {
        throw new Error('Access token expired');
      }

      // Get the associated grant
      const grantKey = `grant:${tokenData.grantId}`;
      const grantData = await env.OAUTH_KV.get(grantKey, { type: 'json' });

      if (!grantData) {
        throw new Error('Grant not found');
      }

      // Call the API handler with the grant props
      return this.options.apiHandler(
        request,
        env,
        ctx,
        this.createOAuthHelpers(env),
        grantData.props
      );
    } catch (error) {
      return new Response(JSON.stringify({
        error: 'invalid_token',
        error_description: error instanceof Error ? error.message : 'Invalid access token'
      }), {
        status: 401,
        headers: {
          'Content-Type': 'application/json',
          'WWW-Authenticate': 'Bearer realm="OAuth", error="invalid_token"'
        }
      });
    }
  }

  private async getClient(env: any, clientId: string): Promise<ClientInfo | null> {
    try {
      const clientKey = `client:${clientId}`;
      const clientData = await env.OAUTH_KV.get(clientKey, { type: 'json' });
      return clientData;
    } catch (error) {
      return null;
    }
  }

  private async updateClientsList(env: any, clientId: string): Promise<void> {
    try {
      const clientsListKey = 'clients_list';
      const clientsList = await env.OAUTH_KV.get(clientsListKey, { type: 'json' }) || [];

      if (!clientsList.includes(clientId)) {
        clientsList.push(clientId);
        await env.OAUTH_KV.put(clientsListKey, JSON.stringify(clientsList));
      }
    } catch (error) {
      // If this fails, it's not critical
      console.error('Failed to update clients list:', error);
    }
  }

  private createOAuthHelpers(env: any): OAuthHelpers {
    return {
      parseAuthRequest: (request: Request): AuthRequest => {
        const url = new URL(request.url);
        const responseType = url.searchParams.get('response_type') || '';
        const clientId = url.searchParams.get('client_id') || '';
        const redirectUri = url.searchParams.get('redirect_uri') || '';
        const scope = (url.searchParams.get('scope') || '').split(' ').filter(Boolean);
        const state = url.searchParams.get('state') || '';

        return {
          responseType,
          clientId,
          redirectUri,
          scope,
          state
        };
      },

      lookupClient: async (clientId: string): Promise<ClientInfo | null> => {
        return await this.getClient(env, clientId);
      },

      completeAuthorization: (options: CompleteAuthorizationOptions): { redirectTo: string } => {
        // Generate a random authorization code
        const code = generateRandomString(32);

        // Generate a unique grant ID
        const grantId = generateRandomString(16);

        // Store the grant
        const grant: Grant = {
          id: grantId,
          clientId: options.request.clientId,
          userId: options.userId,
          scope: options.scope,
          metadata: options.metadata,
          props: options.props,
          createdAt: Math.floor(Date.now() / 1000)
        };

        // Store the grant with long TTL (or no expiry)
        env.OAUTH_KV.put(`grant:${grantId}`, JSON.stringify(grant));

        // Also store in user's grants list
        this.updateUserGrantsList(env, options.userId, grantId);

        // Store the authorization code with short TTL (10 minutes)
        const codeExpiresIn = 600; // 10 minutes
        env.OAUTH_KV.put(`auth_code:${code}`, grantId, { expirationTtl: codeExpiresIn });

        // Build the redirect URL
        const redirectUrl = new URL(options.request.redirectUri);
        redirectUrl.searchParams.set('code', code);
        if (options.request.state) {
          redirectUrl.searchParams.set('state', options.request.state);
        }

        return { redirectTo: redirectUrl.toString() };
      },

      createClient: async (clientInfo: Partial<ClientInfo>): Promise<ClientInfo> => {
        const clientId = generateRandomString(16);
        const clientSecret = generateRandomString(32);

        const newClient: ClientInfo = {
          clientId,
          clientSecret,
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

        await env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(newClient));
        await this.updateClientsList(env, clientId);

        return newClient;
      },

      listClients: async (): Promise<ClientInfo[]> => {
        const clientsListKey = 'clients_list';
        const clientsList = await env.OAUTH_KV.get(clientsListKey, { type: 'json' }) || [];

        const clients: ClientInfo[] = [];
        for (const clientId of clientsList) {
          const client = await this.getClient(env, clientId);
          if (client) {
            clients.push(client);
          }
        }

        return clients;
      },

      updateClient: async (clientId: string, updates: Partial<ClientInfo>): Promise<ClientInfo | null> => {
        const client = await this.getClient(env, clientId);
        if (!client) {
          return null;
        }

        const updatedClient: ClientInfo = {
          ...client,
          ...updates,
          clientId: client.clientId, // Ensure clientId doesn't change
          clientSecret: updates.clientSecret || client.clientSecret
        };

        await env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(updatedClient));
        return updatedClient;
      },

      deleteClient: async (clientId: string): Promise<boolean> => {
        try {
          // Delete client
          await env.OAUTH_KV.delete(`client:${clientId}`);

          // Update clients list
          const clientsListKey = 'clients_list';
          const clientsList = await env.OAUTH_KV.get(clientsListKey, { type: 'json' }) || [];
          const updatedList = clientsList.filter((id: string) => id !== clientId);
          await env.OAUTH_KV.put(clientsListKey, JSON.stringify(updatedList));

          return true;
        } catch (error) {
          return false;
        }
      },

      listUserGrants: async (userId: string): Promise<Grant[]> => {
        const userGrantsKey = `user_grants:${userId}`;
        const grantIds = await env.OAUTH_KV.get(userGrantsKey, { type: 'json' }) || [];

        const grants: Grant[] = [];
        for (const grantId of grantIds) {
          const grantKey = `grant:${grantId}`;
          const grantData = await env.OAUTH_KV.get(grantKey, { type: 'json' });
          if (grantData) {
            grants.push(grantData);
          }
        }

        return grants;
      },

      revokeGrant: async (grantId: string): Promise<boolean> => {
        try {
          // Get grant to find user ID
          const grantKey = `grant:${grantId}`;
          const grantData = await env.OAUTH_KV.get(grantKey, { type: 'json' });

          if (!grantData) {
            return false;
          }

          // Delete grant
          await env.OAUTH_KV.delete(grantKey);

          // Update user's grants list
          const userId = grantData.userId;
          const userGrantsKey = `user_grants:${userId}`;
          const userGrants = await env.OAUTH_KV.get(userGrantsKey, { type: 'json' }) || [];
          const updatedGrants = userGrants.filter((id: string) => id !== grantId);
          await env.OAUTH_KV.put(userGrantsKey, JSON.stringify(updatedGrants));

          // Note: We don't need to delete tokens as they'll expire via TTL

          return true;
        } catch (error) {
          return false;
        }
      }
    };
  }

  private async updateUserGrantsList(env: any, userId: string, grantId: string): Promise<void> {
    try {
      const userGrantsKey = `user_grants:${userId}`;
      const userGrants = await env.OAUTH_KV.get(userGrantsKey, { type: 'json' }) || [];

      if (!userGrants.includes(grantId)) {
        userGrants.push(grantId);
        await env.OAUTH_KV.put(userGrantsKey, JSON.stringify(userGrants));
      }
    } catch (error) {
      // If this fails, it's not critical
      console.error('Failed to update user grants list:', error);
    }
  }
}

export default OAuthProvider;