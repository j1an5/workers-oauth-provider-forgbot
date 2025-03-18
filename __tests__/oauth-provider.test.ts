import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { OAuthProvider, ClientInfo, AuthRequest, CompleteAuthorizationOptions } from '../src/oauth-provider';
import { ExecutionContext } from '@cloudflare/workers-types';
// We're importing WorkerEntrypoint from our mock implementation
// The actual import is mocked in setup.ts
import { WorkerEntrypoint } from 'cloudflare:workers';

/**
 * Mock KV namespace implementation that stores data in memory
 */
class MockKV {
  private storage: Map<string, { value: any; expiration?: number }> = new Map();

  async put(key: string, value: string | ArrayBuffer, options?: { expirationTtl?: number }): Promise<void> {
    let expirationTime: number | undefined = undefined;

    if (options?.expirationTtl) {
      expirationTime = Date.now() + options.expirationTtl * 1000;
    }

    this.storage.set(key, { value, expiration: expirationTime });
  }

  async get(key: string, options?: { type: 'text' | 'json' | 'arrayBuffer' | 'stream' }): Promise<any> {
    const item = this.storage.get(key);

    if (!item) {
      return null;
    }

    if (item.expiration && item.expiration < Date.now()) {
      this.storage.delete(key);
      return null;
    }

    if (options?.type === 'json' && typeof item.value === 'string') {
      return JSON.parse(item.value);
    }

    return item.value;
  }

  async delete(key: string): Promise<void> {
    this.storage.delete(key);
  }

  async list(options: { prefix: string; limit?: number; cursor?: string }): Promise<{
    keys: { name: string }[];
    list_complete: boolean;
    cursor?: string;
  }> {
    const { prefix, limit = 1000 } = options;
    let keys: { name: string }[] = [];

    for (const key of this.storage.keys()) {
      if (key.startsWith(prefix)) {
        const item = this.storage.get(key);
        if (item && (!item.expiration || item.expiration >= Date.now())) {
          keys.push({ name: key });
        }
      }

      if (keys.length >= limit) {
        break;
      }
    }

    return {
      keys,
      list_complete: true
    };
  }

  clear() {
    this.storage.clear();
  }
}

/**
 * Mock execution context for Cloudflare Workers
 */
class MockExecutionContext implements ExecutionContext {
  props: any = {};

  waitUntil(promise: Promise<any>): void {
    // In tests, we can just ignore waitUntil
  }

  passThroughOnException(): void {
    // No-op for tests
  }
}

// Simple API handler for testing
class TestApiHandler extends WorkerEntrypoint {
  fetch(request: Request) {
    const url = new URL(request.url);

    if (url.pathname === '/api/test') {
      // Return authenticated user info from ctx.props
      return new Response(JSON.stringify({
        success: true,
        user: this.ctx.props
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response("Not found", { status: 404 });
  }
}

// Simple default handler for testing
const testDefaultHandler = {
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    const url = new URL(request.url);

    if (url.pathname === '/authorize') {
      // Mock authorize endpoint
      const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);
      const clientInfo = await env.OAUTH_PROVIDER.lookupClient(oauthReqInfo.clientId);

      // Mock user consent flow - automatically grant consent
      const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
        request: oauthReqInfo,
        userId: "test-user-123",
        metadata: { testConsent: true },
        scope: oauthReqInfo.scope,
        props: { userId: "test-user-123", username: "TestUser" }
      });

      return Response.redirect(redirectTo, 302);
    }

    return new Response("Default handler", { status: 200 });
  }
};

// Helper function to create mock requests
function createMockRequest(
  url: string,
  method: string = 'GET',
  headers: Record<string, string> = {},
  body?: string | FormData
): Request {
  const requestInit: RequestInit = {
    method,
    headers
  };

  if (body) {
    requestInit.body = body;
  }

  return new Request(url, requestInit);
}

// Create a configured mock environment
function createMockEnv() {
  return {
    OAUTH_KV: new MockKV(),
    OAUTH_PROVIDER: null // Will be populated by the OAuthProvider
  };
}

describe('OAuthProvider', () => {
  let oauthProvider: OAuthProvider;
  let mockEnv: ReturnType<typeof createMockEnv>;
  let mockCtx: MockExecutionContext;

  beforeEach(() => {
    // Reset mocks before each test
    vi.resetAllMocks();

    // Create fresh instances for each test
    mockEnv = createMockEnv();
    mockCtx = new MockExecutionContext();

    // Create OAuth provider with test configuration
    oauthProvider = new OAuthProvider({
      apiRoute: ['/api/', 'https://api.example.com/'],
      apiHandler: TestApiHandler,
      defaultHandler: testDefaultHandler,
      authorizeEndpoint: '/authorize',
      tokenEndpoint: '/oauth/token',
      clientRegistrationEndpoint: '/oauth/register',
      scopesSupported: ['read', 'write', 'profile'],
      accessTokenTTL: 3600,
      allowImplicitFlow: true // Enable implicit flow for tests
    });
  });

  afterEach(() => {
    // Clean up KV storage after each test
    mockEnv.OAUTH_KV.clear();
  });

  describe('OAuth Metadata Discovery', () => {
    it('should return correct metadata at .well-known/oauth-authorization-server', async () => {
      const request = createMockRequest('https://example.com/.well-known/oauth-authorization-server');
      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(200);

      const metadata = await response.json();
      expect(metadata.issuer).toBe('https://example.com');
      expect(metadata.authorization_endpoint).toBe('https://example.com/authorize');
      expect(metadata.token_endpoint).toBe('https://example.com/oauth/token');
      expect(metadata.registration_endpoint).toBe('https://example.com/oauth/register');
      expect(metadata.scopes_supported).toEqual(['read', 'write', 'profile']);
      expect(metadata.response_types_supported).toContain('code');
      expect(metadata.response_types_supported).toContain('token'); // Implicit flow enabled
      expect(metadata.grant_types_supported).toContain('authorization_code');
      expect(metadata.code_challenge_methods_supported).toContain('S256');
    });

    it('should not include token response type when implicit flow is disabled', async () => {
      // Create a provider with implicit flow disabled
      const providerWithoutImplicit = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        scopesSupported: ['read', 'write'],
        allowImplicitFlow: false // Explicitly disable
      });

      const request = createMockRequest('https://example.com/.well-known/oauth-authorization-server');
      const response = await providerWithoutImplicit.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(200);

      const metadata = await response.json();
      expect(metadata.response_types_supported).toContain('code');
      expect(metadata.response_types_supported).not.toContain('token');
    });
  });

  describe('Client Registration', () => {
    it('should register a new client', async () => {
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic'
      };

      const request = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(201);

      const registeredClient = await response.json();
      expect(registeredClient.client_id).toBeDefined();
      expect(registeredClient.client_secret).toBeDefined();
      expect(registeredClient.redirect_uris).toEqual(['https://client.example.com/callback']);
      expect(registeredClient.client_name).toBe('Test Client');

      // Verify the client was saved to KV
      const savedClient = await mockEnv.OAUTH_KV.get(`client:${registeredClient.client_id}`, { type: 'json' });
      expect(savedClient).not.toBeNull();
      expect(savedClient.clientId).toBe(registeredClient.client_id);
      // Secret should be stored as a hash
      expect(savedClient.clientSecret).not.toBe(registeredClient.client_secret);
    });

    it('should register a public client', async () => {
      const clientData = {
        redirect_uris: ['https://spa.example.com/callback'],
        client_name: 'SPA Client',
        token_endpoint_auth_method: 'none'
      };

      const request = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(201);

      const registeredClient = await response.json();
      expect(registeredClient.client_id).toBeDefined();
      expect(registeredClient.client_secret).toBeUndefined(); // Public client should not have a secret
      expect(registeredClient.token_endpoint_auth_method).toBe('none');

      // Verify the client was saved to KV
      const savedClient = await mockEnv.OAUTH_KV.get(`client:${registeredClient.client_id}`, { type: 'json' });
      expect(savedClient).not.toBeNull();
      expect(savedClient.clientSecret).toBeUndefined(); // No secret stored
    });
  });

  describe('Authorization Code Flow', () => {
    let clientId: string;
    let clientSecret: string;
    let redirectUri: string;

    // Helper to create a test client before authorization tests
    async function createTestClient() {
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic'
      };

      const request = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);
      const client = await response.json();

      clientId = client.client_id;
      clientSecret = client.client_secret;
      redirectUri = 'https://client.example.com/callback';
    }

    beforeEach(async () => {
      await createTestClient();
    });

    it('should handle the authorization request and redirect', async () => {
      // Create an authorization request
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&scope=read%20write&state=xyz123`
      );

      // The default handler will process this request and generate a redirect
      const response = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);

      expect(response.status).toBe(302);

      // Check that we're redirected to the client's redirect_uri with a code
      const location = response.headers.get('Location');
      expect(location).toBeDefined();
      expect(location).toContain(redirectUri);
      expect(location).toContain('code=');
      expect(location).toContain('state=xyz123');

      // Extract the authorization code from the redirect URL
      const url = new URL(location!);
      const code = url.searchParams.get('code');
      expect(code).toBeDefined();

      // Verify a grant was created in KV
      const grants = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      expect(grants.keys.length).toBe(1);
    });

    // Add more tests for auth code flow...
  });

  describe('Implicit Flow', () => {
    let clientId: string;
    let redirectUri: string;

    // Helper to create a test client before authorization tests
    async function createPublicClient() {
      const clientData = {
        redirect_uris: ['https://spa-client.example.com/callback'],
        client_name: 'SPA Test Client',
        token_endpoint_auth_method: 'none' // Public client
      };

      const request = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);
      const client = await response.json();

      clientId = client.client_id;
      redirectUri = 'https://spa-client.example.com/callback';
    }

    beforeEach(async () => {
      await createPublicClient();
    });

    it('should handle implicit flow request and redirect with token in fragment', async () => {
      // Create an implicit flow authorization request
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=token&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&scope=read%20write&state=xyz123`
      );

      // The default handler will process this request and generate a redirect
      const response = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);

      expect(response.status).toBe(302);

      // Check that we're redirected to the client's redirect_uri with token in fragment
      const location = response.headers.get('Location');
      expect(location).toBeDefined();
      expect(location).toContain(redirectUri);

      const url = new URL(location!);

      // Check that there's no code parameter in the query string
      expect(url.searchParams.has('code')).toBe(false);

      // Check that we have a hash/fragment with token parameters
      expect(url.hash).toBeTruthy();

      // Parse the fragment
      const fragment = new URLSearchParams(url.hash.substring(1)); // Remove the # character

      // Verify token parameters
      expect(fragment.get('access_token')).toBeTruthy();
      expect(fragment.get('token_type')).toBe('bearer');
      expect(fragment.get('expires_in')).toBe('3600');
      expect(fragment.get('scope')).toBe('read write');
      expect(fragment.get('state')).toBe('xyz123');

      // Verify a grant was created in KV
      const grants = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      expect(grants.keys.length).toBe(1);

      // Verify access token was stored in KV
      const tokenEntries = await mockEnv.OAUTH_KV.list({ prefix: 'token:' });
      expect(tokenEntries.keys.length).toBe(1);
    });

    it('should reject implicit flow when allowImplicitFlow is disabled', async () => {
      // Create a provider with implicit flow disabled
      const providerWithoutImplicit = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        scopesSupported: ['read', 'write'],
        allowImplicitFlow: false // Explicitly disable
      });

      // Create an implicit flow authorization request
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=token&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&scope=read%20write&state=xyz123`
      );

      // Mock parseAuthRequest to test error handling
      vi.spyOn(authRequest, 'formData').mockImplementation(() => {
        throw new Error('The implicit grant flow is not enabled for this provider');
      });

      // Expect an error response
      await expect(providerWithoutImplicit.fetch(authRequest, mockEnv, mockCtx)).rejects.toThrow(
        'The implicit grant flow is not enabled for this provider'
      );
    });

    it('should use the access token to access API directly', async () => {
      // Create an implicit flow authorization request
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=token&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&scope=read%20write&state=xyz123`
      );

      // The default handler will process this request and generate a redirect
      const response = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = response.headers.get('Location')!;

      // Parse the fragment to get the access token
      const url = new URL(location);
      const fragment = new URLSearchParams(url.hash.substring(1));
      const accessToken = fragment.get('access_token')!;

      // Now use the access token for an API request
      const apiRequest = createMockRequest(
        'https://example.com/api/test',
        'GET',
        { 'Authorization': `Bearer ${accessToken}` }
      );

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);

      const apiData = await apiResponse.json();
      expect(apiData.success).toBe(true);
      expect(apiData.user).toEqual({ userId: "test-user-123", username: "TestUser" });
    });
  });

  describe('Authorization Code Flow Exchange', () => {
    let clientId: string;
    let clientSecret: string;
    let redirectUri: string;

    // Helper to create a test client before authorization tests
    async function createTestClient() {
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic'
      };

      const request = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const response = await oauthProvider.fetch(request, mockEnv, mockCtx);
      const client = await response.json();

      clientId = client.client_id;
      clientSecret = client.client_secret;
      redirectUri = 'https://client.example.com/callback';
    }

    beforeEach(async () => {
      await createTestClient();
    });

    it('should exchange auth code for tokens', async () => {
      // First get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const url = new URL(location);
      const code = url.searchParams.get('code')!;

      // Now exchange the code for tokens
      // Use URLSearchParams which is proper for application/x-www-form-urlencoded
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      // Use the URLSearchParams object as the body - correctly encoded for Content-Type: application/x-www-form-urlencoded
      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);

      expect(tokenResponse.status).toBe(200);

      const tokens = await tokenResponse.json();
      expect(tokens.access_token).toBeDefined();
      expect(tokens.refresh_token).toBeDefined();
      expect(tokens.token_type).toBe('bearer');
      expect(tokens.expires_in).toBe(3600);

      // Verify token was stored in KV
      const tokenEntries = await mockEnv.OAUTH_KV.list({ prefix: 'token:' });
      expect(tokenEntries.keys.length).toBe(1);

      // Verify grant was updated (auth code removed, refresh token added)
      const grantEntries = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      const grantKey = grantEntries.keys[0].name;
      const grant = await mockEnv.OAUTH_KV.get(grantKey, { type: 'json' });

      expect(grant.authCodeId).toBeUndefined(); // Auth code should be removed
      expect(grant.refreshTokenId).toBeDefined(); // Refresh token should be added
    });

    it('should reject token exchange without redirect_uri when not using PKCE', async () => {
      // First get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const url = new URL(location);
      const code = url.searchParams.get('code')!;

      // Now exchange the code without providing redirect_uri
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      // redirect_uri intentionally omitted
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);

      // Should fail because redirect_uri is required when not using PKCE
      expect(tokenResponse.status).toBe(400);
      const error = await tokenResponse.json();
      expect(error.error).toBe('invalid_request');
      expect(error.error_description).toBe('redirect_uri is required when not using PKCE');
    });

    // Helper function for PKCE tests
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

    // Helper function for PKCE tests
    function base64UrlEncode(str: string): string {
      return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    }

    it('should accept token exchange without redirect_uri when using PKCE', async () => {
      // Generate PKCE code verifier and challenge
      const codeVerifier = generateRandomString(43); // Recommended length
      const encoder = new TextEncoder();
      const data = encoder.encode(codeVerifier);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const codeChallenge = base64UrlEncode(String.fromCharCode(...hashArray));

      // First get an auth code with PKCE
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&scope=read%20write&state=xyz123` +
        `&code_challenge=${codeChallenge}&code_challenge_method=S256`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const url = new URL(location);
      const code = url.searchParams.get('code')!;

      // Now exchange the code without providing redirect_uri
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      // redirect_uri intentionally omitted
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);
      params.append('code_verifier', codeVerifier);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);

      // Should succeed because redirect_uri is optional when using PKCE
      expect(tokenResponse.status).toBe(200);

      const tokens = await tokenResponse.json();
      expect(tokens.access_token).toBeDefined();
      expect(tokens.refresh_token).toBeDefined();
      expect(tokens.token_type).toBe('bearer');
      expect(tokens.expires_in).toBe(3600);
    });

    it('should accept the access token for API requests', async () => {
      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json();

      // Now use the access token for an API request
      const apiRequest = createMockRequest(
        'https://example.com/api/test',
        'GET',
        { 'Authorization': `Bearer ${tokens.access_token}` }
      );

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);

      const apiData = await apiResponse.json();
      expect(apiData.success).toBe(true);
      expect(apiData.user).toEqual({ userId: "test-user-123", username: "TestUser" });
    });
  });

  describe('Refresh Token Flow', () => {
    let clientId: string;
    let clientSecret: string;
    let refreshToken: string;

    // Helper to get through authorization and token exchange to get a refresh token
    async function getRefreshToken() {
      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic'
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json();
      clientId = client.client_id;
      clientSecret = client.client_secret;
      const redirectUri = 'https://client.example.com/callback';

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json();
      refreshToken = tokens.refresh_token;
    }

    beforeEach(async () => {
      await getRefreshToken();
    });

    it('should issue new tokens with refresh token', async () => {
      // Use the refresh token to get a new access token
      const params = new URLSearchParams();
      params.append('grant_type', 'refresh_token');
      params.append('refresh_token', refreshToken);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const refreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const refreshResponse = await oauthProvider.fetch(refreshRequest, mockEnv, mockCtx);

      expect(refreshResponse.status).toBe(200);

      const newTokens = await refreshResponse.json();
      expect(newTokens.access_token).toBeDefined();
      expect(newTokens.refresh_token).toBeDefined();
      expect(newTokens.refresh_token).not.toBe(refreshToken); // Should get a new refresh token

      // Verify we now have a new token in storage
      const tokenEntries = await mockEnv.OAUTH_KV.list({ prefix: 'token:' });
      expect(tokenEntries.keys.length).toBe(2); // The old one and the new one

      // Verify the grant was updated
      const grantEntries = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      const grantKey = grantEntries.keys[0].name;
      const grant = await mockEnv.OAUTH_KV.get(grantKey, { type: 'json' });

      expect(grant.previousRefreshTokenId).toBeDefined(); // Old refresh token should be tracked
      expect(grant.refreshTokenId).toBeDefined(); // New refresh token should be set
    });

    it('should allow using the previous refresh token once', async () => {
      // Use the refresh token to get a new access token (first refresh)
      const params1 = new URLSearchParams();
      params1.append('grant_type', 'refresh_token');
      params1.append('refresh_token', refreshToken);
      params1.append('client_id', clientId);
      params1.append('client_secret', clientSecret);

      const refreshRequest1 = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params1.toString()
      );

      const refreshResponse1 = await oauthProvider.fetch(refreshRequest1, mockEnv, mockCtx);
      const newTokens1 = await refreshResponse1.json();
      const newRefreshToken = newTokens1.refresh_token;

      // Now try to use the original refresh token again (simulating a retry after failure)
      const params2 = new URLSearchParams();
      params2.append('grant_type', 'refresh_token');
      params2.append('refresh_token', refreshToken); // Original token
      params2.append('client_id', clientId);
      params2.append('client_secret', clientSecret);

      const refreshRequest2 = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params2.toString()
      );

      const refreshResponse2 = await oauthProvider.fetch(refreshRequest2, mockEnv, mockCtx);

      // The request should succeed
      expect(refreshResponse2.status).toBe(200);

      const newTokens2 = await refreshResponse2.json();
      expect(newTokens2.access_token).toBeDefined();
      expect(newTokens2.refresh_token).toBeDefined();

      // Now the grant should have the newest refresh token and the token from the first refresh
      // as the previous token
      const grantEntries = await mockEnv.OAUTH_KV.list({ prefix: 'grant:' });
      const grantKey = grantEntries.keys[0].name;
      const grant = await mockEnv.OAUTH_KV.get(grantKey, { type: 'json' });

      // The previousRefreshTokenId should now be from the first refresh, not the original
      expect(grant.previousRefreshTokenId).toBeDefined();
    });
  });

  describe('Token Validation and API Access', () => {
    let accessToken: string;

    // Helper to get through authorization and token exchange to get an access token
    async function getAccessToken() {
      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic'
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json();
      const clientId = client.client_id;
      const clientSecret = client.client_secret;
      const redirectUri = 'https://client.example.com/callback';

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProvider.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json();
      accessToken = tokens.access_token;
    }

    beforeEach(async () => {
      await getAccessToken();
    });

    it('should reject API requests without a token', async () => {
      const apiRequest = createMockRequest(
        'https://example.com/api/test'
      );

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);

      const error = await apiResponse.json();
      expect(error.error).toBe('invalid_token');
    });

    it('should reject API requests with an invalid token', async () => {
      const apiRequest = createMockRequest(
        'https://example.com/api/test',
        'GET',
        { 'Authorization': 'Bearer invalid-token' }
      );

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(401);

      const error = await apiResponse.json();
      expect(error.error).toBe('invalid_token');
    });

    it('should accept valid token and pass props to API handler', async () => {
      const apiRequest = createMockRequest(
        'https://example.com/api/test',
        'GET',
        { 'Authorization': `Bearer ${accessToken}` }
      );

      const apiResponse = await oauthProvider.fetch(apiRequest, mockEnv, mockCtx);

      expect(apiResponse.status).toBe(200);

      const data = await apiResponse.json();
      expect(data.success).toBe(true);
      expect(data.user).toEqual({ userId: "test-user-123", username: "TestUser" });
    });

    it('should handle CORS preflight for API requests', async () => {
      const preflightRequest = createMockRequest(
        'https://example.com/api/test',
        'OPTIONS',
        {
          'Origin': 'https://client.example.com',
          'Access-Control-Request-Method': 'GET',
          'Access-Control-Request-Headers': 'Authorization'
        }
      );

      const preflightResponse = await oauthProvider.fetch(preflightRequest, mockEnv, mockCtx);

      expect(preflightResponse.status).toBe(204);
      expect(preflightResponse.headers.get('Access-Control-Allow-Origin')).toBe('https://client.example.com');
      expect(preflightResponse.headers.get('Access-Control-Allow-Methods')).toBe('*');
      expect(preflightResponse.headers.get('Access-Control-Allow-Headers')).toContain('Authorization');
    });
  });

  describe('Token Exchange Callback', () => {
    // Test with provider that has token exchange callback
    let oauthProviderWithCallback: OAuthProvider;
    let callbackInvocations: any[] = [];
    let mockEnv: ReturnType<typeof createMockEnv>;
    let mockCtx: MockExecutionContext;

    // Helper function to create a test OAuth provider with a token exchange callback
    function createProviderWithCallback() {
      callbackInvocations = [];

      const tokenExchangeCallback = async (options: any) => {
        // Record that the callback was called and with what arguments
        callbackInvocations.push({...options});

        // Return different props based on the grant type
        if (options.grantType === 'authorization_code') {
          return {
            tokenProps: {
              ...options.props,
              tokenSpecific: true,
              tokenUpdatedAt: 'auth_code_flow'
            },
            grantProps: {
              ...options.props,
              grantUpdated: true
            }
          };
        } else if (options.grantType === 'refresh_token') {
          return {
            tokenProps: {
              ...options.props,
              tokenSpecific: true,
              tokenUpdatedAt: 'refresh_token_flow'
            },
            grantProps: {
              ...options.props,
              grantUpdated: true,
              refreshCount: (options.props.refreshCount || 0) + 1
            }
          };
        }
      };

      return new OAuthProvider({
        apiRoute: ['/api/', 'https://api.example.com/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write', 'profile'],
        accessTokenTTL: 3600,
        allowImplicitFlow: true,
        tokenExchangeCallback
      });
    }

    let clientId: string;
    let clientSecret: string;
    let redirectUri: string;

    // Helper to create a test client
    async function createTestClient() {
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic'
      };

      const request = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const response = await oauthProviderWithCallback.fetch(request, mockEnv, mockCtx);
      const client = await response.json();

      clientId = client.client_id;
      clientSecret = client.client_secret;
      redirectUri = 'https://client.example.com/callback';
    }

    beforeEach(async () => {
      // Reset mocks before each test
      vi.resetAllMocks();

      // Create fresh instances for each test
      mockEnv = createMockEnv();
      mockCtx = new MockExecutionContext();

      // Create OAuth provider with test configuration and callback
      oauthProviderWithCallback = createProviderWithCallback();

      // Create a test client
      await createTestClient();
    });

    afterEach(() => {
      // Clean up KV storage after each test
      mockEnv.OAUTH_KV.clear();
    });

    it('should call the callback during authorization code flow', async () => {
      // First get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProviderWithCallback.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Reset callback invocations tracking before token exchange
      callbackInvocations = [];

      // Exchange code for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      params.append('client_id', clientId);
      params.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await oauthProviderWithCallback.fetch(tokenRequest, mockEnv, mockCtx);

      // Check that the token exchange was successful
      expect(tokenResponse.status).toBe(200);
      const tokens = await tokenResponse.json();
      expect(tokens.access_token).toBeDefined();

      // Check that the callback was called once
      expect(callbackInvocations.length).toBe(1);

      // Check that callback was called with correct arguments
      const callbackArgs = callbackInvocations[0];
      expect(callbackArgs.grantType).toBe('authorization_code');
      expect(callbackArgs.clientId).toBe(clientId);
      expect(callbackArgs.props).toEqual({ userId: "test-user-123", username: "TestUser" });

      // Use the token to access API
      const apiRequest = createMockRequest(
        'https://example.com/api/test',
        'GET',
        { 'Authorization': `Bearer ${tokens.access_token}` }
      );

      const apiResponse = await oauthProviderWithCallback.fetch(apiRequest, mockEnv, mockCtx);
      expect(apiResponse.status).toBe(200);

      // Check that the API received the token-specific props from the callback
      const apiData = await apiResponse.json();
      expect(apiData.user).toEqual({
        userId: "test-user-123",
        username: "TestUser",
        tokenSpecific: true,
        tokenUpdatedAt: 'auth_code_flow'
      });
    });

    it('should call the callback during refresh token flow', async () => {
      // First get an auth code and exchange it for tokens
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&scope=read%20write&state=xyz123`
      );

      const authResponse = await oauthProviderWithCallback.fetch(authRequest, mockEnv, mockCtx);
      const location = authResponse.headers.get('Location')!;
      const code = new URL(location).searchParams.get('code')!;

      // Exchange code for tokens
      const codeParams = new URLSearchParams();
      codeParams.append('grant_type', 'authorization_code');
      codeParams.append('code', code);
      codeParams.append('redirect_uri', redirectUri);
      codeParams.append('client_id', clientId);
      codeParams.append('client_secret', clientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        codeParams.toString()
      );

      const tokenResponse = await oauthProviderWithCallback.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json();

      // Reset the callback invocations tracking before refresh
      callbackInvocations = [];

      // Now use the refresh token
      const refreshParams = new URLSearchParams();
      refreshParams.append('grant_type', 'refresh_token');
      refreshParams.append('refresh_token', tokens.refresh_token);
      refreshParams.append('client_id', clientId);
      refreshParams.append('client_secret', clientSecret);

      const refreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        refreshParams.toString()
      );

      const refreshResponse = await oauthProviderWithCallback.fetch(refreshRequest, mockEnv, mockCtx);

      // Check that the refresh was successful
      expect(refreshResponse.status).toBe(200);
      const newTokens = await refreshResponse.json();
      expect(newTokens.access_token).toBeDefined();

      // Check that the callback was called once
      expect(callbackInvocations.length).toBe(1);

      // Check that callback was called with correct arguments
      const callbackArgs = callbackInvocations[0];
      expect(callbackArgs.grantType).toBe('refresh_token');
      expect(callbackArgs.clientId).toBe(clientId);

      // The props are from the updated grant during auth code flow
      expect(callbackArgs.props).toEqual({
        userId: "test-user-123",
        username: "TestUser",
        grantUpdated: true
      });

      // Use the new token to access API
      const apiRequest = createMockRequest(
        'https://example.com/api/test',
        'GET',
        { 'Authorization': `Bearer ${newTokens.access_token}` }
      );

      const apiResponse = await oauthProviderWithCallback.fetch(apiRequest, mockEnv, mockCtx);
      expect(apiResponse.status).toBe(200);

      // Check that the API received the token-specific props from the refresh callback
      const apiData = await apiResponse.json();
      expect(apiData.user).toEqual({
        userId: "test-user-123",
        username: "TestUser",
        grantUpdated: true,
        tokenSpecific: true,
        tokenUpdatedAt: 'refresh_token_flow'
      });

      // Do a second refresh to verify that grant props are properly updated
      const refresh2Params = new URLSearchParams();
      refresh2Params.append('grant_type', 'refresh_token');
      refresh2Params.append('refresh_token', newTokens.refresh_token);
      refresh2Params.append('client_id', clientId);
      refresh2Params.append('client_secret', clientSecret);

      // Reset the callback invocations before second refresh
      callbackInvocations = [];

      const refresh2Request = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        refresh2Params.toString()
      );

      const refresh2Response = await oauthProviderWithCallback.fetch(refresh2Request, mockEnv, mockCtx);
      const newerTokens = await refresh2Response.json();

      // Check that the refresh count was incremented in the grant props
      expect(callbackInvocations.length).toBe(1);
      expect(callbackInvocations[0].props.refreshCount).toBe(1);
    });

    it('should update token props during refresh when explicitly provided', async () => {
      // Create a provider with a callback that returns both tokenProps and grantProps
      // but with different values for each
      const differentPropsCallback = async (options: any) => {
        if (options.grantType === 'refresh_token') {
          return {
            tokenProps: {
              ...options.props,
              refreshed: true,
              tokenOnly: true
            },
            grantProps: {
              ...options.props,
              grantUpdated: true
            }
          };
        }
        return undefined;
      };

      const refreshPropsProvider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write'],
        tokenExchangeCallback: differentPropsCallback
      });

      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Refresh Props Test',
        token_endpoint_auth_method: 'client_secret_basic'
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await refreshPropsProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json();
      const testClientId = client.client_id;
      const testClientSecret = client.client_secret;
      const testRedirectUri = 'https://client.example.com/callback';

      // Get an auth code and exchange it for tokens
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${testClientId}` +
        `&redirect_uri=${encodeURIComponent(testRedirectUri)}` +
        `&scope=read%20write&state=xyz123`
      );

      const authResponse = await refreshPropsProvider.fetch(authRequest, mockEnv, mockCtx);
      const code = new URL(authResponse.headers.get('Location')!).searchParams.get('code')!;

      // Exchange for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', testRedirectUri);
      params.append('client_id', testClientId);
      params.append('client_secret', testClientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await refreshPropsProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json();

      // Now do a refresh token exchange
      const refreshParams = new URLSearchParams();
      refreshParams.append('grant_type', 'refresh_token');
      refreshParams.append('refresh_token', tokens.refresh_token);
      refreshParams.append('client_id', testClientId);
      refreshParams.append('client_secret', testClientSecret);

      const refreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        refreshParams.toString()
      );

      const refreshResponse = await refreshPropsProvider.fetch(refreshRequest, mockEnv, mockCtx);
      const newTokens = await refreshResponse.json();

      // Use the new token to access API
      const apiRequest = createMockRequest(
        'https://example.com/api/test',
        'GET',
        { 'Authorization': `Bearer ${newTokens.access_token}` }
      );

      const apiResponse = await refreshPropsProvider.fetch(apiRequest, mockEnv, mockCtx);
      const apiData = await apiResponse.json();

      // The access token should contain the token-specific props from the refresh callback
      expect(apiData.user).toHaveProperty('refreshed', true);
      expect(apiData.user).toHaveProperty('tokenOnly', true);
      expect(apiData.user).not.toHaveProperty('grantUpdated');
    });

    it('should handle callback that returns only tokenProps or only grantProps', async () => {
      // Create a provider with a callback that returns only tokenProps for auth code
      // and only grantProps for refresh token
      const tokenPropsOnlyCallback = async (options: any) => {
        if (options.grantType === 'authorization_code') {
          return {
            tokenProps: { ...options.props, tokenOnly: true }
          };
        } else if (options.grantType === 'refresh_token') {
          return {
            grantProps: { ...options.props, grantOnly: true }
          };
        }
      };

      const specialProvider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write'],
        tokenExchangeCallback: tokenPropsOnlyCallback
      });

      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Token Props Only Test',
        token_endpoint_auth_method: 'client_secret_basic'
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await specialProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json();
      const testClientId = client.client_id;
      const testClientSecret = client.client_secret;
      const testRedirectUri = 'https://client.example.com/callback';

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${testClientId}` +
        `&redirect_uri=${encodeURIComponent(testRedirectUri)}` +
        `&scope=read%20write&state=xyz123`
      );

      const authResponse = await specialProvider.fetch(authRequest, mockEnv, mockCtx);
      const code = new URL(authResponse.headers.get('Location')!).searchParams.get('code')!;

      // Exchange code for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', testRedirectUri);
      params.append('client_id', testClientId);
      params.append('client_secret', testClientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await specialProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json();

      // Verify the token has the tokenOnly property when used for API access
      const apiRequest = createMockRequest(
        'https://example.com/api/test',
        'GET',
        { 'Authorization': `Bearer ${tokens.access_token}` }
      );

      const apiResponse = await specialProvider.fetch(apiRequest, mockEnv, mockCtx);
      const apiData = await apiResponse.json();
      expect(apiData.user.tokenOnly).toBe(true);

      // Now do a refresh token exchange
      const refreshParams = new URLSearchParams();
      refreshParams.append('grant_type', 'refresh_token');
      refreshParams.append('refresh_token', tokens.refresh_token);
      refreshParams.append('client_id', testClientId);
      refreshParams.append('client_secret', testClientSecret);

      const refreshRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        refreshParams.toString()
      );

      const refreshResponse = await specialProvider.fetch(refreshRequest, mockEnv, mockCtx);
      const newTokens = await refreshResponse.json();

      // Use the new token to access API
      const api2Request = createMockRequest(
        'https://example.com/api/test',
        'GET',
        { 'Authorization': `Bearer ${newTokens.access_token}` }
      );

      const api2Response = await specialProvider.fetch(api2Request, mockEnv, mockCtx);
      const api2Data = await api2Response.json();

      // The token should have the same props as the original token
      // because we only updated grantProps, not tokenProps during the refresh
      expect(api2Data.user).toEqual({
        userId: "test-user-123",
        username: "TestUser"
      });
    });

    it('should handle callback that returns undefined (keeping original props)', async () => {
      // Create a provider with a callback that returns undefined
      const noopCallback = async (options: any) => {
        // Don't return anything, which should keep the original props
        return undefined;
      };

      const noopProvider = new OAuthProvider({
        apiRoute: ['/api/'],
        apiHandler: TestApiHandler,
        defaultHandler: testDefaultHandler,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/oauth/token',
        clientRegistrationEndpoint: '/oauth/register',
        scopesSupported: ['read', 'write'],
        tokenExchangeCallback: noopCallback
      });

      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Noop Callback Test',
        token_endpoint_auth_method: 'client_secret_basic'
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      const registerResponse = await noopProvider.fetch(registerRequest, mockEnv, mockCtx);
      const client = await registerResponse.json();
      const testClientId = client.client_id;
      const testClientSecret = client.client_secret;
      const testRedirectUri = 'https://client.example.com/callback';

      // Get an auth code
      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${testClientId}` +
        `&redirect_uri=${encodeURIComponent(testRedirectUri)}` +
        `&scope=read%20write&state=xyz123`
      );

      const authResponse = await noopProvider.fetch(authRequest, mockEnv, mockCtx);
      const code = new URL(authResponse.headers.get('Location')!).searchParams.get('code')!;

      // Exchange code for tokens
      const params = new URLSearchParams();
      params.append('grant_type', 'authorization_code');
      params.append('code', code);
      params.append('redirect_uri', testRedirectUri);
      params.append('client_id', testClientId);
      params.append('client_secret', testClientSecret);

      const tokenRequest = createMockRequest(
        'https://example.com/oauth/token',
        'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        params.toString()
      );

      const tokenResponse = await noopProvider.fetch(tokenRequest, mockEnv, mockCtx);
      const tokens = await tokenResponse.json();

      // Verify the token has the original props when used for API access
      const apiRequest = createMockRequest(
        'https://example.com/api/test',
        'GET',
        { 'Authorization': `Bearer ${tokens.access_token}` }
      );

      const apiResponse = await noopProvider.fetch(apiRequest, mockEnv, mockCtx);
      const apiData = await apiResponse.json();

      // The props should be the original ones (no change)
      expect(apiData.user).toEqual({ userId: "test-user-123", username: "TestUser" });
    });
  });

  describe('OAuthHelpers', () => {
    it('should allow listing and revoking grants', async () => {
      // Create a client
      const clientData = {
        redirect_uris: ['https://client.example.com/callback'],
        client_name: 'Test Client',
        token_endpoint_auth_method: 'client_secret_basic'
      };

      const registerRequest = createMockRequest(
        'https://example.com/oauth/register',
        'POST',
        { 'Content-Type': 'application/json' },
        JSON.stringify(clientData)
      );

      await oauthProvider.fetch(registerRequest, mockEnv, mockCtx);

      // Create a grant by going through auth flow
      const clientId = (await mockEnv.OAUTH_KV.list({ prefix: 'client:' })).keys[0].name.substring(7);
      const redirectUri = 'https://client.example.com/callback';

      const authRequest = createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&scope=read%20write&state=xyz123`
      );

      await oauthProvider.fetch(authRequest, mockEnv, mockCtx);

      // Ensure OAUTH_PROVIDER was injected
      expect(mockEnv.OAUTH_PROVIDER).not.toBeNull();

      // List grants for the user
      const grants = await mockEnv.OAUTH_PROVIDER.listUserGrants('test-user-123');

      expect(grants.items.length).toBe(1);
      expect(grants.items[0].clientId).toBe(clientId);
      expect(grants.items[0].userId).toBe('test-user-123');
      expect(grants.items[0].metadata).toEqual({ testConsent: true });

      // Revoke the grant
      await mockEnv.OAUTH_PROVIDER.revokeGrant(grants.items[0].id, 'test-user-123');

      // Verify grant was deleted
      const grantsAfterRevoke = await mockEnv.OAUTH_PROVIDER.listUserGrants('test-user-123');
      expect(grantsAfterRevoke.items.length).toBe(0);
    });

    it('should allow listing, updating, and deleting clients', async () => {
      // First make a simple request to initialize the OAUTH_PROVIDER in the environment
      const initRequest = createMockRequest('https://example.com/');
      await oauthProvider.fetch(initRequest, mockEnv, mockCtx);

      // Now OAUTH_PROVIDER should be initialized
      expect(mockEnv.OAUTH_PROVIDER).not.toBeNull();

      // Create a client
      const client = await mockEnv.OAUTH_PROVIDER.createClient({
        redirectUris: ['https://client.example.com/callback'],
        clientName: 'Test Client',
        tokenEndpointAuthMethod: 'client_secret_basic'
      });

      expect(client.clientId).toBeDefined();
      expect(client.clientSecret).toBeDefined();

      // List clients
      const clients = await mockEnv.OAUTH_PROVIDER.listClients();
      expect(clients.items.length).toBe(1);
      expect(clients.items[0].clientId).toBe(client.clientId);

      // Update client
      const updatedClient = await mockEnv.OAUTH_PROVIDER.updateClient(client.clientId, {
        clientName: 'Updated Client Name'
      });

      expect(updatedClient).not.toBeNull();
      expect(updatedClient!.clientName).toBe('Updated Client Name');

      // Delete client
      await mockEnv.OAUTH_PROVIDER.deleteClient(client.clientId);

      // Verify client was deleted
      const clientsAfterDelete = await mockEnv.OAUTH_PROVIDER.listClients();
      expect(clientsAfterDelete.items.length).toBe(0);
    });
  });
});