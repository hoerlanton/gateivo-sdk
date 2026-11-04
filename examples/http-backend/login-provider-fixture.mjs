import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

/**
 * Finite, signed, synthetic provider responses for the local login exercise.
 * Only transport is substituted: the real SDK still exchanges PKCE codes,
 * verifies JWT signatures/claims, and persists the resulting consent itself.
 * This never calls WorkOS or implements a provider service.
 */
export async function createLoginProviderFixture({ config, apiKey }) {
  const resource = `${config.publicUrl}/agent/mcp`;
  const callback = `${config.publicUrl}/account/assistant/callback`;
  const key = await generateKeyPair('RS256', { extractable: true });
  const publicJwk = { ...await exportJWK(key.publicKey), kid: 'local-login-fixture', alg: 'RS256', use: 'sig' };
  const codes = new Map();
  const authorized = new Set();
  const issued = [];
  const counts = { jwks: 0, exchanges: 0, reads: 0, resets: 0 };
  const subjects = new Set(config.accounts.map(account => account.providerSubject));
  const sign = async (payload, header = {}) => new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', kid: publicJwk.kid, typ: 'JWT', ...header }).sign(key.privateKey);

  return Object.freeze({
    counts, issued,
    async approve(location, providerSubject) {
      assert.ok(subjects.has(providerSubject), 'Use only a preprovisioned fictional provider account.');
      assert.ok(issued.length < 16, 'Fixture approval limit reached.');
      const url = new URL(location);
      assert.ok(url.origin === config.issuer && url.pathname === '/oauth2/authorize');
      assert.ok(url.searchParams.get('client_id') === config.clientId);
      assert.ok(url.searchParams.get('resource') === resource);
      assert.ok(url.searchParams.get('redirect_uri') === callback);
      assert.ok(url.searchParams.get('code_challenge_method') === 'S256');
      assert.ok(/^[A-Za-z0-9_-]{43}$/.test(url.searchParams.get('code_challenge') ?? ''));
      assert.ok(/^[A-Za-z0-9_-]{43}$/.test(url.searchParams.get('state') ?? ''));
      assert.ok((url.searchParams.get('scope') ?? '').split(' ').includes('workouts:read'));
      const now = Math.floor(Date.now() / 1000);
      const payload = { iss: config.issuer, aud: resource, sub: providerSubject,
        client_id: config.clientId, sid: `app_consent_${randomUUID().replaceAll('-', '')}`,
        iat: now - 1, exp: now + 300, jti: randomUUID(), scope: 'openid offline_access workouts:read' };
      const approval = Object.freeze({ token: await sign(payload), payload: Object.freeze(payload),
        state: url.searchParams.get('state'), code: `synthetic_${randomUUID()}` });
      issued.push(approval);
      codes.set(approval.code, { approval, challenge: url.searchParams.get('code_challenge') });
      return approval;
    },
    async variant(approval, payload = {}, header = {}) {
      assert.ok(issued.includes(approval), 'Variants require a previously exercised synthetic approval.');
      return sign({ ...approval.payload, jti: randomUUID(), ...payload }, header);
    },
    async fetch(raw, init = {}) {
      const url = new URL(typeof raw === 'string' ? raw : raw instanceof URL ? raw.href : raw.url);
      const headers = new Headers(init.headers);
      assert.ok(init.credentials === 'omit' && init.signal
        && ['error', 'manual'].includes(init.redirect), 'Provider requests must remain bounded and credential-isolated.');
      if (url.origin === config.issuer) {
        assert.ok(!headers.has('authorization'), 'Management credentials must not reach the issuer.');
        if (url.pathname === '/oauth2/jwks') {
          counts.jwks++;
          return Response.json({ keys: [publicJwk] });
        }
        if (url.pathname === '/oauth2/token' && init.method === 'POST') {
          const body = new URLSearchParams(init.body);
          assert.ok(body.get('grant_type') === 'authorization_code'
            && body.get('client_id') === config.clientId && body.get('resource') === resource
            && body.get('redirect_uri') === callback && !body.has('client_secret'));
          const pending = codes.get(body.get('code'));
          if (!pending || pending.challenge !== createHash('sha256')
            .update(body.get('code_verifier') ?? '').digest('base64url')) {
            return Response.json({ error: 'invalid_grant' }, { status: 400 });
          }
          codes.delete(body.get('code'));
          authorized.add(pending.approval.payload.sub);
          counts.exchanges++;
          return Response.json({ access_token: pending.approval.token, token_type: 'bearer',
            refresh_token: 'SYNTHETIC_REFRESH_MUST_NOT_PERSIST', id_token: 'SYNTHETIC_ID_MUST_NOT_PERSIST' });
        }
      }
      if (url.origin === 'https://api.workos.com') {
        assert.ok(headers.get('authorization') === `Bearer ${apiKey}` && init.body === undefined);
        if (url.pathname === `/connect/applications/${config.clientId}`) {
          return Response.json({ id: config.applicationId, client_id: config.clientId });
        }
        const match = /^\/user_management\/users\/(user_[A-Za-z0-9]+)\/authorized_applications(?:\/(connect_app_[A-Za-z0-9]+))?$/.exec(url.pathname);
        if (match && subjects.has(match[1])) {
          if (!match[2] && init.method === 'GET') {
            assert.ok(url.searchParams.get('limit') === '100');
            counts.reads++;
            return Response.json({ data: authorized.has(match[1])
              ? [{ id: 'fixture-authorization', application: { id: config.applicationId, client_id: config.clientId } }]
              : [], list_metadata: { before: null, after: null } });
          }
          if (match[2] === config.applicationId && init.method === 'DELETE') {
            counts.resets++;
            authorized.delete(match[1]);
            return new Response(null, { status: 204 });
          }
        }
      }
      throw new Error('Unexpected destination in the synthetic provider fixture.');
    },
  });
}
