/**
 * OpenSky CORS relay — Cloudflare Worker
 *
 * Purpose
 *   The OpenSky API does not return an Access-Control-Allow-Origin header that a
 *   GitHub Pages origin can use, so a browser cannot call it directly. This Worker
 *   sits in front of it, adds the CORS headers, and optionally performs the OAuth2
 *   client-credentials exchange so the client secret never reaches the browser.
 *
 * Usage from the app
 *   Settings -> CORS proxy prefix:  https://<name>.<subdomain>.workers.dev/?url=
 *   The app appends encodeURIComponent(targetUrl).
 *
 * Credentials (optional but recommended)
 *   Set these as Worker secrets, NOT as plain variables:
 *     npx wrangler secret put OPENSKY_CLIENT_ID
 *     npx wrangler secret put OPENSKY_CLIENT_SECRET
 *   When present, the Worker authenticates upstream and you leave the client
 *   ID/secret fields in the app blank.
 *
 * Origin lock
 *   Set ALLOWED_ORIGIN as a plain variable to your Pages origin, e.g.
 *     https://ianhay.github.io
 *   Leave unset to allow any origin (fine while testing, less so afterwards).
 */

const UPSTREAM_HOSTS = new Set([
  'opensky-network.org',
  'auth.opensky-network.org'
]);

const TOKEN_URL =
  'https://auth.opensky-network.org/auth/realms/opensky-network/protocol/openid-connect/token';

// Module-scope token cache. Workers are ephemeral, but a warm isolate will reuse
// this across requests, which keeps token exchanges rare.
let cachedToken = null;
let cachedExpiry = 0;

function corsHeaders(env, request) {
  const allowed = env.ALLOWED_ORIGIN || '*';
  const origin = request.headers.get('Origin') || '';
  return {
    'Access-Control-Allow-Origin': allowed === '*' ? '*' : (origin === allowed ? origin : allowed),
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}

function reject(message, status, env, request) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(env, request) }
  });
}

async function getToken(env) {
  if (!env.OPENSKY_CLIENT_ID || !env.OPENSKY_CLIENT_SECRET) return null;
  if (cachedToken && Date.now() < cachedExpiry - 60000) return cachedToken;

  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: env.OPENSKY_CLIENT_ID,
    client_secret: env.OPENSKY_CLIENT_SECRET
  });

  // The OpenSky auth host intermittently fails to answer from Cloudflare's
  // network, which surfaces as a 522. One retry clears most of these.
  let res = null, lastErr = '';
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      res = await fetch(TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
        signal: AbortSignal.timeout(12000)
      });
      if (res.ok) break;
      lastErr = 'HTTP ' + res.status;
      res = null;
    } catch (e) {
      lastErr = e.name === 'TimeoutError' ? 'timed out after 12 s' : e.message;
      res = null;
    }
  }
  if (!res) {
    cachedToken = null;
    throw new Error('Token exchange failed: ' + lastErr);
  }
  const json = await res.json();
  cachedToken = json.access_token;
  cachedExpiry = Date.now() + (Number(json.expires_in) || 1800) * 1000;
  return cachedToken;
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env, request) });
    }

    const target = new URL(request.url).searchParams.get('url');
    if (!target) {
      // A bare GET is a health probe: report configuration without exposing secrets.
      let tokenState;
      try {
        const t = await getToken(env);
        tokenState = t ? 'ok — token obtained' : 'no credentials bound';
      } catch (e) {
        tokenState = 'FAILED — ' + e.message;
      }
      return new Response(JSON.stringify({
        relay: 'opensky-cors-relay',
        version: '1.1.0',
        allowedOrigin: env.ALLOWED_ORIGIN || '(any)',
        credentialsBound: !!(env.OPENSKY_CLIENT_ID && env.OPENSKY_CLIENT_SECRET),
        tokenExchange: tokenState,
        usage: 'append ?url=<encoded OpenSky URL>'
      }, null, 2), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders(env, request) }
      });
    }

    let upstream;
    try {
      upstream = new URL(target);
    } catch (e) {
      return reject('Malformed target URL.', 400, env, request);
    }

    // Never operate as an open proxy.
    if (upstream.protocol !== 'https:' || !UPSTREAM_HOSTS.has(upstream.hostname)) {
      return reject('Target host not permitted by this relay.', 403, env, request);
    }

    // The app may still try to exchange a token itself; if this relay holds the
    // credentials that is redundant, so short-circuit it.
    if (upstream.hostname === 'auth.opensky-network.org' && env.OPENSKY_CLIENT_SECRET) {
      return new Response(
        JSON.stringify({ access_token: 'relay-managed', expires_in: 1800, relay_managed: true,
                         note: 'This relay authenticates upstream; the browser does not need a token.' }),
        { headers: { 'Content-Type': 'application/json', ...corsHeaders(env, request) } }
      );
    }

    const headers = new Headers();
    headers.set('Accept', 'application/json');
    headers.set('User-Agent', 'traffic-monitor-relay/1.0');

    // Authentication is an optimisation, not a prerequisite. If the token
    // exchange fails the request still goes through anonymously — degraded
    // rate limits beat no data at all.
    let authMode = 'anonymous';
    let authNote = '';
    try {
      const token = await getToken(env);
      if (token) { headers.set('Authorization', 'Bearer ' + token); authMode = 'bearer'; }
      else authNote = 'no credentials bound to this relay';
    } catch (e) {
      authNote = e.message;
    }

    // Pass through a browser-supplied bearer token only when the relay has none.
    if (!headers.has('Authorization')) {
      const inbound = request.headers.get('Authorization');
      if (inbound) headers.set('Authorization', inbound);
    }

    let res;
    try {
      res = await fetch(upstream.toString(), {
        method: request.method === 'POST' ? 'POST' : 'GET',
        headers,
        body: request.method === 'POST' ? await request.text() : undefined
      });
    } catch (e) {
      return reject('Upstream fetch failed: ' + e.message, 502, env, request);
    }

    // A 401 usually means a stale cached token; drop it so the next call refreshes.
    if (res.status === 401) {
      cachedToken = null;
      cachedExpiry = 0;
    }

    const out = new Headers(corsHeaders(env, request));
    out.set('Content-Type', res.headers.get('Content-Type') || 'application/json');
    out.set('X-Relay-Auth', authMode);
    if (authNote) out.set('X-Relay-Auth-Note', authNote.slice(0, 200));
    out.set('Access-Control-Expose-Headers', 'X-Rate-Limit-Remaining, X-Relay-Auth, X-Relay-Auth-Note');
    const remaining = res.headers.get('X-Rate-Limit-Remaining');
    if (remaining) {
      out.set('X-Rate-Limit-Remaining', remaining);
    }
    const retryAfter = res.headers.get('Retry-After');
    if (retryAfter) out.set('Retry-After', retryAfter);

    return new Response(res.body, { status: res.status, headers: out });
  }
};
