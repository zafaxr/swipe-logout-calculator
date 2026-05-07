const express = require('express');
const fetch   = require('node-fetch');
const forge   = require('node-forge');
const cors    = require('cors');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3001;

const GREYTHR_BASE = 'https://hashconnect.greythr.com';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ── RSA public key extracted from greytHR's main.js bundle ───────────────────
const GREYTHR_RSA_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoLf7n9YvJsoinXlx6hNS
qcwLZVKR1VoMgrvYPPyfk0c5OmgUoECdxsSwr7fY58BDnAJL/t4xSWjlP8wccPRH
L6R6wXJhBc4/9S7jows/Bc5TqDOdP7TRwhmmHzgBJLabNuDvS5H77iGNjnoob3AW
s/a1dTG0Ztf2p7TUCG2leHW6UckUTvYhGpO9W7WO1rqBpdPlfN7fhhbkNermzfe0
dJSQdTaztAmLco8QCKhKwvMvMXNfF53sAOOkNGBkF/R7TIHtu9slfVy+gJbBYwAr
vmEyoYitD76f7v73YRlMGJcVj+9aWCSQ0Mpdc39wmiH9z9WQdC9TsVVc0TOcF3Ov
FQIDAQAB
-----END PUBLIC KEY-----`;

// Matches greytHR's own JS: publicKeyFromPem(key).encrypt(e, 'RSA-OAEP', {md: sha256.create()})
function encryptPassword(plaintext) {
  const pubKey    = forge.pki.publicKeyFromPem(GREYTHR_RSA_PUBLIC_KEY_PEM);
  const encrypted = pubKey.encrypt(plaintext, 'RSA-OAEP', { md: forge.md.sha256.create() });
  return forge.util.encode64(encrypted);
}

// ── Get login_challenge via the Hydra OAuth2 authorization flow ───────────────
async function getLoginChallenge() {
  // 1. Get session config to find Hydra server + client details
  const configRes = await fetch(`${GREYTHR_BASE}/uas/v1/session-config`, {
    headers: { accept: 'application/json' },
  });
  const config = await configRes.json();

  // 2. Hit Hydra's /oauth2/auth → redirects to idp-coral with login_challenge
  const params = new URLSearchParams({
    client_id:     config.hydraClient,
    response_type: 'code',
    scope:         'openid',
    redirect_uri:  config.oAuthRedirectUrl,
    state:         config.accessId,
  });
  const authUrl = config.hydraFrontendServer + 'oauth2/auth?' + params;
  const authRes = await fetch(authUrl, { redirect: 'manual' });
  const location = authRes.headers.get('location');
  if (!location) throw new Error('No redirect from Hydra auth endpoint');

  // 3. Extract login_challenge from the redirect URL
  const redirectUrl = new URL(location.startsWith('http') ? location : `${GREYTHR_BASE}${location}`);
  const challenge   = redirectUrl.searchParams.get('login_challenge');
  if (!challenge) throw new Error('login_challenge not found in Hydra redirect: ' + location);
  return challenge;
}

// ── Merge Set-Cookie headers across a redirect chain into a cookie jar ────────
function parseCookies(rawHeaders = []) {
  return rawHeaders.map(c => c.split(';')[0]);
}

// Follow redirects manually, accumulating all Set-Cookie headers
async function fetchFollowingRedirects(url, options = {}, cookieJar = []) {
  const headers = { ...(options.headers || {}) };
  if (cookieJar.length) headers['cookie'] = cookieJar.join('; ');

  const res = await fetch(url, { ...options, headers, redirect: 'manual' });
  const setCookie = res.headers.raw()['set-cookie'] || [];
  const newCookies = parseCookies(setCookie);
  const merged = [...new Map([...cookieJar, ...newCookies].map(c => [c.split('=')[0], c])).values()];

  const location = res.headers.get('location');
  if ((res.status === 301 || res.status === 302 || res.status === 303) && location) {
    const nextUrl = location.startsWith('http') ? location : new URL(location, url).toString();
    return fetchFollowingRedirects(nextUrl, { method: 'GET' }, merged);
  }

  return { res, cookieJar: merged };
}

// ── POST /api/login ───────────────────────────────────────────────────────────

app.post('/api/login', async (req, res) => {
  const { userName, password } = req.body;
  if (!userName || !password) return res.status(400).json({ error: 'userName and password required' });

  try {
    console.log(`[login] fetching challenge for ${userName}…`);
    const challenge     = await getLoginChallenge();
    const encryptedPass = encryptPassword(password);

    console.log(`[login] challenge=${challenge.substring(0, 20)}… posting credentials…`);
    const loginRes  = await fetch(`${GREYTHR_BASE}/uas/v1/login`, {
      method: 'POST',
      headers: {
        'content-type':      'application/json',
        'accept':            'application/json, text/plain, */*',
        'origin':            GREYTHR_BASE,
        'referer':           `${GREYTHR_BASE}/uas/portal/auth/login?login_challenge=${challenge}`,
        'x-oauth-challenge': challenge,
        'x-greytip-domain':  Buffer.from(`${GREYTHR_BASE.replace('https://', '')}`).toString('base64'),
      },
      body: JSON.stringify({ userName, password: encryptedPass }),
    });

    const loginBody = await loginRes.text();
    let parsed;
    try { parsed = JSON.parse(loginBody); } catch { parsed = { raw: loginBody }; }

    console.log(`[login] status=${loginRes.status} body=`, JSON.stringify(parsed).substring(0, 200));

    if (!loginRes.ok) {
      return res.status(loginRes.status).json({ error: 'Login failed', detail: parsed });
    }

    // Response shape: { redirectUrl, loginType } — NOT redirect_to
    const redirectTo = parsed.redirectUrl;
    if (!redirectTo) {
      // Empty body = wrong credentials (server returns 200 silently on bad login)
      return res.status(401).json({ error: 'Invalid credentials', detail: parsed });
    }

    // Follow the OAuth redirect chain to get the final session cookies
    console.log(`[login] following OAuth redirects from ${redirectTo.substring(0, 60)}…`);
    const initialCookies = parseCookies(loginRes.headers.raw()['set-cookie'] || []);
    const { cookieJar } = await fetchFollowingRedirects(redirectTo, {}, initialCookies);

    const sessionCookie = cookieJar.join('; ');
    console.log(`[login] done — ${cookieJar.length} cookies collected`);

    res.json({ ok: true, sessionCookie });

  } catch (err) {
    console.error('[login] error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/attendance?date=YYYY-MM-DD ───────────────────────────────────────
// TODO: fill in the real endpoint once the post-login attendance curl is shared.
// The server will dump the raw response so we can inspect the shape.

app.get('/api/attendance', async (req, res) => {
  const { date, sessionCookie } = req.query;
  if (!sessionCookie) return res.status(401).json({ error: 'sessionCookie required' });

  const today = date || new Date().toISOString().split('T')[0];

  try {
    // Placeholder — replace URL once the real attendance curl is shared
    const attRes = await fetch(
      `${GREYTHR_BASE}/v1/attendance/swipes?date=${today}`,
      {
        headers: {
          'accept':  'application/json',
          'cookie':  sessionCookie,
          'origin':  GREYTHR_BASE,
          'referer': `${GREYTHR_BASE}/`,
        },
      }
    );

    const body = await attRes.text();
    let data;
    try { data = JSON.parse(body); } catch { data = body; }

    console.log(`[attendance] status=${attRes.status}`);
    res.json({ raw: data, status: attRes.status });

  } catch (err) {
    console.error('[attendance] error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`\n  Swipe Logout — local server`);
  console.log(`  http://localhost:${PORT}\n`);
});
