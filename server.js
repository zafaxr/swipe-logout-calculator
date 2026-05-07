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

// ── Step 1: fetch login page → extract login_challenge + RSA public key ──────

async function getLoginChallenge() {
  const res = await fetch(`${GREYTHR_BASE}/`, { redirect: 'follow' });
  const url  = new URL(res.url);
  const challenge = url.searchParams.get('login_challenge');
  if (!challenge) throw new Error('Could not extract login_challenge from redirect URL: ' + res.url);
  return challenge;
}

// TODO: replace with the actual greytHR RSA public key (PEM format).
// Find it by checking the Network tab for a request like /uas/v1/auth/config
// or /uas/v1/rsa-key before login, or look for a publicKey field in any
// pre-login API response.
const GREYTHR_RSA_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
REPLACE_WITH_ACTUAL_GREYTHR_RSA_PUBLIC_KEY
-----END PUBLIC KEY-----`;

function encryptPassword(plaintext) {
  const pubKey = forge.pki.publicKeyFromPem(GREYTHR_RSA_PUBLIC_KEY_PEM);
  const encrypted = pubKey.encrypt(plaintext, 'RSA-OAEP');
  return forge.util.encode64(encrypted);
}

// ── POST /api/login ───────────────────────────────────────────────────────────

app.post('/api/login', async (req, res) => {
  const { userName, password } = req.body;
  if (!userName || !password) return res.status(400).json({ error: 'userName and password required' });

  try {
    const challenge       = await getLoginChallenge();
    const encryptedPass   = encryptPassword(password);

    const loginRes = await fetch(`${GREYTHR_BASE}/uas/v1/login`, {
      method: 'POST',
      headers: {
        'content-type':      'application/json',
        'accept':            'application/json, text/plain, */*',
        'origin':            GREYTHR_BASE,
        'x-oauth-challenge': challenge,
      },
      body: JSON.stringify({ userName, password: encryptedPass }),
    });

    const loginBody = await loginRes.text();
    const setCookie = loginRes.headers.raw()['set-cookie'];

    // Forward cookies so the browser can use them for subsequent calls
    if (setCookie) {
      setCookie.forEach(c => res.append('Set-Cookie', c));
    }

    // greytHR typically returns a redirect_to URL on success
    let parsed;
    try { parsed = JSON.parse(loginBody); } catch { parsed = { raw: loginBody }; }

    if (!loginRes.ok) {
      return res.status(loginRes.status).json({ error: 'Login failed', detail: parsed });
    }

    // Extract session cookie for use in attendance calls
    const sessionCookie = (setCookie || [])
      .map(c => c.split(';')[0])
      .join('; ');

    res.json({ ok: true, sessionCookie, redirect: parsed.redirect_to || null });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/attendance?date=YYYY-MM-DD ───────────────────────────────────────
// TODO: replace the URL and response parsing once the actual attendance
// endpoint curl is shared. The placeholder below is a best guess based on
// the greytHR API structure.

app.get('/api/attendance', async (req, res) => {
  const { date, sessionCookie } = req.query;
  if (!sessionCookie) return res.status(401).json({ error: 'sessionCookie required' });

  const today = date || new Date().toISOString().split('T')[0]; // YYYY-MM-DD

  try {
    // TODO: confirm exact endpoint + query params from your Network tab
    const attRes = await fetch(
      `${GREYTHR_BASE}/v1/attendance/swipes?date=${today}`,
      {
        headers: {
          'accept': 'application/json',
          'cookie': sessionCookie,
          'origin': GREYTHR_BASE,
        },
      }
    );

    if (!attRes.ok) {
      const body = await attRes.text();
      return res.status(attRes.status).json({ error: 'Attendance fetch failed', detail: body });
    }

    const data = await attRes.json();

    // TODO: transform data into the swipe-log text format the calculator expects.
    // For now return raw so we can inspect the response shape.
    res.json({ raw: data });

  } catch (err) {
    console.error('Attendance error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`\n  Swipe Logout — local server`);
  console.log(`  http://localhost:${PORT}\n`);
});
