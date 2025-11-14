// server.mjs
import 'dotenv/config';
import express from 'express';
import axios from 'axios';
import https from 'https';
import crypto from 'crypto';
import { SignJWT, importPKCS8, decodeProtectedHeader } from 'jose';
import fs from 'fs/promises';

// ======================
// CONFIG
// ======================
const cfg = {
  base: process.env.ASB_BASE,              // e.g. https://api.asb.io/v2.3/open-banking-nz
  auth: process.env.ASB_AUTH,              // e.g. https://asb.glueware.dev/oauth/v2.0
  clientId: process.env.CLIENT_ID,
  redirect: process.env.REDIRECT_URI,      // e.g. https://asb-xsea.onrender.com/auth/callback
  mtlsCert: process.env.MTLS_CERT,         // e.g. /etc/secrets/client_cert.pem
  mtlsKey: process.env.MTLS_KEY,           // e.g. /etc/secrets/client_key.pem
  oidcPk: process.env.OIDC_PRIVATE_KEY,    // e.g. /etc/secrets/private_key.pem (PKCS#8)
  oidcKid: process.env.OIDC_KID,
  apiKey: process.env.API_KEY,

  // Auth toggles
  authMethod: (process.env.AUTH_METHOD || 'private_key_jwt').toLowerCase(), // private_key_jwt | mtls_with_client_id | mtls_no_client_id
  algToken: (process.env.ALG_TOKEN || 'PS256').toUpperCase(),               // for token/client_assertion
  algRequest: (process.env.ALG_REQUEST || 'PS256').toUpperCase(),           // for request object to /authorize
  kidHeader: (process.env.KID_HEADER || 'true').toLowerCase() === 'true',
  includeClientIdInTokenBody: (process.env.INCLUDE_CLIENT_ID_IN_TOKEN_BODY || 'true').toLowerCase() === 'true',
  tokenScope: process.env.TOKEN_SCOPE || 'accounts',                        // you can change to 'openid accounts' if needed
  typHeader: (process.env.TYP_HEADER || 'true').toLowerCase() === 'true'
};

if (!cfg.base || !cfg.auth || !cfg.clientId || !cfg.redirect) {
  console.error('❌ Missing mandatory environment variables: ASB_BASE, ASB_AUTH, CLIENT_ID, REDIRECT_URI');
  process.exit(1);
}

const app = express();
app.use(express.json());

// ======================
// mTLS Agent
// ======================
const [cert, key] = await Promise.all([
  fs.readFile(cfg.mtlsCert),
  fs.readFile(cfg.mtlsKey)
]);

const mtlsAgent = new https.Agent({
  cert,
  key
});

// ======================
// JWT helpers
// ======================
async function signJwt(payload, { alg, aud, includeKid }) {
  const pkPath = cfg.oidcPk;
  if (!pkPath) throw new Error('OIDC_PRIVATE_KEY env not set');
  const pkcs8 = await fs.readFile(pkPath, 'utf8');

  const key = await importPKCS8(pkcs8, alg);
  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomBytes(16).toString('hex');

  const header = { alg };
  if (includeKid && cfg.oidcKid) header.kid = cfg.oidcKid;
  if (cfg.typHeader) header.typ = 'JWT';

  return await new SignJWT({ ...payload, jti })
    .setProtectedHeader(header)
    .setIssuer(cfg.clientId)
    .setSubject(cfg.clientId)
    .setAudience(aud)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(key);
}

async function clientAssertion(aud) {
  return signJwt({}, { alg: cfg.algToken, aud, includeKid: cfg.kidHeader });
}

async function buildRequestObject({ consentId, state, nonce }) {
  const aud = `${cfg.auth}/authorize`;
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: cfg.clientId,
    aud,
    client_id: cfg.clientId,
    response_type: 'code id_token',
    redirect_uri: cfg.redirect,
    scope: cfg.tokenScope,
    state,
    nonce,
    claims: {
      id_token: {
        ConsentId: { essential: true, value: consentId }
      }
    },
    exp: now + 300,
    iat: now
  };

  return signJwt(payload, {
    alg: cfg.algRequest,
    aud,
    includeKid: cfg.kidHeader
  });
}

// ======================
// Token helpers (3 modes)
// ======================
async function tokenClientCredentials() {
  const tokenUrl = `${cfg.auth}/token`;

  // private_key_jwt
  if (cfg.authMethod === 'private_key_jwt') {
    const assertion = await clientAssertion(tokenUrl);
    const body = {
      grant_type: 'client_credentials',
      scope: cfg.tokenScope,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion
    };
    if (cfg.includeClientIdInTokenBody) body.client_id = cfg.clientId;

    const form = new URLSearchParams(body);
    const { data } = await axios.post(tokenUrl, form, {
      httpsAgent: mtlsAgent,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    return data.access_token;
  }

  // mTLS + client_id
  if (cfg.authMethod === 'mtls_with_client_id') {
    const form = new URLSearchParams({
      grant_type: 'client_credentials',
      scope: cfg.tokenScope,
      client_id: cfg.clientId
    });
    const { data } = await axios.post(tokenUrl, form, {
      httpsAgent: mtlsAgent,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    return data.access_token;
  }

  // pure mTLS, no client_id
  if (cfg.authMethod === 'mtls_no_client_id') {
    const form = new URLSearchParams({
      grant_type: 'client_credentials',
      scope: cfg.tokenScope
    });
    const { data } = await axios.post(tokenUrl, form, {
      httpsAgent: mtlsAgent,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    return data.access_token;
  }

  throw new Error(`Unknown AUTH_METHOD: ${cfg.authMethod}`);
}

async function tokenRefresh(refreshToken) {
  const tokenUrl = `${cfg.auth}/token`;

  if (cfg.authMethod === 'private_key_jwt') {
    const assertion = await clientAssertion(tokenUrl);
    const body = {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion
    };
    if (cfg.includeClientIdInTokenBody) body.client_id = cfg.clientId;

    const form = new URLSearchParams(body);
    const { data } = await axios.post(tokenUrl, form, {
      httpsAgent: mtlsAgent,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    return data.access_token;
  }

  if (cfg.authMethod === 'mtls_with_client_id') {
    const form = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: cfg.clientId
    });
    const { data } = await axios.post(tokenUrl, form, {
      httpsAgent: mtlsAgent,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    return data.access_token;
  }

  if (cfg.authMethod === 'mtls_no_client_id') {
    const form = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    });
    const { data } = await axios.post(tokenUrl, form, {
      httpsAgent: mtlsAgent,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    return data.access_token;
  }

  throw new Error(`Unknown AUTH_METHOD: ${cfg.authMethod}`);
}

// ======================
// ASB resource helper
// ======================
async function createAccountAccessConsent(clientToken) {
  const body = {
    Data: {
      Permissions: [
        'ReadAccountsBasic',
        'ReadAccountsDetail',
        'ReadBalances',
        'ReadTransactionsDetail'
      ]
    },
    Risk: {}
  };

  const { data } = await axios.post(
    `${cfg.base}/account-access-consents`,
    body,
    {
      httpsAgent: mtlsAgent,
      headers: { Authorization: `Bearer ${clientToken}` }
    }
  );

  return data?.Data?.ConsentId;
}

// ======================
// Diagnostics
// ======================

// safe env view
app.get('/diag/env', (req, res) => {
  const safe = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (key.includes('KEY') || key.includes('SECRET') || key.includes('TOKEN') || key.includes('PASS')) {
      safe[key] = '[hidden]';
    } else {
      safe[key] = value;
    }
  }
  res.json(safe);
});

// show what JWT we build for client_assertion (only in private_key_jwt mode)
app.get('/diag/jwt', async (req, res) => {
  try {
    const aud = `${cfg.auth}/token`;
    if (cfg.authMethod !== 'private_key_jwt') {
      return res.json({
        ok: true,
        note: 'AUTH_METHOD is not private_key_jwt, no client_assertion JWT is used for token.',
        authMethod: cfg.authMethod
      });
    }
    const jwt = await clientAssertion(aud);
    const header = decodeProtectedHeader(jwt);
    const parts = jwt.split('.');
    const payloadJson = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

    res.json({
      ok: true,
      env: {
        AUTH_METHOD: cfg.authMethod,
        ALG_TOKEN: cfg.algToken,
        ALG_REQUEST: cfg.algRequest,
        KID_HEADER: cfg.kidHeader,
        INCLUDE_CLIENT_ID_IN_TOKEN_BODY: cfg.includeClientIdInTokenBody,
        TYP_HEADER: cfg.typHeader
      },
      kid: cfg.oidcKid,
      client_id: cfg.clientId,
      aud,
      header,
      payload: {
        iss: payloadJson.iss,
        sub: payloadJson.sub,
        aud: payloadJson.aud,
        jti: payloadJson.jti,
        iat: payloadJson.iat,
        exp: payloadJson.exp
      }
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// test the token endpoint using current AUTH_METHOD
app.get('/diag/token', async (req, res) => {
  try {
    const token = await tokenClientCredentials();
    res.json({
      ok: true,
      method: cfg.authMethod,
      token: token ? '[received]' : null
    });
  } catch (e) {
    res.status(500).json({
      ok: false,
      method: cfg.authMethod,
      error: e.response?.data || e.message
    });
  }
});

// ======================
// Main flows
// ======================
app.get('/auth/start', async (req, res) => {
  try {
    const state = crypto.randomBytes(16).toString('hex');
    const nonce = crypto.randomBytes(16).toString('hex');

    // 1) client credentials (for consent creation)
    const clientToken = await tokenClientCredentials();

    // 2) create consent
    const consentId = await createAccountAccessConsent(clientToken);

    // 3) request object
    const requestJws = await buildRequestObject({ consentId, state, nonce });

    // 4) redirect to ASB authorisation
    const authUrl = new URL(`${cfg.auth}/authorize`);
    authUrl.searchParams.set('client_id', cfg.clientId);
    authUrl.searchParams.set('request', requestJws);

    res.redirect(authUrl.toString());
  } catch (e) {
    res
      .status(500)
      .send(
        `auth/start error: ${
          e.response?.data ? JSON.stringify(e.response.data) : e.message
        }`
      );
  }
});

app.get('/auth/callback', async (req, res) => {
  try {
    const tokenUrl = `${cfg.auth}/token`;
    const code = req.query.code;
    if (!code) {
      return res.status(400).send('Missing code in callback.');
    }

    let form;

    if (cfg.authMethod === 'private_key_jwt') {
      const assertion = await clientAssertion(tokenUrl);
      const body = {
        grant_type: 'authorization_code',
        code,
        redirect_uri: cfg.redirect,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion
      };
      if (cfg.includeClientIdInTokenBody) body.client_id = cfg.clientId;
      form = new URLSearchParams(body);
    } else if (cfg.authMethod === 'mtls_with_client_id') {
      form = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: cfg.redirect,
        client_id: cfg.clientId
      });
    } else if (cfg.authMethod === 'mtls_no_client_id') {
      form = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: cfg.redirect
      });
    } else {
      throw new Error(`Unknown AUTH_METHOD: ${cfg.authMethod}`);
    }

    const { data } = await axios.post(tokenUrl, form, {
      httpsAgent: mtlsAgent,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    res
      .status(200)
      .send(
        `✅ Copy this REFRESH TOKEN and save it as <code>ASB_REFRESH_TOKEN</code> in Render:<br><br><code style="word-break:break-all">${data.refresh_token}</code>`
      );
  } catch (e) {
    res
      .status(500)
      .send(
        `Auth error: ${
          e.response?.data ? JSON.stringify(e.response.data) : e.message
        }`
      );
  }
});

app.get('/sync', async (req, res) => {
  try {
    if (req.header('x-api-key') !== cfg.apiKey) {
      return res.status(401).json({ error: 'unauthorized' });
    }

    const refreshToken = process.env.ASB_REFRESH_TOKEN;
    if (!refreshToken) {
      return res.status(400).json({ error: 'missing ASB_REFRESH_TOKEN' });
    }

    const access = await tokenRefresh(refreshToken);
    const asb = axios.create({
      baseURL: cfg.base,
      httpsAgent: mtlsAgent,
      headers: { Authorization: `Bearer ${access}` }
    });

    const { data: acc } = await asb.get('/accounts');
    const accounts = acc?.Data?.Account ?? [];
    const balances = [];
    const transactions = [];

    for (const a of accounts) {
      const id = a.AccountId;
      const bal = await asb.get(`/accounts/${id}/balances`);
      const tx = await asb.get(`/accounts/${id}/transactions`);
      balances.push({ accountId: id, ...bal.data });
      transactions.push({ accountId: id, ...tx.data });
    }

    res.json({ accounts, balances, transactions });
  } catch (e) {
    res.status(500).json({ error: e.response?.data || e.message });
  }
});

app.get('/', (req, res) => {
  res.send('💫 ASB Open Banking connector is running.');
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`✅ ASB connector running on port ${port}`);
});
