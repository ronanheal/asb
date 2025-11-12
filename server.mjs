import 'dotenv/config';
import express from 'express';
import axios from 'axios';
import https from 'https';
import crypto from 'crypto';
import { SignJWT, importPKCS8 } from 'jose';
import fs from 'fs/promises';

// ======================
// CONFIG
// ======================
const cfg = {
  base: process.env.ASB_BASE,              // https://api.asb.io/v2.3/open-banking-nz
  auth: process.env.ASB_AUTH,              // https://asb.glueware.dev/oauth/v2.0
  clientId: process.env.CLIENT_ID,
  redirect: process.env.REDIRECT_URI,      // https://asb-xsea.onrender.com/auth/callback
  mtlsCert: process.env.MTLS_CERT,         // /etc/secrets/client_cert.pem
  mtlsKey: process.env.MTLS_KEY,           // /etc/secrets/client_key.pem
  oidcPk: process.env.OIDC_PRIVATE_KEY,    // /etc/secrets/private_key.pem
  oidcKid: process.env.OIDC_KID,           // cf70509a-4b97-4cf5-9609-cd313c19aecc
  apiKey: process.env.API_KEY              // Random secret for /sync
};

if (!cfg.base || !cfg.auth || !cfg.clientId || !cfg.redirect) {
  console.error("❌ Missing mandatory environment variables.");
  process.exit(1);
}

const app = express();
app.use(express.json());

// ======================
// mTLS Agent
// ======================
const mtlsAgent = new https.Agent({
  cert: await fs.readFile(cfg.mtlsCert),
  key: await fs.readFile(cfg.mtlsKey)
});

// ======================
// JWT Client Assertion
// ======================
async function clientAssertion(aud) {
  const pkcs8 = await fs.readFile(cfg.oidcPk, 'utf8');
  const alg = 'PS256';
  const key = await importPKCS8(pkcs8, alg);
  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomBytes(16).toString('hex');

  return await new SignJWT({ jti })
    .setProtectedHeader({ alg: 'PS256', kid: cfg.oidcKid })
    .setIssuer(cfg.clientId)
    .setSubject(cfg.clientId)
    .setAudience(aud)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(key);
}

// ======================
// Token + Consent Helpers
// ======================
async function getClientCredentialsToken() {
  const tokenUrl = `${cfg.auth}/token`;
  const assertion = await clientAssertion(tokenUrl);
  const form = new URLSearchParams({
    grant_type: 'client_credentials',
    scope: 'openid accounts',
    client_id: cfg.clientId,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: assertion
  });
  const { data } = await axios.post(tokenUrl, form, {
    httpsAgent: mtlsAgent,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });
  return data.access_token;
}

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
    { httpsAgent: mtlsAgent, headers: { Authorization: `Bearer ${clientToken}` } }
  );
  return data?.Data?.ConsentId;
}

// ======================
// Request Object (for authorization)
// ======================
async function buildRequestObject({ consentId, state, nonce }) {
  const pkcs8 = await fs.readFile(cfg.oidcPk, 'utf8');
  const alg = 'PS256';
  const key = await importPKCS8(pkcs8, alg);
  const now = Math.floor(Date.now() / 1000);

  const payload = {
    iss: cfg.clientId,
    aud: `${cfg.auth}/authorize`,
    client_id: cfg.clientId,
    response_type: 'code id_token',
    redirect_uri: cfg.redirect,
    scope: 'openid accounts',
    state,
    nonce,
    claims: {
      id_token: { ConsentId: { essential: true, value: consentId } }
    },
    exp: now + 300,
    iat: now
  };

  return await new SignJWT(payload)
    .setProtectedHeader({ alg: 'PS256', kid: cfg.oidcKid })
    .sign(key);
}

// ======================
// ROUTES
// ======================
app.get('/auth/start', async (req, res) => {
  try {
    const state = crypto.randomBytes(16).toString('hex');
    const nonce = crypto.randomBytes(16).toString('hex');
    const clientToken = await getClientCredentialsToken();
    const consentId = await createAccountAccessConsent(clientToken);
    const requestJws = await buildRequestObject({ consentId, state, nonce });

    const authUrl = new URL(`${cfg.auth}/authorize`);
    authUrl.searchParams.set('client_id', cfg.clientId);
    authUrl.searchParams.set('request', requestJws);

    res.redirect(authUrl.toString());
  } catch (e) {
    res
      .status(500)
      .send(`auth/start error: ${e.response?.data ? JSON.stringify(e.response.data) : e.message}`);
  }
});

app.get('/auth/callback', async (req, res) => {
  try {
    const tokenUrl = `${cfg.auth}/token`;
    const assertion = await clientAssertion(tokenUrl);
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: req.query.code,
      redirect_uri: cfg.redirect,
      client_id: cfg.clientId,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion
    });
    const { data } = await axios.post(tokenUrl, body, {
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
      .send(`Auth error: ${e.response?.data ? JSON.stringify(e.response.data) : e.message}`);
  }
});

async function refreshAccessToken(refreshToken) {
  const tokenUrl = `${cfg.auth}/token`;
  const assertion = await clientAssertion(tokenUrl);
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: cfg.clientId,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: assertion
  });
  const { data } = await axios.post(tokenUrl, body, {
    httpsAgent: mtlsAgent,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });
  return data.access_token;
}

app.get('/sync', async (req, res) => {
  try {
    if (req.header('x-api-key') !== cfg.apiKey)
      return res.status(401).json({ error: 'unauthorized' });

    const refreshToken = process.env.ASB_REFRESH_TOKEN;
    if (!refreshToken) return res.status(400).json({ error: 'missing ASB_REFRESH_TOKEN' });

    const access = await refreshAccessToken(refreshToken);
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

app.get('/', (_, res) => res.send('💫 ASB Open Banking connector is running.'));
app.listen(process.env.PORT || 8080, () => console.log('✅ ASB connector running on port 8080'));
