import 'dotenv/config';
import express from 'express';
import axios from 'axios';
import https from 'https';
import crypto from 'crypto';
import { SignJWT, importPKCS8 } from 'jose';
import fs from 'fs/promises';

const cfg = {
  base: process.env.ASB_BASE,
  auth: process.env.ASB_AUTH,
  clientId: process.env.CLIENT_ID,
  redirect: process.env.REDIRECT_URI,
  mtlsCert: process.env.MTLS_CERT,
  mtlsKey: process.env.MTLS_KEY,
  oidcPk: process.env.OIDC_PRIVATE_KEY,
  oidcKid: process.env.OIDC_KID,
  apiKey: process.env.API_KEY
};

if (!cfg.base || !cfg.auth || !cfg.clientId || !cfg.redirect) {
  console.error("Missing mandatory environment variables. Check .env.example");
  process.exit(1);
}

const app = express();
app.use(express.json());

const mtlsAgent = new https.Agent({
  cert: await fs.readFile(cfg.mtlsCert),
  key:  await fs.readFile(cfg.mtlsKey)
});

async function clientAssertion(aud) {
  const pkcs8 = await fs.readFile(cfg.oidcPk, 'utf8');
  const alg = 'PS256';
  const key = await importPKCS8(pkcs8, alg);
  const now = Math.floor(Date.now()/1000);
  return await new SignJWT({})
    .setProtectedHeader({ alg, kid: cfg.oidcKid, typ: 'JWT' })
    .setIssuer(cfg.clientId)
    .setSubject(cfg.clientId)
    .setAudience(aud)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(key);
}

app.get('/auth/start', async (req,res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  const url = new URL(`${cfg.auth}/authorize`);
  url.searchParams.set('client_id', cfg.clientId);
  url.searchParams.set('redirect_uri', cfg.redirect);
  url.searchParams.set('response_type', 'code id_token');
  url.searchParams.set('scope', 'openid accounts');
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  return res.redirect(url.toString());
});

app.get('/auth/callback', async (req,res) => {
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
      headers: {'Content-Type':'application/x-www-form-urlencoded'}
    });
    res.status(200).send(`Copy this REFRESH TOKEN and save it as ASB_REFRESH_TOKEN in Render:<br><br><code style="word-break:break-all">${data.refresh_token}</code>`);
  } catch (e) {
    res.status(500).send(`Auth error: ${e.response?.data ? JSON.stringify(e.response.data) : e.message}`);
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
    headers: {'Content-Type':'application/x-www-form-urlencoded'}
  });
  return data.access_token;
}

app.get('/sync', async (req,res) => {
  try {
    if (req.header('x-api-key') !== cfg.apiKey) return res.status(401).json({error:'unauthorized'});
    const refreshToken = process.env.ASB_REFRESH_TOKEN;
    if (!refreshToken) return res.status(400).json({error:'missing ASB_REFRESH_TOKEN'});

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
      const tx  = await asb.get(`/accounts/${id}/transactions`);
      balances.push({ accountId: id, ...bal.data });
      transactions.push({ accountId: id, ...tx.data });
    }

    res.json({ accounts, balances, transactions });
  } catch (e) {
    res.status(500).json({ error: e.response?.data || e.message });
  }
});

app.get('/', (req,res)=>res.send('ASB Open Banking connector is running.'));
app.listen(process.env.PORT || 8080, () => console.log('ASB connector running on port 8080'));
