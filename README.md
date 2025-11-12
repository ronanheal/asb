# ASB Open Banking Connector (Render-ready)

Tiny Node/Express backend that handles mTLS + private_key_jwt to fetch **accounts, balances, and transactions** from ASB's Open Banking API. Intended to be called from Google Sheets.

## Deploy on Render
1) Push this folder to a new GitHub repo.
2) In Render → New → **Web Service** → Deploy from repo → Environment: **Docker**.
3) Add Environment Variables:
```
ASB_BASE = https://api.asb.io/v2.3/open-banking-nz
ASB_AUTH = https://asb.glueware.dev/oauth/v2.0
CLIENT_ID = <your client id>
REDIRECT_URI = https://<your-service>.onrender.com/auth/callback
OIDC_KID = <your key id>
API_KEY = <long random secret>
```
4) Add **Secret Files**:
   - `/etc/ssl/client_cert.pem`  → your mTLS client cert (PEM)
   - `/etc/ssl/client_key.pem`   → your mTLS client private key (PEM)
   - `/etc/keys/private_key.pem` → your private_key_jwt signing key (PEM)
5) Deploy → open `/auth/start` and approve. The callback shows a **refresh token**.
6) In Render → add env var `ASB_REFRESH_TOKEN = <paste>` → redeploy.

### Test
```
curl -H "x-api-key: <API_KEY>" https://<your-service>.onrender.com/sync
```

### Google Sheets (Apps Script)
Use this to fetch and write into your `Transactions` sheet:
```javascript
function onOpen() {
  SpreadsheetApp.getUi().createMenu('ASB Sync').addItem('Sync now', 'asbSync').addToUi();
}
function asbSync() {
  const url = 'https://<your-service>.onrender.com/sync';
  const resp = UrlFetchApp.fetch(url, {headers:{'x-api-key':'<YOUR_API_KEY>'}, muteHttpExceptions:true});
  if (resp.getResponseCode() !== 200) throw new Error(resp.getContentText());
  const payload = JSON.parse(resp.getContentText());
  const ss = SpreadsheetApp.getActive();
  const txSheet = ss.getSheetByName('Transactions');
  const rows = [];
  (payload.transactions || []).forEach(pack => {
    const list = (pack.Data && pack.Data.Transaction) || [];
    list.forEach(t => {
      const d = new Date(t.BookingDateTime || t.ValueDateTime || t.TransactionDateTime);
      const desc = t.MerchantName || t.TransactionInformation || '';
      const raw = parseFloat(t.Amount?.Amount || '0');
      const type = raw >= 0 ? 'Income' : 'Expense';
      const amount = Math.abs(raw);
      const month = new Date(d.getFullYear(), d.getMonth(), 1);
      rows.push([d, desc, '', pack.accountId, type, amount, month, '', '', 'Yes']);
    });
  });
  if (rows.length) {
    const start = Math.max(4, txSheet.getLastRow()+1);
    txSheet.getRange(start,1,rows.length,rows[0].length).setValues(rows);
  }
  SpreadsheetApp.getUi().alert(`ASB sync complete. Transactions added: ${rows.length}`);
}
```

### Notes
- Keep scopes minimal (`openid accounts`), permissions: `ReadAccountsBasic`, `ReadAccountsDetail`, `ReadBalances`, `ReadTransactionsDetail`.
- This skeleton does not build a signed `request` object; add it if ASB requires `ConsentId` in the authorisation request.
- Protect `/sync` with the `x-api-key` and/or Render's auth.
