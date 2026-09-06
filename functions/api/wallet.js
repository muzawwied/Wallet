// Wallet API — ledger nyata di D1 (Cloudflare Pages Functions)
// POST /api/wallet {action:'init'|'send', ...}   GET /api/wallet?action=state&address=0x...


const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, x-wallet-secret'
};

function j(data, status) {
  return new Response(JSON.stringify(data), { status: status || 200, headers: { 'Content-Type': 'application/json', ...CORS } });
}

export async function onRequestOptions() { return new Response(null, { headers: CORS }); }

async function ensureSchema(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS wallet_accounts (
    address TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL,
    balance INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  )`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS wallet_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    txid TEXT NOT NULL,
    from_addr TEXT NOT NULL,
    to_addr TEXT NOT NULL,
    amount INTEGER NOT NULL,
    note TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_tx_from ON wallet_transactions (from_addr)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_tx_to ON wallet_transactions (to_addr)`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS wallet_notif_reads (
    addr TEXT NOT NULL,
    tx_id INTEGER NOT NULL,
    PRIMARY KEY (addr, tx_id)
  )`).run();
}

function sha256(text) {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(text)))
    .then(buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''));
}

const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;

export async function onRequestGet({ request, env }) {
  const db = env.DB;
  if (!db) return j({ error: 'D1 not bound' }, 500);
  try {
    await ensureSchema(db);
    const url = new URL(request.url);
    const address = (url.searchParams.get('addr') || url.searchParams.get('address') || '').toLowerCase();
    if (!ADDR_RE.test(address)) return j({ error: 'Alamat tidak valid' }, 400);

    // ---- notifikasi (transaksi terbaru sebagai notif, penanda dibaca per alamat) ----
    if (url.searchParams.get('action') === 'external_pull') {
      const acc0 = await db.prepare('SELECT address FROM wallet_accounts WHERE address = ?').bind(address).first();
      if (!acc0) return j({ success: true, data: { notifications: [] } });
      const rows = await db.prepare(
        'SELECT id, from_addr, to_addr, amount, note, created_at FROM wallet_transactions WHERE from_addr = ? OR to_addr = ? ORDER BY created_at DESC, id DESC LIMIT 30'
      ).bind(address, address).all();
      const reads = await db.prepare('SELECT tx_id FROM wallet_notif_reads WHERE addr = ?').bind(address).all();
      const readSet = new Set((reads.results || []).map(r => r.tx_id));
      const notifications = (rows.results || []).map(t => ({
        id: t.id,
        source: 'Wallet',
        message: (t.to_addr === address
          ? 'Menerima Rp ' + t.amount + ' dari 0x…' + t.from_addr.slice(-6)
          : 'Mengirim Rp ' + t.amount + ' ke 0x…' + t.to_addr.slice(-6)) + (t.note ? ' — ' + t.note : ''),
        read: readSet.has(t.id),
        created_at: t.created_at
      }));
      return j({ success: true, data: { notifications } });
    }

    const acc = await db.prepare('SELECT balance FROM wallet_accounts WHERE address = ?').bind(address).first();
    if (!acc) return j({ error: 'Akun tidak ditemukan', not_found: true }, 404);

    const txs = await db.prepare(
      'SELECT txid, from_addr, to_addr, amount, note, created_at FROM wallet_transactions WHERE from_addr = ? OR to_addr = ? ORDER BY created_at DESC, id DESC LIMIT 100'
    ).bind(address, address).all();

    const history = (txs.results || []).map(t => ({
      id: t.txid,
      type: t.to_addr === address ? 'masuk' : 'keluar',
      name: t.to_addr === address
        ? 'Dari 0x…' + t.from_addr.slice(-6)
        : 'Ke 0x…' + t.to_addr.slice(-6),
      peer: t.to_addr === address ? t.from_addr : t.to_addr,
      note: t.note || '',
      date: t.created_at,
      amount: t.amount
    }));

    return j({ success: true, address: address, balance: acc.balance, transactions: history });
  } catch (err) {
    return j({ error: err.message }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  const db = env.DB;
  if (!db) return j({ error: 'D1 not bound' }, 500);
  try {
    await ensureSchema(db);
    const body = await request.json();
    const action = body.action || '';

    // ---- init: klaim alamat baru (sekali, dapat secret) ----
    if (action === 'init') {
      const address = String(body.address || '').toLowerCase();
      if (!ADDR_RE.test(address)) return j({ error: 'Alamat tidak valid' }, 400);
      const existing = await db.prepare('SELECT address FROM wallet_accounts WHERE address = ?').bind(address).first();
      if (existing) {
        // alamat sudah diklaim: hanya valid kalau secret cocok
        const secretHash = await sha256(body.secret || '');
        const acc = await db.prepare('SELECT secret_hash FROM wallet_accounts WHERE address = ?').bind(address).first();
        if (body.secret && acc && acc.secret_hash === secretHash) return j({ success: true, balance: await getBalance(db, address) });
        return j({ error: 'Alamat ini sudah diklaim perangkat lain. Buat alamat baru.' }, 409);
      }
      const secret = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
      const secretHash = await sha256(secret);
      await db.prepare('INSERT INTO wallet_accounts (address, secret_hash, balance) VALUES (?, ?, 0)').bind(address, secretHash).run();
      return j({ success: true, secret: secret, balance: 0 });
    }

    // ---- send: transfer saldo antar alamat (double-entry) ----
    if (action === 'send') {
      const from = String(body.from || '').toLowerCase();
      const to = String(body.to || '').toLowerCase();
      const amount = Math.floor(Number(body.amount));
      const note = String(body.note || '').slice(0, 140);
      const secret = request.headers.get('x-wallet-secret') || body.secret || '';

      if (!ADDR_RE.test(from) || !ADDR_RE.test(to)) return j({ error: 'Alamat pengirim/penerima tidak valid' }, 400);
      if (from === to) return j({ error: 'Tidak bisa kirim ke alamat sendiri' }, 400);
      if (!amount || amount < 1000) return j({ error: 'Minimal kirim Rp 1.000' }, 400);

      const sender = await db.prepare('SELECT * FROM wallet_accounts WHERE address = ?').bind(from).first();
      if (!sender) return j({ error: 'Akun pengirim tidak ditemukan — muat ulang halaman.' }, 404);
      const secretHash = await sha256(secret);
      if (sender.secret_hash !== secretHash) return j({ error: 'Kunci dompet tidak cocok (perangkat ini bukan pemilik alamat).' }, 403);

      const receiver = await db.prepare('SELECT address FROM wallet_accounts WHERE address = ?').bind(to).first();
      if (!receiver) return j({ error: 'Alamat penerima belum terdaftar di Wallet.' }, 404);

      if (sender.balance < amount) return j({ error: 'Saldo tidak cukup. Saldo Anda ' + sender.balance + '.' }, 402);

      const txid = 'TX-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
      await db.prepare('INSERT INTO wallet_transactions (txid, from_addr, to_addr, amount, note) VALUES (?, ?, ?, ?, ?)')
        .bind(txid, from, to, amount, note).run();
      await db.prepare('UPDATE wallet_accounts SET balance = balance - ? WHERE address = ?').bind(amount, from).run();
      await db.prepare('UPDATE wallet_accounts SET balance = balance + ? WHERE address = ?').bind(amount, to).run();

      const newBal = await getBalance(db, from);
      return j({ success: true, txid: txid, balance: newBal });
    }

    // ---- tandai notifikasi dibaca ----
    if (action === 'external_read') {
      const addr = String(body.addr || '').toLowerCase();
      const txId = parseInt(body.id, 10);
      if (!ADDR_RE.test(addr) || !txId) return j({ error: 'Parameter tidak valid' }, 400);
      const acc = await db.prepare('SELECT address FROM wallet_accounts WHERE address = ?').bind(addr).first();
      if (!acc) return j({ error: 'Akun tidak ditemukan' }, 404);
      const tx = await db.prepare('SELECT id FROM wallet_transactions WHERE id = ? AND (from_addr = ? OR to_addr = ?)').bind(txId, addr, addr).first();
      if (!tx) return j({ error: 'Notifikasi tidak ditemukan' }, 404);
      await db.prepare('INSERT OR IGNORE INTO wallet_notif_reads (addr, tx_id) VALUES (?, ?)').bind(addr, txId).run();
      return j({ success: true });
    }

    return j({ error: 'unknown action' }, 400);
  } catch (err) {
    return j({ error: err.message }, 500);
  }
}

async function getBalance(db, address) {
  const r = await db.prepare('SELECT balance FROM wallet_accounts WHERE address = ?').bind(address).first();
  return r ? r.balance : 0;
}
