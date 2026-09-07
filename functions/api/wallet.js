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
  try { await db.prepare(`ALTER TABLE wallet_accounts ADD COLUMN role TEXT NOT NULL DEFAULT 'user'`).run(); } catch (e) {}
  await db.prepare(`CREATE TABLE IF NOT EXISTS google_pending_tokens (
    nonce TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    name TEXT,
    created_at DATETIME DEFAULT (datetime('now'))
  )`).run();
  try { await db.prepare(`ALTER TABLE google_pending_tokens ADD COLUMN picture TEXT`).run(); } catch (e) {}
  for (const col of ['email TEXT', 'pin_hash TEXT', 'pin_salt TEXT', 'display_name TEXT', 'failed_logins INTEGER NOT NULL DEFAULT 0', 'locked_until TEXT', 'picture TEXT']) {
    try { await db.prepare(`ALTER TABLE wallet_accounts ADD COLUMN ${col}`).run(); } catch (e) {}
  }
  await db.prepare(`CREATE TABLE IF NOT EXISTS wallet_notif_reads (
    addr TEXT NOT NULL,
    tx_id INTEGER NOT NULL,
    PRIMARY KEY (addr, tx_id)
  )`).run();
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function hashPin(pin, saltHex) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(pin)), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: hexToBytes(saltHex), iterations: 100000 }, key, 256);
  return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function randomAddress() {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return '0x' + [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomSecret() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
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
    if (url.searchParams.get('action') === 'ping') {
      return j({ ok: true, t: Date.now() });
    }
    if (url.searchParams.get('action') === 'google_config') {
      return j({ configured: !!env.GOOGLE_CLIENT_ID, client_id: env.GOOGLE_CLIENT_ID || '' });
    }

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

    const acc = await db.prepare('SELECT balance, display_name, email, picture FROM wallet_accounts WHERE address = ?').bind(address).first();
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

    return j({ success: true, address: address, balance: acc.balance, display_name: acc.display_name || '', email: acc.email || '', picture: acc.picture || '', transactions: history });
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

    // ===== GOOGLE AUTH: pilih akun Google → PIN (nonce server-side, 10 menit) =====
    async function getPendingNonce(nonceRaw) {
      if (!nonceRaw) return null;
      return await db.prepare("SELECT nonce, email, name, picture FROM google_pending_tokens WHERE nonce = ? AND created_at > datetime('now', '-10 minutes')").bind(String(nonceRaw)).first();
    }

    if (action === 'google_verify') {
      const cred = String(body.credential || '');
      if (!cred) return j({ error: 'Token Google kosong' }, 400);
      if (!env.GOOGLE_CLIENT_ID) return j({ error: 'Login Google belum dikonfigurasi di server' }, 503);
      let t;
      try {
        const r = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(cred));
        if (!r.ok) return j({ error: 'Token Google tidak valid' }, 401);
        t = await r.json();
      } catch (e) { return j({ error: 'Gagal memverifikasi ke Google' }, 502); }
      if (t.aud !== env.GOOGLE_CLIENT_ID) return j({ error: 'Verifikasi Google gagal (aud)' }, 401);
      if (String(t.email_verified) !== 'true' || !t.email) return j({ error: 'Email Google belum terverifikasi' }, 401);
      if (Number(t.exp) * 1000 < Date.now()) return j({ error: 'Token Google kedaluwarsa' }, 401);
      const email = String(t.email).toLowerCase();
      const name = String(t.name || '').slice(0, 60);
      const picture = String(t.picture || '').slice(0, 500);
      const acc = await db.prepare('SELECT address FROM wallet_accounts WHERE email = ?').bind(email).first();
      const nonce = randomSecret().slice(0, 48);
      await db.prepare('DELETE FROM google_pending_tokens WHERE email = ?').bind(email).run();
      await db.prepare("INSERT INTO google_pending_tokens (nonce, email, name, picture) VALUES (?, ?, ?, ?)").bind(nonce, email, name, picture).run();
      return j({ registered: !!acc, email: email, name: name, nonce: nonce });
    }

    if (action === 'google_login') {
      const row = await getPendingNonce(body.nonce);
      if (!row) return j({ error: 'Sesi Google kedaluwarsa — silakan mulai ulang' }, 401);
      const email = row.email;
      const pin = String(body.pin || '');
      const acc = await db.prepare('SELECT address, pin_hash, pin_salt, failed_logins, locked_until FROM wallet_accounts WHERE email = ?').bind(email).first();
      if (!acc || !acc.pin_hash || !acc.pin_salt) return j({ error: 'Akun tidak ditemukan — buat PIN dulu' }, 404);
      if (acc.locked_until && Date.now() < new Date(acc.locked_until + 'Z').getTime()) {
        return j({ error: 'Akun terkunci sementara. Coba lagi beberapa menit.' }, 423);
      }
      if ((await hashPin(pin, acc.pin_salt)) !== acc.pin_hash) {
        const fails = (acc.failed_logins || 0) + 1;
        if (fails >= 5) {
          await db.prepare("UPDATE wallet_accounts SET locked_until = datetime('now', '+15 minutes'), failed_logins = 0 WHERE address = ?").bind(acc.address).run();
          await db.prepare('DELETE FROM google_pending_tokens WHERE nonce = ?').bind(row.nonce).run();
          return j({ error: 'Terlalu banyak percobaan gagal. Akun terkunci 15 menit.' }, 423);
        }
        await db.prepare('UPDATE wallet_accounts SET failed_logins = ? WHERE address = ?').bind(fails, acc.address).run();
        return j({ error: 'PIN salah. Sisa percobaan: ' + (5 - fails) }, 401);
      }
      const secret = randomSecret();
      const secretHash = await sha256(secret);
      if (row.picture) {
        await db.prepare('UPDATE wallet_accounts SET secret_hash = ?, failed_logins = 0, locked_until = NULL, picture = ? WHERE address = ?').bind(secretHash, row.picture, acc.address).run();
      } else {
        await db.prepare('UPDATE wallet_accounts SET secret_hash = ?, failed_logins = 0, locked_until = NULL WHERE address = ?').bind(secretHash, acc.address).run();
      }
      const p = await db.prepare('SELECT display_name, picture FROM wallet_accounts WHERE address = ?').bind(acc.address).first();
      await db.prepare('DELETE FROM google_pending_tokens WHERE nonce = ?').bind(row.nonce).run();
      return j({ success: true, address: acc.address, secret: secret, display_name: (p && p.display_name) || '', picture: (p && p.picture) || '' });
    }

    if (action === 'google_register') {
      const row = await getPendingNonce(body.nonce);
      if (!row) return j({ error: 'Sesi Google kedaluwarsa — silakan mulai ulang' }, 401);
      const pin = String(body.pin || '');
      if (!/^\d{6}$/.test(pin)) return j({ error: 'PIN harus 6 digit angka' }, 400);
      const email = row.email;
      const taken = await db.prepare('SELECT address FROM wallet_accounts WHERE email = ?').bind(email).first();
      if (taken) return j({ error: 'Email sudah terdaftar — masuk dengan PIN Anda' }, 409);
      const pinSalt = [...new Uint8Array(16)].map(() => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');
      const pinHash = await hashPin(pin, pinSalt);
      const name = row.name || '';

      const bindAddr = String(body.address || '').toLowerCase();
      const devSecret = request.headers.get('x-wallet-secret') || '';
      if (bindAddr && ADDR_RE.test(bindAddr) && devSecret) {
        const acc = await db.prepare('SELECT secret_hash, email FROM wallet_accounts WHERE address = ?').bind(bindAddr).first();
        if (acc && acc.secret_hash === await sha256(devSecret) && !acc.email) {
          await db.prepare('UPDATE wallet_accounts SET email = ?, pin_hash = ?, pin_salt = ?, display_name = COALESCE(NULLIF(display_name, \'\'), ?), picture = ? WHERE address = ?')
            .bind(email, pinHash, pinSalt, name, row.picture || null, bindAddr).run();
          await db.prepare('DELETE FROM google_pending_tokens WHERE nonce = ?').bind(row.nonce).run();
          return j({ success: true, bound: true, address: bindAddr, picture: row.picture || '' });
        }
      }

      let address = randomAddress();
      while (await db.prepare('SELECT address FROM wallet_accounts WHERE address = ?').bind(address).first()) address = randomAddress();
      const secret = randomSecret();
      const secretHash = await sha256(secret);
      await db.prepare('INSERT INTO wallet_accounts (address, secret_hash, balance, role, email, pin_hash, pin_salt, display_name, picture) VALUES (?, ?, 0, ?, ?, ?, ?, ?, ?)')
        .bind(address, secretHash, 'user', email, pinHash, pinSalt, name || null, row.picture || null).run();
      await db.prepare('DELETE FROM google_pending_tokens WHERE nonce = ?').bind(row.nonce).run();
      return j({ success: true, address: address, secret: secret, picture: row.picture || '' });
    }

    // ===== AUTH: register / login / sinkron profile =====
    if (action === 'auth_register') {
      const email = String(body.email || '').trim().toLowerCase();
      const pin = String(body.pin || '');
      if (!EMAIL_RE.test(email)) return j({ error: 'Format email tidak valid' }, 400);
      if (!/^\d{6}$/.test(pin)) return j({ error: 'PIN harus 6 digit angka' }, 400);
      const taken = await db.prepare('SELECT address FROM wallet_accounts WHERE email = ?').bind(email).first();
      if (taken) return j({ error: 'Email sudah terdaftar — silakan masuk' }, 409);
      const pinSalt = [...new Uint8Array(16)].map(() => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');
      const pinHash = await hashPin(pin, pinSalt);

      // opsi 1: ikat email+PIN ke dompet yang sudah ada di perangkat ini (saldo tetap)
      const bindAddr = String(body.address || '').toLowerCase();
      const devSecret = request.headers.get('x-wallet-secret') || '';
      if (bindAddr && ADDR_RE.test(bindAddr) && devSecret) {
        const acc = await db.prepare('SELECT address, secret_hash, email FROM wallet_accounts WHERE address = ?').bind(bindAddr).first();
        if (acc && acc.secret_hash === await sha256(devSecret) && !acc.email) {
          await db.prepare('UPDATE wallet_accounts SET email = ?, pin_hash = ?, pin_salt = ? WHERE address = ?').bind(email, pinHash, pinSalt, bindAddr).run();
          return j({ success: true, bound: true, address: bindAddr });
        }
        if (acc && acc.email) return j({ error: 'Dompet ini sudah terikat ke email lain' }, 409);
      }

      // opsi 2: akun baru
      let address = randomAddress();
      while (await db.prepare('SELECT address FROM wallet_accounts WHERE address = ?').bind(address).first()) address = randomAddress();
      const secret = randomSecret();
      const secretHash = await sha256(secret);
      await db.prepare('INSERT INTO wallet_accounts (address, secret_hash, balance, role, email, pin_hash, pin_salt) VALUES (?, ?, 0, ?, ?, ?, ?)')
        .bind(address, secretHash, 'user', email, pinHash, pinSalt).run();
      return j({ success: true, address, secret });
    }

    if (action === 'auth_login') {
      const email = String(body.email || '').trim().toLowerCase();
      const pin = String(body.pin || '');
      const acc = await db.prepare('SELECT address, pin_hash, pin_salt, failed_logins, locked_until FROM wallet_accounts WHERE email = ?').bind(email).first();
      if (!acc) return j({ error: 'Email atau PIN salah' }, 401);
      if (acc.locked_until) {
        const lockUntil = new Date(acc.locked_until + 'Z').getTime();
        if (Date.now() < lockUntil) {
          const mins = Math.ceil((lockUntil - Date.now()) / 60000);
          return j({ error: 'Akun terkunci sementara. Coba lagi dalam ' + mins + ' menit.' }, 423);
        }
        await db.prepare('UPDATE wallet_accounts SET locked_until = NULL, failed_logins = 0 WHERE address = ?').bind(acc.address).run();
      }
      if (!acc.pin_hash || !acc.pin_salt) return j({ error: 'Akun ini belum punya PIN — daftar dulu' }, 400);
      const ok = (await hashPin(pin, acc.pin_salt)) === acc.pin_hash;
      if (!ok) {
        const fails = (acc.failed_logins || 0) + 1;
        if (fails >= 5) {
          await db.prepare("UPDATE wallet_accounts SET locked_until = datetime('now', '+15 minutes'), failed_logins = 0 WHERE address = ?").bind(acc.address).run();
          return j({ error: 'Terlalu banyak percobaan gagal. Akun terkunci 15 menit.' }, 423);
        }
        await db.prepare('UPDATE wallet_accounts SET failed_logins = ? WHERE address = ?').bind(fails, acc.address).run();
        return j({ error: 'Email atau PIN salah. Sisa percobaan: ' + (5 - fails) }, 401);
      }
      // sukses: rotasi kunci perangkat (sesi perangkat lama otomatis keluar)
      const secret = randomSecret();
      const secretHash = await sha256(secret);
      await db.prepare('UPDATE wallet_accounts SET secret_hash = ?, failed_logins = 0, locked_until = NULL WHERE address = ?').bind(secretHash, acc.address).run();
      return j({ success: true, address: acc.address, secret });
    }

    if (action === 'pin_verify') {
      const address = String(body.address || '').toLowerCase();
      const secret = String(request.headers.get('x-wallet-secret') || '');
      if (!ADDR_RE.test(address)) return j({ error: 'Alamat tidak valid' }, 400);
      const acc = await db.prepare('SELECT pin_hash, pin_salt, secret_hash, failed_logins, locked_until FROM wallet_accounts WHERE address = ?').bind(address).first();
      if (!acc) return j({ error: 'Akun tidak ditemukan' }, 404);
      if (!secret || (await sha256(secret)) !== acc.secret_hash) return j({ error: 'Sesi tidak valid — silakan masuk lagi' }, 401);
      if (acc.locked_until) {
        const lockUntil = new Date(acc.locked_until + 'Z').getTime();
        if (Date.now() < lockUntil) {
          const mins = Math.ceil((lockUntil - Date.now()) / 60000);
          return j({ error: 'Akun terkunci sementara. Coba lagi dalam ' + mins + ' menit.' }, 423);
        }
        await db.prepare('UPDATE wallet_accounts SET locked_until = NULL, failed_logins = 0 WHERE address = ?').bind(address).run();
      }
      if (!acc.pin_hash || !acc.pin_salt) return j({ error: 'Akun ini belum punya PIN — daftar dulu' }, 400);
      const pin = String(body.pin || '');
      if ((await hashPin(pin, acc.pin_salt)) !== acc.pin_hash) {
        const fails = (acc.failed_logins || 0) + 1;
        if (fails >= 5) {
          await db.prepare("UPDATE wallet_accounts SET locked_until = datetime('now', '+15 minutes'), failed_logins = 0 WHERE address = ?").bind(address).run();
          return j({ error: 'Terlalu banyak percobaan gagal. Akun terkunci 15 menit.' }, 423);
        }
        await db.prepare('UPDATE wallet_accounts SET failed_logins = ? WHERE address = ?').bind(fails, address).run();
        return j({ error: 'PIN salah. Sisa percobaan: ' + (5 - fails) }, 401);
      }
      await db.prepare('UPDATE wallet_accounts SET failed_logins = 0, locked_until = NULL WHERE address = ?').bind(address).run();
      return j({ success: true });
    }

    if (action === 'profile_set') {
      const address = String(body.address || '').toLowerCase();
      const name = String(body.display_name || '').trim().slice(0, 40);
      if (!ADDR_RE.test(address) || !name) return j({ error: 'Parameter tidak valid' }, 400);
      const secret = request.headers.get('x-wallet-secret') || '';
      const acc = await db.prepare('SELECT secret_hash FROM wallet_accounts WHERE address = ?').bind(address).first();
      if (!acc) return j({ error: 'Akun tidak ditemukan' }, 404);
      if (!secret || acc.secret_hash !== await sha256(secret)) return j({ error: 'Kunci dompet tidak cocok' }, 403);
      await db.prepare('UPDATE wallet_accounts SET display_name = ? WHERE address = ?').bind(name, address).run();
      return j({ success: true, display_name: name });
    }

    // ===== SISTEM ADMIN/OWNER (backend-only, digerbangi x-admin-secret dari env) =====
    const adminSecret = request.headers.get('x-admin-secret') || '';
    if (!env.ADMIN_SECRET || adminSecret !== env.ADMIN_SECRET) return j({ error: 'Akses admin ditolak' }, 403);

    if (action === 'admin_setup') {
      // Jadikan alamat = owner + seed saldo awal (untuk bootstrap transfer ke pengguna)
      const address = String(body.address || '').toLowerCase();
      const amount = Math.floor(Number(body.amount != null ? body.amount : 10000000));
      if (!ADDR_RE.test(address)) return j({ error: 'Alamat tidak valid' }, 400);
      if (!amount || amount <= 0) return j({ error: 'Jumlah seed tidak valid' }, 400);
      const ZERO = '0x' + '0'.repeat(40);

      const existing = await db.prepare('SELECT address FROM wallet_accounts WHERE address = ?').bind(address).first();
      const txid = 'ADM-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
      await db.prepare('INSERT INTO wallet_transactions (txid, from_addr, to_addr, amount, note) VALUES (?, ?, ?, ?, ?)')
        .bind(txid, ZERO, address, amount, 'Saldo awal owner (admin)').run();

      if (existing) {
        await db.prepare("UPDATE wallet_accounts SET role = 'owner', balance = balance + ? WHERE address = ?").bind(amount, address).run();
        return j({ success: true, role: 'owner', seeded: amount });
      }
      const secret = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
      const secretHash = await sha256(secret);
      await db.prepare("INSERT INTO wallet_accounts (address, secret_hash, balance, role) VALUES (?, ?, ?, 'owner')").bind(address, secretHash, amount).run();
      return j({ success: true, role: 'owner', seeded: amount, secret: secret });
    }

    if (action === 'admin_grant') {
      // Owner menambah saldo pengguna lain (muncul di riwayat penerima sebagai dana masuk)
      const to = String(body.to || '').toLowerCase();
      const amount = Math.floor(Number(body.amount));
      const note = String(body.note || 'Top-up dari owner').slice(0, 140);
      if (!ADDR_RE.test(to)) return j({ error: 'Alamat tidak valid' }, 400);
      if (!amount || amount <= 0) return j({ error: 'Jumlah tidak valid' }, 400);
      const target = await db.prepare('SELECT address FROM wallet_accounts WHERE address = ?').bind(to).first();
      if (!target) return j({ error: 'Alamat penerima belum terdaftar di Wallet.' }, 404);
      const ZERO = '0x' + '0'.repeat(40);
      const txid = 'ADM-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
      await db.prepare('INSERT INTO wallet_transactions (txid, from_addr, to_addr, amount, note) VALUES (?, ?, ?, ?, ?)')
        .bind(txid, ZERO, to, amount, note).run();
      await db.prepare('UPDATE wallet_accounts SET balance = balance + ? WHERE address = ?').bind(amount, to).run();
      return j({ success: true, granted: amount, to: to });
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
