// Webhook Pakasir — top up QRIS Wallet (POST /api/wallet-pakasir)
// Pasang URL ini di dashboard Pakasir (Project → Webhook URL):
//   https://wallet.clincoo.buzz/api/wallet-pakasir
// Secret: isi "Webhook Secret" di Pakasir = nilai PAKASIR_WEBHOOK_SECRET (Pages secret).
import { pakasirReady, pakasirFetch, pksStatus, claimAndCreditTopup } from './wallet.js';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Secret'
};
function j(data, status) {
  return new Response(JSON.stringify(data), { status: status || 200, headers: { 'Content-Type': 'application/json', ...CORS } });
}

export async function onRequestOptions() { return new Response(null, { status: 204, headers: CORS }); }

export async function onRequestPost({ request, env }) {
  const db = env.DB;
  if (!db) return j({ error: 'D1 not bound' }, 500);
  try {
    let body = {};
    try { body = await request.json(); } catch (e) { return j({ error: 'body JSON tidak valid' }, 400); }

    // secret webhook opsional: kalau PAKASIR_WEBHOOK_SECRET diset, header X-Secret wajib cocok
    if (env.PAKASIR_WEBHOOK_SECRET) {
      const sig = request.headers.get('x-secret') || '';
      if (sig !== env.PAKASIR_WEBHOOK_SECRET) return j({ error: 'unauthorized' }, 401);
    }
    if (!pakasirReady(env)) return j({ error: 'gateway tidak aktif' }, 503);

    const txnId = String(body.txn_id || '').trim();
    const orderId = String(body.order_id || '').trim();
    if (!txnId && !orderId) return j({ error: 'txn_id/order_id wajib diisi' }, 400);

    // cari order top up wallet: prioritas txn_ref provider, fallback order id internal
    let order = txnId ? await db.prepare('SELECT * FROM wallet_topups WHERE txn_ref = ?').bind(txnId).first() : null;
    if (!order && orderId) order = await db.prepare('SELECT * FROM wallet_topups WHERE id = ?').bind(orderId).first();
    if (!order) return j({ received: true, matched: false });

    // KEAMANAN: jangan percaya body webhook mentah — verifikasi ulang ke Pakasir
    // dengan API key sebelum kredisi saldo (kredisi tanpa konfirmasi provider DITOLAK)
    const completed = String(body.status || '').toLowerCase() === 'completed' || pksStatus(body.status) === 'paid';
    if (completed && order.status === 'pending' && order.txn_ref) {
      const d = await pakasirFetch(env, '/api/v2/transaction-status/' + encodeURIComponent(env.PAKASIR_SLUG) + '/' + encodeURIComponent(order.txn_ref), { method: 'GET' });
      if (!d.error && pksStatus(d.status) === 'paid') {
        await claimAndCreditTopup(db, env, order.id);
      }
    }
    return j({ received: true, matched: true });
  } catch (err) {
    return j({ error: err.message }, 500);
  }
}
