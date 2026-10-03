// Template email penarikan Wallet ClincooPay — FLAT (tanpa card): logo kiri atas,
// judul, tanggal WIB, sapaan, intro, detail label, CTA kapsul, footer seragam.
// Dipisah dari wallet.js supaya bisa diuji/dirender lokal dan dipakai ulang.

const LOGO = 'https://wallet.clincoo.buzz/logo.png';
const BRAND = 'ClincooPay';

function tglWIB() {
  return new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta', day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' }) + ' WIB';
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Wrapper FLAT seragam (pola disetujui: non-card, profesional, bersih).
// details = [[label, value]], extraCtas = [{text, link, kind:'dark'|'danger'}]
export function wdFlatTemplate(title, name, introHtml, details, ctaText, ctaLink, footerNote, extraCtas) {
  const sapaan = name ? ('Halo ' + esc(name) + ',') : 'Halo,';
  const rows = (details || []).map(function (d, i) {
    var border = i < details.length - 1 ? 'border-bottom:1px solid #eceef1;' : '';
    return '<tr>' +
      '<td style="padding:12px 0;' + border + 'color:#9ca3af;font-size:11px;font-weight:bold;letter-spacing:1px;text-transform:uppercase;white-space:nowrap;padding-right:16px">' + esc(d[0]) + '</td>' +
      '<td style="padding:12px 0;' + border + 'color:#111827;font-size:13px;font-weight:bold;text-align:right;word-break:break-word">' + d[1] + '</td>' +
    '</tr>';
  }).join('');
  const extras = (extraCtas || []).map(function (c) {
    const st = c.kind === 'danger'
      ? 'background:#ffffff;color:#b91c1c;border:2px solid #b91c1c;'
      : 'background:#ffffff;color:#0a0a0a;border:2px solid #0a0a0a;';
    return '<a href="' + esc(c.link) + '" style="display:inline-block;' + st + 'padding:11px 30px;border-radius:999px;text-decoration:none;font-size:13px;font-weight:bold;margin:12px 12px 0 0">' + esc(c.text) + '</a>';
  }).join('');
  const cta = (ctaText && ctaLink
    ? '<a href="' + esc(ctaLink) + '" style="display:inline-block;background:#0a0a0a;color:#ffffff;padding:13px 32px;border-radius:999px;text-decoration:none;font-size:13px;font-weight:bold;margin-top:24px">' + esc(ctaText) + '</a>'
    : '') + extras;
  return '<div style="background:#ffffff;padding:36px 24px;font-family:Arial,Helvetica,sans-serif">' +
    '<div style="max-width:520px;margin:0 auto">' +
      '<div style="padding-bottom:20px;border-bottom:1px solid #eceef1">' +
        '<img src="' + LOGO + '" width="36" height="36" alt="' + BRAND + '" style="display:inline-block;vertical-align:middle;border-radius:10px;margin-right:12px">' +
        '<span style="font-size:20px;font-weight:bold;letter-spacing:2px;color:#0a0a0a;vertical-align:middle">' + BRAND + '</span>' +
      '</div>' +
      '<h1 style="margin:28px 0 6px;font-size:18px;color:#111827;font-weight:bold">' + esc(title) + '</h1>' +
      '<p style="margin:0 0 18px;color:#9ca3af;font-size:12px">' + tglWIB() + '</p>' +
      '<p style="margin:0 0 12px;color:#374151;font-size:14px;line-height:1.7">' + sapaan + '</p>' +
      introHtml +
      (rows ? '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin:0 0 24px">' + rows + '</table>' : '') +
      cta +
      '<div style="margin-top:36px;border-top:1px solid #eceef1;padding-top:16px">' +
        (footerNote ? '<p style="margin:0 0 10px;color:#9ca3af;font-size:12px;line-height:1.6">' + esc(footerNote) + '</p>' : '') +
        '<p style="margin:0 0 10px;color:#9ca3af;font-size:11px;line-height:1.7">Butuh bantuan? Buka Pusat Bantuan di wallet.clincoo.buzz.</p>' +
        '<p style="margin:0 0 10px;color:#9ca3af;font-size:11px;line-height:1.7">Email ini dikirim otomatis oleh sistem ' + BRAND + '. ' + BRAND + ' tidak membagikan data pribadi Anda kepada pihak ketiga &mdash; mohon jangan dibalas.</p>' +
        '<p style="margin:0;color:#d1d5db;font-size:11px">&copy; 2026 ' + BRAND + ' &middot; Semua hak dilindungi</p>' +
      '</div>' +
    '</div>' +
  '</div>';
}

function rp(n) {
  return 'Rp ' + Number(n || 0).toLocaleString('id-ID');
}

function destLabel(t) {
  const m = { dana: 'DANA', ovo: 'OVO', gopay: 'GoPay', shopeepay: 'ShopeePay', bank: 'Bank' };
  return m[String(t || '').toLowerCase()] || String(t || '').toUpperCase();
}

// Detail bersama untuk email pemilik & admin. values sudah di-escape HTML-nya.
function wdDetails(w) {
  return [
    ['ID Penarikan', esc(w.id)],
    ['Nominal', esc(rp(w.amount))],
    ['Biaya penarikan', esc(rp(w.fee))],
    ['Total potong saldo', esc(rp(Number(w.amount) + Number(w.fee)))],
    ['Diterima pemilik', esc(rp(w.amount))],
    ['Tujuan', esc(destLabel(w.dest_type) + ' - ' + w.dest_account + (w.dest_name ? ' (' + w.dest_name + ')' : ''))]
  ];
}

function wdTextDetail(w) {
  const L = [];
  L.push('ID Penarikan: ' + w.id);
  L.push('Nominal: ' + rp(w.amount));
  L.push('Biaya penarikan: ' + rp(w.fee));
  L.push('Total potong saldo: ' + rp(Number(w.amount) + Number(w.fee)));
  L.push('Diterima pemilik: ' + rp(w.amount));
  L.push('Tujuan: ' + destLabel(w.dest_type) + ' - ' + w.dest_account + (w.dest_name ? ' (' + w.dest_name + ')' : ''));
  return L.join('\n');
}

// ===== Email ADMIN: permintaan baru (dengan tautan bertanda tangan) =====
// w = { id, address, amount, fee, dest_type, dest_account, dest_name }, sigs = { verify, done, rejected }
export function buildWdAdminEmail(w, sigs) {
  const rpA = rp(w.amount);
  const label = destLabel(w.dest_type);
  const subject = '[Permintaan Penarikan] ' + rpA + ' - ' + label + ' ' + w.dest_account + ' - ' + String(w.address || '').slice(0, 10) + '...';
  const text = [
    'Ada permintaan tarik saldo baru dari Wallet ClincooPay.',
    '',
    wdTextDetail(w),
    'Alamat dompet: ' + w.address,
    '',
    'Verifikasi cepat:',
    sigs.verify,
    '',
    '=== KONFIRMASI PENARIKAN (klik salah satu) ===',
    '',
    '1. Tandai Selesai - dana sudah dikirim ke tujuan:',
    sigs.done,
    '',
    '2. Tolak Penarikan - batalkan dan kembalikan saldo dompet:',
    sigs.rejected,
    '',
    'Tautan di atas bertanda tangan digital dan hanya berlaku untuk penarikan ini.'
  ].join('\n');
  const html = wdFlatTemplate(
    'Permintaan Penarikan Dana',
    'Admin',
    '<p style="margin:0 0 20px;color:#374151;font-size:14px;line-height:1.7">Ada permintaan tarik saldo baru dari Wallet ClincooPay yang menunggu konfirmasi Anda. Permintaan ini dibuat otomatis oleh server dan bertanda tangan digital — <b>jangan proses penarikan tanpa verifikasi tanda tangan</b> berikut.</p>' +
      '<p style="margin:0 0 20px;color:#9ca3af;font-size:11px;line-height:1.7">Tanda tangan digital (HMAC-SHA256) sudah terverifikasi pada tautan di bawah dan hanya berlaku untuk penarikan ini.</p>',
    wdDetails(w).concat([['Alamat Dompet', esc(String(w.address || '').slice(0, 14) + '...')]]),
    'Verifikasi Penarikan',
    sigs.verify,
    'Tautan di atas bertanda tangan digital dan hanya berlaku untuk penarikan ini.',
    [
      { text: 'Tandai Selesai', link: sigs.done },
      { text: 'Tolak Penarikan', link: sigs.rejected, kind: 'danger' }
    ]
  );
  return { subject: subject, html: html, text: text };
}

// ===== Email PEMILIK DOMPET: status penarikan =====
// stage: 'requested' | 'paid' | 'rejected'
export function buildWdOwnerEmail(w, stage, name) {
  const intro = (stage) => ({
    html: '',
    text: '',
    title: '',
    subject: '',
    status: '',
    footer: ''
  });
  if (stage === 'requested') {
    return {
      subject: 'Permintaan penarikan diterima (' + w.id + ')',
      html: wdFlatTemplate(
        'Permintaan Penarikan Diterima',
        name,
        '<p style="margin:0 0 20px;color:#374151;font-size:14px;line-height:1.7">Permintaan penarikan dana Anda sudah kami terima dan sedang diproses. Saldo dompet Anda sudah dipotong sesuai rincian di bawah — Anda bisa memantau statusnya di halaman Riwayat Dompet.</p>',
        wdDetails(w).concat([['Status', 'Diproses &mdash; menunggu konfirmasi tim']]),
        'Buka Dompet',
        'https://wallet.clincoo.buzz/',
        'Dana akan dikirim ke tujuan setelah permintaan diverifikasi tim ClincooPay.'
      ),
      text: [
        'Permintaan penarikan dana Anda sudah kami terima dan sedang diproses.',
        '',
        wdTextDetail(w),
        'Status: Diproses — menunggu konfirmasi tim',
        '',
        'Pantau statusnya di halaman Riwayat Dompet: https://wallet.clincoo.buzz/'
      ].join('\n')
    };
  }
  if (stage === 'paid') {
    return {
      subject: 'Penarikan ' + w.id + ' selesai',
      html: wdFlatTemplate(
        'Penarikan Selesai',
        name,
        '<p style="margin:0 0 20px;color:#374151;font-size:14px;line-height:1.7">Permintaan penarikan dana Anda telah diproses dan <b>dana sudah dikirim</b> ke tujuan. Berikut rincian penarikannya:</p>',
        wdDetails(w).concat([['Status', 'Selesai &mdash; dana terkirim']]),
        'Buka Dompet',
        'https://wallet.clincoo.buzz/',
        null
      ),
      text: [
        'Permintaan penarikan dana Anda telah diproses dan dana sudah dikirim ke tujuan.',
        '',
        wdTextDetail(w),
        'Status: Selesai — dana terkirim',
        '',
        'Lihat riwayatnya di https://wallet.clincoo.buzz/'
      ].join('\n')
    };
  }
  if (stage === 'rejected') {
    return {
      subject: 'Penarikan ' + w.id + ' ditolak — saldo dikembalikan',
      html: wdFlatTemplate(
        'Penarikan Ditolak',
        name,
        '<p style="margin:0 0 20px;color:#374151;font-size:14px;line-height:1.7">Permintaan penarikan dana Anda <b>ditolak</b> oleh tim ClincooPay, dan saldo (nominal + biaya) sudah <b>dikembalikan penuh</b> ke dompet Anda. Berikut rinciannya:</p>',
        wdDetails(w).concat([['Status', 'Ditolak &mdash; saldo dikembalikan']]),
        'Buka Dompet',
        'https://wallet.clincoo.buzz/',
        'Jika merasa ini keliru, hubungi tim ClincooPay lewat Pusat Bantuan.'
      ),
      text: [
        'Permintaan penarikan dana Anda ditolak, dan saldo (nominal + biaya) sudah dikembalikan penuh ke dompet Anda.',
        '',
        wdTextDetail(w),
        'Status: Ditolak — saldo dikembalikan',
        '',
        'Lihat riwayatnya di https://wallet.clincoo.buzz/'
      ].join('\n')
    };
  }
  return null;
}
