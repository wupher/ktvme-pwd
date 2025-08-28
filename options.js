// ===================== Crypto helpers (AES-GCM, PBKDF2) =====================
async function deriveKeyFromPass(pass) {
  const enc = new TextEncoder();
  const salt = enc.encode('autofill-helper:v1'); // fixed salt for personal use
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits', 'deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 150000 },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  return crypto.subtle.exportKey('raw', key); // ArrayBuffer
}
async function exportB64Key(rawKey) {
  return btoa(String.fromCharCode(...new Uint8Array(rawKey)));
}
async function encryptText(masterKeyB64, text) {
  const keyRaw = Uint8Array.from(atob(masterKeyB64), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('raw', keyRaw, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
  return {
    iv: btoa(String.fromCharCode(...iv)),
    cipher: btoa(String.fromCharCode(...new Uint8Array(enc)))
  };
}
function isEncryptedField(v) {
  return v && typeof v === 'object' && 'cipher' in v && 'iv' in v;
}

// ===================== Elements =====================
const els = {
  autoSubmit: document.getElementById('autoSubmit'),
  masterPass: document.getElementById('masterPass'),
  setMaster: document.getElementById('setMaster'),
  clearMaster: document.getElementById('clearMaster'),

  domain: document.getElementById('domain'),
  username: document.getElementById('username'),
  password: document.getElementById('password'),
  encrypt: document.getElementById('encrypt'),
  save: document.getElementById('save'),

  otpSecret: document.getElementById('otpSecret'),
  otpDigits: document.getElementById('otpDigits'),
  otpPeriod: document.getElementById('otpPeriod'),
  otpEncrypt: document.getElementById('otpEncrypt'),
  otpTest: document.getElementById('otpTest'),

  list: document.getElementById('list').querySelector('tbody')
};

function hostnameOf(h) {
  try { return new URL(h).hostname; } catch { return (h || '').trim(); }
}

// ===================== Init / Load =====================
async function loadSettings() {
  const { settings = {} } = await chrome.storage.local.get(['settings']);
  els.autoSubmit.checked = !!settings.autoSubmit;

  // Prefill domain from context menu
  const session = await chrome.storage.session.get(['lastDomain']);
  if (session.lastDomain && !els.domain.value) {
    els.domain.value = session.lastDomain;
    await chrome.storage.session.remove('lastDomain');
  }

  renderList();
}

// ===================== Event handlers =====================
els.autoSubmit.addEventListener('change', async () => {
  const { settings = {} } = await chrome.storage.local.get(['settings']);
  settings.autoSubmit = els.autoSubmit.checked;
  await chrome.storage.local.set({ settings });
});

els.setMaster.addEventListener('click', async () => {
  const pass = els.masterPass.value.trim();
  if (!pass) { alert('请输入主口令'); return; }
  const raw = await deriveKeyFromPass(pass);
  const b64 = await exportB64Key(raw);
  await chrome.storage.session.set({ masterKey: b64 });
  alert('主口令已设置（仅本次浏览器会话有效）');
});

els.clearMaster.addEventListener('click', async () => {
  await chrome.storage.session.remove('masterKey');
  els.masterPass.value = '';
  alert('主口令已清除');
});

els.save.addEventListener('click', async () => {
  const domain = hostnameOf(els.domain.value);
  if (!domain) { alert('请填写域名'); return; }

  const username = els.username.value;
  const password = els.password.value;
  const useEnc = els.encrypt.checked;

  const otpSecret = els.otpSecret.value.trim();
  const otpDigits = parseInt(els.otpDigits.value || '6', 10);
  const otpPeriod = parseInt(els.otpPeriod.value || '30', 10);
  const otpUseEnc = els.otpEncrypt.checked;

  // Build username/password record
  let recUP;
  if (useEnc) {
    const { masterKey } = await chrome.storage.session.get(['masterKey']);
    if (!masterKey) { alert('请先设置主口令再选择加密保存'); return; }
    recUP = {
      enc: true,
      username: username ? await encryptText(masterKey, username) : { cipher: '', iv: '' },
      password: password ? await encryptText(masterKey, password) : { cipher: '', iv: '' }
    };
  } else {
    recUP = {
      enc: false,
      username: username || '',
      password: password || ''
    };
  }

  // Build OTP record (optional)
  let recOTP = null;
  if (otpSecret) {
    if (otpUseEnc) {
      const { masterKey } = await chrome.storage.session.get(['masterKey']);
      if (!masterKey) { alert('请先设置主口令再选择加密保存 OTP'); return; }
      recOTP = { enc: true, secret: await encryptText(masterKey, otpSecret), digits: otpDigits, period: otpPeriod };
    } else {
      recOTP = { enc: false, secret: otpSecret, digits: otpDigits, period: otpPeriod };
    }
  }

  const { credentials = {} } = await chrome.storage.local.get(['credentials']);
  const old = credentials[domain] || {};
  const merged = {
    // username/password section
    enc: recUP.enc,
    username: recUP.username,
    password: recUP.password,
    // keep other possible fields, then overwrite otp
    ...old,
    otp: recOTP // may be null to clear OTP if empty
  };
  credentials[domain] = merged;
  await chrome.storage.local.set({ credentials });

  // Clear only sensitive input fields in the UI
  els.password.value = '';
  if (!otpUseEnc) {
    // keep visible for testing if you want; here we don't clear to allow Test
  }
  alert('已保存/更新');
  renderList();
});

// Test current OTP
els.otpTest.addEventListener('click', async () => {
  const b32 = els.otpSecret.value.trim();
  const digits = parseInt(els.otpDigits.value || '6', 10);
  const period = parseInt(els.otpPeriod.value || '30', 10);
  if (!b32) { alert('请输入 Base32 OTP 密钥'); return; }

  const code = await (async function totpNowLocal(b32Secret, period, digits) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const clean = b32Secret.replace(/[\s=]/g, '').toUpperCase();
    let bits = '';
    for (const c of clean) {
      const v = alphabet.indexOf(c); if (v < 0) throw new Error('Base32 无效字符');
      bits += v.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
    const secret = new Uint8Array(bytes);
    const counter = Math.floor(Date.now() / 1000 / period);
    const buf = new ArrayBuffer(8);
    new DataView(buf).setUint32(4, counter, false);
    const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, new Uint8Array(buf)));
    const off = sig[sig.length - 1] & 0x0f;
    const codeNum = ((sig[off] & 0x7f) << 24) | (sig[off + 1] << 16) | (sig[off + 2] << 8) | sig[off + 3];
    const mod = 10 ** digits;
    return String(codeNum % mod).padStart(digits, '0');
  })(b32, period, digits);

  alert(`当前验证码：${code}\n（每 ${period}s 变更一次）`);
});

// ===================== Render list =====================
async function renderList() {
  const { credentials = {} } = await chrome.storage.local.get(['credentials']);
  els.list.innerHTML = '';
  Object.entries(credentials).forEach(([domain, rec]) => {
    const mode = rec.enc ? '加密' : '明文';
    const uname = rec.enc
      ? (isEncryptedField(rec.username) ? '***（已加密）' : (rec.username || ''))
      : (rec.username || '');
    const otpMode = rec.otp ? (rec.otp.enc ? '加密' : '明文') : '—';

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${domain}</td>
      <td>${mode}</td>
      <td>${uname}</td>
      <td>${otpMode}</td>
      <td>
        <button data-domain="${domain}" data-act="fill">填入域名</button>
        <button data-domain="${domain}" data-act="delete">删除</button>
      </td>
    `;
    els.list.appendChild(tr);
  });
}

els.list.addEventListener('click', async (e) => {
  const btn = e.target.closest('button'); if (!btn) return;
  const domain = btn.dataset.domain;
  const act = btn.dataset.act;

  if (act === 'delete') {
    const { credentials = {} } = await chrome.storage.local.get(['credentials']);
    delete credentials[domain];
    await chrome.storage.local.set({ credentials });
    renderList();
  } else if (act === 'fill') {
    els.domain.value = domain;
    const { credentials = {} } = await chrome.storage.local.get(['credentials']);
    const rec = credentials[domain] || {};

    // username/password
    if (rec.enc) {
      els.username.value = '';
      els.password.value = '';
      els.encrypt.checked = true;
    } else {
      els.username.value = rec.username || '';
      els.password.value = rec.password || '';
      els.encrypt.checked = false;
    }

    // otp
    if (rec.otp) {
      if (rec.otp.enc) {
        els.otpSecret.value = '';
        els.otpDigits.value = rec.otp.digits || 6;
        els.otpPeriod.value = rec.otp.period || 30;
        els.otpEncrypt.checked = true;
        alert('该域名的 OTP 为加密保存，无法在此查看明文。若需修改，请重新输入并保存。');
      } else {
        els.otpSecret.value = rec.otp.secret || '';
        els.otpDigits.value = rec.otp.digits || 6;
        els.otpPeriod.value = rec.otp.period || 30;
        els.otpEncrypt.checked = false;
      }
    } else {
      els.otpSecret.value = '';
      els.otpDigits.value = 6;
      els.otpPeriod.value = 30;
      els.otpEncrypt.checked = false;
    }
  }
});

// ===================== Go =====================
loadSettings();