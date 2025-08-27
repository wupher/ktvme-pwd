// --- Helpers: Crypto with master passphrase (AES-GCM, 256-bit) ---
async function deriveKeyFromPass(pass) {
  const enc = new TextEncoder();
  const salt = enc.encode('autofill-helper:v1'); // fixed salt for personal use
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits', 'deriveKey']);
  return crypto.subtle.exportKey('raw', await crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 150000 },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  ));
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

// --- UI / Storage ---
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
  list: document.getElementById('list').querySelector('tbody')
};

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

function hostnameOf(h) {
  try { return new URL(h).hostname; } catch { return h.trim(); }
}

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
  const username = els.username.value;
  const password = els.password.value;
  const useEnc = els.encrypt.checked;

  if (!domain || !password) {
    alert('域名与密码必填（用户名可选）');
    return;
  }

  let record = {};
  if (useEnc) {
    const { masterKey } = await chrome.storage.session.get(['masterKey']);
    if (!masterKey) {
      alert('请先设置主口令再选择加密保存');
      return;
    }
    record = {
      enc: true,
      username: username ? await encryptText(masterKey, username) : { cipher: '', iv: '' },
      password: await encryptText(masterKey, password)
    };
  } else {
    record = { enc: false, username, password };
  }

  const { credentials = {} } = await chrome.storage.local.get(['credentials']);
  credentials[domain] = record;
  await chrome.storage.local.set({ credentials });
  els.username.value = '';
  els.password.value = '';
  renderList();
  alert('已保存/更新');
});

async function renderList() {
  const { credentials = {} } = await chrome.storage.local.get(['credentials']);
  els.list.innerHTML = '';
  Object.entries(credentials).forEach(([domain, rec]) => {
    const tr = document.createElement('tr');
    const mode = rec.enc ? '加密' : '明文';
    const uname = rec.enc
      ? (isEncryptedField(rec.username) ? '***（已加密）' : (rec.username || ''))
      : (rec.username || '');
    tr.innerHTML = `
      <td>${domain}</td>
      <td>${mode}</td>
      <td>${uname}</td>
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
    const rec = credentials[domain];
    if (rec && !rec.enc) {
      els.username.value = rec.username || '';
      els.password.value = rec.password || '';
      els.encrypt.checked = false;
    } else {
      els.username.value = '';
      els.password.value = '';
      els.encrypt.checked = true;
      alert('该条目为加密保存，不能在此直接查看明文。要更新请重新输入并保存。');
    }
  }
});

loadSettings();