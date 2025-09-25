// ===================== Helper: find username/password fields =====================
function findUserPassFields() {
  const pass = document.querySelector('input[type="password"]');
  if (!pass) return { user: null, pass: null };

  let user =
    document.querySelector(
      [
        // Prioritize Kibana's specific selector
        'input[data-test-subj="user-name"]',
        // Original selectors
        'input[name="username"]',
        'input[name="user"]',
        'input[name="email"]',
        'input[type="email"]',
        'input[type="text"][autocomplete="username"]',
        'input[autocomplete="email"]',
        'input[id="username-textfield"]',
      ].join(',')
    );

  if (!user) {
    console.info("Not found by specific selectors, trying generic fallback.");
    const inputs = Array.from(
      document.querySelectorAll('input[type="text"], input[type="email"], input:not([type])')
    );
    // pick nearest text-like input that appears before the password in the DOM
    user = inputs.reverse().find(el => el.compareDocumentPosition(pass) & Node.DOCUMENT_POSITION_FOLLOWING);
  }
  return { user, pass };
}

function getDomain() {
  return location.hostname;
}

// ===================== Master key RPC via background =====================
async function getMasterKey() {
  try {
    const { masterKey } = await chrome.runtime.sendMessage({ type: 'getMasterKey' });
    return masterKey || null;
  } catch {
    return null;
  }
}

// ===================== AES-GCM decrypt (username/password/otp secret) =====================
async function decryptIfNeededB64(masterKeyB64, objOrPlain) {
  // plain string
  if (!objOrPlain || typeof objOrPlain !== 'object' || !('cipher' in objOrPlain)) return objOrPlain;
  if (!masterKeyB64) return null; // cannot decrypt

  const keyRaw = Uint8Array.from(atob(masterKeyB64), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('raw', keyRaw, 'AES-GCM', false, ['decrypt']);
  const iv = Uint8Array.from(atob(objOrPlain.iv), c => c.charCodeAt(0));
  const data = Uint8Array.from(atob(objOrPlain.cipher), c => c.charCodeAt(0));
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  return new TextDecoder().decode(new Uint8Array(plain));
}

// ===================== TOTP (RFC 6238, SHA-1) =====================
function base32ToBytes(b32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = b32.replace(/[\s=]/g, '').toUpperCase();
  let bits = '';
  for (const c of clean) {
    const val = alphabet.indexOf(c);
    if (val < 0) throw new Error('Invalid base32 char');
    bits += val.toString(2).padStart(5, '0');
  }
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    out.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(out);
}
async function hmacSha1(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
  return new Uint8Array(sig);
}
async function totpNow(b32Secret, period = 30, digits = 6) {
  const counter = Math.floor(Date.now() / 1000 / period);
  const buf = new ArrayBuffer(8);
  new DataView(buf).setUint32(4, counter, false); // big-endian low 4 bytes
  const secret = base32ToBytes(b32Secret);
  const mac = await hmacSha1(secret, new Uint8Array(buf));
  const offset = mac[mac.length - 1] & 0x0f;
  const code =
    ((mac[offset] & 0x7f) << 24) |
    (mac[offset + 1] << 16) |
    (mac[offset + 2] << 8) |
    (mac[offset + 3]);
  const mod = 10 ** digits;
  return String(code % mod).padStart(digits, '0');
}

// ===================== OTP field finder (single input or 6-box inputs) =====================
function findOtpSingleField() {
  const sel = [
    'input[autocomplete="one-time-code"]',
    'input[name=otpCode]',
    'input[name*=otp i]', 'input[id*=otp i]',
    'input[name*=code i]', 'input[id*=code i]',
    'input[name*="2fa" i]', 'input[id*="2fa" i]',
    'input[type="tel"]',
    // 'input[type="text"]'
  ].join(',');

  const candidates = Array.from(document.querySelectorAll(sel))
    .filter(el => el.offsetParent !== null);

  // Prefer reasonable length fields (<= 8 chars)
  const shortlist = candidates.filter(el => (el.maxLength || 6) <= 8);
  if (shortlist.length === 1) return shortlist[0];
  if (shortlist.length > 1) {
    // Naive heuristic by proximity to text content
    const text = document.body.innerText.toLowerCase();
    return shortlist.sort((a, b) => {
      const na = (a.name || a.id || '').toLowerCase();
      const nb = (b.name || b.id || '').toLowerCase();
      const ax = text.indexOf(na || 'otp');
      const bx = text.indexOf(nb || 'otp');
      return (ax === -1 ? 1 : ax) - (bx === -1 ? 1 : bx);
    })[0];
  }
  return null;
}

function findOtpSegmentFields() {
  const inputs = Array.from(
    document.querySelectorAll('input[type="text"], input[type="tel"], input[autocomplete="one-time-code"]')
  ).filter(el => el.offsetParent !== null && el.maxLength === 1);
  // Group by siblings rows that look like OTP boxes (>= 4 small boxes)
  if (inputs.length < 4) return null;

  // Try to locate a contiguous sequence of 6 single-char inputs
  for (let i = 0; i < inputs.length; i++) {
    const seq = [inputs[i]];
    let parent = inputs[i].parentElement;
    // Collect subsequent siblings visually near
    for (let j = i + 1; j < inputs.length && seq.length < 6; j++) {
      if (inputs[j].parentElement === parent || inputs[j].closest('form') === inputs[i].closest('form')) {
        const rectA = seq[seq.length - 1].getBoundingClientRect();
        const rectB = inputs[j].getBoundingClientRect();
        const close = Math.abs(rectA.top - rectB.top) < 20 && Math.abs(rectA.left - rectB.left) < 200;
        if (close) seq.push(inputs[j]);
      }
    }
    if (seq.length >= 4) return seq.slice(0, 6); // prefer 6 but accept >=4
  }
  return null;
}

// ===================== Main =====================
(async function run() {
  const domain = getDomain();
  const { credentials = {}, settings = {} } = await chrome.storage.local.get(['credentials', 'settings']);
  const record = credentials[domain];
  if (!record) return;

  // ---------- Username / Password autofill ----------
  const tryFillLogin = async () => {
    const { user, pass } = findUserPassFields();
    if (!pass) {
      return false; // If no password field, can't do anything.
    }

    let username = record.username;
    let password = record.password;

    const mk = await getMasterKey();
    if (record.enc) {
      username = await decryptIfNeededB64(mk, record.username);
      password = await decryptIfNeededB64(mk, record.password);
      if (record.username && !username) {
        console.info('[Autofill Helper] Username is encrypted; unlock via options.');
      }
      if (record.password && !password) {
        console.info('[Autofill Helper] Password is encrypted; unlock via options.');
      }
    }
    if (user && typeof username === 'string' && username.length) {
      user.focus();
      user.value = username;
      user.dispatchEvent(new Event('input', { bubbles: true }));
      user.dispatchEvent(new Event('change', { bubbles: true }));
    }
    if (typeof password === 'string' && password.length) {
      pass.focus();
      pass.value = password;
      pass.dispatchEvent(new Event('input', { bubbles: true }));
      pass.dispatchEvent(new Event('change', { bubbles: true }));
    }

    if (settings.autoSubmit) {
      const form = pass.form || user?.form || document.querySelector('form');
      if (form) setTimeout(() => (form.requestSubmit ? form.requestSubmit() : form.submit()), 300);
    }
    
    console.log("Successfully found and filled login fields.");
    return true; // Signal success
  };

  // Attempt to fill login, if it fails, observe DOM for changes.
  // This is the same pattern your OTP fill uses.
  let loginFilled = await tryFillLogin();
  if (!loginFilled) {
    console.log("Login fields not found immediately. Observing DOM changes...");
    const loginObserver = new MutationObserver(async () => {
      if (await tryFillLogin()) {
        loginObserver.disconnect();
      }
    });
    loginObserver.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(() => {
        loginObserver.disconnect();
        console.log("Stopped observing for login fields after 10 seconds.");
    }, 10000);
  }


  // ---------- OTP (TOTP) autofill ----------
  if (record.otp) {
    const mk = await getMasterKey();
    const secret = await decryptIfNeededB64(mk, record.otp.secret);
    const digits = Number(record.otp.digits || 6);
    const period = Number(record.otp.period || 30);

    const tryFillOtp = async () => {
      if (!secret) return false;

      const code = await totpNow(String(secret), period, digits);

      // segmented inputs
      const seg = findOtpSegmentFields();
      if (seg && seg.length) {
        const chars = code.split('');
        seg.forEach((el, idx) => {
          const ch = chars[idx] || '';
          el.focus();
          el.value = ch;
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
        });
        if (settings.autoSubmit) {
          const btn = document.querySelector(
            'button[type="submit"], input[type="submit"], button[name*=verify i], button[id*=verify i]'
          );
          if (btn) setTimeout(() => btn.click(), 200);
        }
        return true;
      }

      // single input
      const input = findOtpSingleField();
      if (input) {
        input.focus();
        input.value = code;
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
        if (settings.autoSubmit) {
          const btn = document.querySelector(
            'button[type="submit"], input[type="submit"], button[name*=verify i], button[id*=verify i]'
          );
          if (btn) setTimeout(() => btn.click(), 200);
        }
        return true;
      }
      return false;
    };

    // first attempt + watch DOM changes for up to 10s
    let done = await tryFillOtp();
    if (!done) {
      const obs = new MutationObserver(async () => {
        if (await tryFillOtp()) obs.disconnect();
      });
      obs.observe(document.documentElement, { childList: true, subtree: true });
      setTimeout(() => obs.disconnect(), 10000);
    }
  }
})();
