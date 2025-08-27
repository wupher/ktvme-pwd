// Heuristics to find username & password fields
function findFields() {
  const password = document.querySelector('input[type="password"]');
  if (!password) return { user: null, pass: null };

  // Candidate username fields near the password
  // Try common selectors first
  let user =
    document.querySelector('input[name="username"], input[name="user"], input[name="email"], input[type="email"], input[type="text"][autocomplete="username"], input[autocomplete="email"]');

  // If not found, pick the closest text-like input before the password
  if (!user) {
    const inputs = Array.from(document.querySelectorAll('input[type="text"], input[type="email"], input:not([type])'));
    user = inputs.reverse().find(el => el.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING);
  }

  return { user, pass: password };
}

function getDomain(origin) {
  try {
    const u = new URL(origin);
    return u.hostname;
  } catch {
    return location.hostname;
  }
}

async function decryptIfNeeded(masterKeyB64, cipherObj) {
  if (!cipherObj || !cipherObj.cipher) return null;
  if (!masterKeyB64) return null; // cannot decrypt
  const keyRaw = Uint8Array.from(atob(masterKeyB64), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('raw', keyRaw, 'AES-GCM', false, ['decrypt']);
  const iv = Uint8Array.from(atob(cipherObj.iv), c => c.charCodeAt(0));
  const data = Uint8Array.from(atob(cipherObj.cipher), c => c.charCodeAt(0));
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  return new TextDecoder().decode(new Uint8Array(plain));
}

(async function run() {
  const domain = getDomain(location.origin);

  const { credentials = {}, settings = {} } = await chrome.storage.local.get(['credentials', 'settings']);
  const record = credentials[domain];
  if (!record) return; // not managed site

  // Try to get session master key (only kept until browser closes)
  // const session = await chrome.storage.session.get(['masterKey']);
  // const masterKey = session.masterKey || null;

  //向 background 请求 masterKey
  const { masterKey } = await chrome.runtime.sendMessage({ type: 'getMasterKey' });

  let username = record.username;
  let password = record.password;

  // If encrypted, decrypt
  if (record.enc) {
    username = await decryptIfNeeded(masterKey, record.username);
    password = await decryptIfNeeded(masterKey, record.password);
    if (!username || !password) {
      console.info('[Autofill Helper] This site is set to encrypted autofill. Unlock in options first.');
      return;
    }
  }

  const { user, pass } = findFields();
  if (!pass) return;

  if (user && username) {
    user.focus();
    user.value = username;
    user.dispatchEvent(new Event('input', { bubbles: true }));
    user.dispatchEvent(new Event('change', { bubbles: true }));
  }

  if (password) {
    pass.focus();
    pass.value = password;
    pass.dispatchEvent(new Event('input', { bubbles: true }));
    pass.dispatchEvent(new Event('change', { bubbles: true }));
  }

  // Optionally auto-submit if form is clear enough
  if (settings.autoSubmit) {
    const form = pass.form || user?.form || document.querySelector('form');
    if (form) {
      // Avoid premature submit if there are visible errors or MFA
      setTimeout(() => form.requestSubmit ? form.requestSubmit() : form.submit(), 300);
    }
  }
})();