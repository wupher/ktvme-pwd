#!/usr/bin/env node

const crypto = require('node:crypto');

function base32ToBytes(b32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(b32).replace(/[\s=]/g, '').toUpperCase();
  let bits = '';

  for (const c of clean) {
    const val = alphabet.indexOf(c);
    if (val < 0) throw new Error(`Invalid base32 char: ${c}`);
    bits += val.toString(2).padStart(5, '0');
  }

  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    out.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(out);
}

function totpNow(b32Secret, period = 30, digits = 6) {
  const counter = Math.floor(Date.now() / 1000 / period);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(counter, 4);

  const secret = base32ToBytes(b32Secret);
  const mac = crypto.createHmac('sha1', secret).update(buf).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const code =
    ((mac[offset] & 0x7f) << 24) |
    (mac[offset + 1] << 16) |
    (mac[offset + 2] << 8) |
    mac[offset + 3];

  return String(code % (10 ** digits)).padStart(digits, '0');
}

function main() {
  const secret = process.argv[2];

  if (!secret) {
    console.error('Usage: node totp.js <base32-secret>');
    process.exit(1);
  }

  try {
    process.stdout.write(`${totpNow(secret)}\n`);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

main();
