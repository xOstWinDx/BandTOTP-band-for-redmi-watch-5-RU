let timeOffset = 0;

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY";
const POW10 = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000];
const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

function nowSeconds() {
  return Math.floor(Date.now() / 1000) + (timeOffset || 0);
}

function normalizeBase32(value) {
  return String(value || "").toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
}

function base32ToBytes(value) {
  const input = normalizeBase32(value);
  const bytes = [];
  let buffer = 0;
  let bitsLeft = 0;

  for (let i = 0; i < input.length; i++) {
    const val = BASE32_ALPHABET.indexOf(input.charAt(i));
    if (val === -1) {
      throw new Error("Недопустимый символ Base32");
    }

    buffer = (buffer << 5) | val;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bytes.push((buffer >>> (bitsLeft - 8)) & 0xff);
      bitsLeft -= 8;
      buffer = bitsLeft ? buffer & ((1 << bitsLeft) - 1) : 0;
    }
  }

  if (!bytes.length) {
    throw new Error("Пустой секрет");
  }

  return bytes;
}

function hexToBytes(value) {
  const text = String(value || "");
  const result = [];
  for (let i = 0; i < text.length; i += 2) {
    result.push(parseInt(text.substr(i, 2), 16) & 0xff);
  }
  return result;
}

function prepareSecret(secret, type) {
  if (secret && secret.length && typeof secret[0] === "number") {
    return secret;
  }

  const value = String(secret || "").trim();
  if (/^[0-9a-f]{40}$/i.test(value) && type === "steam") {
    return hexToBytes(value);
  }

  return base32ToBytes(value);
}

function counterBytes(period, atSeconds) {
  const counter = Math.floor((atSeconds || nowSeconds()) / (period || 30));
  return [0, 0, 0, 0, (counter / 0x1000000) & 0xff, (counter >>> 16) & 0xff, (counter >>> 8) & 0xff, counter & 0xff];
}

function rotl(value, bits) {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

function rotr(value, bits) {
  return ((value >>> bits) | (value << (32 - bits))) >>> 0;
}

function wordsToBytes(words, count) {
  const result = [];
  for (let i = 0; i < count; i++) {
    result.push((words[i >>> 2] >>> (24 - (i & 3) * 8)) & 0xff);
  }
  return result;
}

function sha1(bytes) {
  const bitLength = bytes.length * 8;
  const padded = bytes.slice(0);
  padded.push(0x80);
  while ((padded.length & 63) !== 56) {
    padded.push(0);
  }
  for (let i = 7; i >= 0; i--) {
    padded.push((bitLength / Math.pow(256, i)) & 0xff);
  }

  const w = [];
  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] = ((padded[j] << 24) | (padded[j + 1] << 16) | (padded[j + 2] << 8) | padded[j + 3]) >>> 0;
    }
    for (let i = 16; i < 80; i++) {
      w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;

    for (let i = 0; i < 80; i++) {
      let f;
      let k;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }

      const temp = (rotl(a, 5) + f + e + k + w[i]) >>> 0;
      e = d;
      d = c;
      c = rotl(b, 30);
      b = a;
      a = temp;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  return wordsToBytes([h0, h1, h2, h3, h4], 20);
}

function sha256(bytes) {
  const bitLength = bytes.length * 8;
  const padded = bytes.slice(0);
  padded.push(0x80);
  while ((padded.length & 63) !== 56) {
    padded.push(0);
  }
  for (let i = 7; i >= 0; i--) {
    padded.push((bitLength / Math.pow(256, i)) & 0xff);
  }

  const w = [];
  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] = ((padded[j] << 24) | (padded[j + 1] << 16) | (padded[j + 2] << 8) | padded[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + s1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  return wordsToBytes([h0, h1, h2, h3, h4, h5, h6, h7], 32);
}

function hmacSha(message, secret, algorithm) {
  const normalized = String(algorithm || "SHA1").toUpperCase().replace(/[^A-Z0-9]/g, "");
  const hash = normalized === "SHA256" ? sha256 : sha1;
  let key = secret;

  if (normalized === "SHA512") {
    throw new Error("SHA512 не поддерживается на часах");
  }

  if (key.length > 64) {
    key = hash(key);
  }

  const inner = [];
  const outer = [];
  for (let i = 0; i < 64; i++) {
    const value = key[i] || 0;
    inner.push(value ^ 0x36);
    outer.push(value ^ 0x5c);
  }

  return hash(outer.concat(hash(inner.concat(message))));
}

function padCode(code, digits) {
  const targetLength = Math.max(1, Math.min(digits || 6, 8));
  let value = String(code);

  while (value.length < targetLength) {
    value = "0" + value;
  }

  return value;
}

function createTotpGenerator(secret, options = {}) {
  const type = String(options.type || "").toLowerCase();
  const preparedSecret = prepareSecret(secret, type);
  const period = Math.max(1, Number(options.period) || 30);
  const digits = Math.max(1, Math.min(Number(options.digits) || 6, 8));
  const algorithm = options.algorithm || "SHA1";

  if (type === "steam") {
    return function generateSteamCode(atSeconds) {
      return generateSteamTotp(preparedSecret, atSeconds);
    };
  }

  return function generateTotpCode(atSeconds) {
    return generateTotp(preparedSecret, {
      algorithm: algorithm,
      digits: digits,
      period: period,
      atSeconds: atSeconds
    });
  };
}

function dynamicBinaryCode(hmac) {
  const offset = hmac[hmac.length - 1] & 0x0f;
  return (
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3]
  ) >>> 0;
}

function generateTotp(secretBytes, options = {}) {
  const period = Math.max(1, Number(options.period) || 30);
  const digits = Math.max(1, Math.min(Number(options.digits) || 6, 8));
  const hmac = hmacSha(counterBytes(period, options.atSeconds), secretBytes, options.algorithm);
  return padCode(dynamicBinaryCode(hmac) % POW10[digits], digits);
}

function generateSteamTotp(secretBytes, atSeconds) {
  let codeValue = dynamicBinaryCode(hmacSha(counterBytes(30, atSeconds), secretBytes, "SHA1"));
  let code = "";

  for (let i = 0; i < 5; i++) {
    code += STEAM_ALPHABET.charAt(codeValue % STEAM_ALPHABET.length);
    codeValue = Math.floor(codeValue / STEAM_ALPHABET.length);
  }

  return code;
}

function TOTP(secret, options = {}) {
  return generateTotp(prepareSecret(secret), options);
}

function SteamTotp(secret) {
  return generateSteamTotp(prepareSecret(secret, "steam"));
}

export { TOTP, SteamTotp, createTotpGenerator, nowSeconds, normalizeBase32, timeOffset };
