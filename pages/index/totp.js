var CryptoJS = require("crypto-js");

let timeOffset = 0;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY";
const POW10 = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000];

function nowSeconds() {
  return Math.floor(Date.now() / 1000) + (timeOffset || 0);
}

function normalizeBase32(value) {
  return String(value || "").toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
}

function base32ToWordArray(value) {
  const input = normalizeBase32(value);
  const words = [];
  let buffer = 0;
  let bitsLeft = 0;
  let byteCount = 0;

  for (let i = 0; i < input.length; i++) {
    const val = BASE32_ALPHABET.indexOf(input.charAt(i));
    if (val === -1) {
      throw new Error("Недопустимый символ Base32");
    }

    buffer = (buffer << 5) | val;
    bitsLeft += 5;

    if (bitsLeft >= 8) {
      const byteValue = (buffer >>> (bitsLeft - 8)) & 0xff;
      words[byteCount >>> 2] |= byteValue << (24 - (byteCount % 4) * 8);
      byteCount++;
      bitsLeft -= 8;
      buffer = bitsLeft ? buffer & ((1 << bitsLeft) - 1) : 0;
    }
  }

  if (!byteCount) {
    throw new Error("Пустой секрет");
  }

  return CryptoJS.lib.WordArray.create(words, byteCount);
}

function hexToWordArray(value) {
  return CryptoJS.enc.Hex.parse(String(value || ""));
}

function prepareSecret(secret, type) {
  if (secret && secret.words && typeof secret.sigBytes === "number") {
    return secret;
  }

  const value = String(secret || "").trim();
  if (/^[0-9a-f]{40}$/i.test(value) && type === "steam") {
    return hexToWordArray(value);
  }

  return base32ToWordArray(value);
}

function counterWordArray(period, atSeconds) {
  const counter = Math.floor((atSeconds || nowSeconds()) / (period || 30));
  return CryptoJS.lib.WordArray.create([0, counter], 8);
}

function wordArrayByteAt(wordArray, index) {
  return (wordArray.words[index >>> 2] >>> (24 - (index % 4) * 8)) & 0xff;
}

function hmacSha(message, secret, algorithm) {
  const normalized = String(algorithm || "SHA1").toUpperCase().replace(/[^A-Z0-9]/g, "");

  if (normalized === "SHA256" && CryptoJS.HmacSHA256) {
    return CryptoJS.HmacSHA256(message, secret);
  }

  if (normalized === "SHA512" && CryptoJS.HmacSHA512) {
    return CryptoJS.HmacSHA512(message, secret);
  }

  return CryptoJS.HmacSHA1(message, secret);
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

function generateTotp(secretWordArray, options = {}) {
  const period = Math.max(1, Number(options.period) || 30);
  const digits = Math.max(1, Math.min(Number(options.digits) || 6, 8));
  const hmac = hmacSha(counterWordArray(period, options.atSeconds), secretWordArray, options.algorithm);
  const offset = wordArrayByteAt(hmac, hmac.sigBytes - 1) & 0x0f;
  const binary =
    ((wordArrayByteAt(hmac, offset) & 0x7f) << 24) |
    (wordArrayByteAt(hmac, offset + 1) << 16) |
    (wordArrayByteAt(hmac, offset + 2) << 8) |
    wordArrayByteAt(hmac, offset + 3);

  return padCode(binary % POW10[digits], digits);
}

function generateSteamTotp(secretWordArray, atSeconds) {
  const hmac = CryptoJS.HmacSHA1(counterWordArray(30, atSeconds), secretWordArray);
  const offset = wordArrayByteAt(hmac, 19) & 0x0f;
  let codeValue =
    (((wordArrayByteAt(hmac, offset) & 0x7f) << 24) |
      (wordArrayByteAt(hmac, offset + 1) << 16) |
      (wordArrayByteAt(hmac, offset + 2) << 8) |
      wordArrayByteAt(hmac, offset + 3)) >>> 0;
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
