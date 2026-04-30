var CryptoJS = require("crypto-js/core");
require("crypto-js/enc-base64");
require("crypto-js/enc-utf8");
require("crypto-js/aes");
require("crypto-js/pbkdf2");
require("crypto-js/hmac-sha256");

const VAULT_VERSION = 1;
const DEFAULT_ITERATIONS = 1800;

function wordArrayToBytes(wordArray) {
  const bytes = [];
  const sigBytes = wordArray.sigBytes || 0;

  for (let i = 0; i < sigBytes; i++) {
    bytes.push((wordArray.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff);
  }

  return bytes;
}

function bytesToWordArray(bytes) {
  const words = [];

  for (let i = 0; i < bytes.length; i++) {
    words[i >>> 2] |= bytes[i] << (24 - (i % 4) * 8);
  }

  return CryptoJS.lib.WordArray.create(words, bytes.length);
}

function deriveKeys(pin, saltBase64, iterations) {
  const salt = CryptoJS.enc.Base64.parse(saltBase64);
  const keyMaterial = CryptoJS.PBKDF2(String(pin || ""), salt, {
    keySize: 64 / 4,
    iterations: Number(iterations) || DEFAULT_ITERATIONS,
    hasher: CryptoJS.algo.SHA256
  });
  const bytes = wordArrayToBytes(keyMaterial);

  return {
    encKey: bytesToWordArray(bytes.slice(0, 32)),
    macKey: bytesToWordArray(bytes.slice(32, 64))
  };
}

function macPayload(vault) {
  return [
    vault.version,
    vault.kdf,
    vault.iterations,
    vault.salt,
    vault.iv,
    vault.ciphertext
  ].join("|");
}

function normalizeVault(vault) {
  if (!vault || typeof vault !== "object") {
    throw new Error("Пустое хранилище");
  }

  if (!vault.salt || !vault.iv || !vault.ciphertext || !vault.mac) {
    throw new Error("Поврежденное хранилище");
  }

  return {
    version: Number(vault.version) || VAULT_VERSION,
    kdf: vault.kdf || "PBKDF2-SHA256",
    iterations: Number(vault.iterations) || DEFAULT_ITERATIONS,
    salt: vault.salt,
    iv: vault.iv,
    ciphertext: vault.ciphertext,
    mac: vault.mac
  };
}

function decryptVault(vaultData, pin) {
  const vault = normalizeVault(vaultData);
  const keys = deriveKeys(pin, vault.salt, vault.iterations);
  const expectedMac = CryptoJS.HmacSHA256(macPayload(vault), keys.macKey).toString(CryptoJS.enc.Hex);

  if (expectedMac !== String(vault.mac || "").toLowerCase()) {
    throw new Error("Неверный PIN");
  }

  const cipherParams = CryptoJS.lib.CipherParams.create({
    ciphertext: CryptoJS.enc.Base64.parse(vault.ciphertext)
  });
  const decrypted = CryptoJS.AES.decrypt(cipherParams, keys.encKey, {
    iv: CryptoJS.enc.Base64.parse(vault.iv),
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });
  const text = decrypted.toString(CryptoJS.enc.Utf8);

  if (!text) {
    throw new Error("Неверный PIN");
  }

  return JSON.parse(text);
}

function encryptVault(data, pin, existingVault) {
  const salt = existingVault && existingVault.salt
    ? existingVault.salt
    : CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Base64);
  const iv = CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Base64);
  const iterations = existingVault && existingVault.iterations
    ? existingVault.iterations
    : DEFAULT_ITERATIONS;
  const keys = deriveKeys(pin, salt, iterations);
  const encrypted = CryptoJS.AES.encrypt(JSON.stringify(data || { list: [] }), keys.encKey, {
    iv: CryptoJS.enc.Base64.parse(iv),
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });
  const vault = {
    version: VAULT_VERSION,
    kdf: "PBKDF2-SHA256",
    iterations: iterations,
    salt: salt,
    iv: iv,
    ciphertext: encrypted.ciphertext.toString(CryptoJS.enc.Base64)
  };

  vault.mac = CryptoJS.HmacSHA256(macPayload(vault), keys.macKey).toString(CryptoJS.enc.Hex);
  return vault;
}

export { decryptVault, encryptVault };
