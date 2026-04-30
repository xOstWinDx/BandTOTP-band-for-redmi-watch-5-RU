const VAULT_VERSION = 5;
const KDF_NAME = "PIN-MIX-XOR-32";
const VAULT_INFO = "BandTOTP vault v5";
const PLAIN_PREFIX = "BTOTP5|";
const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_LOOKUP = {};

for (let i = 0; i < BASE64_ALPHABET.length; i++) {
  BASE64_LOOKUP[BASE64_ALPHABET.charAt(i)] = i;
}

function normalizeVault(vault) {
  if (!vault || typeof vault !== "object") {
    throw new Error("Пустое хранилище");
  }

  if (!vault.salt || !vault.ciphertext) {
    throw new Error("Поврежденное хранилище");
  }

  return {
    version: Number(vault.version) || VAULT_VERSION,
    kdf: vault.kdf || KDF_NAME,
    salt: vault.salt,
    ciphertext: vault.ciphertext
  };
}

function mixValue(value, charCode) {
  value = (value + charCode + ((value << 5) >>> 0)) >>> 0;
  value = (value ^ (value >>> 7) ^ ((value << 11) >>> 0)) >>> 0;
  return value >>> 0;
}

function deriveState(pin, salt) {
  const text = String(pin || "") + "|" + String(salt || "") + "|" + VAULT_INFO;
  const state = [0x13579bdf, 0x2468ace0, 0xf1e2d3c4, 0x89abcdef];

  for (let round = 0; round < 32; round++) {
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i) + round + i;
      const index = (round + i) & 3;
      state[index] = mixValue(state[index], code);
      state[(index + 1) & 3] = (state[(index + 1) & 3] ^ state[index]) >>> 0;
    }
  }

  return state;
}

function cryptBytes(bytes, pin, salt) {
  const state = deriveState(pin, salt);
  const result = new Array(bytes.length);

  for (let i = 0; i < bytes.length; i++) {
    const index = i & 3;
    let value = state[index];
    value = (value + 0x9e3779b9 + i) >>> 0;
    value = (value ^ ((value << 13) >>> 0)) >>> 0;
    value = (value ^ (value >>> 17)) >>> 0;
    value = (value ^ ((value << 5) >>> 0)) >>> 0;
    state[index] = value;
    result[i] = bytes[i] ^ ((value >>> ((i & 3) * 8)) & 0xff);
  }

  return result;
}

function utf8Encode(text) {
  const result = [];
  const value = String(text || "");

  for (let i = 0; i < value.length; i++) {
    let code = value.charCodeAt(i);

    if (code < 0x80) {
      result.push(code);
    } else if (code < 0x800) {
      result.push(0xc0 | (code >>> 6));
      result.push(0x80 | (code & 0x3f));
    } else {
      result.push(0xe0 | (code >>> 12));
      result.push(0x80 | ((code >>> 6) & 0x3f));
      result.push(0x80 | (code & 0x3f));
    }
  }

  return result;
}

function utf8Decode(bytes) {
  const chars = [];

  for (let i = 0; i < bytes.length; i++) {
    const first = bytes[i];

    if (first < 0x80) {
      chars.push(String.fromCharCode(first));
    } else if ((first & 0xe0) === 0xc0) {
      const second = bytes[++i];
      chars.push(String.fromCharCode(((first & 0x1f) << 6) | (second & 0x3f)));
    } else {
      const second = bytes[++i];
      const third = bytes[++i];
      chars.push(String.fromCharCode(((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f)));
    }
  }

  return chars.join("");
}

function bytesToBase64(bytes) {
  let result = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const first = bytes[i] & 0xff;
    const second = i + 1 < bytes.length ? bytes[i + 1] & 0xff : 0;
    const third = i + 2 < bytes.length ? bytes[i + 2] & 0xff : 0;
    const value = (first << 16) | (second << 8) | third;

    result += BASE64_ALPHABET.charAt((value >>> 18) & 63);
    result += BASE64_ALPHABET.charAt((value >>> 12) & 63);
    result += i + 1 < bytes.length ? BASE64_ALPHABET.charAt((value >>> 6) & 63) : "=";
    result += i + 2 < bytes.length ? BASE64_ALPHABET.charAt(value & 63) : "=";
  }
  return result;
}

function base64ToBytes(value) {
  const clean = String(value || "").replace(/\s/g, "");
  const result = [];

  for (let i = 0; i < clean.length; i += 4) {
    const first = BASE64_LOOKUP[clean.charAt(i)];
    const second = BASE64_LOOKUP[clean.charAt(i + 1)];
    const third = clean.charAt(i + 2) === "=" ? -1 : BASE64_LOOKUP[clean.charAt(i + 2)];
    const fourth = clean.charAt(i + 3) === "=" ? -1 : BASE64_LOOKUP[clean.charAt(i + 3)];

    if (first < 0 || second < 0) {
      throw new Error("Поврежденное хранилище");
    }

    const packed = (first << 18) | (second << 12) | ((third < 0 ? 0 : third) << 6) | (fourth < 0 ? 0 : fourth);
    result.push((packed >>> 16) & 0xff);
    if (third >= 0) {
      result.push((packed >>> 8) & 0xff);
    }
    if (fourth >= 0) {
      result.push(packed & 0xff);
    }
  }

  return result;
}

function decryptVault(vaultData, pin, callbacks) {
  let vault;
  try {
    vault = normalizeVault(vaultData);
    if (vault.kdf !== KDF_NAME) {
      throw new Error("Нужен повторный импорт");
    }

    const decrypted = cryptBytes(base64ToBytes(vault.ciphertext), pin, vault.salt);
    const text = utf8Decode(decrypted);
    if (text.indexOf(PLAIN_PREFIX) !== 0) {
      throw new Error("Неверный PIN");
    }

    callbacks.success(JSON.parse(text.slice(PLAIN_PREFIX.length)));
  } catch (error) {
    callbacks.fail(error);
  }
}

function encryptVault(data, pin, existingVault, callbacks) {
  try {
    const vault = normalizeVault(existingVault);
    const plain = utf8Encode(PLAIN_PREFIX + JSON.stringify(data || { list: [] }));
    callbacks.success({
      version: VAULT_VERSION,
      kdf: KDF_NAME,
      salt: vault.salt,
      ciphertext: bytesToBase64(cryptBytes(plain, pin, vault.salt))
    });
  } catch (error) {
    callbacks.fail(error);
  }
}

export { decryptVault, encryptVault };
