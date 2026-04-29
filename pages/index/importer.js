const DEFAULT_NAME = "TOTP";

function safeJsonParse(value) {
  if (typeof value !== "string") {
    return value;
  }

  let current = value.trim();
  for (let i = 0; i < 2; i++) {
    if (!current) {
      return current;
    }

    try {
      const parsed = JSON.parse(current);
      if (typeof parsed !== "string") {
        return parsed;
      }
      current = parsed.trim();
    } catch (error) {
      return value;
    }
  }

  return current;
}

function decodeText(value) {
  try {
    return decodeURIComponent(String(value || "").replace(/\+/g, "%20"));
  } catch (error) {
    return String(value || "");
  }
}

function readQuery(query) {
  const result = {};
  const parts = String(query || "").split("&");

  for (let i = 0; i < parts.length; i++) {
    if (!parts[i]) {
      continue;
    }

    const pair = parts[i].split("=");
    result[decodeText(pair[0])] = decodeText(pair.slice(1).join("="));
  }

  return result;
}

function splitLabel(label) {
  const decoded = decodeText(label || "");
  const index = decoded.indexOf(":");

  if (index === -1) {
    return {
      name: decoded || DEFAULT_NAME,
      usr: ""
    };
  }

  return {
    name: decoded.slice(0, index) || DEFAULT_NAME,
    usr: decoded.slice(index + 1)
  };
}

function normalizeAlgorithm(value) {
  const normalized = String(value || "SHA1").toUpperCase().replace("ALGORITHM_", "");

  if (normalized === "SHA256" || normalized === "SHA512") {
    return normalized;
  }

  return "SHA1";
}

function normalizeDigits(value) {
  const raw = String(value || "").toUpperCase();

  if (raw.indexOf("EIGHT") !== -1 || raw === "8") {
    return 8;
  }

  return 6;
}

function normalizePeriod(value) {
  const period = Number(value);
  return period > 0 ? Math.floor(period) : 30;
}

function normalizeType(value, name, issuer) {
  const raw = String(value || "").toLowerCase();
  const title = (String(name || "") + " " + String(issuer || "")).toLowerCase();

  if (raw.indexOf("hotp") !== -1) {
    return "hotp";
  }

  if (raw.indexOf("steam") !== -1 || title.indexOf("steam") !== -1) {
    return "steam";
  }

  return "totp";
}

function normalizeSecret(value) {
  const raw = String(value || "").trim().replace(/[\s-]/g, "");

  if (/^[A-Z2-7]+=*$/i.test(raw)) {
    return raw.replace(/=+$/, "").toUpperCase();
  }

  if (/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) {
    const fromBase64 = base64ToBase32(raw);
    if (fromBase64) {
      return fromBase64;
    }
  }

  return raw.replace(/=+$/, "").toUpperCase();
}

function base64ToBase32(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const bytes = [];
  let buffer = 0;
  let bitsLeft = 0;
  let result = "";

  for (let i = 0; i < value.length; i++) {
    const char = value.charAt(i);
    if (char === "=") {
      break;
    }

    const index = base64.indexOf(char);
    if (index === -1) {
      return "";
    }

    buffer = (buffer << 6) | index;
    bitsLeft += 6;
    if (bitsLeft >= 8) {
      bytes.push((buffer >>> (bitsLeft - 8)) & 0xff);
      bitsLeft -= 8;
      buffer = bitsLeft ? buffer & ((1 << bitsLeft) - 1) : 0;
    }
  }

  buffer = 0;
  bitsLeft = 0;
  for (let j = 0; j < bytes.length; j++) {
    buffer = (buffer << 8) | bytes[j];
    bitsLeft += 8;
    while (bitsLeft >= 5) {
      result += alphabet.charAt((buffer >>> (bitsLeft - 5)) & 31);
      bitsLeft -= 5;
      buffer = bitsLeft ? buffer & ((1 << bitsLeft) - 1) : 0;
    }
  }

  if (bitsLeft > 0) {
    result += alphabet.charAt((buffer << (5 - bitsLeft)) & 31);
  }

  return result;
}

function compactAccount(account) {
  if (!account || !account.key) {
    return null;
  }

  return {
    name: account.name || DEFAULT_NAME,
    usr: account.usr || "",
    key: normalizeSecret(account.key),
    type: account.type === "steam" ? "steam" : "totp",
    period: normalizePeriod(account.period),
    digits: normalizeDigits(account.digits),
    algorithm: normalizeAlgorithm(account.algorithm)
  };
}

function parseOtpAuthUri(uri) {
  const value = String(uri || "").trim();
  if (value.indexOf("otpauth://") !== 0) {
    return null;
  }

  const withoutScheme = value.slice("otpauth://".length);
  const slashIndex = withoutScheme.indexOf("/");
  const queryIndex = withoutScheme.indexOf("?");
  const kind = slashIndex === -1 ? "" : withoutScheme.slice(0, slashIndex);
  const label = withoutScheme.slice(slashIndex + 1, queryIndex === -1 ? withoutScheme.length : queryIndex);
  const query = queryIndex === -1 ? {} : readQuery(withoutScheme.slice(queryIndex + 1));
  const labelParts = splitLabel(label);
  const issuer = query.issuer || labelParts.name;
  const type = normalizeType(kind, labelParts.name, issuer);

  if (type === "hotp") {
    return null;
  }

  return compactAccount({
    name: issuer || labelParts.name,
    usr: labelParts.usr || query.account || query.user || "",
    key: query.secret,
    type: type,
    period: query.period,
    digits: query.digits,
    algorithm: query.algorithm
  });
}

function parseObjectAccount(item) {
  if (!item || typeof item !== "object") {
    return null;
  }

  const uri = item.url || item.uri || item.otpauth || item.otpAuth || item.link;
  if (uri) {
    return parseOtpAuthUri(uri);
  }

  const issuer = item.issuer || item.issuerName || item.service || item.serviceName || item.service_name || item.provider || item.app || "";
  const account = item.usr || item.user || item.username || item.account || item.accountName || item.account_name || item.email || "";
  const secret = item.key || item.secret || item.secretKey || item.secret_key || item.otp_secret || item.otpSecret;
  let name = item.name || item.label || item.serviceName || item.service_name || issuer || DEFAULT_NAME;
  let usr = account;

  if (issuer) {
    const label = splitLabel(item.name || "");
    name = issuer;
    usr = account || label.usr || (item.name && item.name !== issuer ? label.name : "");
  } else if (!issuer && !usr && String(name).indexOf(":") !== -1) {
    const label = splitLabel(name);
    name = label.name;
    usr = label.usr;
  }

  const type = normalizeType(item.type || item.otp_type || item.otpType, name, issuer);
  if (type === "hotp") {
    return null;
  }

  return compactAccount({
    name: name,
    usr: usr,
    key: secret,
    type: type,
    period: item.period,
    digits: item.digits || item.digit_count || item.digitCount,
    algorithm: item.algorithm
  });
}

function collectItems(value) {
  if (!value) {
    return [];
  }

  if (Array.isArray(value)) {
    return value;
  }

  if (typeof value === "object") {
    return value.list || value.accounts || value.tokens || value.items || value.entries ||
      value.otp_params || value.otpParams || value.otp_parameters || value.otpParameters || [];
  }

  const text = String(value || "");
  if (text.indexOf("otpauth://") !== -1) {
    return text.match(/otpauth:\/\/\S+/g) || text.split(/\r?\n/).filter(Boolean);
  }

  return [];
}

function normalizeAccounts(rawData) {
  const parsed = safeJsonParse(rawData);
  const items = collectItems(parsed);
  const result = [];

  for (let i = 0; i < items.length; i++) {
    const item = safeJsonParse(items[i]);
    const account = typeof item === "string" ? parseOtpAuthUri(item) : parseObjectAccount(item);

    if (account) {
      result.push(account);
    }
  }

  return result;
}

export { normalizeAccounts };
