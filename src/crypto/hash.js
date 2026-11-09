import { createHash, createHmac, hkdfSync, randomBytes as nodeRandomBytes, timingSafeEqual } from 'node:crypto';

const textEncoder = new TextEncoder();

export function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (Buffer.isBuffer(value)) return new Uint8Array(value);
  if (typeof value === 'string') return textEncoder.encode(value);
  if (Array.isArray(value)) return Uint8Array.from(value);
  throw new TypeError(`cannot coerce ${typeof value} to bytes`);
}

export function toHex(bytes) {
  return Buffer.from(toBytes(bytes)).toString('hex');
}

export function fromHex(hex) {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

export function toB64u(bytes) {
  return Buffer.from(toBytes(bytes)).toString('base64url');
}

export function fromB64u(str) {
  return new Uint8Array(Buffer.from(str, 'base64url'));
}

export function concatBytes(...parts) {
  const flat = parts.map(toBytes);
  const total = flat.reduce((n, b) => n + b.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const b of flat) {
    out.set(b, at);
    at += b.length;
  }
  return out;
}

export function sha3_256(value) {
  return new Uint8Array(createHash('sha3-256').update(toBytes(value)).digest());
}

export function sha3_384(value) {
  return new Uint8Array(createHash('sha3-384').update(toBytes(value)).digest());
}

export function sha3_512(value) {
  return new Uint8Array(createHash('sha3-512').update(toBytes(value)).digest());
}

export function shake256Bytes(value, length = 32) {
  return new Uint8Array(createHash('shake256', { outputLength: length }).update(toBytes(value)).digest());
}

export function hmacSha3_256(key, value) {
  return new Uint8Array(createHmac('sha3-256', toBytes(key)).update(toBytes(value)).digest());
}

export function hkdfSha3_256(secret, salt, info, length) {
  return new Uint8Array(hkdfSync('sha3-256', toBytes(secret), toBytes(salt), toBytes(info), length));
}

export function randomBytes(length) {
  return new Uint8Array(nodeRandomBytes(length));
}

export function equalBytes(a, b) {
  const x = toBytes(a);
  const y = toBytes(b);
  if (x.length !== y.length) return false;
  return timingSafeEqual(x, y);
}

function normalizeNumber(value) {
  if (Number.isNaN(value)) throw new TypeError('NaN is not canonically encodable');
  if (!Number.isFinite(value)) throw new TypeError('non-finite numbers are not canonically encodable');
  if (Number.isInteger(value)) return String(value);
  return JSON.stringify(value);
}

export function canonicalize(value, seen = new Set()) {
  if (value === null) return 'null';
  const type = typeof value;
  if (type === 'boolean') return value ? 'true' : 'false';
  if (type === 'number') return normalizeNumber(value);
  if (type === 'string') return JSON.stringify(value);
  if (type === 'bigint') return value.toString();
  if (value instanceof Uint8Array || Buffer.isBuffer(value)) return JSON.stringify(toB64u(value));
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (type !== 'object') throw new TypeError(`cannot canonicalize ${type}`);
  if (seen.has(value)) throw new TypeError('cyclic structures are not canonically encodable');
  seen.add(value);
  let out;
  if (Array.isArray(value)) {
    out = `[${value.map((item) => canonicalize(item === undefined ? null : item, seen)).join(',')}]`;
  } else {
    const record = value;
    if (typeof record.canonicalForm === 'function') out = record.canonicalForm(seen);
    else {
      const keys = Object.keys(record).filter((k) => record[k] !== undefined).sort();
      out = `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(record[k], seen)}`).join(',')}}`;
    }
  }
  seen.delete(value);
  return out;
}

export function taggedHash(tag, value) {
  const tagged = concatBytes(
    Uint8Array.from([tag.length]),
    textEncoder.encode(tag),
    Uint8Array.from([0]),
    toBytes(value),
  );
  return sha3_256(tagged);
}

export function digestOf(value, tag = 'verix:generic') {
  return toHex(taggedHash(tag, textEncoder.encode(canonicalize(value))));
}
