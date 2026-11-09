import { createHash, createHmac } from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_KEM_ALG,
  DEFAULT_SIGNING_ALG,
  KEM_ALGS,
  SIGNING_ALGS,
  crossVerify,
  deserializeKemKeyPair,
  deserializeKeyPair,
  generateSigningKeyPair,
  kemDecapsulate,
  kemEncapsulate,
  kemGenerate,
  open,
  seal,
  selfTest,
  serializeKemKeyPair,
  serializeKeyPair,
  sign,
  verify,
} from '../src/crypto/pqc.js';
import {
  canonicalize,
  digestOf,
  equalBytes,
  fromB64u,
  fromHex,
  hkdfSha3_256,
  hmacSha3_256,
  shake256Bytes,
  sha3_256,
  sha3_384,
  sha3_512,
  taggedHash,
  toB64u,
  toBytes,
  toHex,
} from '../src/crypto/hash.js';

const text = (value) => new TextEncoder().encode(value);

test('signing algorithms carry the sizes their standards define', () => {
  // FIPS 204 pk|sig, FIPS 205 pk|sig. Pinned as literals on purpose: if a
  // dependency silently changes its encoding the suite has to notice.
  assert.deepEqual(SIGNING_ALGS['ML-DSA-65'], {
    family: 'ml-dsa', name: 'ML-DSA-65', publicKeyBytes: 1952, signatureBytes: 3309, seedBytes: 32, securityLevel: 3, standard: 'FIPS 204',
  });
  assert.deepEqual(SIGNING_ALGS['ML-DSA-87'], {
    family: 'ml-dsa', name: 'ML-DSA-87', publicKeyBytes: 2592, signatureBytes: 4627, seedBytes: 32, securityLevel: 5, standard: 'FIPS 204',
  });
  assert.equal(SIGNING_ALGS['SLH-DSA-SHA2-128F'].publicKeyBytes, 32);
  assert.equal(SIGNING_ALGS['SLH-DSA-SHA2-128F'].signatureBytes, 17088);
  assert.equal(SIGNING_ALGS['SLH-DSA-SHA2-128F'].standard, 'FIPS 205');
});

test('kem algorithms carry the sizes FIPS 203 defines', () => {
  assert.equal(KEM_ALGS['ML-KEM-512'].publicKeyBytes, 800);
  assert.equal(KEM_ALGS['ML-KEM-512'].secretKeyBytes, 1632);
  assert.equal(KEM_ALGS['ML-KEM-512'].ciphertextBytes, 768);
  assert.equal(KEM_ALGS['ML-KEM-768'].publicKeyBytes, 1184);
  assert.equal(KEM_ALGS['ML-KEM-768'].secretKeyBytes, 2400);
  assert.equal(KEM_ALGS['ML-KEM-768'].ciphertextBytes, 1088);
  assert.equal(KEM_ALGS['ML-KEM-1024'].ciphertextBytes, 1568);
  for (const spec of Object.values(KEM_ALGS)) assert.equal(spec.sharedSecretBytes, 32);
});

for (const [alg, spec] of Object.entries(SIGNING_ALGS)) {
  test(`${alg} produces standard-size keys and signatures that verify`, async () => {
    const keyPair = await generateSigningKeyPair(alg);
    assert.equal(keyPair.publicKey.length, spec.publicKeyBytes);
    assert.equal(keyPair.alg, alg);
    const message = text(`${alg} round trip`);
    const signature = await sign(keyPair, message);
    assert.equal(signature.length, spec.signatureBytes);
    assert.equal(await verify(alg, keyPair.publicKey, message, signature), true);
  });

  test(`${alg} seed derivation is deterministic and rejects the wrong seed length`, async () => {
    const seed = new Uint8Array(spec.seedBytes).fill(7);
    const a = await generateSigningKeyPair(alg, { seed });
    const b = await generateSigningKeyPair(alg, { seed });
    assert.equal(toB64u(a.publicKey), toB64u(b.publicKey));
    assert.equal(toB64u(a.privateKey), toB64u(b.privateKey));
    await assert.rejects(() => generateSigningKeyPair(alg, { seed: new Uint8Array(spec.seedBytes + 1) }), /seed must be/);
  });
}

test('unknown signing algorithms fail instead of falling back', async () => {
  await assert.rejects(() => generateSigningKeyPair('ML-DSA-44'), /unsupported signing algorithm/);
  await assert.rejects(() => verify('SHA-256', new Uint8Array(32), text('a'), new Uint8Array(8)), /unsupported signing algorithm/);
});

test('verify rejects tampered messages, tampered signatures and foreign keys', async () => {
  const keyPair = await generateSigningKeyPair(DEFAULT_SIGNING_ALG);
  const message = text('deploy infra:prod-eu-1');
  const signature = await sign(keyPair, message);
  const tampered = Uint8Array.from(message);
  tampered[0] ^= 0x01;
  assert.equal(await verify(keyPair.alg, keyPair.publicKey, tampered, signature), false);
  const flipped = Uint8Array.from(signature, (byte, index) => (index === 10 ? byte ^ 0x80 : byte));
  assert.equal(await verify(keyPair.alg, keyPair.publicKey, message, flipped), false);
  const foreign = await generateSigningKeyPair(keyPair.alg);
  assert.equal(await verify(keyPair.alg, foreign.publicKey, message, signature), false);
  // Truncated input is refused on length alone, before any crypto runs.
  assert.equal(await verify(keyPair.alg, keyPair.publicKey, message, signature.subarray(0, 100)), false);
  assert.equal(await verify(keyPair.alg, keyPair.publicKey.subarray(0, 1000), message, signature), false);
});

test('deterministic signing is reproducible and the wasm path refuses it', async () => {
  const jsPair = await generateSigningKeyPair(DEFAULT_SIGNING_ALG, { seed: new Uint8Array(32).fill(3) });
  const message = text('deterministic');
  const first = await sign(jsPair, message, { deterministic: true });
  assert.deepEqual(first, await sign(jsPair, message, { deterministic: true }));
  const wasmPair = await generateSigningKeyPair(DEFAULT_SIGNING_ALG);
  assert.equal(wasmPair.implementation, 'wasm');
  await assert.rejects(() => sign(wasmPair, message, { deterministic: true }), /requires the js implementation/);
});

test('the wasm and pure-js ML-DSA implementations agree on every signature', async () => {
  const keyPair = await generateSigningKeyPair(DEFAULT_SIGNING_ALG, { seed: new Uint8Array(32).fill(11) });
  const message = text('cross implementation');
  const signature = await sign(keyPair, message, { deterministic: true });
  const cross = await crossVerify(keyPair.publicKey, message, signature, DEFAULT_SIGNING_ALG);
  assert.equal(cross.viaJs, true, 'pure-js implementation must accept');
  assert.equal(cross.viaWasm, true, 'wasm implementation must accept');
  assert.equal(cross.agreement, true);
  const flipped = Uint8Array.from(signature, (byte, index) => (index === 4 ? byte ^ 1 : byte));
  const bad = await crossVerify(keyPair.publicKey, message, flipped, DEFAULT_SIGNING_ALG);
  assert.equal(bad.viaJs, false);
  assert.equal(bad.viaWasm, false);
  assert.equal(bad.agreement, true, 'both implementations must reject a bad signature');
  const malformed = await crossVerify(new Uint8Array(16), message, signature, DEFAULT_SIGNING_ALG);
  assert.equal(malformed.agreement, null);
  assert.match(malformed.reason, /length does not match/);
});

test('key pair documents survive a serialize/deserialize round trip', async () => {
  const keyPair = await generateSigningKeyPair(DEFAULT_SIGNING_ALG);
  const doc = serializeKeyPair(keyPair);
  assert.equal(typeof doc.publicKey, 'string');
  assert.equal(doc.publicKey.includes('+'), false, 'must be base64url so it is JSON/URL safe');
  const restored = deserializeKeyPair(doc);
  const message = text('round trip key');
  const signature = await sign(keyPair, message);
  assert.equal(await verify(restored.alg, restored.publicKey, message, signature), true);
  assert.throws(() => deserializeKeyPair({ ...doc, alg: 'ML-DSA-99' }), /unsupported signing algorithm/);
  assert.throws(() => deserializeKeyPair({ ...doc, publicKey: toB64u(new Uint8Array(64)) }), /public key must be 1952 bytes/);
});

test('kem key pairs round trip through json and reject truncated keys', async () => {
  const keyPair = await kemGenerate(DEFAULT_KEM_ALG);
  const doc = JSON.parse(JSON.stringify(serializeKemKeyPair(keyPair)));
  const restored = deserializeKemKeyPair(doc);
  assert.equal(restored.publicKey.length, KEM_ALGS[DEFAULT_KEM_ALG].publicKeyBytes);
  const { ciphertext, sharedSecret } = await kemEncapsulate(restored.publicKey);
  assert.deepEqual(await kemDecapsulate(ciphertext, restored.secretKey), sharedSecret);
  assert.throws(() => deserializeKemKeyPair({ ...doc, alg: 'ML-KEM-256' }), /unsupported KEM/);
  assert.throws(() => deserializeKemKeyPair({ ...doc, secretKey: toB64u(new Uint8Array(10)) }), /decapsulation key must be 2400 bytes/);
});

test('ml-kem encapsulation and decapsulation agree for every size', async () => {
  for (const [alg, spec] of Object.entries(KEM_ALGS)) {
    const keyPair = await kemGenerate(alg);
    assert.equal(keyPair.publicKey.length, spec.publicKeyBytes);
    assert.equal(keyPair.secretKey.length, spec.secretKeyBytes);
    const { ciphertext, sharedSecret } = await kemEncapsulate(keyPair.publicKey, alg);
    assert.equal(ciphertext.length, spec.ciphertextBytes);
    assert.equal(sharedSecret.length, spec.sharedSecretBytes);
    assert.deepEqual(await kemDecapsulate(ciphertext, keyPair.secretKey, alg), sharedSecret);
    await assert.rejects(() => kemEncapsulate(keyPair.publicKey.subarray(0, 8), alg), /public key must be/);
    await assert.rejects(() => kemDecapsulate(ciphertext.subarray(0, 8), keyPair.secretKey, alg), /ciphertext must be/);
  }
});

test('hybrid seal/open binds the aad and fails on any substitution', async () => {
  const recipient = await kemGenerate(DEFAULT_KEM_ALG);
  const other = await kemGenerate(DEFAULT_KEM_ALG);
  const plaintext = text('the record an agent committed to');
  const sealed = await seal(recipient.publicKey, plaintext, { aad: 'verix:record:hash' });
  assert.match(sealed.alg, /^ML-KEM-768\+AES-256-GCM$/);
  assert.deepEqual(await open(sealed, recipient.secretKey), plaintext);
  await assert.rejects(() => open(sealed, other.secretKey), /auth|bad decrypt|tag/i);
  const aadSwapped = { ...sealed, aad: 'verix:something-else' };
  await assert.rejects(() => open(aadSwapped, recipient.secretKey), /auth|bad decrypt|tag/i);
  const body = Uint8Array.from(fromB64u(sealed.ciphertext));
  body[0] ^= 0xff;
  await assert.rejects(() => open({ ...sealed, ciphertext: toB64u(body) }, recipient.secretKey), /auth|bad decrypt|tag/i);
});

test('sha3 matches an independent implementation and known nist vectors', () => {
  // node:crypto is built on OpenSSL's FIPS-validated SHA-3, so agreement here is
  // a second implementation confirming ours rather than a restatement of it.
  for (const input of ['', 'a', 'abc', 'verix', 'x'.repeat(200)]) {
    const bytes = text(input);
    assert.equal(toHex(sha3_256(bytes)), createHash('sha3-256').update(bytes).digest('hex'), `sha3-256 ${input.length}`);
    assert.equal(toHex(sha3_384(bytes)), createHash('sha3-384').update(bytes).digest('hex'), `sha3-384 ${input.length}`);
    assert.equal(toHex(sha3_512(bytes)), createHash('sha3-512').update(bytes).digest('hex'), `sha3-512 ${input.length}`);
  }
  assert.equal(toHex(sha3_256('')), 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a');
  assert.equal(toHex(sha3_256(text('abc'))), '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');
  assert.equal(sha3_256('abc').length, 32);
  assert.equal(sha3_512('abc').length, 64);
});

test('hmac, hkdf and shake over sha3 are deterministic and length-correct', () => {
  const key = text('key');
  assert.equal(toHex(hmacSha3_256(key, text('msg'))), createHmac('sha3-256', key).update(text('msg')).digest('hex'));
  const derived = hkdfSha3_256(key, text('salt'), 'verix:derivation:v1', 32);
  assert.equal(derived.length, 32);
  assert.deepEqual(derived, hkdfSha3_256(key, text('salt'), 'verix:derivation:v1', 32));
  assert.notDeepEqual(derived, hkdfSha3_256(key, text('salt'), 'verix:other-info', 32));
  assert.notDeepEqual(derived, hkdfSha3_256(key, text('other-salt'), 'verix:derivation:v1', 32));
  assert.equal(hkdfSha3_256(key, text('salt'), 'info', 48).length, 48);
  assert.equal(shake256Bytes(text('abc'), 32).length, 32);
  // SHAKE256 is the XOF behind SHA3-256 but pads differently, so cross-check it
  // against OpenSSL's own XOF instead of assuming the SHA3 digest is a prefix.
  assert.equal(toHex(shake256Bytes(text('abc'), 32)), createHash('shake256', { outputLength: 32 }).update(text('abc')).digest('hex'));
  assert.equal(toHex(shake256Bytes(text(''), 131)), createHash('shake256', { outputLength: 131 }).update(text('')).digest('hex'));
  assert.notEqual(toHex(shake256Bytes(text('abc'), 32)), toHex(sha3_256(text('abc'))));
});

test('tagged hashes keep domains apart', () => {
  const value = text('same bytes');
  assert.notEqual(toHex(taggedHash('verix:record:v1', value)), toHex(taggedHash('verix:assessment:v1', value)));
  assert.equal(digestOf({ a: 1 }, 'verix:record:v1'), digestOf({ a: 1 }, 'verix:record:v1'));
  assert.notEqual(digestOf({ a: 1 }, 'verix:record:v1'), digestOf({ a: 1 }, 'verix:other:v1'));
  assert.equal(digestOf({ a: 1 }).length, 64);
});

test('canonicalization is order independent, total, and rejects cycles', () => {
  assert.equal(canonicalize({ b: 2, a: 1 }), canonicalize({ a: 1, b: 2 }));
  assert.equal(canonicalize({ nested: { b: 1, a: 2 } }), canonicalize({ nested: { a: 2, b: 1 } }));
  assert.equal(canonicalize({ a: 1, missing: undefined }), canonicalize({ a: 1 }));
  assert.equal(canonicalize([1, null, 'x', true]), '[1,null,"x",true]');
  assert.equal(canonicalize(new Uint8Array([1, 2])), JSON.stringify(toB64u(new Uint8Array([1, 2]))));
  assert.equal(canonicalize(2.0), canonicalize(2));
  assert.equal(canonicalize(Number.MAX_SAFE_INTEGER), '9007199254740991');
  assert.throws(() => canonicalize(() => 1), /cannot canonicalize function/);
  const cycle = { name: 'loop' };
  cycle.self = cycle;
  assert.throws(() => canonicalize(cycle), /cyclic structures/);
  const array = [1];
  array.push(array);
  assert.throws(() => canonicalize(array), /cyclic structures/);
  assert.equal(digestOf({ z: 1, a: 2 }), digestOf({ a: 2, z: 1 }), 'digest must not depend on insertion order');
});

test('byte helpers round trip hex and base64url', () => {
  const bytes = new Uint8Array([0, 1, 254, 255]);
  assert.deepEqual(fromHex(toHex(bytes)), bytes);
  assert.deepEqual(fromB64u(toB64u(bytes)), bytes);
  assert.deepEqual(toBytes('literal string'), text('literal string'));
  assert.deepEqual(toBytes(bytes), bytes);
  assert.equal(equalBytes(toBytes('a'), toBytes('a')), true);
  assert.equal(equalBytes(toBytes('a'), toBytes('b')), false);
  assert.equal(equalBytes(toBytes('a'), new Uint8Array(0)), false);
});

test('crypto selfTest reports every check passing', async () => {
  const result = await selfTest();
  const failed = Object.entries(result.checks).filter(([, passed]) => passed !== true).map(([name]) => name);
  assert.deepEqual(failed, [], `selfTest checks failed: ${failed.join(', ')}`);
  assert.equal(result.passed, true);
  assert.ok(Object.keys(result.checks).length >= 10);
});
