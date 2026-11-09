import mldsa from 'mldsa-wasm';
import { ml_dsa, slh_dsa } from 'pqc';
import { MlKem768, MlKem512, MlKem1024 } from 'mlkem';
import { createCipheriv, createDecipheriv } from 'node:crypto';
import { concatBytes, equalBytes, fromB64u, hkdfSha3_256, randomBytes, sha3_256, toB64u, toBytes } from './hash.js';

export const SIGNING_ALGS = {
  'ML-DSA-65': { family: 'ml-dsa', name: 'ML-DSA-65', publicKeyBytes: 1952, signatureBytes: 3309, seedBytes: 32, securityLevel: 3, standard: 'FIPS 204' },
  'ML-DSA-87': { family: 'ml-dsa', name: 'ML-DSA-87', publicKeyBytes: 2592, signatureBytes: 4627, seedBytes: 32, securityLevel: 5, standard: 'FIPS 204' },
  'SLH-DSA-SHA2-128F': { family: 'slh-dsa', name: 'SLH-DSA-SHA2-128F', publicKeyBytes: 32, signatureBytes: 17088, seedBytes: 48, securityLevel: 1, standard: 'FIPS 205' },
};

export const KEM_ALGS = {
  'ML-KEM-512': { name: 'ML-KEM-512', Class: MlKem512, publicKeyBytes: 800, secretKeyBytes: 1632, ciphertextBytes: 768, sharedSecretBytes: 32, securityLevel: 1, standard: 'FIPS 203' },
  'ML-KEM-768': { name: 'ML-KEM-768', Class: MlKem768, publicKeyBytes: 1184, secretKeyBytes: 2400, ciphertextBytes: 1088, sharedSecretBytes: 32, securityLevel: 3, standard: 'FIPS 203' },
  'ML-KEM-1024': { name: 'ML-KEM-1024', Class: MlKem1024, publicKeyBytes: 1568, secretKeyBytes: 3168, ciphertextBytes: 1568, sharedSecretBytes: 32, securityLevel: 5, standard: 'FIPS 203' },
};

export const DEFAULT_SIGNING_ALG = 'ML-DSA-65';
export const DEFAULT_KEM_ALG = 'ML-KEM-768';

const JS_ML_DSA = { 'ML-DSA-65': ml_dsa.ml_dsa65, 'ML-DSA-87': ml_dsa.ml_dsa87 };
const JS_SLH = { 'SLH-DSA-SHA2-128F': slh_dsa.slh_dsa_sha2_128f };

function requireSigningAlg(alg) {
  const spec = SIGNING_ALGS[alg];
  if (!spec) throw new Error(`unsupported signing algorithm ${alg}, expected one of ${Object.keys(SIGNING_ALGS).join(', ')}`);
  return spec;
}

function jsSigning(alg) {
  return JS_ML_DSA[alg] ?? JS_SLH[alg];
}

function wasmHandle(alg, privateKeyBytes) {
  return mldsa.importKey('pkcs8', privateKeyBytes, alg, true, ['sign']);
}

export async function generateSigningKeyPair(alg = DEFAULT_SIGNING_ALG, { seed } = {}) {
  const spec = requireSigningAlg(alg);
  if (seed !== undefined) {
    const seedBytes = toBytes(seed);
    if (seedBytes.length !== spec.seedBytes) {
      throw new Error(`${alg} derivation seed must be ${spec.seedBytes} bytes, got ${seedBytes.length}`);
    }
    const pair = jsSigning(alg).keygen(seedBytes);
    return {
      alg,
      implementation: 'js',
      publicKey: Uint8Array.from(pair.publicKey),
      privateKey: Uint8Array.from(pair.secretKey),
    };
  }
  if (spec.family === 'ml-dsa') {
    const pair = await mldsa.generateKey({ name: alg }, true, ['sign', 'verify']);
    const jwk = await mldsa.exportKey('jwk', pair.publicKey);
    return {
      alg,
      implementation: 'wasm',
      publicKey: fromB64u(jwk.pub),
      privateKey: new Uint8Array(await mldsa.exportKey('pkcs8', pair.privateKey)),
    };
  }
  const pair = jsSigning(alg).keygen();
  return { alg, implementation: 'js', publicKey: Uint8Array.from(pair.publicKey), privateKey: Uint8Array.from(pair.secretKey) };
}

export function serializeKeyPair(keyPair) {
  return {
    alg: keyPair.alg,
    implementation: keyPair.implementation,
    publicKey: toB64u(keyPair.publicKey),
    privateKey: toB64u(keyPair.privateKey),
  };
}

export function serializeKemKeyPair(keyPair) {
  return {
    alg: keyPair.alg,
    publicKey: toB64u(keyPair.publicKey),
    secretKey: toB64u(keyPair.secretKey),
  };
}

export function deserializeKemKeyPair(doc) {
  const spec = KEM_ALGS[doc.alg];
  if (!spec) throw new Error(`unsupported KEM ${doc.alg}`);
  const publicKey = fromB64u(doc.publicKey);
  const secretKey = fromB64u(doc.secretKey);
  if (publicKey.length !== spec.publicKeyBytes) throw new Error(`${doc.alg} encapsulation key must be ${spec.publicKeyBytes} bytes, got ${publicKey.length}`);
  if (secretKey.length !== spec.secretKeyBytes) throw new Error(`${doc.alg} decapsulation key must be ${spec.secretKeyBytes} bytes, got ${secretKey.length}`);
  return { alg: doc.alg, publicKey, secretKey, kem: new spec.Class() };
}

export function deserializeKeyPair(doc) {
  const spec = requireSigningAlg(doc.alg);
  const publicKey = fromB64u(doc.publicKey);
  const privateKey = fromB64u(doc.privateKey);
  if (publicKey.length !== spec.publicKeyBytes) {
    throw new Error(`${doc.alg} public key must be ${spec.publicKeyBytes} bytes, got ${publicKey.length}`);
  }
  return { alg: doc.alg, implementation: doc.implementation ?? 'js', publicKey, privateKey };
}

export async function sign(keyPair, message, { deterministic = false } = {}) {
  const spec = requireSigningAlg(keyPair.alg);
  const msg = toBytes(message);
  if (keyPair.implementation === 'wasm' && spec.family === 'ml-dsa') {
    if (deterministic) throw new Error('deterministic signing requires the js implementation');
    const handle = await wasmHandle(keyPair.alg, keyPair.privateKey);
    return new Uint8Array(await mldsa.sign({ name: keyPair.alg }, handle, msg));
  }
  if (deterministic) {
    const rnd = hkdfSha3_256(keyPair.privateKey, msg, `verix:sign:${keyPair.alg}`, 32);
    return jsSigning(keyPair.alg).sign(keyPair.privateKey, msg, new Uint8Array(0), rnd);
  }
  return jsSigning(keyPair.alg).sign(keyPair.privateKey, msg);
}

export async function verify(alg, publicKey, message, signature) {
  requireSigningAlg(alg);
  const msg = toBytes(message);
  const sig = toBytes(signature);
  const pk = toBytes(publicKey);
  if (sig.length !== SIGNING_ALGS[alg].signatureBytes) return false;
  if (pk.length !== SIGNING_ALGS[alg].publicKeyBytes) return false;
  if (SIGNING_ALGS[alg].family === 'ml-dsa') {
    try {
      const handle = await mldsa.importKey('jwk', { kty: 'AKP', alg, pub: toB64u(pk), key_ops: ['verify'], ext: true }, alg, false, ['verify']);
      return await mldsa.verify({ name: alg }, handle, sig, msg);
    } catch {
      return false;
    }
  }
  return jsSigning(alg).verify(pk, msg, sig);
}

export async function crossVerify(publicKey, message, signature, alg = DEFAULT_SIGNING_ALG) {
  requireSigningAlg(alg);
  const spec = SIGNING_ALGS[alg];
  const pk = toBytes(publicKey);
  const msg = toBytes(message);
  const sig = toBytes(signature);
  if (pk.length !== spec.publicKeyBytes || sig.length !== spec.signatureBytes) {
    return { alg, viaWasm: null, viaJs: false, agreement: null, reason: 'key or signature length does not match the standard' };
  }
  const viaJs = jsSigning(alg).verify(pk, msg, sig);
  const viaWasm = spec.family === 'ml-dsa' ? await verify(alg, pk, msg, sig) : null;
  return { alg, viaWasm, viaJs, agreement: viaWasm === null ? null : viaWasm === viaJs };
}

export async function kemGenerate(alg = DEFAULT_KEM_ALG, { seed } = {}) {
  const spec = KEM_ALGS[alg];
  if (!spec) throw new Error(`unsupported KEM ${alg}`);
  const kem = new spec.Class();
  const pair = seed === undefined ? await kem.generateKeyPair() : await kem.deriveKeyPair(toBytes(seed));
  return { alg, publicKey: Uint8Array.from(pair[0]), secretKey: Uint8Array.from(pair[1]), kem };
}

export async function kemEncapsulate(publicKey, alg = DEFAULT_KEM_ALG, { seed } = {}) {
  const spec = KEM_ALGS[alg];
  const kem = new spec.Class();
  const pk = toBytes(publicKey);
  if (pk.length !== spec.publicKeyBytes) throw new Error(`${alg} public key must be ${spec.publicKeyBytes} bytes`);
  const outcome = seed === undefined ? await kem.encap(pk) : await kem.encap(pk, toBytes(seed));
  return { ciphertext: Uint8Array.from(outcome[0]), sharedSecret: Uint8Array.from(outcome[1]) };
}

export async function kemDecapsulate(ciphertext, secretKey, alg = DEFAULT_KEM_ALG) {
  const spec = KEM_ALGS[alg];
  const kem = new spec.Class();
  const ct = toBytes(ciphertext);
  if (ct.length !== spec.ciphertextBytes) throw new Error(`${alg} ciphertext must be ${spec.ciphertextBytes} bytes`);
  return Uint8Array.from(await kem.decap(ct, toBytes(secretKey)));
}

function sealKey(sharedSecret, context) {
  return hkdfSha3_256(sharedSecret, sha3_256(context), 'verix:channel:v1', 32);
}

export async function seal(recipientPublicKey, plaintext, { alg = DEFAULT_KEM_ALG, aad = '' } = {}) {
  const { ciphertext: kemCiphertext, sharedSecret } = await kemEncapsulate(recipientPublicKey, alg);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', sealKey(sharedSecret, kemCiphertext), iv);
  const input = toBytes(plaintext);
  if (aad) cipher.setAAD(toBytes(aad));
  const body = Buffer.concat([cipher.update(input), cipher.final()]);
  return {
    alg: `${alg}+AES-256-GCM`,
    kemCiphertext: toB64u(kemCiphertext),
    iv: toB64u(iv),
    ciphertext: toB64u(body),
    authTag: toB64u(cipher.getAuthTag()),
    aad: aad || undefined,
    fingerprint: toB64u(sha3_256(concatBytes(kemCiphertext, iv, body))),
  };
}

export async function open(sealedDoc, recipientSecretKey, { alg = DEFAULT_KEM_ALG } = {}) {
  const kemCiphertext = fromB64u(sealedDoc.kemCiphertext);
  const sharedSecret = await kemDecapsulate(kemCiphertext, recipientSecretKey, alg);
  const decipher = createDecipheriv('aes-256-gcm', sealKey(sharedSecret, kemCiphertext), fromB64u(sealedDoc.iv));
  decipher.setAuthTag(fromB64u(sealedDoc.authTag));
  if (sealedDoc.aad) decipher.setAAD(toBytes(sealedDoc.aad));
  return new Uint8Array(Buffer.concat([decipher.update(fromB64u(sealedDoc.ciphertext)), decipher.final()]));
}

export async function selfTest() {
  const checks = {};
  const message = new TextEncoder().encode('verix crypto self test');
  const keyPair = await generateSigningKeyPair(DEFAULT_SIGNING_ALG);
  const signature = await sign(keyPair, message);
  checks.mlDsaSignVerify = await verify(keyPair.alg, keyPair.publicKey, message, signature);
  const tampered = Uint8Array.from(message);
  tampered[0] ^= 0x01;
  checks.mlDsaRejectsTamperedMessage = !(await verify(keyPair.alg, keyPair.publicKey, tampered, signature));
  const flippedSignature = Uint8Array.from(signature, (byte, index) => (index === 4 ? byte ^ 1 : byte));
  checks.mlDsaRejectsTamperedSignature = !(await verify(keyPair.alg, keyPair.publicKey, message, flippedSignature));
  const foreign = await generateSigningKeyPair(DEFAULT_SIGNING_ALG);
  checks.mlDsaRejectsForeignKey = !(await verify(foreign.alg, foreign.publicKey, message, signature));
  checks.mlDsaKeySizeMatchesStandard = keyPair.publicKey.length === SIGNING_ALGS[keyPair.alg].publicKeyBytes
    && signature.length === SIGNING_ALGS[keyPair.alg].signatureBytes;

  const jsPair = await generateSigningKeyPair(DEFAULT_SIGNING_ALG, { seed: randomBytes(32) });
  const jsSig = await sign(jsPair, message, { deterministic: true });
  const cross = await crossVerify(jsPair.publicKey, message, jsSig);
  checks.mlDsaCrossImplementationAgreement = cross.viaWasm === true && cross.viaJs === true;
  checks.mlDsaDeterministicSigning = equalBytes(jsSig, await sign(jsPair, message, { deterministic: true }));

  const kem = await kemGenerate(DEFAULT_KEM_ALG);
  const encapped = await kemEncapsulate(kem.publicKey);
  const recovered = await kemDecapsulate(encapped.ciphertext, kem.secretKey);
  checks.kemSharedSecretAgreement = equalBytes(encapped.sharedSecret, recovered);
  const sealed = await seal(kem.publicKey, message);
  checks.kemSealOpen = equalBytes(await open(sealed, kem.secretKey), message);
  let openedWrongKey = true;
  try {
    await open(sealed, (await kemGenerate(DEFAULT_KEM_ALG)).secretKey);
  } catch {
    openedWrongKey = false;
  }
  checks.kemSealRejectsWrongKey = openedWrongKey === false;
  const passed = Object.values(checks).every((v) => v === true);
  return { passed, checks };
}
