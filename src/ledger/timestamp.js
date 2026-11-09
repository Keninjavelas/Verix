import { digestOf, fromB64u, toB64u, toBytes } from '../crypto/hash.js';
import { sign, verify } from '../crypto/pqc.js';

const WITNESS_FIELDS = ['nodeId', 'cloud', 'region', 'recordHash', 'entryHash', 'seq', 'observedAt', 'alg', 'publicKey'];

export function witnessBody(witness) {
  const body = {};
  for (const field of WITNESS_FIELDS) body[field] = witness[field];
  return body;
}

export function witnessHash(witness) {
  return digestOf(witnessBody(witness), 'verix:witness:v1');
}

export async function createWitness({ keyPair, node, recordHash, entryHash, seq, observedAt }) {
  if (!keyPair) throw new Error('createWitness requires keyPair');
  if (!node?.nodeId || node.cloud === undefined) throw new Error('createWitness requires node.nodeId and node.cloud');
  const witness = {
    ...witnessBody({
      nodeId: node.nodeId,
      cloud: node.cloud,
      region: node.region ?? null,
      recordHash,
      entryHash,
      seq,
      observedAt,
      alg: keyPair.alg,
      publicKey: toB64u(keyPair.publicKey),
    }),
  };
  witness.signature = toB64u(await sign(keyPair, toBytes(witnessHash(witness))));
  witness.witnessHash = witnessHash(witness);
  return witness;
}

export async function verifyWitness(witness) {
  if (!witness?.publicKey || !witness?.signature) return false;
  const expected = witnessHash(witness);
  if (witness.witnessHash !== expected) return false;
  return verify(witness.alg, fromB64u(witness.publicKey), toBytes(expected), fromB64u(witness.signature));
}

function bucketKey(witness) {
  return JSON.stringify([witness.recordHash, witness.seq]);
}

export function quorumStatus(witnesses = [], { required = 2, expectedRecordHash = null, expectedSeq = null } = {}) {
  const groups = new Map();
  for (const witness of witnesses) {
    const key = bucketKey(witness);
    const bucket = groups.get(key) ?? [];
    bucket.push(witness);
    groups.set(key, bucket);
  }
  const ranked = [...groups.entries()].sort((a, b) => b[1].length - a[1].length || (a[0] < b[0] ? -1 : 1));
  const elected = ranked[0] ?? null;
  const consensus = elected ? JSON.parse(elected[0]) : null;
  const agreeing = elected ? elected[1] : [];
  const divergent = ranked.slice(1).flatMap(([, list]) => list);
  const mismatch = consensus === null ? 'no-witnesses'
    : (expectedRecordHash !== null && consensus[0] !== expectedRecordHash) ? 'record-hash'
      : (expectedSeq !== null && consensus[1] !== expectedSeq) ? 'sequence-position'
        : null;
  return {
    reached: agreeing.length >= required,
    required,
    agreeingCount: agreeing.length,
    total: witnesses.length,
    consensus: consensus === null ? null : { recordHash: consensus[0], seq: consensus[1] },
    divergent: divergent.map((w) => ({ nodeId: w.nodeId, cloud: w.cloud, recordHash: w.recordHash, entryHash: w.entryHash, seq: w.seq })),
    mismatch,
  };
}

function medianOf(sorted) {
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) / 2);
}

export function timestampRecord({ recordHash, seq, witnesses = [], quorum, maxClockSkewSeconds = 120, rootAtCertification = null }) {
  const observed = witnesses.map((w) => Date.parse(w.observedAt)).filter(Number.isFinite).sort((a, b) => a - b);
  const medianMs = observed.length === 0 ? null : medianOf(observed);
  const maxSkewSeconds = medianMs === null ? 0 : Math.max(...observed.map((ms) => Math.abs(ms - medianMs))) / 1000;
  return {
    recordHash,
    seq,
    certifiedAt: medianMs === null ? null : new Date(medianMs).toISOString(),
    witnessCount: witnesses.length,
    witnessNodeIds: witnesses.map((w) => w.nodeId),
    witnessClouds: witnesses.map((w) => w.cloud),
    quorumReached: quorum?.reached ?? witnesses.length > 0,
    maxClockSkewSeconds: Number(maxSkewSeconds.toFixed(0)),
    clockSkewExceeded: maxSkewSeconds > maxClockSkewSeconds,
    rootAtCertification,
  };
}
