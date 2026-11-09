import { concatBytes, fromHex, sha3_256, toHex } from '../crypto/hash.js';

const LEAF = 'verix:merkle:leaf:v1';
const NODE = 'verix:merkle:node:v1';

function normalize(hash) {
  const value = String(hash).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error(`merkle leaves must be 64 hex characters, got ${String(hash).slice(0, 16)}`);
  return value;
}

function hashLeaf(recordHash) {
  return toHex(sha3_256(concatBytes(Buffer.from(LEAF, 'utf8'), Uint8Array.from([0]), fromHex(normalize(recordHash)))));
}

function hashNode(left, right) {
  return toHex(sha3_256(concatBytes(Buffer.from(NODE, 'utf8'), Uint8Array.from([0]), fromHex(left), fromHex(right))));
}

function hashOfEmpty() {
  return toHex(sha3_256(Buffer.from('verix:merkle:empty:v1', 'utf8')));
}

function collapse(level) {
  const next = [];
  for (let i = 0; i < level.length; i += 2) next.push(hashNode(level[i], level[i + 1] ?? level[i]));
  return next;
}

function levelsOf(leaves) {
  const ladder = [leaves.map(hashLeaf)];
  while (ladder[ladder.length - 1].length > 1) ladder.push(collapse(ladder.at(-1)));
  return ladder;
}

export function merkleRoot(recordHashes) {
  const leaves = recordHashes.map(normalize);
  if (leaves.length === 0) return hashNode(hashOfEmpty(), hashOfEmpty());
  return levelsOf(leaves).at(-1)[0];
}

export function inclusionPath(recordHashes, index) {
  const ladder = levelsOf(recordHashes.map(normalize));
  if (index < 0 || index >= ladder[0].length) throw new Error(`index ${index} outside tree of ${ladder[0].length} leaves`);
  const path = [];
  let at = index;
  for (let level = 0; level < ladder.length - 1; level += 1) {
    const current = ladder[level];
    const even = at % 2 === 0;
    const siblingIndex = even ? at + 1 : at - 1;
    const sibling = siblingIndex < current.length ? current[siblingIndex] : current[at];
    path.push({ hash: sibling, side: even ? 'right' : 'left' });
    at = Math.floor(at / 2);
  }
  return path;
}

export function verifyInclusion(root, recordHash, index, path) {
  let running = hashLeaf(recordHash);
  for (const step of path) {
    running = step.side === 'left' ? hashNode(step.hash, running) : hashNode(running, step.hash);
  }
  return running.toLowerCase() === normalize(root).toLowerCase();
}
