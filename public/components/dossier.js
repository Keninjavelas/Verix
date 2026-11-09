import { api, cells, chip, dash, emptyBlock, errorRow, fmtTime, h, hashChip, head, isBlank, plural, relTime, section, severityVar, short, showTip, hideTip } from '../lib/format.js';
import { scoreBar, scoreValue } from './score.js';

function finding(code, detail, severity = 'info', evidence = null) {
  return h('div', { class: 'finding', style: `color: var(--${severityVar(severity)});` },
    h('span', { class: 'finding-code' }, code),
    h('span', { class: 'finding-sev' }, severity),
    h('span', { class: 'finding-detail' }, detail),
    evidence ? h('span', { class: 'finding-evidence' }, evidence) : null);
}

function mark(ok, yes = 'agrees', no = 'diverges') {
  return h('span', { class: 't-state', style: `color: var(--${ok ? 'jade' : 'crimson'});` },
    h('i', null), ok ? yes : no);
}

function yesNo(value) {
  return value ? 'yes' : 'NO';
}

export function createDossier(target, { names, onSelectProof, onSelectAgent }) {
  let token = 0;

  function begin() {
    const current = ++token;
    target.textContent = '';
    target.appendChild(h('div', { class: 'skeleton tall' }));
    target.appendChild(h('div', { class: 'skeleton' }));
    target.appendChild(h('div', { class: 'skeleton' }));
    return (node) => {
      if (current !== token) return false;
      target.textContent = '';
      target.appendChild(node);
      target.scrollTop = 0;
      return true;
    };
  }

  async function proof(hash) {
    const commit = begin();
    let data;
    try {
      data = await api(`/ledger/records/${encodeURIComponent(hash)}`);
    } catch (error) {
      commit(h('div', null, finding('PROOF_UNREADABLE', error.message, 'deny'),
        h('p', { class: 'placeholder' }, 'The primary node could not return this proof.')));
      return;
    }
    const record = data.record;
    const seq = record.seq;
    const [cross, inclusion, audit, revocations] = await Promise.all([
      isBlank(seq) ? null : api(`/ledger/cross-check/${seq}`).catch((error) => ({ error })),
      isBlank(seq) ? null : api(`/ledger/inclusion/${seq}`).catch((error) => ({ error })),
      api('/ledger/audit', { method: 'POST', body: { from: Math.max(1, (seq ?? 1) - 20), to: seq } }).catch((error) => ({ error })),
      api(`/identities/${encodeURIComponent(record.agentId)}/revocations`).catch(() => ({ revocations: [] })),
    ]);

    const trust = record.trust ?? {};
    const who = names.get(record.agentId) ?? head(record.agentId, 24);

    const node = h('article', { class: 'dzr' },
      h('header', { class: 'dzr-head' },
        h('h2', { class: 'dzr-title' }, record.action, ' ', h('em', null, 'on '), record.resource),
        h('div', { class: 'dzr-tags' },
          chip(trust.status ?? 'unattested'),
          h('button', { class: 'pill', onclick: () => onSelectAgent?.(record.agentId) }, who),
          h('span', { class: 'badge', title: `ledger sequence ${seq}` }, `seq ${dash(seq)}`),
          isBlank(trust.cappedAt) ? null : h('span', { class: 'chip chip-rejected' }, h('i', { class: 'dot' }), `capped at ${trust.cappedAt}`)),
        h('div', { class: 'dzr-tags' },
          hashChip(record.recordHash, { label: 'recordHash', toast: 'record hash' }),
          h('span', { class: 't-sub mono' }, `entry ${short(record.entryHash, 10)} · prev ${short(record.prevEntryHash, 10)}`))),

      h('div', { class: 'verdict' },
        h('div', { class: 'verdict-score' },
          scoreValue(trust.score, trust.band),
          h('span', { class: 'verdict-of' }, 'trust / 100')),
        h('div', { class: 'verdict-body' },
          h('p', { class: 'verdict-reason' }, trust.reason ?? 'No reason recorded.'),
          h('div', { class: 'verdict-facts' },
            h('span', null, 'band ', h('b', null, dash(trust.band))),
            h('span', null, 'mode ', h('b', null, dash(trust.allowedMode))),
            h('span', null, trust.trustFloor === null || trust.trustFloor === undefined
              ? 'floor not configured'
              : `floor ${trust.trustFloor} · ${trust.meetsFloor ? 'met' : 'below'}`),
            h('span', { onmousemove: (e) => showTip(`<div class="tip-k">${fmtTime(record.executedAt)}</div>`, e.clientX, e.clientY), onmouseleave: hideTip },
              relTime(record.executedAt))))),

      trust.components?.length
        ? section('Score components',
          scoreBar({ components: trust.components }),
          trust.signals?.length
            ? h('div', { class: 'dzr-tags' }, ...trust.signals.map((signal) => h('span', {
              class: `chip chip-${signal.startsWith('critical') || signal.startsWith('deny') ? 'rejected' : 'flagged'}`,
            }, h('i', { class: 'dot' }), signal)))
            : null)
        : section('Score components', h('p', { class: 'placeholder' }, 'No per-component breakdown stored on this proof.')),

      section('What the agent committed to',
        cells([
          ['Action', record.action],
          ['Resource', record.resource],
          ['Executed', fmtTime(record.executedAt)],
          ['Action digest', short(record.actionDigest, 12), { copy: true, full: record.actionDigest, mono: true }],
          ['Payload digest', short(record.payloadDigest, 12), { copy: true, full: record.payloadDigest, mono: true }],
          ['Signature', `${dash(record.signatureAlg)} · ${short(record.actionSignature, 10)}`, { copy: true, full: record.actionSignature, mono: true }],
        ]),
        cells([
          ['Identity key', short(record.identity?.publicKey, 12), { copy: true, full: record.identity?.publicKey, mono: true }],
          ['Fingerprint', record.executionFingerprint ? JSON.stringify(record.executionFingerprint) : 'not submitted', { mono: true }],
          ['Context', Object.keys(record.context ?? {}).length ? JSON.stringify(record.context) : 'empty', { mono: true }],
        ])),

      section('Policy evaluation',
        h('div', { class: 'dzr-tags' },
          h('span', { class: `chip chip-${record.policy?.authorized ? 'trusted' : 'rejected'}` },
            h('i', { class: 'dot' }), record.policy?.authorized ? 'authorized' : 'denied'),
          ...(record.policy?.matchedScopes ?? []).map((scope) => h('span', { class: 'chip' }, h('span', { class: 'mono' }, `${scope.action}:${scope.resource}`)))),
        (record.policy?.reasons ?? []).length
          ? h('div', { class: 'dzr-section' }, ...record.policy.reasons.map((reason) => finding(reason.code, reason.detail, reason.severity)))
          : h('p', { class: 't-sub muted' }, 'No policy finding on this action.')),

      section('Anomalies',
        ...(record.anomalies?.length
          ? record.anomalies.map((anomaly) => finding(anomaly.code, anomaly.detail, anomaly.severity, anomaly.evidence ? JSON.stringify(anomaly.evidence) : null))
          : [h('p', { class: 't-sub muted' }, 'No detector raised a finding on this proof.')])),

      section('Independent attestation',
        h('div', { class: 'cells' }, ...(record.witnesses ?? []).map((witness) => h('div', { class: 'cell' },
          h('span', { class: 'cell-k' }, head(witness.nodeId.replace('verix-node-', ''), 16)),
          h('span', { class: 'cell-v' }, `${dash(witness.cloud)} · seq ${witness.seq}`),
          h('span', { class: 't-sub mono' }, `${fmtTime(witness.observedAt).slice(11)} · ${witness.alg}`)))),
        record.witnesses?.length ? null : h('p', { class: 't-sub muted' }, 'No witness attestation stored on this record.'),
        rowQuorum(record)),

      section('Cross-cloud agreement',
        cross?.error ? errorRow(cross.error) : cross ? h('div', { class: 'dzr-section' },
          cells([
            ['Consistent', yesNo(cross.consistent), { color: cross.consistent ? 'jade' : 'crimson' }],
            ['Roots', `${cross.distinctRoots} distinct`],
            ['Reporting', `${cross.nodesReporting} of ${cross.nodesRequired}`],
            ['Elected root', short(cross.electedRoot, 12), { copy: true, full: cross.electedRoot, mono: true }],
          ]),
          h('table', { class: 'table' },
            h('tbody', null, ...(cross.perNode ?? []).map((entry) => {
              const good = entry.selfVerified && entry.recordMatchesCommitment && entry.witnessesValid && entry.assessment?.valid !== false;
              return h('tr', {
                onmousemove: (e) => showTip(`<b>${head(entry.nodeId, 26)}</b>
                  <div class="tip-k">root ${short(entry.root, 22)}</div>
                  <div class="tip-k">${entry.treeSize} leaves · ${entry.validWitnessCount}/${entry.witnessCount} witness sigs valid</div>`, e.clientX, e.clientY),
                onmouseleave: hideTip,
              },
              h('td', null, h('span', { class: 't-state' }, h('i', { style: `color: var(--${good ? 'jade' : 'crimson'});` }), h('span', { class: 'mono' }, head(entry.nodeId.replace('verix-node-', ''), 16)))),
              h('td', { class: 'align-right' }, h('span', { class: 't-sub' },
                entry.selfVerified ? 'chain ok' : 'chain BAD', ' · ',
                entry.recordMatchesCommitment ? 'hash ok' : 'hash BAD', ' · ',
                `${entry.validWitnessCount}/${entry.witnessCount} sigs`, ' · ',
                entry.assessment ? (entry.assessment.valid ? 'assessment valid' : 'assessment INVALID') : 'unsigned')));
            }))))
          : null),

      section('Chain integrity',
        audit?.error ? errorRow(audit.error) : audit ? cells([
          ['Window', `${audit.auditedFrom}→${audit.auditedTo}`],
          ['Intact', yesNo(audit.intact), { color: audit.intact ? 'jade' : 'crimson' }],
          ['Assessments', `${audit.assessments.verified} valid · ${audit.assessments.invalid} invalid · ${audit.assessments.unsigned} unsigned`],
          ['Root', `${short(audit.root, 12)}${audit.rootChecked ? ' · matches head' : ''}`, { copy: true, full: audit.root, mono: true }],
        ]) : null,
        inclusion?.error ? errorRow(inclusion.error) : inclusion ? cells([
          ['Merkle tree', `${inclusion.treeSize} leaves`],
          ['Path', `${inclusion.path.length} node(s)`],
          ['Leaf', short(inclusion.recordHash, 12), { copy: true, full: inclusion.recordHash, mono: true }],
          ['Root', short(inclusion.root, 12), { copy: true, full: inclusion.root, mono: true }],
        ]) : null,
        ...(audit?.problems ?? []).slice(0, 12).map((problem) => finding(problem.code, `seq ${problem.seq}: ${problem.detail}`, 'deny'))),

      section('Revocation log',
        ...(revocations.revocations?.length
          ? revocations.revocations.map((entry) => finding('REVOKED', `${fmtTime(entry.revokedAt)} by ${head(entry.revokedBy, 22)} — ${entry.reason}`, 'deny'))
          : [h('p', { class: 't-sub muted' }, `No authentic revocation entry for this identity (${revocations.nodesReporting ?? '?'} node(s) consulted${revocations.forged?.length ? `, ${revocations.forged.length} forged entry(ies) refused` : ''}).`)])),

      h('div', { class: 'seal', dataset: { valid: String(data.assessment?.valid !== false) } },
        h('div', { class: 'seal-head' },
          h('span', { class: 'eyebrow' }, 'Coordinator assessment'),
          chip(data.assessment?.valid ? 'trusted' : 'rejected')),
        h('span', { class: 'seal-line' },
          `${dash(data.assessment?.alg)} over ${short(data.assessment?.digest, 16)} · signed ${dash(data.assessment?.signedAt ? fmtTime(data.assessment.signedAt) : null)} by ${head(data.assessment?.coordinatorId, 24)}`),
        ...(data.assessment?.problems ?? []).map((problem) => finding(problem.code, problem.detail, 'deny'))),

      section('Stored copies',
        h('div', { class: 'dzr-tags' }, ...(data.replication ?? []).map((entry) => h('span', {
          class: `chip chip-${entry.present ? 'trusted' : 'rejected'}`,
        }, h('i', { class: 'dot' }), head(entry.nodeId.replace('verix-node-', ''), 14))))),

      section('Read live from',
        h('div', { class: 'sources' },
          h('span', { class: 'source' }, `/ledger/records/${short(hash, 8)}`),
          isBlank(seq) ? null : h('span', { class: 'source' }, `/ledger/cross-check/${seq}`),
          isBlank(seq) ? null : h('span', { class: 'source' }, `/ledger/inclusion/${seq}`),
          h('span', { class: 'source' }, 'POST /ledger/audit'),
          h('span', { class: 'source' }, `/identities/${short(record.agentId, 8)}/revocations`))));

    commit(node);
  }

  function rowQuorum(record) {
    const ts = record.timestamp;
    if (!ts) return null;
    return h('div', { class: 'rows' },
      h('div', { class: 'rowline' }, h('span', { class: 'rowline-k' }, 'Quorum'),
        h('span', { class: 'rowline-v', style: `color: var(--${ts.quorumReached ? 'jade' : 'crimson'});` },
          ts.quorumReached ? 'reached' : 'NOT reached', ` · ${record.witnesses?.length ?? 0} attestation(s)`)),
      h('div', { class: 'rowline' }, h('span', { class: 'rowline-k' }, 'Witness clock spread'),
        h('span', { class: 'rowline-v', style: `color: var(--${ts.clockSkewExceeded ? 'crimson' : 'fg'});` },
          `${ts.maxClockSkewSeconds}s across ${ts.witnessCount} witness(es)${ts.clockSkewExceeded ? ' — exceeded bound' : ''}`)),
      h('div', { class: 'rowline' }, h('span', { class: 'rowline-k' }, 'Certified'),
        h('span', { class: 'rowline-v' }, dash(ts.certifiedAt ? fmtTime(ts.certifiedAt) : null))));
  }

  async function agent(id) {
    const commit = begin();
    let resolved;
    try {
      resolved = await api(`/identities/${encodeURIComponent(id)}`);
    } catch (error) {
      commit(h('div', null, finding('IDENTITY_UNREADABLE', error.message, 'deny')));
      return;
    }
    const identity = resolved.identity;
    const [revocations, records] = await Promise.all([
      api(`/identities/${encodeURIComponent(id)}/revocations`).catch(() => ({ revocations: [] })),
      api(`/ledger/records?agentId=${encodeURIComponent(id)}&limit=12`).catch(() => ({ records: [] })),
    ]);
    const scopes = identity.scopes ?? [];
    const revoked = Boolean(identity.revokedAt || revocations.revocations?.length);

    const node = h('article', { class: 'dzr' },
      h('header', { class: 'dzr-head' },
        h('h2', { class: 'dzr-title' }, identity.subject?.name ?? head(id, 28)),
        h('div', { class: 'dzr-tags' },
          chip(revoked ? 'revoked' : 'trusted'),
          h('span', { class: 'chip' }, dash(identity.kind)),
          h('span', { class: 'chip' }, dash(identity.alg)),
          h('span', { class: 'badge' }, `${records.records?.length ?? 0} recent`)),
        h('div', { class: 'dzr-tags' }, hashChip(id, { label: 'identity', toast: 'identity id' }))),

      section('Identity document',
        cells([
          ['Subject', identity.subject?.role ?? JSON.stringify(identity.subject ?? {})],
          ['Issued', fmtTime(identity.issuedAt)],
          ['Expires', `${fmtTime(identity.expiresAt).slice(0, 10)} · ${relTime(identity.expiresAt)}`,
            { color: new Date(identity.expiresAt) < new Date() ? 'crimson' : null }],
          ['Issuer', identity.parent?.id ? head(identity.parent.id, 22) : 'none — trust root'],
          ['Self-binding', identity.selfSignature ? 'signature present' : 'MISSING', { color: identity.selfSignature ? 'jade' : 'crimson' }],
          ['Node copies', `${resolved.copies} reporting${resolved.disagreement ? ` · ${resolved.disagreement} disagree` : ''}`,
            { color: resolved.disagreement ? 'crimson' : null }],
        ]),
        cells([['Public key', short(identity.publicKey, 16), { copy: true, full: identity.publicKey, mono: true }]])),

      section('Scopes',
        ...(scopes.length
          ? [h('table', { class: 'table' },
            h('thead', null, h('tr', null, h('th', null, 'Action'), h('th', null, 'Resource'), h('th', { class: 'align-right' }, 'Constraints'))),
            h('tbody', null, ...scopes.map((scope) => h('tr', null,
              h('td', null, h('span', { class: 'mono' }, scope.action)),
              h('td', null, h('span', { class: 'mono' }, scope.resource)),
              h('td', { class: 'align-right' }, scope.constraints
                ? h('span', { class: 't-sub mono', title: JSON.stringify(scope.constraints) }, `${Object.keys(scope.constraints).length} set`)
                : h('span', { class: 't-sub muted' }, 'unconstrained'))))))]
          : [h('p', { class: 't-sub muted' }, 'This identity grants no scopes; every action is denied by policy.')])),

      section('Revocations',
        ...(revocations.revocations?.length
          ? revocations.revocations.map((entry) => finding('REVOKED', `${fmtTime(entry.revokedAt)} by ${head(entry.revokedBy, 24)} — ${entry.reason}`, 'deny', `${entry.alg} signature`))
          : [h('p', { class: 't-sub muted' }, `No authentic revocation on record${revocations.forged?.length ? `; ${revocations.forged.length} forged entry(ies) rejected` : ''}.`)])),

      section('Recent proofs',
        ...(records.records?.length
          ? [h('table', { class: 'table' },
            h('tbody', null, ...records.records.map((record) => h('tr', {
              tabindex: '0',
              onclick: () => onSelectProof?.(record.recordHash),
              onkeydown: (event) => event.key === 'Enter' && onSelectProof?.(record.recordHash),
            },
            h('td', { class: 't-rank' }, String(record.seq ?? '—')),
            h('td', null,
              h('span', { class: 't-name' }, record.action),
              h('span', { class: 't-sub mono' }, head(record.resource, 30))),
            h('td', { class: 'nowrap' }, chip(record.trust?.status ?? 'unattested')),
            h('td', { class: 'align-right' }, h('span', { class: 't-num' }, dash(record.trust?.score))),
            h('td', { class: 'align-right nowrap' }, h('span', { class: 't-sub' }, fmtTime(record.executedAt).slice(11)))))))]
          : [emptyBlock('No proofs yet', h('span', null, 'This identity has not had an action verified.'))])));

    commit(node);
  }

  async function node(nodeId, descriptor) {
    const commit = begin();
    const audit = await api('/ledger/audit', { method: 'POST', body: { nodeId } }).catch((error) => ({ error }));

    const node = h('article', { class: 'dzr' },
      h('header', { class: 'dzr-head' },
        h('h2', { class: 'dzr-title' }, head(nodeId, 30)),
        h('div', { class: 'dzr-tags' },
          descriptor ? chip(descriptor.recentWindowIntact === false ? 'rejected' : 'trusted', null) : null,
          h('span', { class: 'chip' }, `${dash(descriptor?.cloud)}${descriptor?.region ? ` · ${descriptor.region}` : ''}`),
          h('span', { class: 'badge' }, `${dash(descriptor?.chainLength, 0)} entries`)),
        h('div', { class: 'dzr-tags' }, descriptor
          ? hashChip(short(descriptor.publicKey, 16), { full: descriptor.publicKey, label: 'signing key', toast: 'node key' })
          : null)),

      section('Node state',
        descriptor ? cells([
          ['Chain', `${dash(descriptor.chainLength)} ${plural(descriptor.chainLength ?? 0, 'entry', 'entries')}`],
          ['Root', short(descriptor.head?.root, 12), { copy: true, full: descriptor.head?.root, mono: true }],
          ['Last entry', short(descriptor.head?.lastEntryHash, 12), { copy: true, full: descriptor.head?.lastEntryHash, mono: true }],
          ['Updated', `${fmtTime(descriptor.head?.updatedAt)} · ${relTime(descriptor.head?.updatedAt)}`],
          ['Contents', `${dash(descriptor.records)} records · ${dash(descriptor.identities)} identities · ${dash(descriptor.revocations)} revocations`],
          ['Anchors', descriptor.trustAnchorIds?.length ? descriptor.trustAnchorIds.map((id) => head(id, 18)).join(', ') : 'none'],
        ]) : h('p', { class: 'placeholder' }, 'Descriptor not available for this node.')),

      section('Full-chain audit',
        audit.error ? errorRow(audit.error) : h('div', { class: 'dzr-section' },
          cells([
            ['Audited', `${audit.auditedFrom}→${audit.auditedTo}`],
            ['Intact', yesNo(audit.intact), { color: audit.intact ? 'jade' : 'crimson' }],
            ['Assessments', `${audit.assessments.verified} valid · ${audit.assessments.invalid} invalid · ${audit.assessments.unsigned} unsigned`],
            ['Root', `${short(audit.root, 12)}${audit.rootChecked ? ' · matches head' : ''}`, { copy: true, full: audit.root, mono: true }],
          ]),
          ...(audit.problems ?? []).slice(0, 20).map((problem) => finding(problem.code, `seq ${problem.seq}: ${problem.detail}`, 'deny')))),

      h('p', { class: 't-sub muted' },
        'The audit recomputes every entry hash, verifies the node signature over it, checks prev-linkage, re-hashes each record payload against its chain commitment and re-derives the merkle root.'));

    commit(node);
  }

  function clear(message) {
    token += 1;
    target.textContent = '';
    target.appendChild(h('p', { class: 'placeholder' }, message));
  }

  function cancel() {
    token += 1;
    target.textContent = '';
  }

  return { proof, agent, node, clear, cancel };
}
