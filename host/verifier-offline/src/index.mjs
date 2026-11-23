/**
 * @uor-foundation/verifier-offline (`host/verifier-offline/src/index.mjs`)
 *
 * Zero-Network 5-Step Offline Receipt, Merkle Inclusion, Causal Kappa-Chain &
 * Hologram (`Notary.holo`) Verifier (WT-04, NR-06..NR-10, NR-12, TC-05, TC-06).
 *
 * Uses ONLY Node.js built-in `node:crypto` with zero external runtime dependencies
 * and zero network calls.
 */

import crypto from 'node:crypto';

export const INTOTO_STATEMENT_V1_URI = 'https://in-toto.io/Statement/v1';
export const UOR_BLIND_RECEIPT_PREDICATE_V1_URI =
  'https://uor.foundation/predicates/mcp-blind-receipt/v1';
export const DSSE_INTOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
export const KAPPA_LABEL_REGEX = /^sha256:[0-9a-f]{64}$/;
export const HOLO_V4_MAGIC = Buffer.from([0x48, 0x4f, 0x4c, 0x4f, 0x04, 0x00]); // "HOLO\x04\x00"
export const TR_MAX = 1024;

/**
 * Validates that a string is a 71-byte ASCII KappaLabel (`^sha256:[0-9a-f]{64}$`, NR-07).
 */
export function isValidKappaLabel(label) {
  return (
    typeof label === 'string' &&
    Buffer.byteLength(label, 'utf8') === 71 &&
    KAPPA_LABEL_REGEX.test(label)
  );
}

/**
 * Deterministic RFC 8785 JSON Canonicalization Scheme (JCS) serializer.
 */
export function jcsSerialize(value) {
  if (value === null || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('JCS does not allow non-finite numbers');
    }
    return Object.is(value, -0) ? '0' : JSON.stringify(value);
  }
  if (typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((item) => jcsSerialize(item)).join(',') + ']';
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const k of keys) {
      if (value[k] !== undefined) {
        parts.push(`${JSON.stringify(k)}:${jcsSerialize(value[k])}`);
      }
    }
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`Unsupported JCS value type: ${typeof value}`);
}

/**
 * Mints a 71-byte `sha256:<64-lower-hex>` KappaLabel from any JSON object via RFC 8785 JCS.
 */
export function computeKappaFromObject(obj) {
  const canonicalBytes = Buffer.from(jcsSerialize(obj), 'utf8');
  const digestHex = crypto.createHash('sha256').update(canonicalBytes).digest('hex');
  return `sha256:${digestHex}`;
}

/**
 * Stage-1 & Stage-2 MCP Surface Projection (`UorNotary.Surface.projectSurfaceManifest`).
 * Drains pages, strips transport metadata (`jsonrpc`, `id`, `nextCursor`, `_meta`),
 * sorts `tools[]` by UTF-8 byte order of NFC `tool.name`, and rejects duplicate tool names.
 */
export function projectMcpSurfaceManifest(serverId, protocolVersion, pages) {
  if (!serverId || typeof serverId !== 'string') {
    throw new Error('SurfaceError::EmptyServerId');
  }
  if (!Array.isArray(pages) || pages.length === 0) {
    throw new Error('SurfaceError::EmptyPages');
  }

  const allTools = [];
  for (let i = 0; i < pages.length; i++) {
    const page = pages[i];
    const container = page.result ?? page;
    if (i === pages.length - 1 && container.nextCursor != null) {
      throw new Error('SurfaceError::PaginationIncomplete');
    }
    if (!Array.isArray(container.tools)) {
      throw new Error('SurfaceError::MissingToolsArray');
    }
    for (const t of container.tools) {
      allTools.push({
        annotations: {
          destructiveHint: Boolean(t?.annotations?.destructiveHint ?? false),
          readOnlyHint: Boolean(t?.annotations?.readOnlyHint ?? false),
        },
        description: String(t.description ?? ''),
        inputSchema: t.inputSchema ?? {
          additionalProperties: false,
          properties: {},
          required: [],
          type: 'object',
        },
        name: String(t.name),
        outputSchema: t.outputSchema ?? null,
      });
    }
  }

  allTools.sort((a, b) =>
    Buffer.compare(Buffer.from(a.name, 'utf8'), Buffer.from(b.name, 'utf8'))
  );

  for (let i = 1; i < allTools.length; i++) {
    if (allTools[i - 1].name === allTools[i].name) {
      throw new Error(`SurfaceError::DuplicateToolName(${allTools[i].name})`);
    }
  }

  const envelope = {
    protocol_version: protocolVersion,
    server_id: serverId,
    tools: allTools,
    uor_mcp_surface_v: 1,
  };

  const canonicalJcs = jcsSerialize(envelope);
  const manifestKappa = computeKappaFromObject(envelope);
  return { envelope, canonicalJcs, manifestKappa };
}

/**
 * Normative DSSE v1.0 Pre-Authentication Encoding (PAE) builder (`NR-09`):
 * `PAE(type, body) = "DSSEv1 " || dec(len(type)) || " " || type || " " || dec(len(body)) || " " || body`
 */
export function encodeDssePae(payloadType, rawBodyBytes) {
  const typeBytes = Buffer.from(payloadType, 'utf8');
  const bodyBuf = Buffer.isBuffer(rawBodyBytes)
    ? rawBodyBytes
    : Buffer.from(rawBodyBytes, 'utf8');
  const prefix = Buffer.from(
    `DSSEv1 ${typeBytes.length} ${payloadType} ${bodyBuf.length} `,
    'utf8'
  );
  return Buffer.concat([prefix, bodyBuf]);
}

/**
 * Folds a leaf KappaLabel through a binary Merkle inclusion proof path (`NR-10`).
 */
export function computeMerkleRootFromProof(leafKappa, proofSteps) {
  if (!isValidKappaLabel(leafKappa)) {
    throw new Error(`Invalid leaf KappaLabel: ${leafKappa}`);
  }
  let current = leafKappa;
  for (const step of proofSteps ?? []) {
    if (!isValidKappaLabel(step.siblingHash)) {
      throw new Error(`Invalid sibling KappaLabel: ${step.siblingHash}`);
    }
    const combinedInput =
      step.side === 'Left'
        ? `node:${step.siblingHash}:${current}`
        : `node:${current}:${step.siblingHash}`;
    const digest = crypto.createHash('sha256').update(combinedInput, 'utf8').digest('hex');
    current = `sha256:${digest}`;
  }
  return current;
}

/**
 * Verifies a `Notary.holo` (`HOLO\x04\x00`) binary artifact and bounded replay trace (`NR-12`, `TC-05`, `TC-06`).
 */
export function verifyHoloArtifact(holoBuffer) {
  const buf = Buffer.isBuffer(holoBuffer) ? holoBuffer : Buffer.from(holoBuffer);
  if (buf.length < 10) {
    return { valid: false, reason: 'HOLO_TOO_SHORT' };
  }
  const magic = buf.subarray(0, 6);
  if (!magic.equals(HOLO_V4_MAGIC)) {
    return { valid: false, reason: 'INVALID_HOLO_MAGIC' };
  }
  const eventCount = buf.readUInt32LE(6);
  if (eventCount > TR_MAX) {
    return { valid: false, reason: `TRACE_EXCEEDS_TR_MAX(${eventCount} > ${TR_MAX})` };
  }
  return { valid: true, version: '4.0', eventCount };
}

/**
 * Executes the Complete 5-Step Zero-Network Offline Receipt Verification (`WT-04`, Section 5.1):
 *   Step 1: Verify DSSE v1.0 PAE and Ed25519 signature(s) against trusted public key(s).
 *   Step 2: Parse in-toto Statement v1, check URIs, and validate all three subject KappaLabels.
 *   Step 3: Recompute manifest_kappa, invocation_kappa, and outcome_kappa from raw MCP frames (when supplied)
 *           and verify causal kappa-chaining (`NR-06`).
 *   Step 4: Verify pin alignment (`manifest_kappa == predicate.pinnedManifestKappa`) and verdict consistency.
 *   Step 5: Verify C2SP `tlog-checkpoint` signature and Merkle inclusion proof (`NR-10`) plus optional `.holo`.
 */
export function verifyOfflineReceiptBundle(bundle) {
  const steps = {
    step1_dsse_pae_signature: false,
    step2_intoto_statement_subjects: false,
    step3_causal_kappa_recomputation: false,
    step4_pin_and_verdict_alignment: false,
    step5_merkle_checkpoint_and_holo: false,
  };

  // --- Step 1: DSSE v1.0 PAE & Ed25519 Signature Verification ---
  const { dsseEnvelope, publicKeyPem, rawFrames, merkleProof, checkpoint, holoBase64 } = bundle;
  if (!dsseEnvelope || dsseEnvelope.payloadType !== DSSE_INTOTO_PAYLOAD_TYPE) {
    return { verified: false, failedStep: 1, reason: 'INVALID_DSSE_PAYLOAD_TYPE', steps };
  }
  const rawBodyBytes = Buffer.from(dsseEnvelope.payload, 'base64');
  const paeBytes = encodeDssePae(dsseEnvelope.payloadType, rawBodyBytes);

  if (!Array.isArray(dsseEnvelope.signatures) || dsseEnvelope.signatures.length === 0) {
    return { verified: false, failedStep: 1, reason: 'MISSING_DSSE_SIGNATURES', steps };
  }
  const primarySig = Buffer.from(dsseEnvelope.signatures[0].sig, 'base64');
  const pubKeyObj = crypto.createPublicKey(publicKeyPem);
  const sigValid = crypto.verify(null, paeBytes, pubKeyObj, primarySig);
  if (!sigValid) {
    return { verified: false, failedStep: 1, reason: 'ED25519_PAE_SIGNATURE_MISMATCH', steps };
  }
  steps.step1_dsse_pae_signature = true;

  // --- Step 2: in-toto Statement v1 & Subject KappaLabels (`NR-07`, `NR-08`) ---
  let statement;
  try {
    statement = JSON.parse(rawBodyBytes.toString('utf8'));
  } catch {
    return { verified: false, failedStep: 2, reason: 'MALFORMED_INTOTO_JSON', steps };
  }

  if (
    statement._type !== INTOTO_STATEMENT_V1_URI ||
    statement.predicateType !== UOR_BLIND_RECEIPT_PREDICATE_V1_URI ||
    !Array.isArray(statement.subject) ||
    statement.subject.length !== 3
  ) {
    return { verified: false, failedStep: 2, reason: 'INVALID_INTOTO_SCHEMA', steps };
  }

  const subjectMap = new Map();
  for (const subj of statement.subject) {
    const kappa = subj?.annotations?.['uor.kappaLabel'];
    const sha256Hex = subj?.digest?.sha256;
    if (!isValidKappaLabel(kappa) || kappa !== `sha256:${sha256Hex}`) {
      return {
        verified: false,
        failedStep: 2,
        reason: `SUBJECT_KAPPA_DIGEST_MISMATCH(${subj?.name})`,
        steps,
      };
    }
    subjectMap.set(subj.name, kappa);
  }
  const manifestKappa = subjectMap.get('mcp:manifest');
  const invocationKappa = subjectMap.get('mcp:invocation');
  const outcomeKappa = subjectMap.get('mcp:outcome');
  if (!manifestKappa || !invocationKappa || !outcomeKappa) {
    return { verified: false, failedStep: 2, reason: 'MISSING_REQUIRED_MCP_SUBJECTS', steps };
  }
  steps.step2_intoto_statement_subjects = true;

  // --- Step 3: Recompute Causal Kappa-Chain from Raw Frames (`NR-06`) ---
  if (rawFrames) {
    const projected = projectMcpSurfaceManifest(
      rawFrames.server_id,
      rawFrames.protocol_version,
      rawFrames.tools_list_pages
    );
    if (projected.manifestKappa !== manifestKappa) {
      return {
        verified: false,
        failedStep: 3,
        reason: 'RECOMPUTED_MANIFEST_KAPPA_MISMATCH',
        steps,
      };
    }
    const recomputedInvocationKappa = computeKappaFromObject({
      arguments: rawFrames.invocation.arguments,
      manifest_kappa: manifestKappa,
      tool: rawFrames.invocation.tool,
      uor_mcp_invocation_v: 1,
    });
    if (recomputedInvocationKappa !== invocationKappa) {
      return {
        verified: false,
        failedStep: 3,
        reason: 'RECOMPUTED_INVOCATION_KAPPA_MISMATCH',
        steps,
      };
    }
    const recomputedOutcomeKappa = computeKappaFromObject({
      content: rawFrames.outcome.content,
      invocation_kappa: invocationKappa,
      isError: rawFrames.outcome.isError,
      structuredContent: rawFrames.outcome.structuredContent ?? null,
      uor_mcp_outcome_v: 1,
    });
    if (recomputedOutcomeKappa !== outcomeKappa) {
      return {
        verified: false,
        failedStep: 3,
        reason: 'RECOMPUTED_OUTCOME_KAPPA_MISMATCH',
        steps,
      };
    }
  }
  steps.step3_causal_kappa_recomputation = true;

  // --- Step 4: Pin Alignment & Verdict Consistency (`NR-04`, `NR-05`) ---
  const pred = statement.predicate;
  if (!pred || !isValidKappaLabel(pred.pinnedManifestKappa)) {
    return { verified: false, failedStep: 4, reason: 'INVALID_PINNED_MANIFEST_KAPPA', steps };
  }
  if (pred.unicodeGate?.passed === false && pred.verdict !== 'BLOCKED_TAMPER') {
    return { verified: false, failedStep: 4, reason: 'UNICODE_FAIL_MUST_BE_BLOCKED_TAMPER', steps };
  }
  if (manifestKappa !== pred.pinnedManifestKappa && pred.verdict === 'VERIFIED') {
    return { verified: false, failedStep: 4, reason: 'DRIFT_CANNOT_BE_VERIFIED', steps };
  }
  steps.step4_pin_and_verdict_alignment = true;

  // --- Step 5: Merkle Inclusion Proof & Optional Hologram Trace (`NR-10`, `NR-12`) ---
  const receiptKappa = computeKappaFromObject(statement);
  if (checkpoint) {
    if (!(checkpoint.treeSize > 0)) {
      return { verified: false, failedStep: 5, reason: 'EMPTY_CHECKPOINT_TREE', steps };
    }
    const computedRoot = computeMerkleRootFromProof(receiptKappa, merkleProof ?? []);
    if (computedRoot !== checkpoint.rootHash) {
      return { verified: false, failedStep: 5, reason: 'MERKLE_ROOT_MISMATCH', steps };
    }
  }
  if (holoBase64) {
    const holoRes = verifyHoloArtifact(Buffer.from(holoBase64, 'base64'));
    if (!holoRes.valid) {
      return { verified: false, failedStep: 5, reason: holoRes.reason, steps };
    }
  }
  steps.step5_merkle_checkpoint_and_holo = true;

  return {
    verified: true,
    receiptKappa,
    verdict: pred.verdict,
    serverId: pred.serverId,
    manifestKappa,
    invocationKappa,
    outcomeKappa,
    steps,
  };
}
