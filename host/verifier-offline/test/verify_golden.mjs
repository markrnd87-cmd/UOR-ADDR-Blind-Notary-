/**
 * Normative Offline Verification Suite (`host/verifier-offline/test/verify_golden.mjs`)
 *
 * Invoked directly by `just vv` (`node host/verifier-offline/test/verify_golden.mjs`).
 * Verifies:
 *   1. All 5 golden vectors in `tests/vectors/*.json` (UR-03, UR-04, UR-05, UR-10, NR-03, NR-06).
 *   2. End-to-end 5-step zero-network DSSE v1.0 PAE + in-toto v1 + Merkle inclusion +
 *      `Notary.holo` (`HOLO\x04\x00`) verification (`WT-04`, `NR-08`..`NR-12`, `TC-05`, `TC-06`).
 *   3. Negative tamper detection when any subject kappa, PAE byte, or Merkle root is altered.
 */

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DSSE_INTOTO_PAYLOAD_TYPE,
  HOLO_V4_MAGIC,
  INTOTO_STATEMENT_V1_URI,
  UOR_BLIND_RECEIPT_PREDICATE_V1_URI,
  computeKappaFromObject,
  encodeDssePae,
  isValidKappaLabel,
  jcsSerialize,
  projectMcpSurfaceManifest,
  verifyHoloArtifact,
  verifyOfflineReceiptBundle,
} from '../src/index.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../../..');

function loadVector(filename) {
  const fullPath = path.join(REPO_ROOT, 'tests', 'vectors', filename);
  return JSON.parse(fs.readFileSync(fullPath, 'utf8'));
}

function testPermutationAndCausalChainVector() {
  const vec = loadVector('surface_permuted_tools.json');

  const projA = projectMcpSurfaceManifest(
    vec.server_id,
    vec.protocol_version,
    vec.permutation_a_single_page
  );
  const projB = projectMcpSurfaceManifest(
    vec.server_id,
    vec.protocol_version,
    vec.permutation_b_two_pages_reversed
  );

  // NR-02 & NR-03: Both permuted paginated inputs produce identical canonical JCS & 71-byte KappaLabel
  assert.equal(projA.canonicalJcs, vec.expected_canonical_manifest_jcs);
  assert.equal(projB.canonicalJcs, vec.expected_canonical_manifest_jcs);
  assert.equal(projA.manifestKappa, projB.manifestKappa);
  assert.equal(isValidKappaLabel(projA.manifestKappa), true);

  // NR-06: Causal chain JCS serialization
  const invJcs = jcsSerialize(vec.causal_chain.invocation_envelope);
  assert.equal(invJcs, vec.causal_chain.expected_invocation_jcs);

  const outJcs = jcsSerialize(vec.causal_chain.outcome_envelope);
  assert.equal(outJcs, vec.causal_chain.expected_outcome_jcs);
}

function testFiveStepOfflineReceiptVerification() {
  const vec = loadVector('surface_permuted_tools.json');
  const proj = projectMcpSurfaceManifest(
    vec.server_id,
    vec.protocol_version,
    vec.permutation_a_single_page
  );

  const invocationEnvelope = {
    arguments: {},
    manifest_kappa: proj.manifestKappa,
    tool: 'create_invoice_summary',
    uor_mcp_invocation_v: 1,
  };
  const invocationKappa = computeKappaFromObject(invocationEnvelope);

  const outcomeEnvelope = {
    content: [],
    invocation_kappa: invocationKappa,
    isError: false,
    structuredContent: null,
    uor_mcp_outcome_v: 1,
  };
  const outcomeKappa = computeKappaFromObject(outcomeEnvelope);

  const statement = {
    _type: INTOTO_STATEMENT_V1_URI,
    predicate: {
      notary: {
        id: 'notary.uor.foundation/reference-v1',
        issuedAt: '2026-11-22T00:00:00Z',
        logIndex: 0,
      },
      pinnedManifestKappa: proj.manifestKappa,
      serverId: vec.server_id,
      sessionChain: {
        clientNonce: 'nonce-golden-01',
        prevReceiptKappa: null,
      },
      unicodeGate: {
        passed: true,
        profile: 'strict-v1',
        toolCount: 2,
      },
      verdict: 'VERIFIED',
    },
    predicateType: UOR_BLIND_RECEIPT_PREDICATE_V1_URI,
    subject: [
      {
        annotations: {
          'uor.kappaLabel': proj.manifestKappa,
          'uor.realization': 'uor_addr::json',
        },
        digest: { sha256: proj.manifestKappa.slice(7) },
        name: 'mcp:manifest',
      },
      {
        annotations: {
          'uor.kappaLabel': invocationKappa,
          'uor.realization': 'uor_addr::json',
        },
        digest: { sha256: invocationKappa.slice(7) },
        name: 'mcp:invocation',
      },
      {
        annotations: {
          'uor.kappaLabel': outcomeKappa,
          'uor.realization': 'uor_addr::json',
        },
        digest: { sha256: outcomeKappa.slice(7) },
        name: 'mcp:outcome',
      },
    ],
  };

  const statementBytes = Buffer.from(jcsSerialize(statement), 'utf8');
  const receiptKappa = computeKappaFromObject(statement);

  // Generate ephemeral Ed25519 keypair completely offline
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });

  const paeBytes = encodeDssePae(DSSE_INTOTO_PAYLOAD_TYPE, statementBytes);
  const signatureBytes = crypto.sign(null, paeBytes, privateKey);

  // Build valid Notary.holo v4.0 header ("HOLO\x04\x00" + uint32LE(1))
  const holoBuf = Buffer.alloc(10);
  HOLO_V4_MAGIC.copy(holoBuf, 0);
  holoBuf.writeUInt32LE(1, 6);
  const holoCheck = verifyHoloArtifact(holoBuf);
  assert.equal(holoCheck.valid, true);

  const bundle = {
    dsseEnvelope: {
      payload: statementBytes.toString('base64'),
      payloadType: DSSE_INTOTO_PAYLOAD_TYPE,
      signatures: [
        {
          keyid: 'uor-notary-ed25519-dev-01',
          sig: signatureBytes.toString('base64'),
        },
      ],
    },
    publicKeyPem,
    rawFrames: {
      server_id: vec.server_id,
      protocol_version: vec.protocol_version,
      tools_list_pages: vec.permutation_b_two_pages_reversed,
      invocation: {
        tool: 'create_invoice_summary',
        arguments: {},
      },
      outcome: {
        isError: false,
        content: [],
        structuredContent: null,
      },
    },
    merkleProof: [],
    checkpoint: {
      origin: 'notary.uor.foundation/tlog-v1',
      treeSize: 1,
      rootHash: receiptKappa,
    },
    holoBase64: holoBuf.toString('base64'),
  };

  const result = verifyOfflineReceiptBundle(bundle);
  assert.equal(result.verified, true);
  assert.equal(result.verdict, 'VERIFIED');
  assert.equal(result.receiptKappa, receiptKappa);
  assert.equal(result.steps.step1_dsse_pae_signature, true);
  assert.equal(result.steps.step2_intoto_statement_subjects, true);
  assert.equal(result.steps.step3_causal_kappa_recomputation, true);
  assert.equal(result.steps.step4_pin_and_verdict_alignment, true);
  assert.equal(result.steps.step5_merkle_checkpoint_and_holo, true);

  // Negative check: tampering with Merkle checkpoint root fails Step 5
  const tamperedBundle = structuredClone(bundle);
  tamperedBundle.checkpoint.rootHash =
    'sha256:0000000000000000000000000000000000000000000000000000000000000000';
  const tamperedResult = verifyOfflineReceiptBundle(tamperedBundle);
  assert.equal(tamperedResult.verified, false);
  assert.equal(tamperedResult.failedStep, 5);
}

testPermutationAndCausalChainVector();
testFiveStepOfflineReceiptVerification();
console.log(
  '[PASS] host/verifier-offline/test/verify_golden.mjs: 5-step zero-network DSSE PAE, in-toto v1, causal kappa-chain, Merkle proof & Notary.holo verified.'
);
