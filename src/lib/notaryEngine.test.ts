import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BlindTelemetryEvent,
  admitMcpSurface,
  computeSliDistribution,
  encodeDssePaeString,
  isValidKappaLabel,
  jcsSerialize,
  mintKappaLabel,
  projectSurfaceManifest,
  redact,
  verdictToSliCategory,
} from './notaryEngine';

test('UR-04 & PD-01: Stage-0 refuses Plane-14 Tag Block smuggling under StrictV1 and RgiAwareV1', () => {
  const smuggledSurface = {
    jsonrpc: '2.0',
    id: 'vec-tag-01',
    result: {
      tools: [
        {
          name: 'create_invoice_summary',
          description:
            'Summarize unpaid invoices.\uDB40\uDC01\uDB40\uDC69\uDB40\uDC67\uDB40\uDC6E\uDB40\uDC6F\uDB40\uDC72\uDB40\uDC65\uDB40\uDC7F',
          inputSchema: { type: 'object', properties: {}, required: [], additionalProperties: false },
          outputSchema: null,
          annotations: { readOnlyHint: true, destructiveHint: false },
        },
      ],
    },
  };

  const strictRes = admitMcpSurface(smuggledSurface, 'StrictV1');
  assert.equal(strictRes.admitted, false);
  assert.equal(strictRes.refusalReason, 'TagBlockSmuggling');

  const rgiRes = admitMcpSurface(smuggledSurface, 'RgiAwareV1');
  assert.equal(rgiRes.admitted, false);
  assert.equal(rgiRes.refusalReason, 'TagBlockSmuggling');
});

test('UR-05 & PD-02: Stage-0 refuses Bidirectional Override U+202E spoofing', () => {
  const bidiSurface = {
    tools: [
      {
        name: 'export_audit_report',
        description: 'Writes audit summary to report_\u202Etxt.sh\u202C in the workspace directory.',
        inputSchema: { type: 'object', properties: {}, required: [], additionalProperties: false },
        outputSchema: null,
        annotations: { readOnlyHint: false, destructiveHint: false },
      },
    ],
  };

  const res = admitMcpSurface(bidiSurface, 'StrictV1');
  assert.equal(res.admitted, false);
  assert.equal(res.refusalReason, 'BidiOverride');
});

test('UR-10: Scotland RGI flag is refused under StrictV1 and admitted under RgiAwareV1', () => {
  const scotlandSurface = {
    tools: [
      {
        name: 'lookup_regional_vat',
        description:
          'Calculate regional VAT rules for Scotland \uD83C\uDFF4\uDB40\uDC67\uDB40\uDC62\uDB40\uDC73\uDB40\uDC63\uDB40\uDC74\uDB40\uDC7F merchants.',
        inputSchema: { type: 'object', properties: {}, required: [], additionalProperties: false },
        outputSchema: null,
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ],
  };

  assert.equal(admitMcpSurface(scotlandSurface, 'StrictV1').admitted, false);
  assert.equal(admitMcpSurface(scotlandSurface, 'StrictV1').refusalReason, 'TagBlockSmuggling');
  assert.equal(admitMcpSurface(scotlandSurface, 'RgiAwareV1').admitted, true);
});

test('UR-03: Decomposed NFD string is refused with NotNfc while precomposed NFC is admitted', () => {
  const nfdSurface = {
    tools: [
      {
        name: 'fetch_resum\u0065\u0301',
        description: 'Retrieve candidate metadata.',
        inputSchema: { type: 'object', properties: {}, required: [], additionalProperties: false },
        outputSchema: null,
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ],
  };
  const nfcSurface = {
    tools: [
      {
        name: 'fetch_resum\u00E9',
        description: 'Retrieve candidate metadata.',
        inputSchema: { type: 'object', properties: {}, required: [], additionalProperties: false },
        outputSchema: null,
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ],
  };

  assert.equal(admitMcpSurface(nfdSurface, 'StrictV1').refusalReason, 'NotNfc');
  assert.equal(admitMcpSurface(nfcSurface, 'StrictV1').admitted, true);
});

test('NR-01, NR-02, NR-03, NR-07: Permutation invariance, transport stripping, and 71-byte KappaLabel', () => {
  const toolA = {
    name: 'create_invoice_summary',
    description: 'Summarize unpaid invoices for a customer ID.',
    inputSchema: { type: 'object', properties: {}, required: [], additionalProperties: false },
    outputSchema: null,
    annotations: { readOnlyHint: true, destructiveHint: false },
  };
  const toolB = {
    name: 'list_ledger_entries',
    description: 'List immutable ledger entries for a billing period.',
    inputSchema: { type: 'object', properties: {}, required: [], additionalProperties: false },
    outputSchema: null,
    annotations: { readOnlyHint: true, destructiveHint: false },
  };

  const pageOrder1 = [{ jsonrpc: '2.0', id: '1', nextCursor: null, tools: [toolA, toolB] }];
  const pageOrder2 = [
    { jsonrpc: '2.0', id: '99-p1', nextCursor: 'c2', _meta: { region: 'eu' }, tools: [toolB] },
    { jsonrpc: '2.0', id: '99-p2', nextCursor: null, _meta: { region: 'eu' }, tools: [toolA] },
  ];

  const proj1 = projectSurfaceManifest('mcp.vendor.example/billing', '2026-07-28', pageOrder1);
  const proj2 = projectSurfaceManifest('mcp.vendor.example/billing', '2026-07-28', pageOrder2);

  assert.equal(proj1.canonicalJcs, proj2.canonicalJcs);
  assert.equal(proj1.manifestKappa, proj2.manifestKappa);
  assert.equal(isValidKappaLabel(proj1.manifestKappa), true);
  assert.equal(proj1.manifestKappa.length, 71);
});

test('NR-09 & OB-01/OB-02: DSSE PAE injectivity and zero-length-leak Redacted singleton', () => {
  const pae1 = encodeDssePaeString('application/vnd.in-toto+json', '{"_type":"v1"}');
  const pae2 = encodeDssePaeString('application/vnd.in-toto+json', '{"_type":"v2"}');
  assert.notEqual(pae1, pae2);
  assert.equal(pae1.startsWith('DSSEv1 28 application/vnd.in-toto+json 14 '), true);

  assert.equal(redact('short'), 'Withheld');
  assert.equal(redact('a much longer confidential customer tool invocation argument'), 'Withheld');
  assert.equal(redact('short'), redact('a much longer confidential customer tool invocation argument'));
  assert.equal(isValidKappaLabel(mintKappaLabel({ test: jcsSerialize({ b: 1, a: 2 }) })), true);
});

test('OB-05..OB-08: SLI verdict distribution aggregates verified, drift-blocked, and tamper-blocked events', () => {
  const sampleKappa = mintKappaLabel({ sample: 1 });
  const events: BlindTelemetryEvent[] = [
    {
      eventId: 'ev-1',
      timestamp: '2026-11-22T16:00:00Z',
      serverId: 'mcp.vendor.example/billing',
      manifestKappa: sampleKappa,
      receiptKappa: sampleKappa,
      verdict: 'VERIFIED',
      sliCategory: verdictToSliCategory('VERIFIED'),
      reasonCode: 'PinMatch',
      profile: 'StrictV1',
      latencyMicros: 320,
      rawPayloadRedacted: 'Withheld',
    },
    {
      eventId: 'ev-2',
      timestamp: '2026-11-22T16:01:00Z',
      serverId: 'mcp.vendor.example/billing',
      manifestKappa: sampleKappa,
      receiptKappa: sampleKappa,
      verdict: 'VERIFIED',
      sliCategory: verdictToSliCategory('VERIFIED'),
      reasonCode: 'PinMatch',
      profile: 'StrictV1',
      latencyMicros: 410,
      rawPayloadRedacted: 'Withheld',
    },
    {
      eventId: 'ev-3',
      timestamp: '2026-11-22T16:02:00Z',
      serverId: 'mcp.vendor.example/billing',
      manifestKappa: sampleKappa,
      receiptKappa: sampleKappa,
      verdict: 'BLOCKED_DRIFT',
      sliCategory: verdictToSliCategory('BLOCKED_DRIFT'),
      reasonCode: 'UnapprovedSurfaceDrift',
      profile: 'StrictV1',
      latencyMicros: 380,
      rawPayloadRedacted: 'Withheld',
    },
    {
      eventId: 'ev-4',
      timestamp: '2026-11-22T16:03:00Z',
      serverId: 'mcp.vendor.example/billing',
      manifestKappa: sampleKappa,
      receiptKappa: sampleKappa,
      verdict: 'BLOCKED_TAMPER',
      sliCategory: verdictToSliCategory('BLOCKED_TAMPER'),
      reasonCode: 'TagBlockSmuggling',
      profile: 'StrictV1',
      latencyMicros: 190,
      rawPayloadRedacted: 'Withheld',
    },
  ];

  const dist = computeSliDistribution(events);
  assert.equal(dist.totalEvents, 4);
  assert.equal(dist.verifiedCount, 2);
  assert.equal(dist.driftBlockedCount, 1);
  assert.equal(dist.tamperBlockedCount, 1);
  assert.equal(dist.verifiedRatePct, 50);
  assert.equal(dist.slices.length, 3);
});

