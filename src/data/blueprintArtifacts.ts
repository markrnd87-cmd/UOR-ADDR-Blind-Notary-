export interface GoldenPreset {
  id: string;
  label: string;
  registerBinding: string;
  serverId: string;
  defaultProfile: 'StrictV1' | 'RgiAwareV1';
  description: string;
  rawJson: string;
}

export const GOLDEN_PRESETS: GoldenPreset[] = [
  {
    id: 'clean-permuted',
    label: 'Clean Permuted Billing Surface (NR-03)',
    registerBinding: 'NR-01 · NR-02 · NR-03 · NR-07',
    serverId: 'mcp.vendor.example/billing',
    defaultProfile: 'StrictV1',
    description:
      'Two billing MCP tools with transport metadata (jsonrpc, id, _meta) that strip cleanly and sort deterministically by UTF-8 NFC tool name.',
    rawJson: JSON.stringify(
      {
        jsonrpc: '2.0',
        id: 'req-alpha-100',
        nextCursor: null,
        _meta: { traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' },
        tools: [
          {
            name: 'list_ledger_entries',
            description: 'List immutable ledger entries for a billing period.',
            inputSchema: { type: 'object', properties: {}, required: [], additionalProperties: false },
            outputSchema: null,
            annotations: { readOnlyHint: true, destructiveHint: false },
          },
          {
            name: 'create_invoice_summary',
            description: 'Summarize unpaid invoices for a customer ID.',
            inputSchema: { type: 'object', properties: {}, required: [], additionalProperties: false },
            outputSchema: null,
            annotations: { readOnlyHint: true, destructiveHint: false },
          },
        ],
      },
      null,
      2
    ),
  },
  {
    id: 'tag-block-smuggling',
    label: 'Plane-14 Tag-Block Prompt Smuggling (UR-04)',
    registerBinding: 'UR-01 · UR-04 · PD-01 · SM-02',
    serverId: 'mcp.vendor.example/billing',
    defaultProfile: 'StrictV1',
    description:
      'Embeds invisible Plane-14 Tag Block scalars (U+E0001..U+E007F) inside a tool description. Refused before canonicalization.',
    rawJson: JSON.stringify(
      {
        jsonrpc: '2.0',
        id: 'vec-tag-01',
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
      null,
      2
    ),
  },
  {
    id: 'bidi-rlo-spoof',
    label: 'Bidi Right-to-Left Override Spoof (UR-05)',
    registerBinding: 'UR-01 · UR-05 · PD-02 · SM-02',
    serverId: 'mcp.vendor.example/audit',
    defaultProfile: 'StrictV1',
    description:
      'Embeds U+202E (Right-to-Left Override) to visually disguise an executable .sh script as a harmless .txt file.',
    rawJson: JSON.stringify(
      {
        jsonrpc: '2.0',
        id: 'vec-bidi-01',
        tools: [
          {
            name: 'export_audit_report',
            description: 'Writes audit summary to report_\u202Etxt.sh\u202C in the workspace directory.',
            inputSchema: { type: 'object', properties: {}, required: [], additionalProperties: false },
            outputSchema: null,
            annotations: { readOnlyHint: false, destructiveHint: false },
          },
        ],
      },
      null,
      2
    ),
  },
  {
    id: 'scotland-rgi-flag',
    label: 'Scotland RGI Subdivision Flag (UR-10)',
    registerBinding: 'UR-04 · UR-10 · OV-04',
    serverId: 'mcp.vendor.example/vat-eu',
    defaultProfile: 'RgiAwareV1',
    description:
      'Contains the valid RGI Scotland subdivision flag sequence (U+1F3F4 E0067..E007F). Refused under StrictV1; admitted under RgiAwareV1.',
    rawJson: JSON.stringify(
      {
        jsonrpc: '2.0',
        id: 'vec-rgi-01',
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
      },
      null,
      2
    ),
  },
  {
    id: 'nfd-decomposed',
    label: 'Decomposed NFD Combining Sequence (UR-03)',
    registerBinding: 'UR-01 · UR-03 · UR-08',
    serverId: 'mcp.vendor.example/hr',
    defaultProfile: 'StrictV1',
    description:
      'Contains decomposed U+0065 U+0301 ("e" + combining acute accent) instead of precomposed UAX #15 NFC U+00E9. Refused with NotNfc.',
    rawJson: JSON.stringify(
      {
        jsonrpc: '2.0',
        id: 'vec-nfd-01',
        tools: [
          {
            name: 'fetch_resum\u0065\u0301',
            description: 'Retrieve candidate metadata.',
            inputSchema: { type: 'object', properties: {}, required: [], additionalProperties: false },
            outputSchema: null,
            annotations: { readOnlyHint: true, destructiveHint: false },
          },
        ],
      },
      null,
      2
    ),
  },
];

export interface PlantedDefectRecord {
  id: string;
  register: string;
  targetFile: string;
  mutation: string;
  command: string;
  expectedDiagnostic: string;
}

export const PLANTED_DEFECTS: PlantedDefectRecord[] = [
  {
    id: 'PD-01',
    register: 'UR-04',
    targetFile: 'src/Admission.lex.tex',
    mutation: 'Delete Plane-14 Tag Block range check (0xE0000 <= c && c <= 0xE007F) from classifyScalarStrict.',
    command: 'lexlean verify src/Admission.lex.tex',
    expectedDiagnostic: 'FAIL (LLV7002): strictRefusesAllTagBlock fails on c = 0xE0001',
  },
  {
    id: 'PD-02',
    register: 'UR-05',
    targetFile: 'src/Admission.lex.tex',
    mutation: 'Exempt U+202E (Right-to-Left Override) from isBidiScalar under StrictV1.',
    command: 'lexlean verify src/Admission.lex.tex',
    expectedDiagnostic: 'FAIL (LLV7002): strictRefusesBidiUnconditionally fails on c = 0x202E',
  },
  {
    id: 'PD-03',
    register: 'NR-03',
    targetFile: 'src/Surface.lex.tex',
    mutation: 'Replace canonicalSortTools with identity function (omitting UTF-8 lexicographic sort).',
    command: 'lexlean verify src/Surface.lex.tex',
    expectedDiagnostic: 'FAIL (LLV7002): projectionPermutationInvariant fails',
  },
  {
    id: 'PD-04',
    register: 'EF-05',
    targetFile: 'src/Effects.lex.tex',
    mutation: 'Add rawDescription : String to EmitDriftWebhook constructor of HostEffect.',
    command: 'lexlean verify src/Effects.lex.tex',
    expectedDiagnostic: 'FAIL (LLV7002): noRawPayloadInHostEffects fails on EmitDriftWebhook',
  },
  {
    id: 'PD-05',
    register: 'OB-04',
    targetFile: 'src/Observability.lex.tex',
    mutation: 'Add second constructor | Text (s : String) to inductive Redacted.',
    command: 'lexlean verify src/Observability.lex.tex',
    expectedDiagnostic: 'FAIL (LLV7002): redactedHasOneValue and redactionIgnoresText fail',
  },
  {
    id: 'PD-06',
    register: 'SM-02',
    targetFile: 'src/Security.lex.tex',
    mutation: 'Change risk R4 status from Pending to Executed without hardware KMS test binding.',
    command: 'cargo test -p repo-conformance --test security',
    expectedDiagnostic: 'FAIL (SM-04): Executed threat lacks active hardware execution evidence',
  },
  {
    id: 'PD-07',
    register: 'ARCH-01',
    targetFile: 'src/Foundation/Arch.lex.tex',
    mutation: 'Remove Concern.C1_CryptographicBlindness from securityViewpointConcerns.',
    command: 'prismpm check',
    expectedDiagnostic: 'FAIL (PP2015 / LLV7002): Unframed concern C1_CryptographicBlindness',
  },
  {
    id: 'PD-08',
    register: 'AU-13',
    targetFile: 'src/NotaryCore.lex.tex',
    mutation: 'Insert legacy \\begin{semanticdata} ... \\end{semanticdata} block.',
    command: 'lexlean check',
    expectedDiagnostic: 'FAIL (LLP2003): Language 1.2 refuses legacy \\semanticdata block',
  },
];
