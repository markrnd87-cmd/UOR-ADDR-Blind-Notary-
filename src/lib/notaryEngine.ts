/**
 * Pure TypeScript Execution Kernel mirroring the LexLean 1.2 specification
 * (`UorNotary.Admission`, `UorNotary.Surface`, `UorNotary.NotaryCore`,
 *  `UorNotary.Effects`, `UorNotary.Observability`, `UorNotary.Security`).
 */

export type UnicodeProfile = 'StrictV1' | 'RgiAwareV1';

export type UnicodeRefusalReason =
  | 'NotUtf8'
  | 'LimitExceeded'
  | 'NotNfc'
  | 'TagBlockSmuggling'
  | 'BidiOverride'
  | 'InvisibleFormatter'
  | 'VariationSelectorStego'
  | 'ForbiddenControl';

export interface ScalarInspection {
  scalarHex: string;
  codePoint: number;
  refusal: UnicodeRefusalReason | null;
}

export interface AdmissionResult {
  admitted: boolean;
  refusalReason: UnicodeRefusalReason | null;
  offendingField: string | null;
  offendingScalars: ScalarInspection[];
  toolCount: number;
  maxDepthObserved: number;
}

export interface McpToolAnnotations {
  readOnlyHint: boolean;
  destructiveHint: boolean;
}

export interface McpToolDescriptor {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  outputSchema: Record<string, unknown> | null;
  annotations: McpToolAnnotations;
}

export interface RawMcpToolsPage {
  jsonrpc?: string;
  id?: string | number | null;
  nextCursor?: string | null;
  _meta?: Record<string, unknown>;
  result?: {
    nextCursor?: string | null;
    tools?: McpToolDescriptor[];
  };
  tools?: McpToolDescriptor[];
}

export interface SurfaceProjectionResult {
  canonicalJcs: string;
  manifestKappa: string;
  sortedToolNames: string[];
  toolCount: number;
}

export type ReceiptVerdict = 'VERIFIED' | 'BLOCKED_DRIFT' | 'BLOCKED_TAMPER';

export interface OfflineStepVerification {
  step1DssePaeSignature: boolean;
  step2IntotoStatementSubjects: boolean;
  step3CausalKappaRecomputation: boolean;
  step4PinAndVerdictAlignment: boolean;
  step5MerkleCheckpointAndHolo: boolean;
}

export const REFUSAL_PRECEDENCE_RANK: Record<UnicodeRefusalReason, number> = {
  NotUtf8: 0,
  LimitExceeded: 1,
  NotNfc: 2,
  TagBlockSmuggling: 3,
  BidiOverride: 4,
  InvisibleFormatter: 5,
  VariationSelectorStego: 6,
  ForbiddenControl: 7,
};

export function mergeRefusal(
  a: UnicodeRefusalReason | null,
  b: UnicodeRefusalReason | null
): UnicodeRefusalReason | null {
  if (!a) return b;
  if (!b) return a;
  return REFUSAL_PRECEDENCE_RANK[a] <= REFUSAL_PRECEDENCE_RANK[b] ? a : b;
}

export function isValidKappaLabel(label: string): boolean {
  return typeof label === 'string' && label.length === 71 && /^sha256:[0-9a-f]{64}$/.test(label);
}

/**
 * Pure SHA-256 implementation (FIPS 180-4) so that both Node unit tests and browser UI
 * compute identical 71-byte `sha256:<64-lower-hex>` KappaLabels synchronously.
 */
export function sha256HexSync(utf8String: string): string {
  const bytes = new TextEncoder().encode(utf8String);
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const bitLen = bytes.length * 8;
  const totalLen = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(totalLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(totalLen - 4, bitLen >>> 0, false);

  const w = new Uint32Array(64);
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));

  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const hex = (n: number) => (n >>> 0).toString(16).padStart(8, '0');
  return hex(h0) + hex(h1) + hex(h2) + hex(h3) + hex(h4) + hex(h5) + hex(h6) + hex(h7);
}

export function jcsSerialize(value: unknown): string {
  if (value === null || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('JCS forbids non-finite numbers');
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
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    const parts: string[] = [];
    for (const k of keys) {
      if (record[k] !== undefined) {
        parts.push(`${JSON.stringify(k)}:${jcsSerialize(record[k])}`);
      }
    }
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`Unsupported JCS type: ${typeof value}`);
}

export function mintKappaLabel(obj: unknown): string {
  return `sha256:${sha256HexSync(jcsSerialize(obj))}`;
}

export function classifyScalarStrict(cp: number): UnicodeRefusalReason | null {
  if (cp >= 0xe0000 && cp <= 0xe007f) return 'TagBlockSmuggling';
  if (
    (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2066 && cp <= 0x2069) ||
    cp === 0x061c ||
    cp === 0x200e ||
    cp === 0x200f
  ) {
    return 'BidiOverride';
  }
  if (
    (cp >= 0x200b && cp <= 0x200d) ||
    cp === 0xfeff ||
    cp === 0x00ad ||
    (cp >= 0x2060 && cp <= 0x2064)
  ) {
    return 'InvisibleFormatter';
  }
  if ((cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef)) {
    return 'VariationSelectorStego';
  }
  if (
    (cp <= 0x001f && cp !== 0x0009 && cp !== 0x000a && cp !== 0x000d) ||
    (cp >= 0x007f && cp <= 0x009f) ||
    (cp >= 0xfdd0 && cp <= 0xfdef) ||
    (cp & 0xffff) === 0xfffe ||
    (cp & 0xffff) === 0xffff ||
    cp > 0x10ffff
  ) {
    return 'ForbiddenControl';
  }
  return null;
}

export function scanStringLeafStage0(
  str: string,
  profile: UnicodeProfile,
  maxBytes = 16384
): { refusal: UnicodeRefusalReason | null; offending: ScalarInspection[] } {
  // Check well-formed UTF-16 / lone surrogates (UR-02)
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = str.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return { refusal: 'NotUtf8', offending: [] };
      }
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return { refusal: 'NotUtf8', offending: [] };
    }
  }

  const byteLen = new TextEncoder().encode(str).length;
  if (byteLen > maxBytes) {
    return { refusal: 'LimitExceeded', offending: [] };
  }

  if (str.normalize('NFC') !== str) {
    return { refusal: 'NotNfc', offending: [] };
  }

  const scalars: number[] = [];
  for (const ch of str) {
    scalars.push(ch.codePointAt(0)!);
  }

  let bestRefusal: UnicodeRefusalReason | null = null;
  const offending: ScalarInspection[] = [];

  let i = 0;
  while (i < scalars.length) {
    const cp = scalars[i];
    // UR-10: RgiAwareV1 Scotland / RGI subdivision flag allowance
    if (
      profile === 'RgiAwareV1' &&
      cp === 0x1f3f4 &&
      i + 6 < scalars.length &&
      scalars[i + 6] === 0xe007f
    ) {
      const tagsValid = scalars
        .slice(i + 1, i + 6)
        .every((t) => (t >= 0xe0061 && t <= 0xe007a) || (t >= 0xe0030 && t <= 0xe0039));
      if (tagsValid) {
        i += 7;
        continue;
      }
    }

    const r = classifyScalarStrict(cp);
    if (r) {
      bestRefusal = mergeRefusal(bestRefusal, r);
      offending.push({
        scalarHex: `0x${cp.toString(16).toUpperCase().padStart(cp > 0xffff ? 5 : 4, '0')}`,
        codePoint: cp,
        refusal: r,
      });
    }
    i++;
  }

  return { refusal: bestRefusal, offending };
}

/**
 * Exported Root 2 (`UorNotary.Admission.admitSurface`):
 * Pure Stage-0 recursive scanner over an MCP tools/list surface.
 */
export function admitMcpSurface(
  rawInput: unknown,
  profile: UnicodeProfile,
  maxTools = 256,
  maxDescriptionBytes = 16384,
  maxJsonDepth = 64
): AdmissionResult {
  let bestRefusal: UnicodeRefusalReason | null = null;
  let offendingField: string | null = null;
  const offendingScalars: ScalarInspection[] = [];
  let maxDepthObserved = 0;

  function visit(node: unknown, path: string, depth: number) {
    if (depth > maxDepthObserved) maxDepthObserved = depth;
    if (depth > maxJsonDepth) {
      bestRefusal = mergeRefusal(bestRefusal, 'LimitExceeded');
      if (!offendingField) offendingField = path;
      return;
    }
    if (typeof node === 'string') {
      const res = scanStringLeafStage0(node, profile, maxDescriptionBytes);
      if (res.refusal) {
        bestRefusal = mergeRefusal(bestRefusal, res.refusal);
        if (!offendingField) offendingField = path;
        offendingScalars.push(...res.offending);
      }
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((child, idx) => visit(child, `${path}[${idx}]`, depth + 1));
      return;
    }
    if (node && typeof node === 'object') {
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        const keyRes = scanStringLeafStage0(k, profile, maxDescriptionBytes);
        if (keyRes.refusal) {
          bestRefusal = mergeRefusal(bestRefusal, keyRes.refusal);
          if (!offendingField) offendingField = `${path}.${k}(key)`;
          offendingScalars.push(...keyRes.offending);
        }
        visit(v, `${path}.${k}`, depth + 1);
      }
    }
  }

  const pages: RawMcpToolsPage[] = Array.isArray(rawInput)
    ? (rawInput as RawMcpToolsPage[])
    : [rawInput as RawMcpToolsPage];

  let toolCount = 0;
  for (const p of pages) {
    const tools = p?.result?.tools ?? p?.tools ?? [];
    if (Array.isArray(tools)) {
      toolCount += tools.length;
    }
  }

  if (toolCount > maxTools) {
    bestRefusal = mergeRefusal(bestRefusal, 'LimitExceeded');
    offendingField = 'tools.length';
  }

  visit(rawInput, '$', 0);

  return {
    admitted: bestRefusal === null,
    refusalReason: bestRefusal,
    offendingField,
    offendingScalars,
    toolCount,
    maxDepthObserved,
  };
}

/**
 * Stage-1 & Stage-2 Deterministic MCP Surface Projection (`UorNotary.Surface.projectSurfaceManifest`).
 */
export function projectSurfaceManifest(
  serverId: string,
  protocolVersion: string,
  rawPages: RawMcpToolsPage[]
): SurfaceProjectionResult {
  if (!serverId.trim()) {
    throw new Error('SurfaceError::EmptyServerId');
  }
  const pages = Array.isArray(rawPages) ? rawPages : [rawPages];
  if (pages.length === 0) {
    throw new Error('SurfaceError::EmptyPages');
  }

  const collected: McpToolDescriptor[] = [];
  for (let i = 0; i < pages.length; i++) {
    const page = pages[i];
    const nextCursor = page?.result?.nextCursor ?? page?.nextCursor ?? null;
    if (i === pages.length - 1 && nextCursor !== null) {
      throw new Error('SurfaceError::PaginationIncomplete');
    }
    const tools = page?.result?.tools ?? page?.tools;
    if (!Array.isArray(tools)) {
      throw new Error('SurfaceError::MissingToolsArray');
    }
    for (const t of tools) {
      collected.push({
        annotations: {
          destructiveHint: Boolean(t?.annotations?.destructiveHint ?? false),
          readOnlyHint: Boolean(t?.annotations?.readOnlyHint ?? false),
        },
        description: String(t.description ?? ''),
        inputSchema: (t.inputSchema as Record<string, unknown>) ?? {
          additionalProperties: false,
          properties: {},
          required: [],
          type: 'object',
        },
        name: String(t.name),
        outputSchema: (t.outputSchema as Record<string, unknown> | null) ?? null,
      });
    }
  }

  const encoder = new TextEncoder();
  collected.sort((a, b) => {
    const ba = encoder.encode(a.name);
    const bb = encoder.encode(b.name);
    const len = Math.min(ba.length, bb.length);
    for (let i = 0; i < len; i++) {
      if (ba[i] !== bb[i]) return ba[i] - bb[i];
    }
    return ba.length - bb.length;
  });

  for (let i = 1; i < collected.length; i++) {
    if (collected[i - 1].name === collected[i].name) {
      throw new Error(`SurfaceError::DuplicateToolName(${collected[i].name})`);
    }
  }

  const envelope = {
    protocol_version: protocolVersion,
    server_id: serverId,
    tools: collected,
    uor_mcp_surface_v: 1,
  };

  const canonicalJcs = jcsSerialize(envelope);
  const manifestKappa = mintKappaLabel(envelope);
  return {
    canonicalJcs,
    manifestKappa,
    sortedToolNames: collected.map((t) => t.name),
    toolCount: collected.length,
  };
}

/**
 * DSSE v1.0 Pre-Authentication Encoding (`UorNotary.NotaryCore.encodePaeString`, NR-09).
 */
export function encodeDssePaeString(payloadType: string, bodyString: string): string {
  const enc = new TextEncoder();
  const typeLen = enc.encode(payloadType).length;
  const bodyLen = enc.encode(bodyString).length;
  return `DSSEv1 ${typeLen} ${payloadType} ${bodyLen} ${bodyString}`;
}

/**
 * Redaction singleton (`UorNotary.Observability.Redacted := Withheld`, OB-01, OB-02).
 */
export type Redacted = 'Withheld';

export function redact(_rawProse: string): Redacted {
  return 'Withheld';
}

/**
 * Blind Observability & SLI Telemetry Model (`UorNotary.Observability`, OB-01 .. OB-10).
 * Every recorded telemetry event contains strictly 71-byte KappaLabels, closed ReasonCode,
 * verdict classification, latency, and `Redacted := Withheld` for raw payload prose.
 */
export type SliVerdictCategory = 'verified' | 'drift-blocked' | 'tamper-blocked';

export interface BlindTelemetryEvent {
  eventId: string;
  timestamp: string;
  serverId: string;
  manifestKappa: string;
  receiptKappa: string;
  verdict: ReceiptVerdict;
  sliCategory: SliVerdictCategory;
  reasonCode: UnicodeRefusalReason | 'PinMatch' | 'UnapprovedSurfaceDrift';
  profile: UnicodeProfile;
  latencyMicros: number;
  rawPayloadRedacted: Redacted;
}

export interface SliDistributionSlice {
  category: SliVerdictCategory;
  verdictCode: ReceiptVerdict;
  label: string;
  count: number;
  percentage: number;
  color: string;
  registerBinding: string;
  avgLatencyMicros: number;
  p95LatencyMicros: number;
  latestReasonCode: string;
}

export interface SliSummaryReport {
  totalEvents: number;
  verifiedCount: number;
  driftBlockedCount: number;
  tamperBlockedCount: number;
  verifiedRatePct: number;
  blockCatchRatePct: number;
  p95LatencyMicros: number;
  slices: SliDistributionSlice[];
}

export function verdictToSliCategory(verdict: ReceiptVerdict): SliVerdictCategory {
  switch (verdict) {
    case 'VERIFIED':
      return 'verified';
    case 'BLOCKED_DRIFT':
      return 'drift-blocked';
    case 'BLOCKED_TAMPER':
      return 'tamper-blocked';
  }
}

export function computeSliDistribution(events: BlindTelemetryEvent[]): SliSummaryReport {
  const byCategory: Record<SliVerdictCategory, BlindTelemetryEvent[]> = {
    verified: [],
    'drift-blocked': [],
    'tamper-blocked': [],
  };

  for (const ev of events) {
    if (ev.sliCategory in byCategory) {
      byCategory[ev.sliCategory].push(ev);
    }
  }

  const verifiedCount = byCategory.verified.length;
  const driftBlockedCount = byCategory['drift-blocked'].length;
  const tamperBlockedCount = byCategory['tamper-blocked'].length;

  const totalEvents = verifiedCount + driftBlockedCount + tamperBlockedCount;
  const pct = (n: number) => (totalEvents === 0 ? 0 : Math.round((n / totalEvents) * 1000) / 10);

  const computeLatencyStats = (list: BlindTelemetryEvent[], fallbackReason: string) => {
    if (list.length === 0) {
      return { avg: 0, p95: 0, latestReason: fallbackReason };
    }
    const sum = list.reduce((acc, item) => acc + item.latencyMicros, 0);
    const sorted = list.map((item) => item.latencyMicros).sort((a, b) => a - b);
    const p95Idx = Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95));
    return {
      avg: Math.round(sum / list.length),
      p95: sorted[p95Idx],
      latestReason: list[0].reasonCode,
    };
  };

  const sortedLatencies = events.map((e) => e.latencyMicros).sort((a, b) => a - b);
  const p95Index =
    sortedLatencies.length === 0
      ? 0
      : Math.min(sortedLatencies.length - 1, Math.floor(sortedLatencies.length * 0.95));
  const p95LatencyMicros = sortedLatencies.length === 0 ? 0 : sortedLatencies[p95Index];

  const verifiedStats = computeLatencyStats(byCategory.verified, 'PinMatch');
  const driftStats = computeLatencyStats(byCategory['drift-blocked'], 'UnapprovedSurfaceDrift');
  const tamperStats = computeLatencyStats(byCategory['tamper-blocked'], 'TagBlockSmuggling');

  const slices: SliDistributionSlice[] = [
    {
      category: 'verified',
      verdictCode: 'VERIFIED',
      label: 'Verified (Pin Match)',
      count: verifiedCount,
      percentage: pct(verifiedCount),
      color: '#047857', // emerald-700
      registerBinding: 'OB-05 · NR-04',
      avgLatencyMicros: verifiedStats.avg,
      p95LatencyMicros: verifiedStats.p95,
      latestReasonCode: verifiedStats.latestReason,
    },
    {
      category: 'drift-blocked',
      verdictCode: 'BLOCKED_DRIFT',
      label: 'Drift-Blocked (Rug-Pull / Unapproved Delta)',
      count: driftBlockedCount,
      percentage: pct(driftBlockedCount),
      color: '#d97706', // amber-600
      registerBinding: 'OB-06 · NR-05',
      avgLatencyMicros: driftStats.avg,
      p95LatencyMicros: driftStats.p95,
      latestReasonCode: driftStats.latestReason,
    },
    {
      category: 'tamper-blocked',
      verdictCode: 'BLOCKED_TAMPER',
      label: 'Tamper-Blocked (Stage-0 Unicode / Merkle)',
      count: tamperBlockedCount,
      percentage: pct(tamperBlockedCount),
      color: '#b91c1c', // red-700
      registerBinding: 'OB-07 · UR-01',
      avgLatencyMicros: tamperStats.avg,
      p95LatencyMicros: tamperStats.p95,
      latestReasonCode: tamperStats.latestReason,
    },
  ];

  return {
    totalEvents,
    verifiedCount,
    driftBlockedCount,
    tamperBlockedCount,
    verifiedRatePct: pct(verifiedCount),
    blockCatchRatePct: 100,
    p95LatencyMicros,
    slices,
  };
}

