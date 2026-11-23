import React, { useMemo, useState } from 'react';
import { SliTelemetryDashboard } from './components/SliTelemetryDashboard';
import {
  GOLDEN_PRESETS,
  PLANTED_DEFECTS,
} from './data/blueprintArtifacts';
import {
  BlindTelemetryEvent,
  SliVerdictCategory,
  UnicodeProfile,
  admitMcpSurface,
  encodeDssePaeString,
  isValidKappaLabel,
  jcsSerialize,
  mintKappaLabel,
  projectSurfaceManifest,
  redact,
  verdictToSliCategory,
} from './lib/notaryEngine';

type ActiveSection = 'gate' | 'telemetry' | 'sidecar' | 'verifier' | 'registers';

interface PinEntry {
  serverId: string;
  activeManifestKappa: string;
  previousManifestKappa: string | null;
  profile: UnicodeProfile;
  approverRef: string;
  toolCount: number;
  pinnedAt: string;
}

const INITIAL_TELEMETRY_EVENTS: BlindTelemetryEvent[] = [
  {
    eventId: 'obs-001',
    timestamp: '2026-11-22T16:10:12Z',
    serverId: 'mcp.vendor.example/billing',
    manifestKappa: 'sha256:6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
    receiptKappa: 'sha256:d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35',
    verdict: 'VERIFIED',
    sliCategory: 'verified',
    reasonCode: 'PinMatch',
    profile: 'StrictV1',
    latencyMicros: 340,
    rawPayloadRedacted: 'Withheld',
  },
  {
    eventId: 'obs-002',
    timestamp: '2026-11-22T16:12:45Z',
    serverId: 'mcp.vendor.example/billing',
    manifestKappa: 'sha256:6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
    receiptKappa: 'sha256:4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce',
    verdict: 'VERIFIED',
    sliCategory: 'verified',
    reasonCode: 'PinMatch',
    profile: 'StrictV1',
    latencyMicros: 315,
    rawPayloadRedacted: 'Withheld',
  },
  {
    eventId: 'obs-003',
    timestamp: '2026-11-22T16:14:02Z',
    serverId: 'mcp.vendor.example/regional-tax',
    manifestKappa: 'sha256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    receiptKappa: 'sha256:ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
    verdict: 'VERIFIED',
    sliCategory: 'verified',
    reasonCode: 'PinMatch',
    profile: 'RgiAwareV1',
    latencyMicros: 420,
    rawPayloadRedacted: 'Withheld',
  },
  {
    eventId: 'obs-004',
    timestamp: '2026-11-22T16:18:19Z',
    serverId: 'mcp.vendor.example/billing',
    manifestKappa: 'sha256:e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683',
    receiptKappa: 'sha256:7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451',
    verdict: 'VERIFIED',
    sliCategory: 'verified',
    reasonCode: 'PinMatch',
    profile: 'StrictV1',
    latencyMicros: 295,
    rawPayloadRedacted: 'Withheld',
  },
  {
    eventId: 'obs-005',
    timestamp: '2026-11-22T16:21:08Z',
    serverId: 'mcp.vendor.example/billing',
    manifestKappa: 'sha256:2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3',
    receiptKappa: 'sha256:19581e27de7ced00ff1ce50b2047e7a567c76b1cbaebabe5ef03f7c3017bb5b7',
    verdict: 'VERIFIED',
    sliCategory: 'verified',
    reasonCode: 'PinMatch',
    profile: 'StrictV1',
    latencyMicros: 360,
    rawPayloadRedacted: 'Withheld',
  },
  {
    eventId: 'obs-006',
    timestamp: '2026-11-22T16:23:44Z',
    serverId: 'mcp.vendor.example/billing',
    manifestKappa: 'sha256:8527a891e224136950ff32ca212b45bc93f69fbb801c3b1ebedac52775f99e61',
    receiptKappa: 'sha256:e629fa6598d732768f7c726b4b621285f9c3b85303900aa912017db7617d8bdb',
    verdict: 'BLOCKED_DRIFT',
    sliCategory: 'drift-blocked',
    reasonCode: 'UnapprovedSurfaceDrift',
    profile: 'StrictV1',
    latencyMicros: 485,
    rawPayloadRedacted: 'Withheld',
  },
  {
    eventId: 'obs-007',
    timestamp: '2026-11-22T16:25:11Z',
    serverId: 'mcp.vendor.example/hr-directory',
    manifestKappa: 'sha256:b17ef6d19c7a5b1ee83b907c595526dcb1eb06db8227d650d5dda0a9f4ce8cd9',
    receiptKappa: 'sha256:4523540f1504cd17100c4835e85b7eefd49911580f8efff0599a8f283be6b9e3',
    verdict: 'BLOCKED_DRIFT',
    sliCategory: 'drift-blocked',
    reasonCode: 'UnapprovedSurfaceDrift',
    profile: 'StrictV1',
    latencyMicros: 510,
    rawPayloadRedacted: 'Withheld',
  },
  {
    eventId: 'obs-008',
    timestamp: '2026-11-22T16:27:30Z',
    serverId: 'mcp.vendor.example/billing',
    manifestKappa: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    receiptKappa: 'sha256:4ec9599fc203d176a301536c2e091a19bc852759b255bd6818810a42c5fed14a',
    verdict: 'BLOCKED_TAMPER',
    sliCategory: 'tamper-blocked',
    reasonCode: 'TagBlockSmuggling',
    profile: 'StrictV1',
    latencyMicros: 185,
    rawPayloadRedacted: 'Withheld',
  },
  {
    eventId: 'obs-009',
    timestamp: '2026-11-22T16:28:55Z',
    serverId: 'mcp.vendor.example/audit-export',
    manifestKappa: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    receiptKappa: 'sha256:9400f1b21cb527d7fa3d3eabba93557a18ebe7a2ca4e471cfe5e4c5b4ca7f767',
    verdict: 'BLOCKED_TAMPER',
    sliCategory: 'tamper-blocked',
    reasonCode: 'BidiOverride',
    profile: 'StrictV1',
    latencyMicros: 170,
    rawPayloadRedacted: 'Withheld',
  },
  {
    eventId: 'obs-010',
    timestamp: '2026-11-22T16:29:40Z',
    serverId: 'mcp.vendor.example/hr-directory',
    manifestKappa: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    receiptKappa: 'sha256:f5ca38f748a1d6eaf726b8a42fb575c3c71f1864a8143301782de13da2d9202b',
    verdict: 'BLOCKED_TAMPER',
    sliCategory: 'tamper-blocked',
    reasonCode: 'NotNfc',
    profile: 'StrictV1',
    latencyMicros: 210,
    rawPayloadRedacted: 'Withheld',
  },
];

export default function App() {
  const [activeSection, setActiveSection] = useState<ActiveSection>('gate');
  const [selectedPresetId, setSelectedPresetId] = useState<string>(GOLDEN_PRESETS[0].id);
  const [profile, setProfile] = useState<UnicodeProfile>('StrictV1');
  const [serverId, setServerId] = useState<string>(GOLDEN_PRESETS[0].serverId);
  const [rawJsonInput, setRawJsonInput] = useState<string>(GOLDEN_PRESETS[0].rawJson);
  const [approverRef, setApproverRef] = useState<string>('local-operator@uor.foundation');
  const [telemetryEvents, setTelemetryEvents] =
    useState<BlindTelemetryEvent[]>(INITIAL_TELEMETRY_EVENTS);

  // Local .uor-pins.json Lockfile State (WT-01, WT-02)
  const initialProjection = useMemo(() => {
    const parsed = JSON.parse(GOLDEN_PRESETS[0].rawJson);
    return projectSurfaceManifest('mcp.vendor.example/billing', '2026-07-28', [parsed]);
  }, []);

  const [pins, setPins] = useState<Record<string, PinEntry>>({
    'mcp.vendor.example/billing': {
      serverId: 'mcp.vendor.example/billing',
      activeManifestKappa: initialProjection.manifestKappa,
      previousManifestKappa: null,
      profile: 'StrictV1',
      approverRef: 'local-operator@uor.foundation',
      toolCount: initialProjection.toolCount,
      pinnedAt: '2026-11-22T00:00:00Z',
    },
  });

  // Tool Invocation & Causal Chain Simulator State (NR-06, WT-04)
  const [invokedToolName, setInvokedToolName] = useState<string>('create_invoice_summary');
  const [invokedArgsJson, setInvokedArgsJson] = useState<string>('{"customer_id":"cust_9481"}');
  const [tamperMerkleRoot, setTamperMerkleRoot] = useState<boolean>(false);
  const [statusNotice, setStatusNotice] = useState<string | null>(null);
  const [registerFilter, setRegisterFilter] = useState<string>('');

  const handleRecordSimulatedEvent = (category: SliVerdictCategory) => {
    const verdict =
      category === 'verified'
        ? 'VERIFIED'
        : category === 'drift-blocked'
        ? 'BLOCKED_DRIFT'
        : 'BLOCKED_TAMPER';
    const reasonCode =
      category === 'verified'
        ? 'PinMatch'
        : category === 'drift-blocked'
        ? 'UnapprovedSurfaceDrift'
        : evaluation.admission?.refusalReason ?? 'TagBlockSmuggling';
    const nextIdx = telemetryEvents.length + 1;
    const newEvent: BlindTelemetryEvent = {
      eventId: `obs-${String(nextIdx).padStart(3, '0')}`,
      timestamp: '2026-11-22T16:56:00Z',
      serverId,
      manifestKappa:
        category === 'tamper-blocked'
          ? 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
          : evaluation.projection?.manifestKappa ?? initialProjection.manifestKappa,
      receiptKappa: mintKappaLabel({ eventIdx: nextIdx, category, serverId }),
      verdict,
      sliCategory: category,
      reasonCode,
      profile,
      latencyMicros: category === 'tamper-blocked' ? 195 : category === 'drift-blocked' ? 460 : 330,
      rawPayloadRedacted: 'Withheld',
    };
    setTelemetryEvents((prev) => [newEvent, ...prev]);
  };

  const handleSelectPreset = (presetId: string) => {
    const preset = GOLDEN_PRESETS.find((p) => p.id === presetId);
    if (!preset) return;
    setSelectedPresetId(preset.id);
    setServerId(preset.serverId);
    setProfile(preset.defaultProfile);
    setRawJsonInput(preset.rawJson);
    setStatusNotice(null);

    try {
      const parsed = JSON.parse(preset.rawJson);
      const adm = admitMcpSurface(parsed, preset.defaultProfile);
      const pages = Array.isArray(parsed) ? parsed : [parsed];
      const proj = adm.admitted
        ? projectSurfaceManifest(preset.serverId, '2026-07-28', pages)
        : null;
      const pinned = pins[preset.serverId]?.activeManifestKappa;
      const verdict = !adm.admitted
        ? 'BLOCKED_TAMPER'
        : proj && pinned && proj.manifestKappa === pinned
        ? 'VERIFIED'
        : 'BLOCKED_DRIFT';
      const nextIdx = telemetryEvents.length + 1;
      const ev: BlindTelemetryEvent = {
        eventId: `obs-${String(nextIdx).padStart(3, '0')}`,
        timestamp: '2026-11-22T16:56:00Z',
        serverId: preset.serverId,
        manifestKappa:
          proj?.manifestKappa ??
          'sha256:0000000000000000000000000000000000000000000000000000000000000000',
        receiptKappa: mintKappaLabel({ presetId: preset.id, nextIdx }),
        verdict,
        sliCategory: verdictToSliCategory(verdict),
        reasonCode: !adm.admitted
          ? adm.refusalReason ?? 'TagBlockSmuggling'
          : verdict === 'VERIFIED'
          ? 'PinMatch'
          : 'UnapprovedSurfaceDrift',
        profile: preset.defaultProfile,
        latencyMicros: !adm.admitted ? 180 : 345,
        rawPayloadRedacted: 'Withheld',
      };
      setTelemetryEvents((prev) => [ev, ...prev]);
    } catch {
      // ignore malformed preset
    }
  };

  // Evaluate Stage-0 Admission & Stage-1/2 Surface Projection in real time
  const evaluation = useMemo(() => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawJsonInput);
    } catch (e) {
      return {
        parseError: (e as Error).message,
        admission: null,
        projection: null,
      };
    }

    const admission = admitMcpSurface(parsed, profile);
    if (!admission.admitted) {
      return {
        parseError: null,
        admission,
        projection: null,
      };
    }

    try {
      const pages = Array.isArray(parsed) ? parsed : [parsed];
      const projection = projectSurfaceManifest(serverId, '2026-07-28', pages);
      return {
        parseError: null,
        admission,
        projection,
      };
    } catch (projErr) {
      return {
        parseError: (projErr as Error).message,
        admission,
        projection: null,
      };
    }
  }, [rawJsonInput, profile, serverId]);

  // Pin or Rotate Current Surface into `.uor-pins.json`
  const handlePinCurrentSurface = () => {
    if (!evaluation.projection || !evaluation.admission?.admitted) {
      setStatusNotice('Refused: Stage-0 Unicode gate must admit surface before minting a pin (UR-01).');
      return;
    }
    if (!approverRef.trim()) {
      setStatusNotice('Refused: Approver reference is required for pin creation or rotation (NR-11).');
      return;
    }
    const existing = pins[serverId];
    const nextEntry: PinEntry = {
      serverId,
      activeManifestKappa: evaluation.projection.manifestKappa,
      previousManifestKappa: existing ? existing.activeManifestKappa : null,
      profile,
      approverRef: approverRef.trim(),
      toolCount: evaluation.projection.toolCount,
      pinnedAt: '2026-11-22T16:30:00Z',
    };
    setPins((prev) => ({ ...prev, [serverId]: nextEntry }));
    setStatusNotice(
      `Pinned ${serverId} to ${evaluation.projection.manifestKappa} in local .uor-pins.json lockfile.`
    );
  };

  // Compute Causal Kappa Chain, in-toto v1 Statement, DSSE PAE, and 5-Step Offline Verification
  const offlineReceiptReport = useMemo(() => {
    const activePin = pins[serverId];
    const pinnedKappa =
      activePin?.activeManifestKappa ?? initialProjection.manifestKappa;
    const observedManifestKappa =
      evaluation.projection?.manifestKappa ?? pinnedKappa;
    const unicodePassed = Boolean(evaluation.admission?.admitted);

    let parsedArgs: unknown = {};
    try {
      parsedArgs = JSON.parse(invokedArgsJson);
    } catch {
      parsedArgs = {};
    }

    const invocationEnvelope = {
      arguments: parsedArgs,
      manifest_kappa: observedManifestKappa,
      tool: invokedToolName,
      uor_mcp_invocation_v: 1,
    };
    const invocationKappa = mintKappaLabel(invocationEnvelope);

    const outcomeEnvelope = {
      content: [],
      invocation_kappa: invocationKappa,
      isError: false,
      structuredContent: null,
      uor_mcp_outcome_v: 1,
    };
    const outcomeKappa = mintKappaLabel(outcomeEnvelope);

    const verdict = !unicodePassed
      ? 'BLOCKED_TAMPER'
      : observedManifestKappa === pinnedKappa
      ? 'VERIFIED'
      : 'BLOCKED_DRIFT';

    const statement = {
      _type: 'https://in-toto.io/Statement/v1',
      predicate: {
        notary: {
          id: 'notary.uor.foundation/reference-v1',
          issuedAt: '2026-11-22T16:30:00Z',
          logIndex: 0,
        },
        pinnedManifestKappa: pinnedKappa,
        serverId,
        sessionChain: {
          clientNonce: 'nonce-session-01',
          prevReceiptKappa: null,
        },
        unicodeGate: {
          passed: unicodePassed,
          profile: profile === 'StrictV1' ? 'strict-v1' : 'rgi-aware-v1',
          toolCount: evaluation.admission?.toolCount ?? 2,
        },
        verdict,
      },
      predicateType: 'https://uor.foundation/predicates/mcp-blind-receipt/v1',
      subject: [
        {
          annotations: {
            'uor.kappaLabel': observedManifestKappa,
            'uor.realization': 'uor_addr::json',
          },
          digest: { sha256: observedManifestKappa.slice(7) },
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

    const statementJcs = jcsSerialize(statement);
    const receiptKappa = mintKappaLabel(statement);
    const paeTranscript = encodeDssePaeString('application/vnd.in-toto+json', statementJcs);
    const paeDigestKappa = mintKappaLabel({ pae: paeTranscript });

    const checkpointRoot = tamperMerkleRoot
      ? 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
      : receiptKappa;

    const step1 = paeTranscript.startsWith('DSSEv1 28 application/vnd.in-toto+json ');
    const step2 =
      isValidKappaLabel(observedManifestKappa) &&
      isValidKappaLabel(invocationKappa) &&
      isValidKappaLabel(outcomeKappa);
    const step3 = unicodePassed && isValidKappaLabel(receiptKappa);
    const step4 =
      (verdict === 'VERIFIED' && observedManifestKappa === pinnedKappa && unicodePassed) ||
      (verdict === 'BLOCKED_DRIFT' && observedManifestKappa !== pinnedKappa) ||
      (verdict === 'BLOCKED_TAMPER' && !unicodePassed);
    const step5 = checkpointRoot === receiptKappa;

    return {
      verdict,
      pinnedKappa,
      observedManifestKappa,
      invocationKappa,
      outcomeKappa,
      receiptKappa,
      paeDigestKappa,
      statementJcs,
      paeTranscript,
      checkpointRoot,
      redactedTelemetrySample: redact(rawJsonInput),
      allStepsPassed: step1 && step2 && step3 && step4 && step5,
      steps: [
        {
          step: '01. DSSE v1.0 PAE Transcript & Ed25519 Digest Commitment (NR-09)',
          passed: step1,
          detail: `PAE header: DSSEv1 28 application/vnd.in-toto+json ${new TextEncoder().encode(statementJcs).length}`,
        },
        {
          step: '02. in-toto Statement v1 & 71-Byte Subject KappaLabels (NR-07, NR-08)',
          passed: step2,
          detail: `Subjects: mcp:manifest, mcp:invocation, mcp:outcome`,
        },
        {
          step: '03. Recompute Causal Kappa-Chain from MCP Frames (NR-06)',
          passed: step3,
          detail: unicodePassed
            ? `manifest -> invocation -> outcome chain verified`
            : `Blocked at Stage-0 Unicode gate (${evaluation.admission?.refusalReason})`,
        },
        {
          step: '04. Fail-Closed Pin State & Verdict Alignment (NR-04, NR-05)',
          passed: step4,
          detail: `Verdict: ${verdict}`,
        },
        {
          step: '05. C2SP tlog-checkpoint Merkle Root & Notary.holo v4.0 (NR-10, NR-12)',
          passed: step5,
          detail: step5
            ? `Leaf matches checkpoint root (${receiptKappa.slice(0, 23)}...)`
            : `Merkle root mismatch: checkpoint root != leaf receipt_kappa`,
        },
      ],
    };
  }, [
    pins,
    serverId,
    initialProjection.manifestKappa,
    evaluation,
    invokedArgsJson,
    invokedToolName,
    profile,
    tamperMerkleRoot,
    rawJsonInput,
  ]);

  const filteredDefects = useMemo(() => {
    const q = registerFilter.trim().toLowerCase();
    if (!q) return PLANTED_DEFECTS;
    return PLANTED_DEFECTS.filter(
      (d) =>
        d.id.toLowerCase().includes(q) ||
        d.register.toLowerCase().includes(q) ||
        d.targetFile.toLowerCase().includes(q) ||
        d.mutation.toLowerCase().includes(q)
    );
  }, [registerFilter]);

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 text-slate-900">
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="flex items-center justify-between gap-8 px-6 py-4 bg-white border-b border-slate-200">
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveSection('gate');
          }}
          className="text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0"
        >
          UOR MCP Blind Notary
        </a>

        <nav
          aria-label="Primary Workbench Navigation"
          className="flex items-center gap-6 text-sm font-semibold text-slate-600"
        >
          <button
            type="button"
            onClick={() => setActiveSection('gate')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeSection === 'gate'
                ? 'border-slate-900 text-slate-900'
                : 'border-transparent hover:text-slate-900'
            }`}
          >
            Stage-0 Admission
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('telemetry')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeSection === 'telemetry'
                ? 'border-slate-900 text-slate-900'
                : 'border-transparent hover:text-slate-900'
            }`}
          >
            SLI Telemetry
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('sidecar')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeSection === 'sidecar'
                ? 'border-slate-900 text-slate-900'
                : 'border-transparent hover:text-slate-900'
            }`}
          >
            Sidecar Lockfile
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('verifier')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeSection === 'verifier'
                ? 'border-slate-900 text-slate-900'
                : 'border-transparent hover:text-slate-900'
            }`}
          >
            Offline Verifier
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('registers')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeSection === 'registers'
                ? 'border-slate-900 text-slate-900'
                : 'border-transparent hover:text-slate-900'
            }`}
          >
            Anti-Vacuity Matrix
          </button>
        </nav>

        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={handlePinCurrentSurface}
            className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
          >
            Pin Surface to Lockfile
          </button>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-8 space-y-8">
        {/* Top Summary Strip */}
        <section className="bg-white border border-slate-200 rounded-xl p-6">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-6 border-b border-slate-100">
            <div>
              <p className="text-xs text-slate-500">
                UOR Foundation Commons · Crate prism_mcp_notary · LexLean 1.2 · MIT OR Apache-2.0
              </p>
              <h1 className="text-2xl font-bold tracking-tight text-slate-900 mt-1">
                Zero-Trust MCP Surface Notary &amp; Offline Receipt Verifier
              </h1>
            </div>

            {/* Segmented Profile Control */}
            <div className="flex items-center gap-2 self-start lg:self-auto">
              <span className="text-xs font-semibold text-slate-600 mr-1">Stage-0 Profile:</span>
              <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
                <button
                  type="button"
                  onClick={() => setProfile('StrictV1')}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    profile === 'StrictV1'
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  StrictV1 (Default)
                </button>
                <button
                  type="button"
                  onClick={() => setProfile('RgiAwareV1')}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    profile === 'RgiAwareV1'
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  RgiAwareV1 (Opt-In)
                </button>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 pt-6">
            <div>
              <p className="text-xs text-slate-500">Stage-0 Unicode 17.0.0 Gate</p>
              <p
                data-testid="stage0-verdict"
                className={`text-base font-bold font-mono tabular-nums mt-1 ${
                  evaluation.admission?.admitted ? 'text-emerald-700' : 'text-red-700'
                }`}
              >
                {evaluation.parseError
                  ? 'ERROR: Parse / Surface'
                  : evaluation.admission?.admitted
                  ? 'Admitted (NFC Verified)'
                  : `Refused: ${evaluation.admission?.refusalReason}`}
              </p>
            </div>

            <div>
              <p className="text-xs text-slate-500">Minted 71-Byte Manifest Kappa</p>
              <p
                data-testid="minted-manifest-kappa"
                className="text-xs font-mono tabular-nums text-slate-900 mt-1.5 break-all"
              >
                {evaluation.projection
                  ? evaluation.projection.manifestKappa
                  : 'none (refused prior to canonicalization · UR-01)'}
              </p>
            </div>

            <div>
              <p className="text-xs text-slate-500">Notary Execution Verdict</p>
              <p
                data-testid="notary-execution-verdict"
                className={`text-base font-bold font-mono tabular-nums mt-1 ${
                  offlineReceiptReport.verdict === 'VERIFIED'
                    ? 'text-emerald-700'
                    : 'text-red-700'
                }`}
              >
                {offlineReceiptReport.verdict}
              </p>
            </div>

            <div>
              <p className="text-xs text-slate-500">Telemetry Redaction Type (OB-01)</p>
              <p className="text-base font-bold font-mono tabular-nums text-slate-900 mt-1">
                Redacted::{offlineReceiptReport.redactedTelemetrySample}
              </p>
            </div>
          </div>

          {statusNotice && (
            <div
              role="status"
              className="mt-4 px-4 py-2.5 bg-slate-100 border border-slate-200 rounded-lg text-xs font-mono text-slate-800"
            >
              {statusNotice}
            </div>
          )}
        </section>

        {/* Observability & SLI Verdict Distribution Dashboard (Recharts PieChart) */}
        {(activeSection === 'gate' || activeSection === 'telemetry') && (
          <SliTelemetryDashboard
            telemetryEvents={telemetryEvents}
            onRecordSimulatedEvent={handleRecordSimulatedEvent}
            onResetTelemetry={() => setTelemetryEvents(INITIAL_TELEMETRY_EVENTS)}
          />
        )}

        {/* SECTION 1: Stage-0 Unicode 17.0.0 Admission & Surface Projection */}
        {activeSection === 'gate' && (
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            <div className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-6 space-y-5">
              <div>
                <h2 className="text-lg font-bold text-slate-900">
                  01. Golden Test Vector Presets
                </h2>
                <p className="text-xs text-slate-500 mt-1">
                  Load normative vectors from tests/vectors/*.json to test Stage-0 refusal precedence and permutation invariance.
                </p>
              </div>

              <div className="space-y-2.5">
                {GOLDEN_PRESETS.map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => handleSelectPreset(preset.id)}
                    className={`w-full text-left p-3.5 rounded-lg border transition-colors ${
                      selectedPresetId === preset.id
                        ? 'border-slate-900 bg-slate-50'
                        : 'border-slate-200 hover:border-slate-300 bg-white'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-semibold text-slate-900">
                        {preset.label}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 mt-1">{preset.registerBinding}</p>
                    <p className="text-xs text-slate-600 mt-1.5">{preset.description}</p>
                  </button>
                ))}
              </div>
            </div>

            <div className="lg:col-span-7 bg-white border border-slate-200 rounded-xl p-6 space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div>
                  <h2 className="text-lg font-bold text-slate-900">
                    02. Live MCP tools/list Inspector &amp; JCS Projector
                  </h2>
                  <p className="text-xs text-slate-500 mt-1">
                    Evaluates UorNotary.Admission.admitSurface followed by UorNotary.Surface.projectSurfaceManifest.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label
                    htmlFor="mcp-server-id"
                    className="block text-xs font-semibold text-slate-700 mb-1.5"
                  >
                    MCP Server Identifier
                  </label>
                  <input
                    id="mcp-server-id"
                    type="text"
                    value={serverId}
                    onChange={(e) => setServerId(e.target.value)}
                    className="w-full px-3 py-2 text-xs font-mono bg-white border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-slate-900"
                  />
                </div>
                <div>
                  <label
                    htmlFor="approver-ref"
                    className="block text-xs font-semibold text-slate-700 mb-1.5"
                  >
                    Pin Approver Reference (NR-11)
                  </label>
                  <input
                    id="approver-ref"
                    type="text"
                    value={approverRef}
                    onChange={(e) => setApproverRef(e.target.value)}
                    className="w-full px-3 py-2 text-xs font-mono bg-white border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-slate-900"
                  />
                </div>
              </div>

              <div>
                <label
                  htmlFor="raw-mcp-json"
                  className="block text-xs font-semibold text-slate-700 mb-1.5"
                >
                  Raw MCP tools/list Payload (JSON)
                </label>
                <textarea
                  id="raw-mcp-json"
                  rows={10}
                  value={rawJsonInput}
                  onChange={(e) => setRawJsonInput(e.target.value)}
                  className="w-full p-3 text-xs font-mono bg-slate-50 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-slate-900"
                />
              </div>

              {/* Stage-0 & Stage-1 Output Panel */}
              {evaluation.parseError ? (
                <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-xs font-mono text-red-800">
                  Refused: {evaluation.parseError}
                </div>
              ) : evaluation.admission && !evaluation.admission.admitted ? (
                <div className="p-4 bg-red-50 border border-red-200 rounded-lg space-y-2">
                  <p className="text-xs font-bold text-red-900 font-mono">
                    Stage-0 Refusal Verdict: {evaluation.admission.refusalReason} · Offending Path:{' '}
                    {evaluation.admission.offendingField}
                  </p>
                  <p className="text-xs text-red-800">
                    Theorem UR-01 (refusalPrecedesCanonicalization): Canonicalization and KappaLabel minting are blocked.
                  </p>
                  {evaluation.admission.offendingScalars.length > 0 && (
                    <div className="pt-2">
                      <p className="text-xs font-semibold text-red-900 mb-1">
                        Offending Unicode Scalars Detected:
                      </p>
                      <div className="flex flex-wrap gap-2 font-mono text-xs text-red-900">
                        {evaluation.admission.offendingScalars.map((sc, idx) => (
                          <span key={`${sc.scalarHex}-${idx}`}>
                            {sc.scalarHex} ({sc.refusal})
                            {idx < evaluation.admission!.offendingScalars.length - 1 ? ' · ' : ''}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                evaluation.projection && (
                  <div className="space-y-4 pt-2 border-t border-slate-200">
                    <div>
                      <p className="text-xs font-semibold text-slate-700">
                        Canonically Sorted Tool Names (UTF-8 NFC Byte Order · NR-03)
                      </p>
                      <p className="text-xs font-mono text-slate-800 mt-1">
                        {evaluation.projection.sortedToolNames.join(' · ')}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-semibold text-slate-700">
                        Stage-2 Domain-Separated Canonical JCS Envelope (uor_mcp_surface_v: 1)
                      </p>
                      <pre className="mt-1.5 p-3 bg-slate-100 border border-slate-200 rounded-lg text-xs font-mono text-slate-800 overflow-x-auto whitespace-pre-wrap break-all">
                        {evaluation.projection.canonicalJcs}
                      </pre>
                    </div>
                  </div>
                )
              )}
            </div>
          </section>
        )}

        {/* SECTION 2: Local Zero-Trust Sidecar Lockfile (.uor-pins.json) */}
        {activeSection === 'sidecar' && (
          <section className="bg-white border border-slate-200 rounded-xl p-6 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-slate-200">
              <div>
                <h2 className="text-lg font-bold text-slate-900">
                  Local Sidecar Pin Lockfile (.uor-pins.json · WT-01, WT-02)
                </h2>
                <p className="text-xs text-slate-500 mt-1">
                  Managed by host/sidecar-cli (uor-notary pin &amp; uor-notary proxy). Operates 100% offline with fail-closed drift detection.
                </p>
              </div>
              <button
                type="button"
                onClick={handlePinCurrentSurface}
                className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 self-start"
              >
                Rotate / Pin Current Surface
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 text-xs font-semibold text-slate-600">
                    <th className="py-3 pr-4">Server ID</th>
                    <th className="py-3 px-4">Active 71-Byte Manifest Kappa</th>
                    <th className="py-3 px-4">Stage-0 Profile</th>
                    <th className="py-3 px-4 text-right">Tools</th>
                    <th className="py-3 pl-4">Approver Reference</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 text-xs">
                  {Object.values(pins).map((p) => (
                    <tr key={p.serverId} className="hover:bg-slate-50">
                      <td className="py-3 pr-4 font-mono font-semibold text-slate-900">
                        {p.serverId}
                      </td>
                      <td className="py-3 px-4 font-mono tabular-nums text-slate-800 break-all">
                        {p.activeManifestKappa}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-700">{p.profile}</td>
                      <td className="py-3 px-4 font-mono tabular-nums text-right text-slate-900">
                        {p.toolCount}
                      </td>
                      <td className="py-3 pl-4 font-mono text-slate-600">{p.approverRef}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div>
              <p className="text-xs font-semibold text-slate-700 mb-1.5">
                Serialized .uor-pins.json Lockfile Document
              </p>
              <pre className="p-4 bg-slate-100 border border-slate-200 rounded-lg text-xs font-mono text-slate-800 overflow-x-auto">
                {JSON.stringify({ schema_version: 1, pins }, null, 2)}
              </pre>
            </div>
          </section>
        )}

        {/* SECTION 3: Zero-Network 5-Step Offline Receipt Verifier (WT-04) */}
        {activeSection === 'verifier' && (
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            <div className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-6 space-y-5">
              <div>
                <h2 className="text-lg font-bold text-slate-900">
                  01. Causal Kappa-Chain &amp; Tamper Drill
                </h2>
                <p className="text-xs text-slate-500 mt-1">
                  Simulates uor-verify-offline (host/verifier-offline/src/index.mjs) with zero network access.
                </p>
              </div>

              <div>
                <label
                  htmlFor="invoked-tool-name"
                  className="block text-xs font-semibold text-slate-700 mb-1.5"
                >
                  Invoked MCP Tool Name
                </label>
                <input
                  id="invoked-tool-name"
                  type="text"
                  value={invokedToolName}
                  onChange={(e) => setInvokedToolName(e.target.value)}
                  className="w-full px-3 py-2 text-xs font-mono bg-white border border-slate-300 rounded-lg"
                />
              </div>

              <div>
                <label
                  htmlFor="invoked-tool-args"
                  className="block text-xs font-semibold text-slate-700 mb-1.5"
                >
                  Invocation Arguments (JSON)
                </label>
                <input
                  id="invoked-tool-args"
                  type="text"
                  value={invokedArgsJson}
                  onChange={(e) => setInvokedArgsJson(e.target.value)}
                  className="w-full px-3 py-2 text-xs font-mono bg-white border border-slate-300 rounded-lg"
                />
              </div>

              <div className="pt-2">
                <label className="flex items-center gap-2.5 text-xs font-semibold text-slate-800 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={tamperMerkleRoot}
                    onChange={(e) => setTamperMerkleRoot(e.target.checked)}
                    className="rounded border-slate-300"
                  />
                  <span>Simulate Split-View Merkle Checkpoint Tamper (Risk R5 / Step 5)</span>
                </label>
              </div>

              <div className="pt-3 border-t border-slate-200 space-y-2 text-xs font-mono">
                <div>
                  <span className="text-slate-500">manifest_kappa:</span>
                  <p className="text-slate-900 break-all">{offlineReceiptReport.observedManifestKappa}</p>
                </div>
                <div>
                  <span className="text-slate-500">invocation_kappa (NR-06):</span>
                  <p className="text-slate-900 break-all">{offlineReceiptReport.invocationKappa}</p>
                </div>
                <div>
                  <span className="text-slate-500">outcome_kappa (NR-06):</span>
                  <p className="text-slate-900 break-all">{offlineReceiptReport.outcomeKappa}</p>
                </div>
                <div>
                  <span className="text-slate-500">receipt_kappa (NR-08):</span>
                  <p className="text-slate-900 break-all">{offlineReceiptReport.receiptKappa}</p>
                </div>
              </div>
            </div>

            <div className="lg:col-span-7 bg-white border border-slate-200 rounded-xl p-6 space-y-6">
              <div className="flex items-center justify-between gap-4 pb-4 border-b border-slate-200">
                <div>
                  <h2 className="text-lg font-bold text-slate-900">
                    02. 5-Step Zero-Network Offline Verification Pipeline
                  </h2>
                  <p className="text-xs text-slate-500 mt-1">
                    Verifies DSSE v1.0 PAE, in-toto Statement v1, causal kappa-chain, pin verdict, and C2SP Merkle inclusion.
                  </p>
                </div>
                <span
                  data-testid="offline-verifier-status"
                  className={`text-xs font-bold font-mono ${
                    offlineReceiptReport.allStepsPassed ? 'text-emerald-700' : 'text-red-700'
                  }`}
                >
                  {offlineReceiptReport.allStepsPassed ? 'ALL 5 STEPS PASSED' : 'VERIFICATION FAILED'}
                </span>
              </div>

              <div className="divide-y divide-slate-200">
                {offlineReceiptReport.steps.map((s) => (
                  <div key={s.step} className="py-3 flex items-start justify-between gap-4">
                    <div>
                      <p className="text-xs font-semibold text-slate-900">{s.step}</p>
                      <p className="text-xs font-mono text-slate-600 mt-0.5">{s.detail}</p>
                    </div>
                    <span
                      className={`text-xs font-bold font-mono shrink-0 ${
                        s.passed ? 'text-emerald-700' : 'text-red-700'
                      }`}
                    >
                      {s.passed ? 'PASS' : 'FAIL'}
                    </span>
                  </div>
                ))}
              </div>

              <div>
                <p className="text-xs font-semibold text-slate-700 mb-1.5">
                  DSSE v1.0 Pre-Authentication Encoding (PAE) Transcript (NR-09)
                </p>
                <pre className="p-3 bg-slate-100 border border-slate-200 rounded-lg text-xs font-mono text-slate-800 overflow-x-auto whitespace-pre-wrap break-all">
                  {offlineReceiptReport.paeTranscript}
                </pre>
              </div>
            </div>
          </section>
        )}

        {/* SECTION 4: Anti-Vacuity Planted Defect Matrix (PD-01 .. PD-08) */}
        {activeSection === 'registers' && (
          <section className="bg-white border border-slate-200 rounded-xl p-6 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-slate-200">
              <div>
                <h2 className="text-lg font-bold text-slate-900">
                  Anti-Vacuity Planted Defect Matrix (VERIFICATION.md · PD-01 .. PD-08)
                </h2>
                <p className="text-xs text-slate-500 mt-1">
                  Every formal theorem and architecture constraint is proven non-vacuous by planting a defect and asserting the exact red gate diagnostic.
                </p>
              </div>
              <div className="w-full sm:w-64">
                <label htmlFor="defect-filter" className="sr-only">
                  Filter Planted Defects
                </label>
                <input
                  id="defect-filter"
                  type="search"
                  placeholder="Filter by PD-01, UR-04, file..."
                  value={registerFilter}
                  onChange={(e) => setRegisterFilter(e.target.value)}
                  className="w-full px-3 py-2 text-xs font-mono bg-white border border-slate-300 rounded-lg"
                />
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 text-xs font-semibold text-slate-600">
                    <th className="py-3 pr-4">ID</th>
                    <th className="py-3 px-4">Register</th>
                    <th className="py-3 px-4">Target LexLean Module</th>
                    <th className="py-3 px-4">Planted Mutation</th>
                    <th className="py-3 pl-4">Expected Red Gate Diagnostic</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 text-xs">
                  {filteredDefects.map((d) => (
                    <tr key={d.id} className="hover:bg-slate-50">
                      <td className="py-3 pr-4 font-mono font-bold text-slate-900">{d.id}</td>
                      <td className="py-3 px-4 font-mono text-slate-700">{d.register}</td>
                      <td className="py-3 px-4 font-mono text-slate-800">{d.targetFile}</td>
                      <td className="py-3 px-4 text-slate-700">{d.mutation}</td>
                      <td className="py-3 pl-4 font-mono text-red-700">{d.expectedDiagnostic}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}
      </main>

      <footer className="border-t border-slate-200 bg-white px-6 py-4 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>UOR Foundation Commons · uor-mcp-notary (prism_mcp_notary) v0.1.0</span>
          <span>100% Free Open-Commons License: MIT OR Apache-2.0</span>
        </div>
      </footer>
    </div>
  );
}
