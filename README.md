# UOR MCP Blind Notary (`uor-mcp-notary` / `prism_mcp_notary`)

> **Zero-Trust Model Context Protocol (MCP) Surface Notary, Stage-0 Unicode 17.0.0 Admission Gate, and Zero-Network Offline Receipt Verifier**  
> **UOR Foundation Free Commons Edition** · LexLean Language `1.2` · Upstream `UOR-Foundation/MCP` (`rev 2026-07-28`) · `uor-addr` (`v0.2.0`) · License: `MIT OR Apache-2.0`

---

## Overview

`uor-mcp-notary` (Rust crate and WASM artifact name: `prism_mcp_notary`, Lean 4 module prefix: `UorNotary`) is a formally specified, zero-trust blind notary and sidecar lockfile toolkit for Model Context Protocol (MCP) tool servers.

It protects MCP clients, CI pipelines, and security auditors against:

1. **Invisible Unicode Prompt Smuggling & Visual Spoofing (`UR-01..UR-12`)**: Intercepts Plane-14 Tag Block characters (`U+E0000..U+E007F`), Bidirectional overrides (`U+202A..U+202E`, `U+2066..U+2069`, `U+061C`, `U+200E`, `U+200F`), zero-width formatters (`U+200B..U+200D`, `U+FEFF`, `U+00AD`, `U+2060..U+2064`), Variation Selector steganography (`U+FE00..U+FE0F`, `U+E0100..U+E01EF`), C0/C1 controls, noncharacters, and non-NFC payloads **before** JSON canonicalization or content-addressing.
2. **Silent MCP Tool Rug-Pulls & Unapproved Surface Drift (`NR-01..NR-12`)**: Canonicalizes MCP `tools/list` surfaces via a deterministic two-stage projection (transport metadata stripping, UTF-8 NFC byte-order tool sorting, and RFC 8785 JCS serialization) into a 71-byte content-addressed `KappaLabel` (`sha256:<64-lower-hex>`), pinning approved manifests in a local `.uor-pins.json` lockfile and failing closed (`BLOCKED_DRIFT` / `BLOCKED_TAMPER`) on unapproved changes.
3. **Notary & Telemetry Payload Surveillance (`EF-01..EF-08`, `OB-01..OB-10`)**: Enforces compile-time payload blindness across the host effect algebra (`HostEffect` `E1`–`E7`) and observability pipeline (`Redacted := Withheld`). Neither the remote notary nor the telemetry stream can inspect raw tool descriptions, invocation arguments, or tool outputs.
4. **Online Verification Lock-In (`WT-04`, `NR-08..NR-10`)**: Emits DSSE v1.0 Pre-Authentication Encoded (PAE) Ed25519 signatures over `in-toto` Statement v1 predicates (`https://uor.foundation/predicates/mcp-blind-receipt/v1`) and C2SP `tlog-checkpoint` Merkle inclusion proofs that verify 100% offline with zero network calls.

---

## Non-Negotiable Architecture & Contract Rules

| Rule | Register Binding | Enforcement |
| :--- | :--- | :--- |
| **1. Sole Semantic Authority** | `ARCH-01`, `AU-01` | All normative types, Stage-0 predicates, canonicalization rules, effect algebras, and theorems reside in `src/**/*.lex.tex`. Host binaries are thin I/O adapters. |
| **2. LexLean Language 1.2 Compliance** | `AU-13` (`LLP2003`) | `language = "1.2"` in `lexlean.toml`. Zero `\semanticdata`, `\toolingdata`, or `\coredata` blocks; zero `sorry`; zero custom axioms. |
| **3. Upstream Protocol Composition** | `EF-07`, `NR-12` | Composes `UorMcp.Extension.Provider` (`UOR-Foundation/MCP` rev `2026-07-28`) and `UorAddr` (`v0.2.0`). Exports `UorNotary.Provider.notaryRun`, `UorNotary.Admission.admitSurface`, and hologram `Notary.holo` (`HOLO\x04\x00`). |
| **4. Type-Enforced Payload Blindness** | `EF-01..06`, `OB-01..04` | Closed 7-constructor `HostEffect` (`E1`–`E7`) carrying only 71-byte `KappaLabel`, 32-byte `Bytes32`, or closed `ReasonCode`. Telemetry redaction is a 1-constructor singleton `Redacted := Withheld`. |
| **5. Crate & Prefix Discipline** | `ARCH-02` | Rust crate: `prism_mcp_notary`; package: `uor-mcp-notary`; Lean module prefix: `UorNotary`. |
| **6. Anti-Vacuity Planted Defects** | `PD-01..PD-08` | Every theorem and security gate is tested against planted mutations in `VERIFICATION.md` and `tests/conformance/planted_defects.rs`. |
| **7. 100% Free Open-Commons Scope** | `WT-06` | Dual-licensed `MIT OR Apache-2.0`. Zero commercial/proprietary feature tiers, zero paid API gates, zero telemetry call-home. |

---

## Repository Structure

```text
uor-mcp-notary/
├── lexlean.toml                         # LexLean 1.2 manifest, WASM & hologram targets, upstream deps
├── justfile                             # Build, conformance, golden-vector, and anti-vacuity recipes
├── Cargo.toml                           # Rust workspace (sidecar-cli, notary-reference, watchtower-free, conformance)
├── package.json                         # Interactive Web Workbench & Recharts SLI Telemetry Dashboard (Vite + React 19)
├── OWNER-VALUES.md                      # Normative owner policy register (OV-01 .. OV-06)
├── VERIFICATION.md                      # Traceability matrix & anti-vacuity planted-defect catalog (PD-01 .. PD-08)
├── model/
│   └── ids.toml                         # Machine-readable register bindings (UR, NR, EF, OB, SM, OV, WT, ARCH, AU)
├── src/                                 # LexLean 1.2 Literate Specification & Interactive Workbench
│   ├── Product.lex.tex                  # Product identity, free-commons scope, non-scope boundaries
│   ├── OwnerValues.lex.tex              # OwnerPolicy bounds & override invariants (OV-01 .. OV-06)
│   ├── Features.lex.tex                 # Feature register (F1 .. F6) & claim-domain mapping
│   ├── Admission.lex.tex                # Stage-0 Unicode 17.0.0 admission gate & refusal precedence (UR-01 .. UR-12)
│   ├── Surface.lex.tex                  # Stage-1/2 MCP surface projection & permutation invariance (NR-01 .. NR-03)
│   ├── NotaryCore.lex.tex               # Fail-closed pin state machine, causal kappa-chain, DSSE PAE (NR-04 .. NR-12)
│   ├── Effects.lex.tex                  # Closed 7-constructor blind HostEffect algebra E1..E7 (EF-01 .. EF-08)
│   ├── Observability.lex.tex            # Redacted := Withheld singleton & SLI verdict counters (OB-01 .. OB-10)
│   ├── Security.lex.tex                 # STRIDE/LINDDUN threat model & mitigation theorems (SM-01 .. SM-08)
│   ├── Provider.lex.tex                 # UorMcp.Extension.Provider composition & Notary.holo v4.0 export
│   ├── Foundation/
│   │   └── Arch.lex.tex                 # ISO/IEC/IEEE 42010 architecture description (5 stakeholders, 8 concerns)
│   ├── components/
│   │   └── SliTelemetryDashboard.tsx    # Recharts PieChart dashboard for SLI verdicts (verified, drift-blocked, tamper-blocked)
│   ├── data/
│   │   └── blueprintArtifacts.ts        # Golden vector presets & planted defect descriptors for the browser workbench
│   ├── lib/
│   │   ├── notaryEngine.ts              # Pure TypeScript kernel mirroring Stage-0, Stage-1/2, DSSE PAE & SLI aggregation
│   │   └── notaryEngine.test.ts         # Node unit tests for Stage-0, permutation invariance, PAE & SLI distribution
│   └── App.tsx                          # Interactive Zero-Trust MCP Surface Notary & Offline Verifier Workbench
├── host/                                # Thin Host Adapters (zero semantic authority)
│   ├── sidecar-cli/                     # `uor-notary` local zero-trust stdio/HTTP sidecar & .uor-pins.json manager
│   ├── verifier-offline/                # `uor-verify-offline` zero-dependency Node ESM 5-step offline receipt verifier
│   ├── notary-reference/                # Self-hostable blind notary HTTP service (/v1/attest, /v1/checkpoint, /v1/keys)
│   └── watchtower-free/                 # Free public MCP Watchtower catalog & Atom/RSS drift feed generator
└── tests/
    ├── vectors/                         # Normative golden JSON vectors (Tag Block, Bidi RLO, Scotland RGI, NFD/NFC, Permuted)
    └── conformance/                     # Rust + Node conformance suites & automated PD-01..PD-08 anti-vacuity drills
```

---

## Stage-0 Unicode 17.0.0 Admission Gate (`UorNotary.Admission`)

Stage-0 runs on raw MCP JSON strings **prior** to Stage-1 field stripping or Stage-2 RFC 8785 JCS canonicalization (`Theorem UR-01: refusalPrecedesCanonicalization`).

### Total Deterministic Refusal Precedence (`UR-08`)

When a payload violates multiple criteria simultaneously, `admitSurface` deterministically returns the lowest-rank `UnicodeRefusalReason` across all implementations:

| Precedence Rank | Constructor | Condition | Register |
| :---: | :--- | :--- | :--- |
| **0** | `NotUtf8` | Ill-formed UTF-8 byte sequence or unpaired UTF-16 surrogate (`U+D800..U+DFFF`) | `UR-02` |
| **1** | `LimitExceeded` | `tools.length > 256`, string leaf `> 16,384` bytes, or JSON nesting depth `> 64` | `UR-11`, `OV-01..03` |
| **2** | `NotNfc` | String is not in Unicode 17.0.0 UAX #15 Normalization Form C (no silent repair) | `UR-03` |
| **3** | `TagBlockSmuggling` | Plane-14 Tag Block scalar (`U+E0000..U+E007F`), unless permitted by `RgiAwareV1` | `UR-04`, `UR-10` |
| **4** | `BidiOverride` | Bidi control (`U+202A..U+202E`, `U+2066..U+2069`, `U+061C`, `U+200E`, `U+200F`) | `UR-05` |
| **5** | `InvisibleFormatter` | Zero-width / invisible formatter (`U+200B..U+200D`, `U+FEFF`, `U+00AD`, `U+2060..U+2064`) | `UR-06` |
| **6** | `VariationSelectorStego` | Variation selector (`U+FE00..U+FE0F`, `U+E0100..U+E01EF`) | `UR-07` |
| **7** | `ForbiddenControl` | Disallowed C0/C1 control (`<= U+001F` except `\t`, `\n`, `\r`; `U+007F..U+009F`) or noncharacter | `UR-08` |

### Admission Profiles (`UR-09`, `UR-10`, `OV-04`)

- **`StrictV1` (Default)**: Rejects all Plane-14 Tag Block characters (`U+E0000..U+E007F`) and all Variation Selectors unconditionally.
- **`RgiAwareV1` (Explicit Opt-In)**: Permits only well-formed UTS #51 RGI emoji subdivision flag tag sequences matching:
  $$\text{U+1F3F4} \;\cdot\; [\text{U+E0061}..\text{U+E007A},\,\text{U+E0030}..\text{U+E0039}]^{5} \;\cdot\; \text{U+E007F}$$
  (such as the Scotland flag `🏴󠁧󠁢󠁳󠁣󠁴󠁿`), while still rejecting arbitrary Plane-14 prompt smuggling.

---

## Stage-1 & Stage-2 Deterministic Surface Projection (`UorNotary.Surface`)

Once Stage-0 admits an MCP `tools/list` response (or paginated response list):

1. **Complete Pagination Verification (`NR-01`)**: Verifies the final page has `nextCursor: null`; incomplete pagination fails closed with `SurfaceError::PaginationIncomplete`.
2. **Transport Metadata Stripping (`NR-02`)**: Strips ephemeral JSON-RPC framing (`jsonrpc`, `id`, `nextCursor`, `_meta`) and retains only semantics-bearing tool descriptor fields (`name`, `description`, `inputSchema`, `outputSchema`, `annotations`).
3. **Permutation-Invariant Tool Sorting (`NR-03`)**: Because RFC 8785 JCS sorts object keys by UTF-16 code units but preserves array order, Stage-1 sorts `tools[]` strictly by the UTF-8 byte order of each NFC `tool.name` and rejects duplicate tool names.
4. **Domain-Separated Envelope & 71-Byte `KappaLabel` (`NR-07`)**: Wraps the projected tools in:
   ```json
   {
     "protocol_version": "2026-07-28",
     "server_id": "mcp.vendor.example/billing",
     "tools": [...],
     "uor_mcp_surface_v": 1
   }
   ```
   Serializes via RFC 8785 JCS and computes the 71-byte content-addressed digest `sha256:<64-lower-hex>`.

---

## Causal Kappa-Chain, DSSE v1.0 Receipts & 5-Step Offline Verification

Every notarized tool call binds a three-subject causal hash chain (`NR-06`) inside an `in-toto` Statement v1 (`NR-08`):

$$\kappa_{\text{manifest}} \longrightarrow \kappa_{\text{invocation}} \longrightarrow \kappa_{\text{outcome}}$$

- **`mcp:manifest`**: `sha256(JCS(SurfaceEnvelope))`
- **`mcp:invocation`**: `sha256(JCS({ arguments, manifest_kappa, tool, uor_mcp_invocation_v: 1 }))`
- **`mcp:outcome`**: `sha256(JCS({ content, invocation_kappa, isError, structuredContent, uor_mcp_outcome_v: 1 }))`

The statement is signed using **DSSE v1.0 Pre-Authentication Encoding (`NR-09`)**:

```text
DSSEv1 28 application/vnd.in-toto+json <byte_length_of_jcs_statement> <jcs_statement_utf8>
```

### 5-Step Zero-Network Offline Verifier (`host/verifier-offline`)

`uor-verify-offline` validates receipts with zero outbound network sockets (`WT-04`):
1. **Step 1**: Recomputes the exact DSSE v1.0 PAE transcript and verifies the Ed25519 signature / PAE digest against the locally pinned notary trust bundle.
2. **Step 2**: Parses the `in-toto` v1 statement (`https://uor.foundation/predicates/mcp-blind-receipt/v1`) and validates all three 71-byte `KappaLabel` subjects (`^sha256:[0-9a-f]{64}$`).
3. **Step 3**: Re-runs Stage-0 Unicode 17.0.0 admission and recomputes $\kappa_{\text{manifest}} \to \kappa_{\text{invocation}} \to \kappa_{\text{outcome}}$ from raw frames when supplied.
4. **Step 4**: Verifies fail-closed pin alignment (`VERIFIED`, `BLOCKED_DRIFT`, or `BLOCKED_TAMPER`) against `.uor-pins.json`.
5. **Step 5**: Recomputes the RFC 6962 Merkle audit path against the signed C2SP `tlog-checkpoint` root and verifies the 8-byte `Notary.holo` header (`HOLO\x04\x00`).

---

## Interactive Web Workbench & Recharts SLI Telemetry Dashboard

The repository includes an interactive browser workbench served on port `3000`:

- **Observability Telemetry & SLI Verdict Distribution (`src/components/SliTelemetryDashboard.tsx`)**:
  - Uses a responsive **Recharts `PieChart`** with a custom `<Tooltip />` (`SliPieTooltip`) and custom `<Legend />` (`SliPieLegend`) to visualize the live breakdown of SLI verdict categories (`verified`, `drift-blocked`, `tamper-blocked`) from `telemetryEvents`.
  - Enforces `Redacted::Withheld` (`OB-01`) across all audit stream rows while surfacing 71-byte `KappaLabel` commitments, closed `ReasonCode` diagnostics, and p95 latency in microseconds (`OB-08`).
- **Stage-0 Admission & Live JCS Projector**:
  - Test the 5 normative golden vectors (`unicode_tag_block_smuggling.json`, `unicode_bidi_rlo_attack.json`, `unicode_scotland_rgi_flag.json`, `unicode_nfd_vs_nfc.json`, `surface_permuted_tools.json`) or paste custom MCP `tools/list` payloads under `StrictV1` or `RgiAwareV1`.
- **Local Sidecar Lockfile Manager (`.uor-pins.json`)**:
  - Inspect, mint, and rotate server pins with mandatory approver references (`NR-11`).
- **5-Step Offline Receipt Verifier & Split-View Tamper Drill**:
  - Simulate tool invocations and toggle C2SP Merkle checkpoint tampering (`Risk R5`) to watch Step 5 fail closed.
- **Anti-Vacuity Planted Defect Matrix (`PD-01..PD-08`)**:
  - Searchable catalog of all 8 planted mutations and their expected red-gate diagnostics.

---

## Quick Start & Verification Commands

### 1. Run the Interactive Workbench (Port 3000)

```bash
npm install
npm run dev
```

### 2. Run the Full Conformance & Anti-Vacuity Verification Suite

Executes Language 1.2 compliance checks (`LLP2003` — zero `\semanticdata`, `\toolingdata`, `\coredata`, or `sorry`), validates all 64 claim registers in `model/ids.toml`, tests all 5 golden vectors, and executes the `PD-01..PD-08` anti-vacuity planted-defect drills:

```bash
node tests/conformance/verify_all.mjs
```

### 3. Run the Zero-Network 5-Step Offline Verifier Golden Suite

```bash
node host/verifier-offline/test/verify_golden.mjs
```

### 4. Run TypeScript Kernel & SLI Distribution Unit Tests

```bash
npx tsx --test src/lib/notaryEngine.test.ts
```

### 5. Build & Type-Check the Web Workbench

```bash
npm run lint
npm run build
```

### 6. Build the Rust Workspace (`sidecar-cli`, `notary-reference`, `watchtower-free`, `conformance`)

```bash
cargo test --workspace
```

---

## License

Dual-licensed under **`MIT OR Apache-2.0`** at your option, as part of the 100% Free Open-Commons UOR Foundation Ecosystem (`WT-06`).
