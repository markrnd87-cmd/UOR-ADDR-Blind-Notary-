# Owner Values Register (`OWNER-VALUES.md`)

**Package:** `uor-mcp-notary` (`prism_mcp_notary`)  
**Semantic Authority:** [`src/OwnerValues.lex.tex`](src/OwnerValues.lex.tex)  
**Claim Register Domain:** `OV-01` .. `OV-06` in [`model/ids.toml`](model/ids.toml)  
**License:** MIT OR Apache-2.0 (100% Open Foundation Commons)

Every tunable policy constant in `src/OwnerValues.lex.tex` is bound one-to-one to a row in the normative table below. Conformance test `tests/conformance/owner_values.rs` verifies that the compiled constants in `UorNotary.OwnerValues` match this table byte-for-byte.

## Normative Owner Values Table

| Register | Constant (`UorNotary.OwnerValues`) | Default Value | Status | Rationale & Override Rule |
| :--- | :--- | :--- | :--- | :--- |
| `OV-01` | `maxToolsPerManifest` | `256` | `evidenced` | Prevents DoS and ShareLock-style massive tool-surface flooding; overridable up to `1024` (`maxToolsUpperBound`) via local pin policy. Any manifest exceeding the active limit is refused with `UnicodeRefusal.LimitExceeded`. |
| `OV-02` | `maxDescriptionBytes` | `16384` | `evidenced` | Bounds UTF-8 scanning cost and LLM context injection surface per tool description (16 KiB). Enforced during Stage-0 admission before canonicalization. |
| `OV-03` | `maxJsonDepth` | `64` | `evidenced` | Aligns with `uor-addr` ADR-057 `MAX_*_DEPTH` recursion guard (`64` levels). Hard ceiling; overrides above `64` are rejected by `isValidOverride`. |
| `OV-04` | `defaultUnicodeProfile` | `StrictV1` | `evidenced` | Fail-closed maximum safety for autonomous agents (unconditionally rejects all 5 threat classes, non-UTF-8, and non-NFC); `RgiAwareV1` is opt-in per server pin in `.uor-pins.json`. |
| `OV-05` | `failModeOnNotaryTimeout` | `FailClosed` | `needs owner` | Local sidecar halts tool execution if a configured remote notary is unreachable or returns `429 QUOTA_EXCEEDED`; local-only pin mode requires no network. Must remain `FailClosed` in zero-trust deployments. |
| `OV-06` | `maxTraceEvents` (`TR_MAX`) | `1024` | `evidenced` | Fixed-capacity trace buffer for deterministic `prism_verify::certify_from_trace` replay and `Notary.holo` (`HOLO\x04\x00`) generation. |
| `OV-06` | `checkpointIntervalSecs` | `60` | `needs owner` | Frequency (in seconds) of C2SP `tlog-checkpoint` signed Merkle Tree Head publication on the self-hostable reference notary (`host/notary-reference`). Triggers staleness SLI alert (`OB-10`) if age exceeds `2 * checkpointIntervalSecs` (`120` seconds). |
