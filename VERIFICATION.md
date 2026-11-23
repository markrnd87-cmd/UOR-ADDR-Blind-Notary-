# Anti-Vacuity Planted Defect Log (`VERIFICATION.md`)

**Contract Rule:** `AGENTS.md` Rule R2 / Blueprint Section 0 Rule 6  
**Automated Harness:** `cargo test -p repo-conformance --test planted_defects` (`just verify-anti-vacuity`)

Every claimed formal theorem, architecture constraint, language strictness rule, and security control in `uor-mcp-notary` (`prism_mcp_notary`) is proven non-vacuous by planting a targeted defect (`PD-01` through `PD-08`) and confirming that the normative verification gate turns **RED** with the exact expected diagnostic code.

## Normative Planted Defect Matrix

| ID | Register | Target File | Planted Defect (Exact Mutation) | Verification Command | Expected Red Gate & Diagnostic |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `PD-01` | `UR-04` | `src/Admission.lex.tex` | Delete the Plane-14 Tag Block range check (`0xE0000 <= c && c <= 0xE007F`) from `classifyScalarStrict`. | `lexlean verify src/Admission.lex.tex` | **FAIL (`LLV7002`)**: Kernel proof obligation `strictRefusesAllTagBlock` fails to close because `c = 0xE0001` evaluates to `Admitted` instead of `Refused TagBlockSmuggling`. |
| `PD-02` | `UR-05` | `src/Admission.lex.tex` | Exempt `U+202E` (Right-to-Left Override, `0x202E`) from `isBidiScalar` under `StrictV1`. | `lexlean verify src/Admission.lex.tex` | **FAIL (`LLV7002`)**: Kernel theorem `strictRefusesBidiUnconditionally` fails on the `c = 0x202E` branch. |
| `PD-03` | `NR-03` | `src/Surface.lex.tex` | Replace `canonicalSortTools tools` with the identity function `tools` (omitting UTF-8 lexicographic sorting of `tools[]`). | `lexlean verify src/Surface.lex.tex` | **FAIL (`LLV7002`)**: Kernel theorem `projectionPermutationInvariant` fails, and golden vector `tests/vectors/surface_permuted_tools.json` mismatches. |
| `PD-04` | `EF-05` | `src/Effects.lex.tex` | Add field `rawDescription : String` to the `EmitDriftWebhook` constructor of `HostEffect`. | `lexlean verify src/Effects.lex.tex` | **FAIL (`LLV7002`)**: Negative blindness theorem `noRawPayloadInHostEffects` fails on the `EmitDriftWebhook` case analysis. |
| `PD-05` | `OB-04` | `src/Observability.lex.tex` | Add a second constructor `\| Text (s : String)` to `inductive Redacted` and return `Redacted.Text s` in `redact`. | `lexlean verify src/Observability.lex.tex` | **FAIL (`LLV7002`)**: Both `redactedHasOneValue` and `redactionIgnoresText` fail kernel verification. |
| `PD-06` | `SM-02` | `src/Security.lex.tex` | Change risk `R4` (`NotarySigningKeyCompromise`) status from `Pending` to `Executed` without binding an executed KMS hardware test in `model/ids.toml`. | `cargo test -p repo-conformance --test security` | **FAIL (`SM-02 / SM-04`)**: Conformance harness rejects `Executed` threat status lacking an active execution evidence binding in `model/ids.toml`. |
| `PD-07` | `ARCH-01` | `src/Foundation/Arch.lex.tex` | Remove `Concern.C1_CryptographicBlindness` from `securityViewpointConcerns` in the `SecurityAndBlindnessViewpoint` definition. | `prismpm check` and `lexlean verify src/Foundation/Arch.lex.tex` | **FAIL (`PP2015` / `LLV7002`)**: `prismpm check` reports `PP2015: Unframed architectural concern C1_CryptographicBlindness`, and theorem `everyConcernIsFramedByViewpoint` fails. |
| `PD-08` | `AU-13` | `src/NotaryCore.lex.tex` | Insert a legacy `\begin{semanticdata} ... \end{semanticdata}` block into `src/NotaryCore.lex.tex`. | `lexlean check` | **FAIL (`LLP2003`)**: LexLean Language 1.2 parser refuses legacy `\semanticdata` block form. |
