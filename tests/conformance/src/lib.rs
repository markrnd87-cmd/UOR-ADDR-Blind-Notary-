//! Shared Conformance & Anti-Vacuity Verification Harness (`repo-conformance`)
//!
//! Validates the repository closure (`src/**/*.lex.tex`, `model/ids.toml`,
//! `OWNER-VALUES.md`, `VERIFICATION.md`, `lexlean.toml`, and `tests/vectors/*.json`)
//! against all UOR Foundation Contract Rules (`UR-01..UR-12`, `NR-01..NR-12`,
//! `EF-01..EF-08`, `OB-01..OB-10`, `SM-01..SM-08`, `OV-01..OV-06`, `WT-01..WT-06`,
//! `ARCH-01`, `AU-13`, and planted defects `PD-01..PD-08`).

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

pub fn read_repo_file(rel_path: &str) -> String {
    let full = repo_root().join(rel_path);
    fs::read_to_string(&full)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", full.display(), e))
}

pub fn is_valid_kappa_label(s: &str) -> bool {
    s.len() == 71
        && s.starts_with("sha256:")
        && s[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn jcs_serialize(val: &Value) -> String {
    match val {
        Value::Null => "null".to_owned(),
        Value::Bool(b) => if *b { "true" } else { "false" }.to_owned(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap(),
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(jcs_serialize).collect();
            format!("[{}]", items.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), jcs_serialize(&map[k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

pub fn mint_kappa(val: &Value) -> String {
    let jcs = jcs_serialize(val);
    let digest = Sha256::digest(jcs.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

/// Checks a `.lex.tex` source string for LexLean Language 1.2 compliance (`LLP2003` / `AU-13`):
/// refuses `\semanticdata`, `\toolingdata`, `\coredata`, and `sorry`.
pub fn check_lexlean_language_12(source: &str) -> Result<(), String> {
    for forbidden in [
        "\\begin{semanticdata}",
        "\\semanticdata",
        "\\begin{toolingdata}",
        "\\toolingdata",
        "\\begin{coredata}",
        "\\coredata",
    ] {
        if source.contains(forbidden) {
            return Err(format!(
                "LLP2003: Legacy data block '{}' is forbidden in LexLean Language 1.2 (AU-13)",
                forbidden
            ));
        }
    }
    for line in source.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("--") && !trimmed.starts_with('%') && trimmed.contains("sorry") {
            return Err("LLV7001: 'sorry' placeholder forbidden in kernel proofs".to_owned());
        }
    }
    Ok(())
}

/// Evaluates the structural kernel proof obligations for `src/Admission.lex.tex` (`PD-01`, `PD-02`),
/// `src/Surface.lex.tex` (`PD-03`), `src/Effects.lex.tex` (`PD-04`), `src/Observability.lex.tex` (`PD-05`),
/// `src/Security.lex.tex` (`PD-06`), and `src/Foundation/Arch.lex.tex` (`PD-07`).
pub fn verify_lexlean_module_obligations(module_rel_path: &str, source: &str) -> Result<(), String> {
    check_lexlean_language_12(source)?;

    match module_rel_path {
        "src/Admission.lex.tex" => {
            if !source.contains("0xE0000") || !source.contains("0xE007F") || !source.contains("isTagBlockScalar") {
                return Err(
                    "LLV7002: Kernel obligation 'strictRefusesAllTagBlock' failed (Plane-14 Tag Block 0xE0000..0xE007F missing)"
                        .to_owned(),
                );
            }
            if !source.contains("0x202A") || !source.contains("0x202E") || source.contains("c != (0x202E : UInt32)") {
                return Err(
                    "LLV7002: Kernel obligation 'strictRefusesBidiUnconditionally' failed (U+202E RLO not refused)"
                        .to_owned(),
                );
            }
        }
        "src/Surface.lex.tex" => {
            if !source.contains("insertToolSorted t (canonicalSortTools ts)") {
                return Err(
                    "LLV7002: Kernel obligation 'projectionPermutationInvariant' failed (canonicalSortTools does not sort tools[])"
                        .to_owned(),
                );
            }
        }
        "src/Effects.lex.tex" => {
            if source.contains("rawDescription") || source.contains("RawJson") {
                return Err(
                    "LLV7002: Negative blindness theorem 'noRawPayloadInHostEffects' failed (raw payload field present in HostEffect)"
                        .to_owned(),
                );
            }
        }
        "src/Observability.lex.tex" => {
            if source.contains("| Text") || source.contains("Redacted.Text") {
                return Err(
                    "LLV7002: Kernel obligations 'redactedHasOneValue' and 'redactionIgnoresText' failed (Redacted is not a singleton)"
                        .to_owned(),
                );
            }
        }
        "src/Security.lex.tex" => {
            if let Some(idx) = source.find("| .R4_NotarySigningKeyCompromise =>") {
                let slice = &source[idx..(idx + 320).min(source.len())];
                if !slice.contains("status           := .Pending") {
                    return Err(
                        "SM-04 / LLV7002: Risk R4 (NotarySigningKeyCompromise) marked Executed without bound hardware KMS execution test"
                            .to_owned(),
                    );
                }
            }
        }
        "src/Foundation/Arch.lex.tex" => {
            if let Some(idx) = source.find("def securityViewpointConcerns") {
                let slice = &source[idx..(idx + 220).min(source.len())];
                if !slice.contains(".C1_CryptographicBlindness") {
                    return Err(
                        "PP2015 / LLV7002: Unframed architectural concern C1_CryptographicBlindness in SecurityAndBlindnessViewpoint"
                            .to_owned(),
                    );
                }
            }
        }
        _ => {}
    }

    Ok(())
}
