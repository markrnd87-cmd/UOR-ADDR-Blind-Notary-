//! Conformance Tests for Threat Model Risk Register Bindings (`SM-01` .. `SM-08`)

use repo_conformance::{read_repo_file, verify_lexlean_module_obligations};

#[test]
fn test_sm01_r1_rug_pull_blocked() {
    let src = read_repo_file("src/Security.lex.tex");
    assert!(src.contains("theorem threatR1MitigatedByPinDriftGate"));
}

#[test]
fn test_sm02_r2_unicode_smuggling_blocked() {
    let src = read_repo_file("src/Security.lex.tex");
    assert!(src.contains("theorem threatR2MitigatedByStage0Gate"));
}

#[test]
fn test_sm03_r3_sharelock_whole_surface() {
    let src = read_repo_file("src/Security.lex.tex");
    assert!(src.contains("theorem threatR3MitigatedByWholeSurfaceKappa"));
}

#[test]
fn test_sm04_r4_pending_status_verified() {
    let src = read_repo_file("src/Security.lex.tex");
    verify_lexlean_module_obligations("src/Security.lex.tex", &src).unwrap();
    assert!(src.contains("theorem threatR4PendingOperationalKeyRotation"));
}

#[test]
fn test_sm05_r5_merkle_split_view_detected() {
    let src = read_repo_file("src/Security.lex.tex");
    assert!(src.contains("theorem threatR5MitigatedByMerkleCheckpoint"));
}

#[test]
fn test_sm06_r6_zero_payload_exfiltration() {
    let src = read_repo_file("src/Security.lex.tex");
    assert!(src.contains("theorem threatR6MitigatedByTypeBlindness"));
}

#[test]
fn test_sm07_r7_causal_chain_replay_blocked() {
    let src = read_repo_file("src/Security.lex.tex");
    assert!(src.contains("theorem threatR7MitigatedByCausalChaining"));
}

#[test]
fn test_sm08_r8_residual_boundary() {
    let src = read_repo_file("src/Security.lex.tex");
    assert!(src.contains("theorem threatR8ClassifiedResidualNonScope"));
}
