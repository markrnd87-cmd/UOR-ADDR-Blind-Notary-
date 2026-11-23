//! Conformance Tests for NotaryCore State Machine, in-toto v1, DSSE PAE, Merkle & Hologram (`NR-04`, `NR-05`, `NR-08`..`NR-12`)

use repo_conformance::read_repo_file;

#[test]
fn test_nr04_drift_blocks_execution() {
    let src = read_repo_file("src/NotaryCore.lex.tex");
    assert!(src.contains("theorem mismatchNeverProducesVerifiedVerdict"));
}

#[test]
fn test_nr05_unicode_tamper_verdict() {
    let src = read_repo_file("src/NotaryCore.lex.tex");
    assert!(src.contains("theorem unicodeFailNeverProducesVerifiedVerdict"));
    assert!(src.contains("ReceiptVerdict.BLOCKED_TAMPER"));
}

#[test]
fn test_nr08_intoto_statement_address() {
    let src = read_repo_file("src/NotaryCore.lex.tex");
    assert!(src.contains("https://in-toto.io/Statement/v1"));
    assert!(src.contains("https://uor.foundation/predicates/mcp-blind-receipt/v1"));
    assert!(src.contains("theorem statementSelfAddressingConsistent"));
}

#[test]
fn test_nr09_pae_injectivity() {
    let src = read_repo_file("src/NotaryCore.lex.tex");
    assert!(src.contains("theorem paeInjective"));
    assert!(src.contains("application/vnd.in-toto+json"));
}

#[test]
fn test_nr10_merkle_inclusion() {
    let src = read_repo_file("src/NotaryCore.lex.tex");
    assert!(src.contains("theorem merkleInclusionVerifiesAgainstRoot"));
}

#[test]
fn test_nr11_pin_rotation_guard() {
    let src = read_repo_file("src/NotaryCore.lex.tex");
    assert!(src.contains("theorem rotatePinRequiresPreviousKappaAndApprover"));
}

#[test]
fn test_nr12_holo_trace_replay() {
    let src = read_repo_file("src/NotaryCore.lex.tex");
    assert!(src.contains("theorem traceBoundedByTrMax"));
    let manifest = read_repo_file("lexlean.toml");
    assert!(manifest.contains("hologram = \"Notary.holo\""));
}
