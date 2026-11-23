//! Conformance Tests for Stage-0 Unicode 17.0.0 & NFC Refusal Gate (`UR-01` .. `UR-12`)

use repo_conformance::{read_repo_file, verify_lexlean_module_obligations};
use serde_json::Value;

#[test]
fn test_ur01_refusal_blocks_minting() {
    let src = read_repo_file("src/Admission.lex.tex");
    verify_lexlean_module_obligations("src/Admission.lex.tex", &src).unwrap();
    assert!(src.contains("theorem refusalPrecedesCanonicalization"));
    let vec: Value =
        serde_json::from_str(&read_repo_file("tests/vectors/unicode_tag_block_smuggling.json"))
            .unwrap();
    assert!(vec["expected_verdicts"]["StrictV1"]["minted_kappa"].is_null());
}

#[test]
fn test_ur02_invalid_utf8_refused() {
    let src = read_repo_file("src/Admission.lex.tex");
    assert!(src.contains("theorem invalidUtf8RefusedFirst"));
    assert!(src.contains("if !leaf.utf8Valid then"));
}

#[test]
fn test_ur03_nfd_vs_nfc_refusal() {
    let vec: Value =
        serde_json::from_str(&read_repo_file("tests/vectors/unicode_nfd_vs_nfc.json")).unwrap();
    assert_eq!(
        vec["nfd_rejected_case"]["expected_verdict"]["verdict"],
        "Refused"
    );
    assert_eq!(
        vec["nfd_rejected_case"]["expected_verdict"]["reason"],
        "NotNfc"
    );
    assert_eq!(
        vec["nfc_admitted_case"]["expected_verdict"]["verdict"],
        "Admitted"
    );
}

#[test]
fn test_ur04_tag_block_smuggling() {
    let vec: Value =
        serde_json::from_str(&read_repo_file("tests/vectors/unicode_tag_block_smuggling.json"))
            .unwrap();
    assert_eq!(
        vec["expected_verdicts"]["StrictV1"]["reason"],
        "TagBlockSmuggling"
    );
    assert_eq!(
        vec["expected_verdicts"]["RgiAwareV1"]["reason"],
        "TagBlockSmuggling"
    );
}

#[test]
fn test_ur05_bidi_rlo_refusal() {
    let vec: Value =
        serde_json::from_str(&read_repo_file("tests/vectors/unicode_bidi_rlo_attack.json"))
            .unwrap();
    assert_eq!(
        vec["expected_verdicts"]["StrictV1"]["reason"],
        "BidiOverride"
    );
    assert_eq!(
        vec["expected_verdicts"]["RgiAwareV1"]["reason"],
        "BidiOverride"
    );
}

#[test]
fn test_ur06_invisible_formatters() {
    let src = read_repo_file("src/Admission.lex.tex");
    assert!(src.contains("theorem strictRefusesInvisibleFormatters"));
    assert!(src.contains("0x200B"));
    assert!(src.contains("0xFEFF"));
}

#[test]
fn test_ur07_variation_selector_stego() {
    let src = read_repo_file("src/Admission.lex.tex");
    assert!(src.contains("theorem strictRefusesVariationSelectors"));
    assert!(src.contains("0xFE00"));
    assert!(src.contains("0xE0100"));
}

#[test]
fn test_ur08_precedence_order() {
    let src = read_repo_file("src/Admission.lex.tex");
    assert!(src.contains("theorem refusalOrderDeterministic"));
    assert!(src.contains("refusalRank .NotUtf8 < refusalRank .LimitExceeded"));
}

#[test]
fn test_ur09_control_and_nonchars() {
    let src = read_repo_file("src/Admission.lex.tex");
    assert!(src.contains("theorem forbidsControlAndNonCharacters"));
    assert!(src.contains("0xFDD0"));
}

#[test]
fn test_ur10_rgi_scotland_flag() {
    let vec: Value =
        serde_json::from_str(&read_repo_file("tests/vectors/unicode_scotland_rgi_flag.json"))
            .unwrap();
    assert_eq!(vec["expected_verdicts"]["StrictV1"]["verdict"], "Refused");
    assert_eq!(
        vec["expected_verdicts"]["RgiAwareV1"]["verdict"],
        "Admitted"
    );
}

#[test]
fn test_ur11_deep_schema_key_scan() {
    let src = read_repo_file("src/Admission.lex.tex");
    assert!(src.contains("theorem allLeavesAndKeysScanned"));
}

#[test]
fn test_ur12_pure_totality() {
    let src = read_repo_file("src/Admission.lex.tex");
    assert!(src.contains("theorem admitPureTotal"));
    assert!(!src.contains("HostEffect"));
}
