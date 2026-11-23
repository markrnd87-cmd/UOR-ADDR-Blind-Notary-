//! Conformance Tests for Deterministic MCP Surface Projection (`NR-01`..`NR-03`, `NR-06`, `NR-07`)

use repo_conformance::{is_valid_kappa_label, jcs_serialize, read_repo_file};
use serde_json::Value;

#[test]
fn test_nr01_duplicate_tool_refused() {
    let src = read_repo_file("src/Surface.lex.tex");
    assert!(src.contains("theorem duplicateToolNamesRefused"));
    assert!(src.contains("DuplicateToolName"));
}

#[test]
fn test_nr02_transport_stripping() {
    let src = read_repo_file("src/Surface.lex.tex");
    assert!(src.contains("theorem transportMetadataStripped"));
}

#[test]
fn test_nr03_permutation_invariance() {
    let src = read_repo_file("src/Surface.lex.tex");
    assert!(src.contains("theorem projectionPermutationInvariant"));
    let vec: Value =
        serde_json::from_str(&read_repo_file("tests/vectors/surface_permuted_tools.json")).unwrap();
    let expected_jcs = vec["expected_canonical_manifest_jcs"].as_str().unwrap();
    assert!(expected_jcs.contains("\"uor_mcp_surface_v\":1"));
    let idx_create = expected_jcs.find("create_invoice_summary").unwrap();
    let idx_list = expected_jcs.find("list_ledger_entries").unwrap();
    assert!(idx_create < idx_list);
}

#[test]
fn test_nr06_causal_kappa_chain() {
    let vec: Value =
        serde_json::from_str(&read_repo_file("tests/vectors/surface_permuted_tools.json")).unwrap();
    let inv_jcs = jcs_serialize(&vec["causal_chain"]["invocation_envelope"]);
    assert_eq!(
        inv_jcs,
        vec["causal_chain"]["expected_invocation_jcs"]
            .as_str()
            .unwrap()
    );
    let out_jcs = jcs_serialize(&vec["causal_chain"]["outcome_envelope"]);
    assert_eq!(
        out_jcs,
        vec["causal_chain"]["expected_outcome_jcs"]
            .as_str()
            .unwrap()
    );
}

#[test]
fn test_nr07_kappa_label_format() {
    let src = read_repo_file("src/Surface.lex.tex");
    assert!(src.contains("theorem kappaLabelExactLength"));
    let vec: Value =
        serde_json::from_str(&read_repo_file("tests/vectors/surface_permuted_tools.json")).unwrap();
    let k = vec["expected_manifest_kappa"].as_str().unwrap();
    assert!(is_valid_kappa_label(k));
}
