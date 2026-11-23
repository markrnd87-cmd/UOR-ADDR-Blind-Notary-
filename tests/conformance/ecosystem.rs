//! Conformance Tests for Free Commons Ecosystem Components (`WT-01` .. `WT-06`)

use repo_conformance::read_repo_file;

#[test]
fn test_wt01_sidecar_local_lockfile() {
    let sidecar = read_repo_file("host/sidecar-cli/src/main.rs");
    assert!(sidecar.contains(".uor-pins.json"));
    assert!(sidecar.contains("pub struct PinLockfile"));
}

#[test]
fn test_wt02_sidecar_fail_closed_proxy() {
    let sidecar = read_repo_file("host/sidecar-cli/src/main.rs");
    assert!(sidecar.contains("BLOCKED_DRIFT: POLICY_MANIFEST_DRIFT (409)"));
    assert!(sidecar.contains("BLOCKED_TAMPER: UNICODE_GATE_VIOLATION (422)"));
    assert!(sidecar.contains("FAIL_CLOSED_NOTARY_UNAVAILABLE"));
}

#[test]
fn test_wt03_reference_notary_endpoints() {
    let notary = read_repo_file("host/notary-reference/src/main.rs");
    assert!(notary.contains("\"/v1/pins\""));
    assert!(notary.contains("\"/v1/notarize\""));
    assert!(notary.contains("\"/v1/checkpoint\""));
    assert!(notary.contains("\"/.well-known/uor-notary.json\""));
    assert!(notary.contains("INVALID_KAPPA_FORMAT"));
    assert!(notary.contains("SERVER_NOT_PINNED"));
    assert!(notary.contains("POLICY_MANIFEST_DRIFT"));
    assert!(notary.contains("UNICODE_GATE_VIOLATION"));
}

#[test]
fn test_wt05_watchtower_diff_feed() {
    let wt = read_repo_file("host/watchtower-free/src/main.rs");
    assert!(wt.contains("SILENT_SURFACE_DRIFT"));
    assert!(wt.contains("STAGE0_UNICODE_TAMPER"));
    assert!(wt.contains("render_rss_feed"));
}

#[test]
fn test_wt06_free_commons_exit() {
    let prod = read_repo_file("src/Product.lex.tex");
    assert!(prod.contains("theorem freeCommonsZeroLockIn"));
    assert!(prod.contains("MIT OR Apache-2.0"));
}
