//! Conformance Tests for Closed HostEffect Algebra & Blindness Proofs (`EF-01` .. `EF-08`)

use repo_conformance::{read_repo_file, verify_lexlean_module_obligations};

#[test]
fn test_ef01_pin_effects() {
    let src = read_repo_file("src/Effects.lex.tex");
    assert!(src.contains("theorem pinEffectsCarryOnlyIdentifiersAndKappas"));
}

#[test]
fn test_ef02_sign_pae_digest() {
    let src = read_repo_file("src/Effects.lex.tex");
    assert!(src.contains("theorem signPaeCarriesOnlyDigest"));
}

#[test]
fn test_ef03_tlog_effects() {
    let src = read_repo_file("src/Effects.lex.tex");
    assert!(src.contains("theorem transparencyEffectsCarryOnlyKappas"));
}

#[test]
fn test_ef04_blind_webhook() {
    let src = read_repo_file("src/Effects.lex.tex");
    assert!(src.contains("theorem driftWebhookCarriesOnlyBlindMetadata"));
}

#[test]
fn test_ef05_no_raw_payload_in_effects() {
    let src = read_repo_file("src/Effects.lex.tex");
    verify_lexlean_module_obligations("src/Effects.lex.tex", &src).unwrap();
    assert!(src.contains("theorem noRawPayloadInHostEffects"));
}

#[test]
fn test_ef06_closed_seven_effects() {
    let src = read_repo_file("src/Effects.lex.tex");
    assert!(src.contains("theorem hostEffectTagBoundedToSeven"));
}

#[test]
fn test_ef07_provider_root() {
    let src = read_repo_file("src/Provider.lex.tex");
    assert!(src.contains("theorem notaryRunComposesUorMcp"));
    let manifest = read_repo_file("lexlean.toml");
    assert!(manifest.contains("UorNotary.Provider.notaryRun"));
    assert!(manifest.contains("UorNotary.Admission.admitSurface"));
}

#[test]
fn test_ef08_wire_size_ceiling() {
    let src = read_repo_file("src/Effects.lex.tex");
    assert!(src.contains("def maxNotarizeWireBytes : Nat := 2048"));
    assert!(src.contains("theorem notarizeRequestStrictlyBounded"));
}
