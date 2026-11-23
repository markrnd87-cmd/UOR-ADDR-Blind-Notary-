//! Anti-Vacuity Planted Defect Drills (`PD-01` .. `PD-08`)
//!
//! Contract Rule 6 (`VERIFICATION.md` / `AGENTS.md` Rule R2):
//! Every formal theorem, architecture constraint, language strictness rule, and security
//! control is proven non-vacuous by applying each exact mutation (`PD-01`..`PD-08`) in
//! memory / isolated workspace state and asserting that the verification gate turns RED
//! with the exact expected diagnostic code (`LLV7002`, `PP2015`, `LLP2003`, `SM-04`).

use repo_conformance::{
    check_lexlean_language_12, read_repo_file, verify_lexlean_module_obligations,
};

#[test]
fn test_clean_closure_passes_all_gates() {
    for module in [
        "src/Product.lex.tex",
        "src/OwnerValues.lex.tex",
        "src/Foundation/Arch.lex.tex",
        "src/Features.lex.tex",
        "src/Admission.lex.tex",
        "src/Surface.lex.tex",
        "src/NotaryCore.lex.tex",
        "src/Effects.lex.tex",
        "src/Observability.lex.tex",
        "src/Security.lex.tex",
        "src/Provider.lex.tex",
    ] {
        let src = read_repo_file(module);
        verify_lexlean_module_obligations(module, &src)
            .unwrap_or_else(|e| panic!("Clean module {} failed verification: {}", module, e));
    }
}

#[test]
fn test_pd01_delete_tag_block_range_turns_red_llv7002() {
    let clean = read_repo_file("src/Admission.lex.tex");
    let mutated = clean.replace(
        "(0xE0000 : UInt32) ≤ c && c ≤ (0xE007F : UInt32)",
        "false",
    );
    let res = verify_lexlean_module_obligations("src/Admission.lex.tex", &mutated);
    assert!(res.is_err());
    let diag = res.unwrap_err();
    assert!(diag.contains("LLV7002") && diag.contains("strictRefusesAllTagBlock"));
}

#[test]
fn test_pd02_exempt_bidi_rlo_202e_turns_red_llv7002() {
    let clean = read_repo_file("src/Admission.lex.tex");
    let mutated = clean.replace("0x202E", "0x202D");
    let res = verify_lexlean_module_obligations("src/Admission.lex.tex", &mutated);
    assert!(res.is_err());
    let diag = res.unwrap_err();
    assert!(diag.contains("LLV7002") && diag.contains("strictRefusesBidiUnconditionally"));
}

#[test]
fn test_pd03_omit_canonical_tool_sorting_turns_red_llv7002() {
    let clean = read_repo_file("src/Surface.lex.tex");
    let mutated = clean.replace(
        "| t :: ts => insertToolSorted t (canonicalSortTools ts)",
        "| t :: ts => t :: ts",
    );
    let res = verify_lexlean_module_obligations("src/Surface.lex.tex", &mutated);
    assert!(res.is_err());
    let diag = res.unwrap_err();
    assert!(diag.contains("LLV7002") && diag.contains("projectionPermutationInvariant"));
}

#[test]
fn test_pd04_add_raw_description_to_host_effect_turns_red_llv7002() {
    let clean = read_repo_file("src/Effects.lex.tex");
    let mutated = clean.replace(
        "| EmitDriftWebhook      (event : BlindDriftEvent)",
        "| EmitDriftWebhook      (event : BlindDriftEvent) (rawDescription : String)",
    );
    let res = verify_lexlean_module_obligations("src/Effects.lex.tex", &mutated);
    assert!(res.is_err());
    let diag = res.unwrap_err();
    assert!(diag.contains("LLV7002") && diag.contains("noRawPayloadInHostEffects"));
}

#[test]
fn test_pd05_add_text_constructor_to_redacted_turns_red_llv7002() {
    let clean = read_repo_file("src/Observability.lex.tex");
    let mutated = clean.replace(
        "inductive Redacted where\n  | Withheld",
        "inductive Redacted where\n  | Withheld\n  | Text (s : String)",
    );
    let res = verify_lexlean_module_obligations("src/Observability.lex.tex", &mutated);
    assert!(res.is_err());
    let diag = res.unwrap_err();
    assert!(diag.contains("LLV7002") && diag.contains("redactedHasOneValue"));
}

#[test]
fn test_pd06_mark_r4_executed_without_kms_test_turns_red_sm04() {
    let clean = read_repo_file("src/Security.lex.tex");
    let mutated = clean.replace(
        "registerId       := \"SM-04\"\n    , status           := .Pending",
        "registerId       := \"SM-04\"\n    , status           := .Executed",
    );
    let res = verify_lexlean_module_obligations("src/Security.lex.tex", &mutated);
    assert!(res.is_err());
    let diag = res.unwrap_err();
    assert!(diag.contains("SM-04"));
}

#[test]
fn test_pd07_unframed_concern_c1_turns_red_pp2015() {
    let clean = read_repo_file("src/Foundation/Arch.lex.tex");
    let mutated = clean.replace(
        "def securityViewpointConcerns : List Concern :=\n  [ .C1_CryptographicBlindness\n  , .C4_FailClosedDriftDetection",
        "def securityViewpointConcerns : List Concern :=\n  [ .C4_FailClosedDriftDetection",
    );
    let res = verify_lexlean_module_obligations("src/Foundation/Arch.lex.tex", &mutated);
    assert!(res.is_err());
    let diag = res.unwrap_err();
    assert!(diag.contains("PP2015") && diag.contains("C1_CryptographicBlindness"));
}

#[test]
fn test_pd08_legacy_semanticdata_block_turns_red_llp2003() {
    let clean = read_repo_file("src/NotaryCore.lex.tex");
    let mutated = format!("{}\n\\begin{{semanticdata}}\nlegacy\n\\end{{semanticdata}}\n", clean);
    let res = check_lexlean_language_12(&mutated);
    assert!(res.is_err());
    let diag = res.unwrap_err();
    assert!(diag.contains("LLP2003") && diag.contains("AU-13"));
}
