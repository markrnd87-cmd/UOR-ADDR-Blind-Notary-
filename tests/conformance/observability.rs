//! Conformance Tests for Telemetry Blindness & Observability (`OB-01` .. `OB-10`)

use repo_conformance::{read_repo_file, verify_lexlean_module_obligations};

#[test]
fn test_ob01_redacted_unit() {
    let src = read_repo_file("src/Observability.lex.tex");
    verify_lexlean_module_obligations("src/Observability.lex.tex", &src).unwrap();
    assert!(src.contains("theorem redactedHasOneValue"));
}

#[test]
fn test_ob02_redaction_ignores_length() {
    let src = read_repo_file("src/Observability.lex.tex");
    assert!(src.contains("theorem redactionIgnoresText"));
}

#[test]
fn test_ob03_no_server_message_notification() {
    let src = read_repo_file("src/Observability.lex.tex");
    assert!(src.contains("theorem neverEmitsServerMessage"));
}

#[test]
fn test_ob04_telemetry_blindness() {
    let src = read_repo_file("src/Observability.lex.tex");
    assert!(src.contains("theorem telemetryRecordIsBlind"));
}

#[test]
fn test_ob05_alert_matrix() {
    let src = read_repo_file("src/Observability.lex.tex");
    assert!(src.contains("theorem alertMatrixMatchesPolicy"));
}

#[test]
fn test_ob06_no_page_on_400() {
    let src = read_repo_file("src/Observability.lex.tex");
    assert!(src.contains("theorem clientSyntaxErrorNeverPages"));
}

#[test]
fn test_ob07_sli_counter_totality() {
    let src = read_repo_file("src/Observability.lex.tex");
    assert!(src.contains("theorem sliCountersTotalOverVerdicts"));
}

#[test]
fn test_ob08_refusal_class_only() {
    let src = read_repo_file("src/Observability.lex.tex");
    assert!(src.contains("theorem driftReportExposesClassOnly"));
}

#[test]
fn test_ob09_trace_monotonic() {
    let src = read_repo_file("src/Observability.lex.tex");
    assert!(src.contains("theorem traceTelemetryMonotonic"));
}

#[test]
fn test_ob10_checkpoint_staleness() {
    let src = read_repo_file("src/Observability.lex.tex");
    assert!(src.contains("theorem checkpointStalenessAlert"));
}
