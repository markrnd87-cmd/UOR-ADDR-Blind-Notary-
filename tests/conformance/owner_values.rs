//! Conformance Tests Synchronizing `OWNER-VALUES.md` with `src/OwnerValues.lex.tex` (`OV-01` .. `OV-06`)

use repo_conformance::read_repo_file;

#[test]
fn test_ov01_max_tools_sync() {
    let md = read_repo_file("OWNER-VALUES.md");
    let lex = read_repo_file("src/OwnerValues.lex.tex");
    assert!(md.contains("| `OV-01` | `maxToolsPerManifest` | `256` | `evidenced` |"));
    assert!(lex.contains("def maxToolsPerManifest : Nat := 256"));
    assert!(lex.contains("def maxToolsUpperBound : Nat := 1024"));
}

#[test]
fn test_ov02_max_description_bytes_sync() {
    let md = read_repo_file("OWNER-VALUES.md");
    let lex = read_repo_file("src/OwnerValues.lex.tex");
    assert!(md.contains("| `OV-02` | `maxDescriptionBytes` | `16384` | `evidenced` |"));
    assert!(lex.contains("def maxDescriptionBytes : Nat := 16384"));
}

#[test]
fn test_ov03_max_json_depth_sync() {
    let md = read_repo_file("OWNER-VALUES.md");
    let lex = read_repo_file("src/OwnerValues.lex.tex");
    assert!(md.contains("| `OV-03` | `maxJsonDepth` | `64` | `evidenced` |"));
    assert!(lex.contains("def maxJsonDepth : Nat := 64"));
}

#[test]
fn test_ov04_default_unicode_profile_sync() {
    let md = read_repo_file("OWNER-VALUES.md");
    let lex = read_repo_file("src/OwnerValues.lex.tex");
    assert!(md.contains("| `OV-04` | `defaultUnicodeProfile` | `StrictV1` | `evidenced` |"));
    assert!(lex.contains("UnicodeProfileDefault.StrictV1"));
}

#[test]
fn test_ov05_fail_mode_timeout_sync() {
    let md = read_repo_file("OWNER-VALUES.md");
    let lex = read_repo_file("src/OwnerValues.lex.tex");
    assert!(md.contains("| `OV-05` | `failModeOnNotaryTimeout` | `FailClosed` | `needs owner` |"));
    assert!(lex.contains("NotaryTimeoutFailMode.FailClosed"));
    assert!(lex.contains("theorem timeoutModeAlwaysFailClosed"));
}

#[test]
fn test_ov06_trace_and_checkpoint_sync() {
    let md = read_repo_file("OWNER-VALUES.md");
    let lex = read_repo_file("src/OwnerValues.lex.tex");
    assert!(md.contains("| `OV-06` | `maxTraceEvents` (`TR_MAX`) | `1024` | `evidenced` |"));
    assert!(md.contains("| `OV-06` | `checkpointIntervalSecs` | `60` | `needs owner` |"));
    assert!(lex.contains("def maxTraceEvents : Nat := 1024"));
    assert!(lex.contains("def checkpointIntervalSecs : Nat := 60"));
}
