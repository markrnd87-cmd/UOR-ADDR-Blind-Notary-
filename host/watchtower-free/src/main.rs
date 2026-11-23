//! Free Public MCP Watchtower (`uor-watchtower-free`)
//!
//! Blueprint Section 5.3 (`WT-05`, `WT-06`, `NR-03`, `UR-01`):
//! - Scans public MCP server snapshots through the Stage-0 Unicode 17.0.0 refusal gate
//!   and Stage-1/2 deterministic RFC 8785 JCS surface projection.
//! - Compares each server's newly computed 71-byte `manifest_kappa` against the previous
//!   public directory snapshot, detecting silent tool-description rug-pulls (`SM-01` / `R1`),
//!   Stage-0 Unicode smuggling (`SM-02` / `R2`), and ShareLock multi-tool drift (`SM-03` / `R3`).
//! - Emits a static reproducible JSON directory (`watchtower-directory.json`) and an
//!   Atom/RSS silent-drift feed (`watchtower-drift-feed.xml`) under MIT OR Apache-2.0.

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "uor-watchtower-free",
    version = "0.1.0",
    about = "Free Public MCP Watchtower Registry Scanner & Silent-Drift Feed Generator"
)]
pub struct Cli {
    /// Input JSON snapshot of public MCP server manifests to scan
    #[arg(long)]
    pub snapshot_in: PathBuf,

    /// Optional previous Watchtower directory JSON for silent-drift diffing
    #[arg(long)]
    pub previous_directory: Option<PathBuf>,

    /// Output path for the reproducible κ-label directory JSON
    #[arg(long, default_value = "watchtower-directory.json")]
    pub directory_out: PathBuf,

    /// Output path for the public RSS/Atom silent-drift feed XML
    #[arg(long, default_value = "watchtower-drift-feed.xml")]
    pub rss_out: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicRegistrySnapshot {
    pub scanned_at_utc: String,
    pub servers: Vec<PublicServerManifestInput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicServerManifestInput {
    pub server_id: String,
    pub protocol_version: String,
    pub tools: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchtowerServerEntry {
    pub server_id: String,
    pub protocol_version: String,
    pub stage0_verdict: String,
    pub refusal_reason: Option<String>,
    pub manifest_kappa: Option<String>,
    pub previous_manifest_kappa: Option<String>,
    pub drift_status: String,
    pub tool_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchtowerDirectory {
    pub schema_version: u32,
    pub license: String,
    pub scanned_at_utc: String,
    pub entries: BTreeMap<String, WatchtowerServerEntry>,
    pub drift_alerts: Vec<WatchtowerDriftAlert>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchtowerDriftAlert {
    pub server_id: String,
    pub alert_kind: String,
    pub previous_kappa: Option<String>,
    pub observed_kappa: Option<String>,
    pub refusal_reason: Option<String>,
    pub detected_at_utc: String,
}

/// Pure Stage-0 string leaf check (`StrictV1` profile, `UR-01..UR-09`).
pub fn check_stage0_strict(s: &str) -> Option<&'static str> {
    if s.len() > 16384 {
        return Some("LimitExceeded");
    }
    for ch in s.chars() {
        let c = ch as u32;
        if (0x0300..=0x036F).contains(&c) {
            return Some("NotNfc");
        }
        if (0xE0000..=0xE007F).contains(&c) {
            return Some("TagBlockSmuggling");
        }
        if (0x202A..=0x202E).contains(&c)
            || (0x2066..=0x2069).contains(&c)
            || c == 0x061C
            || c == 0x200E
            || c == 0x200F
        {
            return Some("BidiOverride");
        }
        if (0x200B..=0x200D).contains(&c)
            || c == 0xFEFF
            || c == 0x00AD
            || (0x2060..=0x2064).contains(&c)
        {
            return Some("InvisibleFormatter");
        }
        if (0xFE00..=0xFE0F).contains(&c) || (0xE0100..=0xE01EF).contains(&c) {
            return Some("VariationSelectorStego");
        }
        if (c <= 0x001F && c != 0x0009 && c != 0x000A && c != 0x000D)
            || (0x007F..=0x009F).contains(&c)
            || (0xFDD0..=0xFDEF).contains(&c)
            || (c & 0xFFFF) == 0xFFFE
            || (c & 0xFFFF) == 0xFFFF
        {
            return Some("ForbiddenControl");
        }
    }
    None
}

pub fn scan_value_stage0(val: &Value, depth: usize) -> Option<&'static str> {
    if depth > 64 {
        return Some("LimitExceeded");
    }
    match val {
        Value::String(s) => check_stage0_strict(s),
        Value::Array(arr) => {
            for item in arr {
                if let Some(r) = scan_value_stage0(item, depth + 1) {
                    return Some(r);
                }
            }
            None
        }
        Value::Object(map) => {
            for (k, v) in map {
                if let Some(r) = check_stage0_strict(k) {
                    return Some(r);
                }
                if let Some(r) = scan_value_stage0(v, depth + 1) {
                    return Some(r);
                }
            }
            None
        }
        _ => None,
    }
}

pub fn jcs_serialize(val: &Value) -> String {
    match val {
        Value::Null => "null".to_owned(),
        Value::Bool(b) => if *b { "true" } else { "false" }.to_owned(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned()),
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(jcs_serialize).collect();
            format!("[{}]", items.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        jcs_serialize(&map[k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

pub fn project_and_mint_kappa(server: &PublicServerManifestInput) -> Result<String> {
    if server.tools.len() > 256 {
        bail!("LimitExceeded");
    }
    let mut projected: Vec<(String, String)> = Vec::with_capacity(server.tools.len());
    for tool in &server.tools {
        let name = tool
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing tool.name"))?
            .to_owned();
        let desc = tool
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let in_schema = tool.get("inputSchema").cloned().unwrap_or_else(|| json!({}));
        let out_schema = tool.get("outputSchema").cloned().unwrap_or(Value::Null);
        let ro = tool
            .get("annotations")
            .and_then(|a| a.get("readOnlyHint"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let de = tool
            .get("annotations")
            .and_then(|a| a.get("destructiveHint"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let tool_jcs = format!(
            "{{\"annotations\":{{\"destructiveHint\":{},\"readOnlyHint\":{}}},\"description\":{},\"inputSchema\":{},\"name\":{},\"outputSchema\":{}}}",
            de,
            ro,
            jcs_serialize(&Value::String(desc)),
            jcs_serialize(&in_schema),
            jcs_serialize(&Value::String(name.clone())),
            jcs_serialize(&out_schema)
        );
        projected.push((name, tool_jcs));
    }

    projected.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    for pair in projected.windows(2) {
        if pair[0].0 == pair[1].0 {
            bail!("DuplicateToolName({})", pair[0].0);
        }
    }

    let tools_joined: Vec<&str> = projected.iter().map(|(_, j)| j.as_str()).collect();
    let manifest_jcs = format!(
        "{{\"protocol_version\":{},\"server_id\":{},\"tools\":[{}],\"uor_mcp_surface_v\":1}}",
        jcs_serialize(&Value::String(server.protocol_version.clone())),
        jcs_serialize(&Value::String(server.server_id.clone())),
        tools_joined.join(",")
    );
    let digest = Sha256::digest(manifest_jcs.as_bytes());
    Ok(format!("sha256:{}", hex::encode(digest)))
}

pub fn build_watchtower_directory(
    snapshot: &PublicRegistrySnapshot,
    previous: Option<&WatchtowerDirectory>,
) -> WatchtowerDirectory {
    let mut entries = BTreeMap::new();
    let mut drift_alerts = Vec::new();

    for srv in &snapshot.servers {
        let prev_kappa = previous
            .and_then(|d| d.entries.get(&srv.server_id))
            .and_then(|e| e.manifest_kappa.clone());

        let mut refusal: Option<&'static str> = None;
        if srv.tools.len() > 256 {
            refusal = Some("LimitExceeded");
        } else {
            for t in &srv.tools {
                if let Some(r) = scan_value_stage0(t, 0) {
                    refusal = Some(r);
                    break;
                }
            }
        }

        if let Some(reason) = refusal {
            drift_alerts.push(WatchtowerDriftAlert {
                server_id: srv.server_id.clone(),
                alert_kind: "STAGE0_UNICODE_TAMPER".to_owned(),
                previous_kappa: prev_kappa.clone(),
                observed_kappa: None,
                refusal_reason: Some(reason.to_owned()),
                detected_at_utc: snapshot.scanned_at_utc.clone(),
            });
            entries.insert(
                srv.server_id.clone(),
                WatchtowerServerEntry {
                    server_id: srv.server_id.clone(),
                    protocol_version: srv.protocol_version.clone(),
                    stage0_verdict: "Refused".to_owned(),
                    refusal_reason: Some(reason.to_owned()),
                    manifest_kappa: None,
                    previous_manifest_kappa: prev_kappa,
                    drift_status: "BLOCKED_TAMPER".to_owned(),
                    tool_count: srv.tools.len(),
                },
            );
        } else {
            let kappa = project_and_mint_kappa(srv).ok();
            let drift_status = match (&prev_kappa, &kappa) {
                (Some(prev), Some(curr)) if prev != curr => {
                    drift_alerts.push(WatchtowerDriftAlert {
                        server_id: srv.server_id.clone(),
                        alert_kind: "SILENT_SURFACE_DRIFT".to_owned(),
                        previous_kappa: Some(prev.clone()),
                        observed_kappa: Some(curr.clone()),
                        refusal_reason: None,
                        detected_at_utc: snapshot.scanned_at_utc.clone(),
                    });
                    "DRIFT_DETECTED".to_owned()
                }
                (Some(_), Some(_)) => "VERIFIED_UNCHANGED".to_owned(),
                _ => "INITIAL_SNAPSHOT".to_owned(),
            };

            entries.insert(
                srv.server_id.clone(),
                WatchtowerServerEntry {
                    server_id: srv.server_id.clone(),
                    protocol_version: srv.protocol_version.clone(),
                    stage0_verdict: "Admitted".to_owned(),
                    refusal_reason: None,
                    manifest_kappa: kappa,
                    previous_manifest_kappa: prev_kappa,
                    drift_status,
                    tool_count: srv.tools.len(),
                },
            );
        }
    }

    WatchtowerDirectory {
        schema_version: 1,
        license: "MIT OR Apache-2.0".to_owned(),
        scanned_at_utc: snapshot.scanned_at_utc.clone(),
        entries,
        drift_alerts,
    }
}

pub fn render_rss_feed(dir: &WatchtowerDirectory) -> String {
    let mut items = String::new();
    for alert in &dir.drift_alerts {
        items.push_str(&format!(
            "    <item>\n      <title>[{}] {}</title>\n      <guid isPermaLink=\"false\">{}:{}</guid>\n      <pubDate>{}</pubDate>\n      <description>previous_kappa={:?} observed_kappa={:?} refusal_reason={:?}</description>\n    </item>\n",
            alert.alert_kind,
            alert.server_id,
            alert.server_id,
            alert.detected_at_utc,
            alert.detected_at_utc,
            alert.previous_kappa,
            alert.observed_kappa,
            alert.refusal_reason
        ));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<rss version=\"2.0\">\n  <channel>\n    <title>UOR Public MCP Watchtower Silent-Drift Feed</title>\n    <link>https://github.com/UOR-Foundation/uor-mcp-notary</link>\n    <description>Reproducible 71-byte KappaLabel diffs and Stage-0 Unicode 17.0.0 alerts (MIT OR Apache-2.0)</description>\n    <lastBuildDate>{}</lastBuildDate>\n{}</channel>\n</rss>\n",
        dir.scanned_at_utc, items
    )
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let raw_snap = fs::read_to_string(&cli.snapshot_in)?;
    let snapshot: PublicRegistrySnapshot = serde_json::from_str(&raw_snap)?;

    let prev_dir: Option<WatchtowerDirectory> = match &cli.previous_directory {
        Some(path) if path.exists() => {
            let raw = fs::read_to_string(path)?;
            Some(serde_json::from_str(&raw)?)
        }
        _ => None,
    };

    let directory = build_watchtower_directory(&snapshot, prev_dir.as_ref());
    fs::write(&cli.directory_out, serde_json::to_string_pretty(&directory)?)?;
    fs::write(&cli.rss_out, render_rss_feed(&directory))?;

    println!(
        "uor-watchtower-free: scanned {} servers, emitted {} alerts -> {}",
        directory.entries.len(),
        directory.drift_alerts.len(),
        cli.directory_out.display()
    );
    Ok(())
}
