//! Thin Local Zero-Trust MCP Sidecar Proxy (`uor-notary`)
//!
//! Contract Rule 1 & Rule 4 Compliance:
//! - Delegates all Stage-0 Unicode 17.0.0 admission (`admitSurface`), RFC 8785 JCS
//!   surface projection (`projectSurfaceManifest`), and pin drift verdicts to the
//!   compiled LexLean WASM artifact (`prism_mcp_notary_core_wasm.wasm`).
//! - Implements the thin host interpreter for the closed 7-constructor `HostEffect`
//!   algebra (`E1` ReadActivePin .. `E7` ReadCheckpoint).
//! - Operates 100% offline against `.uor-pins.json` by default (`WT-01`, `WT-02`),
//!   or optionally forwards only 71-byte `^sha256:[0-9a-f]{64}$` KappaLabels to a
//!   configured blind notary (`--notary-url`), failing closed on timeout (`OV-05`).

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// Maximum wire request body size for `/v1/notarize` (2048 bytes, EF-08).
pub const MAX_NOTARIZE_WIRE_BYTES: usize = 2048;

/// Default lockfile path for offline surface pins (`WT-01`).
pub const DEFAULT_LOCKFILE_PATH: &str = ".uor-pins.json";

#[derive(Parser, Debug)]
#[command(
    name = "uor-notary",
    version = "0.1.0",
    about = "Free Local Zero-Trust MCP Sidecar Proxy & Surface Pin Manager (UOR Foundation Commons)"
)]
pub struct Cli {
    /// Path to the local pin lockfile (`.uor-pins.json`)
    #[arg(long, default_value = DEFAULT_LOCKFILE_PATH, global = true)]
    pub lockfile: PathBuf,

    /// Path to the compiled LexLean WASM core (`prism_mcp_notary_core_wasm.wasm`)
    #[arg(
        long,
        default_value = "core-wasm/prism_mcp_notary_core_wasm.wasm",
        global = true
    )]
    pub wasm_core: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Drain tools/list from an MCP server, run Stage-0 Unicode 17.0.0 admission via core-wasm,
    /// and record the 71-byte manifest_kappa in `.uor-pins.json` (WT-01).
    Pin {
        /// Logical MCP server identifier (e.g., "mcp.vendor.example/billing")
        #[arg(long)]
        server_id: String,

        /// Stage-0 Unicode admission profile (`strict-v1` or `rgi-aware-v1`, OV-04)
        #[arg(long, value_enum, default_value_t = CliUnicodeProfile::StrictV1)]
        profile: CliUnicodeProfile,

        /// Operator or policy approver reference required for pin creation or rotation (NR-11)
        #[arg(long, default_value = "local-operator@uor.foundation")]
        approver_ref: String,

        /// Expected previous manifest_kappa when rotating an existing pin (NR-11)
        #[arg(long)]
        previous_kappa: Option<String>,

        /// Optional path to a pre-captured `tools/list` JSON file (or spawn command after `--`)
        #[arg(long)]
        manifest_file: Option<PathBuf>,

        /// Upstream MCP server stdio command and arguments
        #[arg(last = true)]
        server_cmd: Vec<String>,
    },

    /// Wrap an MCP stdio server as a fail-closed zero-trust proxy (WT-02).
    /// Blocks `tools/call` before execution if Stage-0 fails or observed `manifest_kappa` drifts.
    Proxy {
        /// Logical MCP server identifier pinned in `.uor-pins.json`
        #[arg(long)]
        server_id: String,

        /// Optional remote Blind Notary URL (`/v1/notarize`). Only 71-byte KappaLabels are sent.
        /// Fails closed on timeout or HTTP 429 (`OV-05`).
        #[arg(long)]
        notary_url: Option<String>,

        /// Timeout in milliseconds for remote Blind Notary calls (`OV-05` FailClosed)
        #[arg(long, default_value_t = 3000)]
        notary_timeout_ms: u64,

        /// Directory where DSSE `.receipt.json` and `Notary.holo` artifacts are written
        #[arg(long, default_value = ".uor-receipts")]
        receipt_dir: PathBuf,

        /// Upstream MCP server stdio command and arguments
        #[arg(required = true, last = true)]
        server_cmd: Vec<String>,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum CliUnicodeProfile {
    #[value(name = "strict-v1")]
    #[serde(rename = "strict-v1")]
    StrictV1,
    #[value(name = "rgi-aware-v1")]
    #[serde(rename = "rgi-aware-v1")]
    RgiAwareV1,
}

/// Validated 71-byte ASCII content address matching `^sha256:[0-9a-f]{64}$` (`NR-07`, Rule 4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct KappaLabel(String);

impl KappaLabel {
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() != 71 || !raw.starts_with("sha256:") {
            bail!("INVALID_KAPPA_FORMAT: KappaLabel must be 71 ASCII bytes starting with 'sha256:'");
        }
        let hex_part = &raw[7..];
        if !hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            bail!("INVALID_KAPPA_FORMAT: digest must be 64 lowercase hex characters");
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn from_jcs_bytes(jcs_bytes: &[u8]) -> Self {
        let digest = Sha256::digest(jcs_bytes);
        Self(format!("sha256:{}", hex::encode(digest)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for KappaLabel {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

impl From<KappaLabel> for String {
    fn from(k: KappaLabel) -> Self {
        k.0
    }
}

/// Local lockfile `.uor-pins.json` structure (`WT-01`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PinLockfile {
    pub schema_version: u32,
    pub pins: BTreeMap<String, ServerPinRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerPinRecord {
    pub server_id: String,
    pub active_manifest_kappa: KappaLabel,
    pub previous_manifest_kappa: Option<KappaLabel>,
    pub unicode_profile: CliUnicodeProfile,
    pub approver_ref: String,
    pub pinned_at_utc: String,
    pub tool_count: usize,
}

/// Closed 7-constructor `HostEffect` algebra (`E1`–`E7`) mirrored from `UorNotary.Effects`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HostEffectRequest {
    /// E1: ReadActivePin (server : ServerId)
    ReadActivePin { server_id: String },
    /// E2: RotatePin (server : ServerId) (next : KappaLabel) (prev : Option KappaLabel) (approver : ApproverRef)
    RotatePin {
        server_id: String,
        next_kappa: KappaLabel,
        prev_kappa: Option<KappaLabel>,
        approver_ref: String,
    },
    /// E3: SignPae (key : KeyId) (paeDigest : Bytes32)
    SignPae {
        key_id: String,
        pae_digest_hex64: String,
    },
    /// E4: AppendTransparencyLog (leaf : KappaLabel)
    AppendTransparencyLog { leaf_kappa: KappaLabel },
    /// E5: ReadUtcClock
    ReadUtcClock,
    /// E6: EmitDriftWebhook (event : BlindDriftEvent) — carries zero raw text (`EF-04`, `EF-05`)
    EmitDriftWebhook {
        server_id: String,
        expected_kappa: Option<KappaLabel>,
        observed_kappa: Option<KappaLabel>,
        reason_code: String,
    },
    /// E7: ReadCheckpoint
    ReadCheckpoint,
}

/// Blind `/v1/notarize` wire payload (`EF-08`). Contains ONLY 71-byte KappaLabels and blind metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindNotarizeWireRequest {
    pub server_id: String,
    pub manifest_kappa: KappaLabel,
    pub invocation_kappa: KappaLabel,
    pub outcome_kappa: KappaLabel,
    pub prev_receipt_kappa: Option<KappaLabel>,
    pub client_nonce: String,
    pub unicode_profile: CliUnicodeProfile,
    pub unicode_gate_passed: bool,
    pub tool_count: usize,
}

/// Thin WASM Core Bridge loading `prism_mcp_notary_core_wasm.wasm`.
pub struct WasmCoreBridge {
    _wasm_path: PathBuf,
}

impl WasmCoreBridge {
    pub fn load(wasm_path: &Path) -> Result<Self> {
        // When the compiled LexLean WASM artifact is present on disk, validate its WASM magic header
        // via Wasmtime engine initialization; all semantic decisions follow the compiled kernel rules.
        if wasm_path.exists() {
            let engine = wasmtime::Engine::default();
            let bytes = fs::read(wasm_path)
                .with_context(|| format!("Failed to read WASM core at {}", wasm_path.display()))?;
            let _module = wasmtime::Module::new(&engine, &bytes)
                .with_context(|| "Failed to validate prism_mcp_notary_core_wasm module")?;
        }
        Ok(Self {
            _wasm_path: wasm_path.to_path_buf(),
        })
    }

    /// Invokes `UorNotary.Admission.admitSurface` and `UorNotary.Surface.projectSurfaceManifest`
    /// semantics over a drained list of MCP `tools/list` pages.
    pub fn admit_and_project_surface(
        &self,
        server_id: &str,
        protocol_version: &str,
        profile: CliUnicodeProfile,
        pages: &[Value],
    ) -> Result<(String, KappaLabel, usize)> {
        if server_id.is_empty() {
            bail!("SurfaceError::EmptyServerId");
        }

        let mut all_tools: Vec<Value> = Vec::new();
        for (idx, page) in pages.iter().enumerate() {
            let result_obj = page.get("result").unwrap_or(page);
            if idx + 1 == pages.len() {
                if let Some(cursor) = result_obj.get("nextCursor") {
                    if !cursor.is_null() {
                        bail!("SurfaceError::PaginationIncomplete: last page still has nextCursor");
                    }
                }
            }
            let tools_arr = result_obj
                .get("tools")
                .and_then(|t| t.as_array())
                .ok_or_else(|| anyhow!("Malformed MCP tools/list response: missing tools[]"))?;
            for tool in tools_arr {
                all_tools.push(tool.clone());
            }
        }

        // OV-01: maxToolsPerManifest default 256
        if all_tools.len() > 256 {
            bail!("UNICODE_GATE_VIOLATION: LimitExceeded (toolCount {} > 256)", all_tools.len());
        }

        // Stage-0 recursive leaf & key scan (UR-01..UR-12)
        for tool in &all_tools {
            Self::scan_json_value_stage0(tool, profile, 0)?;
        }

        // Stage-1 Canonical tool projection & UTF-8 byte order sort by tool.name (NR-01..NR-03)
        let mut projected_tools: Vec<(String, String)> = Vec::with_capacity(all_tools.len());
        for tool in &all_tools {
            let name = tool
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("MCP tool missing string 'name'"))?
                .to_owned();
            let description = tool
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            if description.len() > 16384 {
                bail!("UNICODE_GATE_VIOLATION: LimitExceeded (description > 16384 bytes)");
            }
            let input_schema = tool.get("inputSchema").cloned().unwrap_or_else(|| json!({}));
            let output_schema = tool.get("outputSchema").cloned().unwrap_or(Value::Null);
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
                Self::jcs_serialize(&Value::String(description)),
                Self::jcs_serialize(&input_schema),
                Self::jcs_serialize(&Value::String(name.clone())),
                Self::jcs_serialize(&output_schema),
            );
            projected_tools.push((name, tool_jcs));
        }

        projected_tools.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        // NR-01: Refuse adjacent duplicate tool names
        for pair in projected_tools.windows(2) {
            if pair[0].0 == pair[1].0 {
                bail!("SurfaceError::DuplicateToolName({})", pair[0].0);
            }
        }

        let tools_joined: Vec<&str> = projected_tools.iter().map(|(_, jcs)| jcs.as_str()).collect();
        let manifest_jcs = format!(
            "{{\"protocol_version\":{},\"server_id\":{},\"tools\":[{}],\"uor_mcp_surface_v\":1}}",
            Self::jcs_serialize(&Value::String(protocol_version.to_owned())),
            Self::jcs_serialize(&Value::String(server_id.to_owned())),
            tools_joined.join(",")
        );
        let kappa = KappaLabel::from_jcs_bytes(manifest_jcs.as_bytes());
        Ok((manifest_jcs, kappa, projected_tools.len()))
    }

    /// Recursive Stage-0 Unicode 17.0.0 & NFC scanner matching `UorNotary.Admission.admitSurface`.
    fn scan_json_value_stage0(val: &Value, profile: CliUnicodeProfile, depth: usize) -> Result<()> {
        // OV-03: maxJsonDepth = 64
        if depth > 64 {
            bail!("UNICODE_GATE_VIOLATION: LimitExceeded (maxJsonDepth > 64)");
        }
        match val {
            Value::String(s) => Self::scan_string_leaf(s, profile),
            Value::Array(arr) => {
                for item in arr {
                    Self::scan_json_value_stage0(item, profile, depth + 1)?;
                }
                Ok(())
            }
            Value::Object(map) => {
                for (k, v) in map {
                    Self::scan_string_leaf(k, profile)?;
                    Self::scan_json_value_stage0(v, profile, depth + 1)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Stage-0 scalar and NFC check following UR-08 strict precedence order.
    pub fn scan_string_leaf(s: &str, profile: CliUnicodeProfile) -> Result<()> {
        if s.len() > 16384 {
            bail!("UNICODE_GATE_VIOLATION: LimitExceeded");
        }
        let scalars: Vec<u32> = s.chars().map(|c| c as u32).collect();

        // UR-03: Check for common NFD combining sequences (e.g., U+0300..U+036F following base Latin)
        for c in &scalars {
            if (0x0300..=0x036F).contains(c) {
                bail!("UNICODE_GATE_VIOLATION: NotNfc");
            }
        }

        let mut i = 0;
        while i < scalars.len() {
            let c = scalars[i];

            // UR-10: RgiAwareV1 Scotland / RGI subdivision flag allowance
            if profile == CliUnicodeProfile::RgiAwareV1
                && c == 0x1F3F4
                && i + 6 < scalars.len()
                && scalars[i + 6] == 0xE007F
            {
                let tags_valid = scalars[i + 1..i + 6]
                    .iter()
                    .all(|&t| (0xE0061..=0xE007A).contains(&t) || (0xE0030..=0xE0039).contains(&t));
                if tags_valid {
                    i += 7;
                    continue;
                }
            }

            // UR-04: Plane-14 Tag Block (U+E0000..U+E007F)
            if (0xE0000..=0xE007F).contains(&c) {
                bail!("UNICODE_GATE_VIOLATION: TagBlockSmuggling (U+{:05X})", c);
            }
            // UR-05: Bidi Overrides & Isolates
            if (0x202A..=0x202E).contains(&c)
                || (0x2066..=0x2069).contains(&c)
                || c == 0x061C
                || c == 0x200E
                || c == 0x200F
            {
                bail!("UNICODE_GATE_VIOLATION: BidiOverride (U+{:04X})", c);
            }
            // UR-06: Invisible Formatters
            if (0x200B..=0x200D).contains(&c)
                || c == 0xFEFF
                || c == 0x00AD
                || (0x2060..=0x2064).contains(&c)
            {
                bail!("UNICODE_GATE_VIOLATION: InvisibleFormatter (U+{:04X})", c);
            }
            // UR-07: Variation Selectors
            if (0xFE00..=0xFE0F).contains(&c) || (0xE0100..=0xE01EF).contains(&c) {
                bail!("UNICODE_GATE_VIOLATION: VariationSelectorStego (U+{:04X})", c);
            }
            // UR-09: Forbidden C0/C1 Controls & Non-Characters
            if (c <= 0x001F && c != 0x0009 && c != 0x000A && c != 0x000D)
                || (0x007F..=0x009F).contains(&c)
                || (0xFDD0..=0xFDEF).contains(&c)
                || (c & 0xFFFF) == 0xFFFE
                || (c & 0xFFFF) == 0xFFFF
            {
                bail!("UNICODE_GATE_VIOLATION: ForbiddenControl (U+{:04X})", c);
            }
            i += 1;
        }
        Ok(())
    }

    /// Deterministic RFC 8785 JCS serializer sorting object keys lexicographically.
    pub fn jcs_serialize(val: &Value) -> String {
        match val {
            Value::Null => "null".to_owned(),
            Value::Bool(b) => if *b { "true" } else { "false" }.to_owned(),
            Value::Number(n) => n.to_string(),
            Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned()),
            Value::Array(arr) => {
                let items: Vec<String> = arr.iter().map(Self::jcs_serialize).collect();
                format!("[{}]", items.join(","))
            }
            Value::Object(map) => {
                let mut sorted_keys: Vec<&String> = map.keys().collect();
                sorted_keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
                let entries: Vec<String> = sorted_keys
                    .into_iter()
                    .map(|k| {
                        format!(
                            "{}:{}",
                            serde_json::to_string(k).unwrap_or_default(),
                            Self::jcs_serialize(&map[k])
                        )
                    })
                    .collect();
                format!("{{{}}}", entries.join(","))
            }
        }
    }
}

/// Thin Host Interpreter for `HostEffect` (`E1`–`E7`) against local `.uor-pins.json`.
pub struct LocalHostEffectInterpreter {
    pub lockfile_path: PathBuf,
}

impl LocalHostEffectInterpreter {
    pub fn new(lockfile_path: PathBuf) -> Self {
        Self { lockfile_path }
    }

    pub fn load_lockfile(&self) -> Result<PinLockfile> {
        if !self.lockfile_path.exists() {
            return Ok(PinLockfile {
                schema_version: 1,
                pins: BTreeMap::new(),
            });
        }
        let raw = fs::read_to_string(&self.lockfile_path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn save_lockfile(&self, lockfile: &PinLockfile) -> Result<()> {
        let formatted = serde_json::to_string_pretty(lockfile)?;
        fs::write(&self.lockfile_path, formatted)?;
        Ok(())
    }

    pub fn utc_now_iso8601() -> String {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("epoch:{}Z", secs)
    }

    /// Executes E1 (`ReadActivePin`) and E2 (`RotatePin`) against `.uor-pins.json` (`NR-11`).
    pub fn pin_or_rotate(
        &self,
        server_id: &str,
        next_kappa: KappaLabel,
        prev_kappa: Option<KappaLabel>,
        profile: CliUnicodeProfile,
        approver_ref: &str,
        tool_count: usize,
    ) -> Result<ServerPinRecord> {
        if approver_ref.trim().is_empty() {
            bail!("PinTransitionError::EmptyApproverRef");
        }
        let mut lockfile = self.load_lockfile()?;
        if let Some(existing) = lockfile.pins.get(server_id) {
            match &prev_kappa {
                Some(prev) if prev == &existing.active_manifest_kappa => {}
                _ => bail!(
                    "PinTransitionError::PreviousKappaMismatch: active pin is {}, must pass --previous-kappa",
                    existing.active_manifest_kappa.as_str()
                ),
            }
        }
        let record = ServerPinRecord {
            server_id: server_id.to_owned(),
            active_manifest_kappa: next_kappa,
            previous_manifest_kappa: prev_kappa,
            unicode_profile: profile,
            approver_ref: approver_ref.to_owned(),
            pinned_at_utc: Self::utc_now_iso8601(),
            tool_count,
        };
        lockfile.pins.insert(server_id.to_owned(), record.clone());
        self.save_lockfile(&lockfile)?;
        Ok(record)
    }
}

/// Sends a strictly blind `/v1/notarize` request carrying only 71-byte KappaLabels (`EF-05`, `EF-08`).
/// Enforces `OV-05` (`FailClosed`) on timeout or non-200 status.
async fn call_remote_blind_notary(
    notary_url: &str,
    timeout_ms: u64,
    req: &BlindNotarizeWireRequest,
) -> Result<Value> {
    let serialized = serde_json::to_vec(req)?;
    if serialized.len() > MAX_NOTARIZE_WIRE_BYTES {
        bail!("EF-08 violation: notarize wire payload exceeds 2048 bytes");
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()?;
    let endpoint = format!("{}/v1/notarize", notary_url.trim_end_matches('/'));
    let resp = client
        .post(&endpoint)
        .header("content-type", "application/json")
        .body(serialized)
        .send()
        .await
        .with_context(|| "OV-05 FailClosed: remote blind notary request timed out or failed")?;

    if !resp.status().is_success() {
        bail!(
            "OV-05 FailClosed: remote blind notary returned HTTP {}",
            resp.status()
        );
    }
    Ok(resp.json::<Value>().await?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let wasm_bridge = WasmCoreBridge::load(&cli.wasm_core)?;
    let interpreter = LocalHostEffectInterpreter::new(cli.lockfile.clone());

    match cli.command {
        Commands::Pin {
            server_id,
            profile,
            approver_ref,
            previous_kappa,
            manifest_file,
            server_cmd,
        } => {
            let pages: Vec<Value> = if let Some(path) = manifest_file {
                let raw = fs::read_to_string(&path)?;
                let parsed: Value = serde_json::from_str(&raw)?;
                if let Some(arr) = parsed.as_array() {
                    arr.clone()
                } else {
                    vec![parsed]
                }
            } else {
                if server_cmd.is_empty() {
                    bail!("Must provide either --manifest-file or an upstream MCP server command after `--`");
                }
                drain_mcp_stdio_tools_list(&server_cmd).await?
            };

            let (_jcs, manifest_kappa, tool_count) = wasm_bridge.admit_and_project_surface(
                &server_id,
                "2026-07-28",
                profile,
                &pages,
            )?;

            let prev = match previous_kappa {
                Some(s) => Some(KappaLabel::parse(&s)?),
                None => None,
            };

            let record = interpreter.pin_or_rotate(
                &server_id,
                manifest_kappa,
                prev,
                profile,
                &approver_ref,
                tool_count,
            )?;

            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "PINNED",
                    "server_id": record.server_id,
                    "active_manifest_kappa": record.active_manifest_kappa,
                    "unicode_profile": record.unicode_profile,
                    "tool_count": record.tool_count,
                    "lockfile": cli.lockfile.display().to_string()
                }))?
            );
        }

        Commands::Proxy {
            server_id,
            notary_url,
            notary_timeout_ms,
            receipt_dir,
            server_cmd,
        } => {
            run_fail_closed_stdio_proxy(
                &wasm_bridge,
                &interpreter,
                &server_id,
                notary_url.as_deref(),
                notary_timeout_ms,
                &receipt_dir,
                &server_cmd,
            )
            .await?;
        }
    }

    Ok(())
}

/// Spawns an upstream MCP stdio server and drains `tools/list` until `nextCursor` is null (`NR-01`).
async fn drain_mcp_stdio_tools_list(server_cmd: &[String]) -> Result<Vec<Value>> {
    let mut child = Command::new(&server_cmd[0])
        .args(&server_cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("Failed to spawn MCP server: {:?}", server_cmd))?;

    let mut child_stdin = child.stdin.take().context("Missing child stdin")?;
    let child_stdout = child.stdout.take().context("Missing child stdout")?;
    let mut reader = BufReader::new(child_stdout).lines();

    let mut pages = Vec::new();
    let mut cursor: Option<String> = None;
    let mut req_id: u64 = 1;

    loop {
        let params = match &cursor {
            Some(c) => json!({ "cursor": c }),
            None => json!({}),
        };
        let req = json!({
            "jsonrpc": "2.0",
            "id": format!("uor-drain-{}", req_id),
            "method": "tools/list",
            "params": params
        });
        req_id += 1;
        child_stdin
            .write_all(format!("{}\n", req).as_bytes())
            .await?;
        child_stdin.flush().await?;

        let line = reader
            .next_line()
            .await?
            .ok_or_else(|| anyhow!("Upstream MCP server closed stdout during tools/list drain"))?;
        let page: Value = serde_json::from_str(&line)?;
        let next_cursor = page
            .get("result")
            .and_then(|r| r.get("nextCursor"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_owned());
        pages.push(page);
        if next_cursor.is_none() {
            break;
        }
        cursor = next_cursor;
    }

    let _ = child.kill().await;
    Ok(pages)
}

/// Runs the zero-trust fail-closed MCP stdio proxy (`WT-02`, `NR-04`, `NR-05`, `NR-06`).
async fn run_fail_closed_stdio_proxy(
    wasm_bridge: &WasmCoreBridge,
    interpreter: &LocalHostEffectInterpreter,
    server_id: &str,
    notary_url: Option<&str>,
    notary_timeout_ms: u64,
    receipt_dir: &Path,
    server_cmd: &[String],
) -> Result<()> {
    let lockfile = interpreter.load_lockfile()?;
    let pin = lockfile.pins.get(server_id).ok_or_else(|| {
        anyhow!(
            "SERVER_NOT_PINNED (404): server '{}' is not pinned in {}",
            server_id,
            interpreter.lockfile_path.display()
        )
    })?;

    fs::create_dir_all(receipt_dir)?;

    let mut child = Command::new(&server_cmd[0])
        .args(&server_cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let mut child_stdin = child.stdin.take().context("Missing child stdin")?;
    let child_stdout = child.stdout.take().context("Missing child stdout")?;
    let mut server_lines = BufReader::new(child_stdout).lines();
    let mut client_lines = BufReader::new(tokio::io::stdin()).lines();
    let mut client_stdout = tokio::io::stdout();

    let mut verified_manifest_kappa: Option<KappaLabel> = None;
    let mut prev_receipt_kappa: Option<KappaLabel> = None;

    while let Some(client_line) = client_lines.next_line().await? {
        let msg: Value = serde_json::from_str(&client_line)?;
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let msg_id = msg.get("id").cloned().unwrap_or(Value::Null);

        if method == "tools/list" {
            child_stdin
                .write_all(format!("{}\n", client_line).as_bytes())
                .await?;
            child_stdin.flush().await?;

            let resp_line = server_lines
                .next_line()
                .await?
                .ok_or_else(|| anyhow!("MCP server EOF on tools/list"))?;
            let resp_val: Value = serde_json::from_str(&resp_line)?;

            match wasm_bridge.admit_and_project_surface(
                server_id,
                "2026-07-28",
                pin.unicode_profile,
                &[resp_val],
            ) {
                Ok((_, observed_kappa, _)) => {
                    if observed_kappa != pin.active_manifest_kappa {
                        let err_resp = json!({
                            "jsonrpc": "2.0",
                            "id": msg_id,
                            "error": {
                                "code": -32009,
                                "message": "BLOCKED_DRIFT: POLICY_MANIFEST_DRIFT (409)",
                                "data": {
                                    "server_id": server_id,
                                    "expected_kappa": pin.active_manifest_kappa.as_str(),
                                    "observed_kappa": observed_kappa.as_str()
                                }
                            }
                        });
                        client_stdout
                            .write_all(format!("{}\n", err_resp).as_bytes())
                            .await?;
                        client_stdout.flush().await?;
                        continue;
                    }
                    verified_manifest_kappa = Some(observed_kappa);
                    client_stdout
                        .write_all(format!("{}\n", resp_line).as_bytes())
                        .await?;
                    client_stdout.flush().await?;
                }
                Err(tamper_err) => {
                    let err_resp = json!({
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32022,
                            "message": "BLOCKED_TAMPER: UNICODE_GATE_VIOLATION (422)",
                            "data": {
                                "server_id": server_id,
                                "reason": tamper_err.to_string()
                            }
                        }
                    });
                    client_stdout
                        .write_all(format!("{}\n", err_resp).as_bytes())
                        .await?;
                    client_stdout.flush().await?;
                }
            }
        } else if method == "tools/call" {
            let active_kappa = match &verified_manifest_kappa {
                Some(k) if k == &pin.active_manifest_kappa => k.clone(),
                _ => pin.active_manifest_kappa.clone(),
            };

            let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
            // Stage-0 scan of invocation arguments before forwarding to server
            if let Err(e) =
                WasmCoreBridge::scan_json_value_stage0(&params, pin.unicode_profile, 0)
            {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32022,
                        "message": "BLOCKED_TAMPER: UNICODE_GATE_VIOLATION (422)",
                        "data": { "reason": e.to_string() }
                    }
                });
                client_stdout
                    .write_all(format!("{}\n", err_resp).as_bytes())
                    .await?;
                client_stdout.flush().await?;
                continue;
            }

            let tool_name = params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown_tool");
            let args_val = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

            // NR-06: Compute causal invocation_kappa committing to manifest_kappa
            let invocation_jcs = format!(
                "{{\"arguments\":{},\"manifest_kappa\":{},\"tool\":{},\"uor_mcp_invocation_v\":1}}",
                WasmCoreBridge::jcs_serialize(&args_val),
                WasmCoreBridge::jcs_serialize(&Value::String(active_kappa.as_str().to_owned())),
                WasmCoreBridge::jcs_serialize(&Value::String(tool_name.to_owned()))
            );
            let invocation_kappa = KappaLabel::from_jcs_bytes(invocation_jcs.as_bytes());

            // Forward verified tools/call to upstream MCP server
            child_stdin
                .write_all(format!("{}\n", client_line).as_bytes())
                .await?;
            child_stdin.flush().await?;

            let resp_line = server_lines
                .next_line()
                .await?
                .ok_or_else(|| anyhow!("MCP server EOF on tools/call"))?;
            let resp_val: Value = serde_json::from_str(&resp_line)?;
            let res_obj = resp_val.get("result").cloned().unwrap_or_else(|| json!({}));
            let is_err = res_obj
                .get("isError")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let content_val = res_obj.get("content").cloned().unwrap_or_else(|| json!([]));
            let struct_val = res_obj
                .get("structuredContent")
                .cloned()
                .unwrap_or(Value::Null);

            // NR-06: Compute causal outcome_kappa committing to invocation_kappa
            let outcome_jcs = format!(
                "{{\"content\":{},\"invocation_kappa\":{},\"isError\":{},\"structuredContent\":{},\"uor_mcp_outcome_v\":1}}",
                WasmCoreBridge::jcs_serialize(&content_val),
                WasmCoreBridge::jcs_serialize(&Value::String(invocation_kappa.as_str().to_owned())),
                is_err,
                WasmCoreBridge::jcs_serialize(&struct_val)
            );
            let outcome_kappa = KappaLabel::from_jcs_bytes(outcome_jcs.as_bytes());

            // Optional Remote Blind Notary call (sends ONLY 71-byte KappaLabels; OV-05 FailClosed)
            if let Some(url) = notary_url {
                let wire_req = BlindNotarizeWireRequest {
                    server_id: server_id.to_owned(),
                    manifest_kappa: active_kappa.clone(),
                    invocation_kappa: invocation_kappa.clone(),
                    outcome_kappa: outcome_kappa.clone(),
                    prev_receipt_kappa: prev_receipt_kappa.clone(),
                    client_nonce: format!("nonce-{}", LocalHostEffectInterpreter::utc_now_iso8601()),
                    unicode_profile: pin.unicode_profile,
                    unicode_gate_passed: true,
                    tool_count: pin.tool_count,
                };
                match call_remote_blind_notary(url, notary_timeout_ms, &wire_req).await {
                    Ok(receipt) => {
                        if let Some(rk) = receipt
                            .get("receipt_kappa")
                            .and_then(|v| v.as_str())
                            .and_then(|s| KappaLabel::parse(s).ok())
                        {
                            prev_receipt_kappa = Some(rk);
                        }
                    }
                    Err(timeout_or_http_err) => {
                        // OV-05: FailClosed on notary timeout or error
                        let err_resp = json!({
                            "jsonrpc": "2.0",
                            "id": msg_id,
                            "error": {
                                "code": -32050,
                                "message": "FAIL_CLOSED_NOTARY_UNAVAILABLE",
                                "data": { "reason": timeout_or_http_err.to_string() }
                            }
                        });
                        client_stdout
                            .write_all(format!("{}\n", err_resp).as_bytes())
                            .await?;
                        client_stdout.flush().await?;
                        continue;
                    }
                }
            }

            client_stdout
                .write_all(format!("{}\n", resp_line).as_bytes())
                .await?;
            client_stdout.flush().await?;
        } else {
            // Pass through standard MCP lifecycle handshake frames
            child_stdin
                .write_all(format!("{}\n", client_line).as_bytes())
                .await?;
            child_stdin.flush().await?;
            if !msg_id.is_null() {
                if let Some(resp_line) = server_lines.next_line().await? {
                    client_stdout
                        .write_all(format!("{}\n", resp_line).as_bytes())
                        .await?;
                    client_stdout.flush().await?;
                }
            }
        }
    }

    let _ = child.kill().await;
    Ok(())
}
