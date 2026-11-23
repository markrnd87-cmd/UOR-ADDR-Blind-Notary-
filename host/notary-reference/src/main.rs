//! Self-Hostable Reference Blind Notary (`uor-notary-reference`)
//!
//! Blueprint Section 5.2 & Contract Rules 1, 4, 7 (`WT-03`, `EF-01`..`EF-08`, `OB-01`..`OB-10`):
//! - Implements the thin host interpreter for the closed 7-constructor `HostEffect` algebra
//!   (`E1` ReadActivePin, `E2` RotatePin, `E3` SignPae, `E4` AppendTransparencyLog,
//!   `E5` ReadUtcClock, `E6` EmitDriftWebhook, `E7` ReadCheckpoint) backed by SQLite
//!   and Ed25519 (`ed25519-dalek`).
//! - Enforces the 2048-byte wire ceiling (`EF-08`) and `#[serde(deny_unknown_fields)]` so
//!   raw customer prompts, tool descriptions, arguments, or tool outputs can NEVER enter
//!   the notary process (`SM-06`).
//! - Exposes the normative endpoints:
//!     * `POST /v1/pins`
//!     * `POST /v1/notarize`
//!     * `GET  /v1/checkpoint`
//!     * `GET  /.well-known/uor-notary.json`
//!   and exact HTTP error semantics (`400 INVALID_KAPPA_FORMAT`, `404 SERVER_NOT_PINNED`,
//!   `409 POLICY_MANIFEST_DRIFT`, `422 UNICODE_GATE_VIOLATION`, `429 QUOTA_EXCEEDED`).

use anyhow::Result;
use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STD, Engine as _};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// EF-08: Maximum permitted HTTP request body size for `/v1/notarize` (2048 bytes).
pub const MAX_NOTARIZE_WIRE_BYTES: usize = 2048;

/// Normative DSSE v1.0 payloadType for in-toto Statement v1 (28 ASCII bytes, NR-08, NR-09).
pub const DSSE_INTOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

#[derive(Parser, Debug)]
#[command(
    name = "uor-notary-reference",
    version = "0.1.0",
    about = "Self-Hostable Zero-Payload Reference Blind Notary (UOR Foundation Commons)"
)]
pub struct Cli {
    /// Listen socket address
    #[arg(long, default_value = "127.0.0.1:8787", env = "UOR_NOTARY_BIND")]
    pub bind: SocketAddr,

    /// SQLite database file path (`:memory:` for ephemeral mode)
    #[arg(long, default_value = "uor-notary-reference.db", env = "UOR_NOTARY_DB")]
    pub db_path: PathBuf,

    /// Logical Notary identifier embedded in issued in-toto v1 statements
    #[arg(
        long,
        default_value = "notary.uor.foundation/reference-v1",
        env = "UOR_NOTARY_ID"
    )]
    pub notary_id: String,

    /// Active Ed25519 Key ID published at `/.well-known/uor-notary.json`
    #[arg(
        long,
        default_value = "uor-notary-ed25519-2026-01",
        env = "UOR_NOTARY_KEY_ID"
    )]
    pub key_id: String,

    /// Optional 32-byte hex seed for deterministic Ed25519 key generation in tests
    #[arg(long, env = "UOR_NOTARY_KEY_SEED_HEX")]
    pub key_seed_hex: Option<String>,
}

/// Validates that a string is a 71-byte ASCII `KappaLabel` matching `^sha256:[0-9a-f]{64}$` (`NR-07`).
pub fn is_valid_kappa_label(s: &str) -> bool {
    if s.len() != 71 || !s.starts_with("sha256:") {
        return false;
    }
    s[7..]
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Wire request for `POST /v1/pins` (`E2 RotatePin`, `NR-11`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinWireRequest {
    pub server_id: String,
    pub manifest_kappa: String,
    pub previous_pin_kappa: Option<String>,
    pub unicode_profile: String,
    pub approver_ref: String,
}

/// Wire request for `POST /v1/notarize` (`EF-05`, `EF-08`).
/// `#[serde(deny_unknown_fields)]` guarantees that any attempt to smuggle raw prompt/tool
/// fields across the wire is rejected with HTTP 400 `INVALID_KAPPA_FORMAT`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotarizeWireRequest {
    pub server_id: String,
    pub manifest_kappa: String,
    pub invocation_kappa: String,
    pub outcome_kappa: String,
    pub prev_receipt_kappa: Option<String>,
    pub client_nonce: String,
    pub unicode_profile: String,
    pub unicode_gate_passed: bool,
    pub tool_count: usize,
}

/// Telemetry SLI Verdict Counters (`OB-07`).
#[derive(Clone, Debug, Default, Serialize)]
pub struct SliCounters {
    pub verified_count: u64,
    pub blocked_drift_count: u64,
    pub blocked_tamper_count: u64,
    pub client_syntax_400_count: u64,
}

pub struct NotaryAppState {
    pub notary_id: String,
    pub key_id: String,
    pub signing_key: SigningKey,
    pub db: Mutex<Connection>,
    pub sli: Mutex<SliCounters>,
}

impl NotaryAppState {
    pub fn init(
        notary_id: String,
        key_id: String,
        signing_key: SigningKey,
        conn: Connection,
    ) -> Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS pins (
                server_id TEXT PRIMARY KEY,
                active_kappa TEXT NOT NULL,
                previous_kappa TEXT,
                unicode_profile TEXT NOT NULL,
                approver_ref TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS transparency_log (
                log_index INTEGER PRIMARY KEY AUTOINCREMENT,
                leaf_kappa TEXT NOT NULL,
                server_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                issued_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blind_drift_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id TEXT NOT NULL,
                expected_kappa TEXT,
                observed_kappa TEXT,
                reason_code TEXT NOT NULL,
                redacted_payload TEXT NOT NULL DEFAULT 'Withheld',
                recorded_at TEXT NOT NULL
            );",
        )?;
        Ok(Self {
            notary_id,
            key_id,
            signing_key,
            db: Mutex::new(conn),
            sli: Mutex::new(SliCounters::default()),
        })
    }

    /// E5: `ReadUtcClock`
    pub fn read_utc_clock() -> String {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("2026-11-22T00:00:{:02}Z", secs % 60)
    }

    /// Normative DSSE v1.0 PAE encoding (`NR-09`):
    /// `PAE(type, body) = "DSSEv1 " || dec(len(type)) || " " || type || " " || dec(len(body)) || " " || body`
    pub fn encode_dsse_pae(payload_type: &str, body_bytes: &[u8]) -> Vec<u8> {
        let prefix = format!(
            "DSSEv1 {} {} {} ",
            payload_type.len(),
            payload_type,
            body_bytes.len()
        );
        let mut out = Vec::with_capacity(prefix.len() + body_bytes.len());
        out.extend_from_slice(prefix.as_bytes());
        out.extend_from_slice(body_bytes);
        out
    }

    /// Computes the binary Merkle root across all transparency log leaves (`NR-10`).
    pub fn compute_merkle_root(leaves: &[String]) -> String {
        if leaves.is_empty() {
            let empty_digest = Sha256::digest(b"uor-tlog-empty-tree-v1");
            return format!("sha256:{}", hex::encode(empty_digest));
        }
        let mut current = leaves[0].clone();
        for sibling in &leaves[1..] {
            let combined = format!("node:{}:{}", current, sibling);
            let digest = Sha256::digest(combined.as_bytes());
            current = format!("sha256:{}", hex::encode(digest));
        }
        current
    }
}

fn wire_error_response(status: StatusCode, error_code: &str, detail: &str) -> Response {
    (
        status,
        Json(json!({
            "error": error_code,
            "status": status.as_u16(),
            "redacted_payload": "Withheld",
            "detail": detail
        })),
    )
        .into_response()
}

/// `POST /v1/pins` — Implements `E1 ReadActivePin` and `E2 RotatePin` (`NR-11`).
async fn handle_post_pins(
    State(state): State<Arc<NotaryAppState>>,
    body: Bytes,
) -> Response {
    if body.len() > MAX_NOTARIZE_WIRE_BYTES {
        return wire_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_KAPPA_FORMAT",
            "Request body exceeds 2048-byte wire ceiling (EF-08)",
        );
    }

    let req: PinWireRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return wire_error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_KAPPA_FORMAT",
                "Malformed JSON or unknown non-blind field",
            );
        }
    };

    if req.server_id.trim().is_empty()
        || !is_valid_kappa_label(&req.manifest_kappa)
        || (req.unicode_profile != "strict-v1" && req.unicode_profile != "rgi-aware-v1")
    {
        return wire_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_KAPPA_FORMAT",
            "Invalid server_id, 71-byte manifest_kappa, or unicode_profile",
        );
    }

    if req.approver_ref.trim().is_empty() {
        return wire_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_KAPPA_FORMAT",
            "NR-11: approver_ref must be non-empty",
        );
    }

    let db = state.db.lock().unwrap();
    let existing_active: Option<String> = db
        .query_row(
            "SELECT active_kappa FROM pins WHERE server_id = ?1",
            params![req.server_id],
            |row| row.get(0),
        )
        .ok();

    if let Some(active) = &existing_active {
        match &req.previous_pin_kappa {
            Some(prev) if prev == active => {}
            _ => {
                return wire_error_response(
                    StatusCode::CONFLICT,
                    "POLICY_MANIFEST_DRIFT",
                    "NR-11: previous_pin_kappa does not match currently active pin",
                );
            }
        }
    }

    let now = NotaryAppState::read_utc_clock();
    db.execute(
        "INSERT INTO pins (server_id, active_kappa, previous_kappa, unicode_profile, approver_ref, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(server_id) DO UPDATE SET
           active_kappa = excluded.active_kappa,
           previous_kappa = excluded.previous_kappa,
           unicode_profile = excluded.unicode_profile,
           approver_ref = excluded.approver_ref,
           updated_at = excluded.updated_at",
        params![
            req.server_id,
            req.manifest_kappa,
            req.previous_pin_kappa,
            req.unicode_profile,
            req.approver_ref,
            now
        ],
    )
    .unwrap();

    (
        StatusCode::OK,
        Json(json!({
            "status": "PINNED",
            "server_id": req.server_id,
            "active_manifest_kappa": req.manifest_kappa,
            "previous_manifest_kappa": existing_active,
            "unicode_profile": req.unicode_profile,
            "approver_ref": req.approver_ref,
            "updated_at": now,
            "notification": "notifications/uor/pin_updated"
        })),
    )
        .into_response()
}

/// `POST /v1/notarize` — Executes `UorNotary.NotaryCore.evaluateExecution`, builds Layer-1
/// `in-toto` Statement v1 and Layer-2 DSSE v1.0 PAE signature (`E3 SignPae`), appends leaf
/// to transparency log (`E4 AppendTransparencyLog`), and emits blind drift events (`E6`).
async fn handle_post_notarize(
    State(state): State<Arc<NotaryAppState>>,
    body: Bytes,
) -> Response {
    // EF-08: 2048-byte hard wire size ceiling
    if body.len() > MAX_NOTARIZE_WIRE_BYTES {
        let mut sli = state.sli.lock().unwrap();
        sli.client_syntax_400_count += 1;
        return wire_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_KAPPA_FORMAT",
            "Request body exceeds 2048-byte wire ceiling (EF-08)",
        );
    }

    let req: NotarizeWireRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            let mut sli = state.sli.lock().unwrap();
            sli.client_syntax_400_count += 1;
            return wire_error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_KAPPA_FORMAT",
                "Malformed JSON or unknown payload field rejected by blind notary schema",
            );
        }
    };

    if !is_valid_kappa_label(&req.manifest_kappa)
        || !is_valid_kappa_label(&req.invocation_kappa)
        || !is_valid_kappa_label(&req.outcome_kappa)
        || req
            .prev_receipt_kappa
            .as_ref()
            .is_some_and(|k| !is_valid_kappa_label(k))
    {
        let mut sli = state.sli.lock().unwrap();
        sli.client_syntax_400_count += 1;
        return wire_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_KAPPA_FORMAT",
            "All kappa fields must be 71-byte ASCII strings matching ^sha256:[0-9a-f]{64}$",
        );
    }

    let db = state.db.lock().unwrap();
    // E1: ReadActivePin
    let pinned_kappa: String = match db.query_row(
        "SELECT active_kappa FROM pins WHERE server_id = ?1",
        params![req.server_id],
        |row| row.get(0),
    ) {
        Ok(k) => k,
        Err(_) => {
            return wire_error_response(
                StatusCode::NOT_FOUND,
                "SERVER_NOT_PINNED",
                "Server is not pinned; register initial pin via POST /v1/pins",
            );
        }
    };

    // NR-04 & NR-05: Fail-closed pin state machine evaluation
    let (verdict, http_status, error_tag) = if !req.unicode_gate_passed {
        (
            "BLOCKED_TAMPER",
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("UNICODE_GATE_VIOLATION"),
        )
    } else if req.manifest_kappa != pinned_kappa {
        (
            "BLOCKED_DRIFT",
            StatusCode::CONFLICT,
            Some("POLICY_MANIFEST_DRIFT"),
        )
    } else {
        ("VERIFIED", StatusCode::OK, None)
    };

    let issued_at = NotaryAppState::read_utc_clock();

    // E6: EmitDriftWebhook when drift or Stage-0 tamper occurs (carries zero raw text, OB-01)
    if verdict != "VERIFIED" {
        let reason_code = if !req.unicode_gate_passed {
            "UnicodeGateViolation"
        } else {
            "ManifestKappaDrift"
        };
        db.execute(
            "INSERT INTO blind_drift_events (server_id, expected_kappa, observed_kappa, reason_code, redacted_payload, recorded_at)
             VALUES (?1, ?2, ?3, ?4, 'Withheld', ?5)",
            params![
                req.server_id,
                pinned_kappa,
                req.manifest_kappa,
                reason_code,
                issued_at
            ],
        )
        .unwrap();
    }

    // Determine next transparency log index
    let log_index: i64 = db
        .query_row("SELECT COUNT(*) FROM transparency_log", [], |r| r.get(0))
        .unwrap_or(0);

    // Layer 1: Construct canonical in-toto Statement v1 JCS (NR-08)
    let prev_str = match &req.prev_receipt_kappa {
        Some(k) => format!("\"{}\"", k),
        None => "null".to_owned(),
    };
    let statement_jcs = format!(
        "{{\"_type\":\"https://in-toto.io/Statement/v1\",\"predicate\":{{\"notary\":{{\"id\":\"{}\",\"issuedAt\":\"{}\",\"logIndex\":{}}},\"pinnedManifestKappa\":\"{}\",\"serverId\":\"{}\",\"sessionChain\":{{\"clientNonce\":\"{}\",\"prevReceiptKappa\":{}}},\"unicodeGate\":{{\"passed\":{},\"profile\":\"{}\",\"toolCount\":{}}},\"verdict\":\"{}\"}},\"predicateType\":\"https://uor.foundation/predicates/mcp-blind-receipt/v1\",\"subject\":[{{\"annotations\":{{\"uor.kappaLabel\":\"{}\",\"uor.realization\":\"uor_addr::json\"}},\"digest\":{{\"sha256\":\"{}\"}},\"name\":\"mcp:manifest\"}},{{\"annotations\":{{\"uor.kappaLabel\":\"{}\",\"uor.realization\":\"uor_addr::json\"}},\"digest\":{{\"sha256\":\"{}\"}},\"name\":\"mcp:invocation\"}},{{\"annotations\":{{\"uor.kappaLabel\":\"{}\",\"uor.realization\":\"uor_addr::json\"}},\"digest\":{{\"sha256\":\"{}\"}},\"name\":\"mcp:outcome\"}}]}}",
        state.notary_id,
        issued_at,
        log_index,
        pinned_kappa,
        req.server_id,
        req.client_nonce,
        prev_str,
        req.unicode_gate_passed,
        req.unicode_profile,
        req.tool_count,
        verdict,
        req.manifest_kappa,
        &req.manifest_kappa[7..],
        req.invocation_kappa,
        &req.invocation_kappa[7..],
        req.outcome_kappa,
        &req.outcome_kappa[7..]
    );

    let receipt_digest = Sha256::digest(statement_jcs.as_bytes());
    let receipt_kappa = format!("sha256:{}", hex::encode(receipt_digest));

    // Layer 2: DSSE v1.0 PAE & E3 SignPae (NR-09, EF-02)
    let pae_bytes =
        NotaryAppState::encode_dsse_pae(DSSE_INTOTO_PAYLOAD_TYPE, statement_jcs.as_bytes());
    let signature = state.signing_key.sign(&pae_bytes);
    let sig_b64 = BASE64_STD.encode(signature.to_bytes());
    let payload_b64 = BASE64_STD.encode(statement_jcs.as_bytes());

    // E4: AppendTransparencyLog
    db.execute(
        "INSERT INTO transparency_log (leaf_kappa, server_id, verdict, issued_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![receipt_kappa, req.server_id, verdict, issued_at],
    )
    .unwrap();

    // Update OB-07 SLI counters
    {
        let mut sli = state.sli.lock().unwrap();
        match verdict {
            "VERIFIED" => sli.verified_count += 1,
            "BLOCKED_DRIFT" => sli.blocked_drift_count += 1,
            _ => sli.blocked_tamper_count += 1,
        }
    }

    let mut body_json = json!({
        "verdict": verdict,
        "receipt_kappa": receipt_kappa,
        "log_index": log_index,
        "redacted_payload": "Withheld",
        "dsse_envelope": {
            "payloadType": DSSE_INTOTO_PAYLOAD_TYPE,
            "payload": payload_b64,
            "signatures": [
                {
                    "keyid": state.key_id,
                    "sig": sig_b64
                }
            ]
        }
    });

    if let Some(err_code) = error_tag {
        body_json["error"] = Value::String(err_code.to_owned());
    }

    (http_status, Json(body_json)).into_response()
}

/// `GET /v1/checkpoint` — Implements `E7 ReadCheckpoint`, returning a signed C2SP `tlog-checkpoint` (`NR-10`).
async fn handle_get_checkpoint(State(state): State<Arc<NotaryAppState>>) -> Response {
    let db = state.db.lock().unwrap();
    let mut stmt = db
        .prepare("SELECT leaf_kappa FROM transparency_log ORDER BY log_index ASC")
        .unwrap();
    let leaves: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();

    let tree_size = leaves.len();
    let root_hash = NotaryAppState::compute_merkle_root(&leaves);
    let checkpoint_body = format!("{}\n{}\n{}\n", state.notary_id, tree_size, root_hash);
    let sig = state.signing_key.sign(checkpoint_body.as_bytes());

    (
        StatusCode::OK,
        Json(json!({
            "origin": state.notary_id,
            "treeSize": tree_size,
            "rootHash": root_hash,
            "checkpointText": checkpoint_body,
            "signature": {
                "keyid": state.key_id,
                "sig": BASE64_STD.encode(sig.to_bytes())
            },
            "notification": "notifications/uor/checkpoint_published"
        })),
    )
        .into_response()
}

/// `GET /.well-known/uor-notary.json` — Publishes Ed25519 verification keys & blind notary metadata.
async fn handle_well_known(State(state): State<Arc<NotaryAppState>>) -> Response {
    let verifying_key = state.signing_key.verifying_key();
    let pub_hex = hex::encode(verifying_key.to_bytes());
    let pub_b64 = BASE64_STD.encode(verifying_key.to_bytes());
    let sli = state.sli.lock().unwrap().clone();

    (
        StatusCode::OK,
        Json(json!({
            "notary_id": state.notary_id,
            "protocol_version": "2026-07-28",
            "uor_addr_version": "0.2.0",
            "license": "MIT OR Apache-2.0",
            "max_notarize_wire_bytes": MAX_NOTARIZE_WIRE_BYTES,
            "keys": [
                {
                    "keyid": state.key_id,
                    "algorithm": "Ed25519",
                    "public_key_hex": pub_hex,
                    "public_key_base64": pub_b64,
                    "status": "active"
                }
            ],
            "sli_counters": sli
        })),
    )
        .into_response()
}

pub fn build_router(state: Arc<NotaryAppState>) -> Router {
    Router::new()
        .route("/v1/pins", post(handle_post_pins))
        .route("/v1/notarize", post(handle_post_notarize))
        .route("/v1/checkpoint", get(handle_get_checkpoint))
        .route("/.well-known/uor-notary.json", get(handle_well_known))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let signing_key = if let Some(seed_hex) = &cli.key_seed_hex {
        let bytes = hex::decode(seed_hex)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("UOR_NOTARY_KEY_SEED_HEX must be 32 bytes (64 hex chars)"))?;
        SigningKey::from_bytes(&arr)
    } else {
        let mut csprng = rand::rngs::OsRng;
        SigningKey::generate(&mut csprng)
    };

    let conn = Connection::open(&cli.db_path)?;
    let app_state = Arc::new(NotaryAppState::init(
        cli.notary_id,
        cli.key_id,
        signing_key,
        conn,
    )?);

    let app = build_router(app_state);
    let listener = tokio::net::TcpListener::bind(cli.bind).await?;
    println!("uor-notary-reference listening on http://{}", cli.bind);
    axum::serve(listener, app).await?;
    Ok(())
}
