//! Host function imports for WASM guest plugins.
//!
//! These functions call into the host runtime via hyperlight's primitive-mode FFI.
//!
//! # ABI Contract
//!
//! Hyperlight-wasm's linker maps host functions into the WASM module's "env"
//! namespace using its own type system (ParameterType/ReturnType), which does
//! NOT match the standard Rust wasm32 ABI. The mapping is:
//!
//! | Hyperlight Type | WASM ValType | Guest representation |
//! |-----------------|-------------|----------------------|
//! | String (param)  | i32         | pointer to NUL-terminated C string |
//! | String (return) | i32         | pointer to NUL-terminated C string |
//! | VecBytes (param)| i32         | pointer to raw bytes (followed by i32 length) |
//! | Int / UInt      | i32         | raw value |
//! | Long / ULong    | i64         | raw value |
//! | Bool            | i32         | 0 or 1 |
//! | Void            | (none)      | no return |
//!
//! VecBytes return is declared as i64 in hyperlight's type system but the
//! wasm_runtime's hl_return_to_val actually returns i32 — this is a known
//! hyperlight-wasm 0.12 bug. All functions that previously returned Vec<u8>
//! have been changed to return String (base64-encoded where needed) to work
//! around this limitation.
//!
//! Guest extern declarations MUST use raw types (i32, i64, etc.) and manually
//! marshal String/VecBytes through guest memory, not Rust's String/Vec types
//! which produce incompatible multi-value ABI signatures on wasm32.

use core::ffi::{CStr, c_char};
use std::ffi::CString;

// ---------------------------------------------------------------------------
// Raw extern declarations matching hyperlight's WASM-level ABI
// ---------------------------------------------------------------------------

unsafe extern "C" {
    // Logging (String → void)
    fn log_info(msg: *const c_char);
    fn log_debug(msg: *const c_char);
    fn log_warn(msg: *const c_char);

    // Time (→ u64)
    fn now_ms() -> u64;
    fn hlc_now() -> u64;

    // KV operations
    fn kv_get(key: *const c_char) -> *const c_char;        // String → String (base64-tagged)
    fn kv_put(key: *const c_char, value: *const u8, value_len: i32) -> *const c_char;
    fn kv_delete(key: *const c_char) -> *const c_char;
    fn kv_scan(prefix: *const c_char, limit: u32) -> *const c_char; // String, u32 → String (base64-tagged)
    fn kv_cas(key: *const c_char, packed: *const u8, packed_len: i32) -> *const c_char;
    fn kv_batch(ops: *const u8, ops_len: i32) -> *const c_char;
    fn kv_execute(request_json: *const c_char) -> *const c_char;

    // Blob operations
    fn blob_has(hash: *const c_char) -> i32;                // bool
    fn blob_get(hash: *const c_char) -> *const c_char;      // String → String (base64-tagged)
    fn blob_put(data: *const u8, data_len: i32) -> *const c_char;

    // Cluster info
    fn node_id() -> u64;
    fn is_leader() -> i32;                                   // bool
    fn leader_id() -> u64;

    // Crypto
    fn random_bytes(count: u32) -> *const c_char;            // u32 → String (base64)
    fn sign(data: *const u8, data_len: i32) -> *const c_char; // VecBytes → String (base64)
    fn verify(key: *const c_char, packed: *const u8, packed_len: i32) -> i32; // bool
    fn public_key_hex() -> *const c_char;

    // Timers
    fn schedule_timer(config: *const u8, config_len: i32) -> *const c_char;
    fn cancel_timer(name: *const c_char) -> *const c_char;

    // Hooks
    fn hook_subscribe(pattern: *const c_char) -> *const c_char;
    fn hook_unsubscribe(pattern: *const c_char) -> *const c_char;
    fn hook_list(unused: *const c_char) -> *const c_char;
    fn hook_metrics(handler_name: *const c_char) -> *const c_char;
    fn hook_trigger(request_json: *const c_char) -> *const c_char;

    // SQL
    fn sql_query(request_json: *const c_char) -> *const c_char;

    // Generic service
    fn service_execute(request_json: *const c_char) -> *const c_char;

    // API version & capabilities
    fn query_host_api_version() -> *const c_char;
    fn host_capabilities() -> *const c_char;
}

// ---------------------------------------------------------------------------
// Raw ABI helpers
// ---------------------------------------------------------------------------

/// Convert a Rust &str to a NUL-terminated C string pointer for hyperlight.
/// The CString must be kept alive for the duration of the call.
fn to_cstr(s: &str) -> CString {
    CString::new(s).unwrap_or_else(|_| {
        // If the string contains NUL bytes, replace them
        let cleaned: Vec<u8> = s.bytes().filter(|&b| b != 0).collect();
        CString::new(cleaned).unwrap()
    })
}

/// Read a NUL-terminated C string returned by a host function.
///
/// # Safety
/// The pointer must be valid and point to a NUL-terminated string in guest memory.
///
/// Hyperlight's `hl_return_to_val` allocates this via guest `malloc` but does NOT
/// track it in `RETURN_VALUE_ALLOCATIONS` (that tracking is only for guest function
/// return values, not host function return values). The guest should free it.
///
/// On wasm32, we call the exported `free` from `register_plugin!` which reads
/// the malloc header to recover the correct size. On non-wasm (tests), no-op.
unsafe fn read_cstr_return(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let s = cstr.to_string_lossy().into_owned();

    // Free the allocation made by hyperlight's hl_return_to_val via guest malloc.
    // The exported free() from register_plugin! reads the size header.
    #[cfg(target_arch = "wasm32")]
    {
        unsafe extern "C" {
            fn free(ptr: i32);
        }
        unsafe { free(ptr as i32) };
    }

    s
}

// ---------------------------------------------------------------------------
// Safe wrappers — Logging
// ---------------------------------------------------------------------------

/// Log an info-level message on the host.
pub fn log_info_msg(msg: &str) {
    let c = to_cstr(msg);
    unsafe { log_info(c.as_ptr()) }
}

/// Log a debug-level message on the host.
pub fn log_debug_msg(msg: &str) {
    let c = to_cstr(msg);
    unsafe { log_debug(c.as_ptr()) }
}

/// Log a warn-level message on the host.
pub fn log_warn_msg(msg: &str) {
    let c = to_cstr(msg);
    unsafe { log_warn(c.as_ptr()) }
}

// ---------------------------------------------------------------------------
// Safe wrappers — Time
// ---------------------------------------------------------------------------

/// Get the current wall-clock time in milliseconds from the host.
pub fn current_time_ms() -> u64 {
    unsafe { now_ms() }
}

/// Get the current HLC timestamp as milliseconds.
pub fn hlc_now_ms() -> u64 {
    unsafe { hlc_now() }
}

// ---------------------------------------------------------------------------
// Safe wrappers — KV Store
// ---------------------------------------------------------------------------

/// Read a value from the distributed KV store.
///
/// Returns `Ok(Some(data))` if the key exists, `Ok(None)` if not found,
/// or `Err(message)` on error.
///
/// Host encoding (String, base64-tagged):
/// `\x01` + base64(value) = found, `\x02` = not-found,
/// `\x03` + error_msg = error.
pub fn kv_get_value(key: &str) -> Result<Option<Vec<u8>>, String> {
    let c_key = to_cstr(key);
    let result = unsafe { read_cstr_return(kv_get(c_key.as_ptr())) };
    decode_tagged_b64_option_result(&result)
}

/// Write a value to the distributed KV store.
/// Returns `Ok(())` on success or `Err(message)` on failure.
pub fn kv_put_value(key: &str, value: &[u8]) -> Result<(), String> {
    let c_key = to_cstr(key);
    let result = unsafe {
        read_cstr_return(kv_put(c_key.as_ptr(), value.as_ptr(), value.len() as i32))
    };
    decode_tagged_unit_result(&result)
}

/// Delete a key from the distributed KV store.
pub fn kv_delete_key(key: &str) -> Result<(), String> {
    let c_key = to_cstr(key);
    let result = unsafe { read_cstr_return(kv_delete(c_key.as_ptr())) };
    decode_tagged_unit_result(&result)
}

/// Scan keys by prefix from the distributed KV store.
/// Returns a list of `(key, value)` pairs, JSON-decoded from the host response.
///
/// Host encoding (String, base64-tagged):
/// `\x01` + base64(json_bytes) = ok, `\x02` + error_msg = error.
pub fn kv_scan_prefix(prefix: &str, limit: u32) -> Result<Vec<(String, Vec<u8>)>, String> {
    let c_prefix = to_cstr(prefix);
    let result = unsafe { read_cstr_return(kv_scan(c_prefix.as_ptr(), limit)) };
    if result.is_empty() {
        return Ok(Vec::new());
    }
    match result.as_bytes()[0] {
        b'\x01' => {
            // Decode base64 → JSON bytes → Vec<(String, Vec<u8>)>
            let b64 = &result[1..];
            if b64.is_empty() {
                return Ok(Vec::new());
            }
            let bytes = base64_decode(b64).map_err(|e| format!("base64 decode failed: {e}"))?;
            Ok(serde_json::from_slice(&bytes).unwrap_or_default())
        }
        b'\x02' => {
            let msg = &result[1..];
            Err(msg.to_string())
        }
        _ => {
            // Backwards compat: no tag byte, try raw JSON decode
            Ok(serde_json::from_str(&result).unwrap_or_default())
        }
    }
}

/// Compare-and-swap a value in the distributed KV store.
///
/// Parameters are packed into a single byte buffer because hyperlight's
/// ABI requires VecBytes to be immediately followed by Int (length).
/// Packing: `[4-byte expected_len (LE)] ++ expected ++ new_value`
pub fn kv_compare_and_swap(key: &str, expected: &[u8], new_value: &[u8]) -> Result<(), String> {
    let c_key = to_cstr(key);
    let packed = pack_two_vecs(expected, new_value);
    let result = unsafe {
        read_cstr_return(kv_cas(c_key.as_ptr(), packed.as_ptr(), packed.len() as i32))
    };
    decode_tagged_unit_result(&result)
}

/// Execute a batch of KV operations atomically.
pub fn kv_batch_write(ops: &[aspen_plugin_api::KvBatchOp]) -> Result<(), String> {
    let json = serde_json::to_vec(ops).map_err(|e| format!("failed to serialize batch: {e}"))?;
    let result = unsafe {
        read_cstr_return(kv_batch(json.as_ptr(), json.len() as i32))
    };
    decode_tagged_unit_result(&result)
}

// ---------------------------------------------------------------------------
// Safe wrappers — Blob Store
// ---------------------------------------------------------------------------

/// Check whether a blob exists in the content-addressed store.
pub fn blob_exists(hash: &str) -> bool {
    let c = to_cstr(hash);
    unsafe { blob_has(c.as_ptr()) != 0 }
}

/// Retrieve a blob by hash. Returns `Ok(None)` if the blob does not exist,
/// or `Err(message)` on error.
///
/// Host encoding (String, base64-tagged):
/// `\x01` + base64(data) = found, `\x02` = not-found,
/// `\x03` + error_msg = error.
pub fn blob_get_data(hash: &str) -> Result<Option<Vec<u8>>, String> {
    let c = to_cstr(hash);
    let result = unsafe { read_cstr_return(blob_get(c.as_ptr())) };
    decode_tagged_b64_option_result(&result)
}

/// Store a blob and return its content hash.
pub fn blob_put_data(data: &[u8]) -> Result<String, String> {
    let result = unsafe {
        read_cstr_return(blob_put(data.as_ptr(), data.len() as i32))
    };
    if let Some(stripped) = result.strip_prefix('\x02') {
        Err(stripped.to_string())
    } else if let Some(stripped) = result.strip_prefix('\x01') {
        Ok(stripped.to_string())
    } else {
        // No prefix — treat entire string as the hash (backwards compat).
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Safe wrappers — Cluster Info
// ---------------------------------------------------------------------------

/// Get the numeric node ID of the host node.
pub fn get_node_id() -> u64 {
    unsafe { node_id() }
}

/// Check whether the host node is currently the Raft leader.
pub fn is_current_leader() -> bool {
    unsafe { is_leader() != 0 }
}

/// Get the numeric node ID of the current Raft leader.
pub fn get_leader_id() -> u64 {
    unsafe { leader_id() }
}

// ---------------------------------------------------------------------------
// Safe wrappers — Crypto
// ---------------------------------------------------------------------------

/// Get cryptographically random bytes from the host.
///
/// Host returns base64-encoded string (workaround for VecBytes return bug).
pub fn get_random_bytes(count: u32) -> Vec<u8> {
    let result = unsafe { read_cstr_return(random_bytes(count)) };
    base64_decode(&result).unwrap_or_default()
}

/// Sign data with the host node's Ed25519 secret key.
///
/// Host returns base64-encoded signature.
pub fn sign_data(data: &[u8]) -> Vec<u8> {
    let result = unsafe {
        read_cstr_return(sign(data.as_ptr(), data.len() as i32))
    };
    base64_decode(&result).unwrap_or_default()
}

/// Verify an Ed25519 signature using a hex-encoded public key.
///
/// Parameters are packed because hyperlight's ABI forbids multiple
/// VecBytes params. Packing: `[4-byte data_len (LE)] ++ data ++ sig`
pub fn verify_signature(public_key_hex_str: &str, data: &[u8], signature: &[u8]) -> bool {
    let c_key = to_cstr(public_key_hex_str);
    let packed = pack_two_vecs(data, signature);
    unsafe { verify(c_key.as_ptr(), packed.as_ptr(), packed.len() as i32) != 0 }
}

/// Get the host node's Ed25519 public key as a hex string.
pub fn public_key() -> String {
    unsafe { read_cstr_return(public_key_hex()) }
}

// ---------------------------------------------------------------------------
// Safe wrappers — Timers
// ---------------------------------------------------------------------------

/// Schedule a timer on the host.
pub fn schedule_timer_on_host(config: &aspen_plugin_api::TimerConfig) -> Result<(), String> {
    let json = serde_json::to_vec(config)
        .map_err(|e| format!("failed to serialize timer config: {e}"))?;
    let result = unsafe {
        read_cstr_return(schedule_timer(json.as_ptr(), json.len() as i32))
    };
    decode_tagged_unit_result(&result)
}

/// Cancel a named timer on the host.
pub fn cancel_timer_on_host(name: &str) -> Result<(), String> {
    let c = to_cstr(name);
    let result = unsafe { read_cstr_return(cancel_timer(c.as_ptr())) };
    decode_tagged_unit_result(&result)
}

// ---------------------------------------------------------------------------
// Safe wrappers — Hook Event Subscriptions
// ---------------------------------------------------------------------------

/// Subscribe to hook events matching a NATS-style topic pattern.
pub fn subscribe_hook_events(pattern: &str) -> Result<(), String> {
    let c = to_cstr(pattern);
    let result = unsafe { read_cstr_return(hook_subscribe(c.as_ptr())) };
    decode_tagged_unit_result(&result)
}

/// Unsubscribe from a previously registered hook event pattern.
pub fn unsubscribe_hook_events(pattern: &str) -> Result<(), String> {
    let c = to_cstr(pattern);
    let result = unsafe { read_cstr_return(hook_unsubscribe(c.as_ptr())) };
    decode_tagged_unit_result(&result)
}

// ---------------------------------------------------------------------------
// Hook management
// ---------------------------------------------------------------------------

/// Handler info returned by `list_hooks`.
#[derive(serde::Deserialize)]
pub struct HookHandlerInfo {
    pub name: String,
    pub pattern: String,
    pub handler_type: String,
    pub execution_mode: String,
    pub enabled: bool,
    pub timeout_ms: u64,
    pub retry_count: u32,
}

#[derive(serde::Deserialize)]
pub struct HookListResult {
    pub is_enabled: bool,
    pub handlers: Vec<HookHandlerInfo>,
}

#[derive(serde::Deserialize)]
pub struct HookHandlerMetricsInfo {
    pub name: String,
    pub success_count: u64,
    pub failure_count: u64,
    pub dropped_count: u64,
    pub jobs_submitted: u64,
    pub avg_duration_us: u64,
    pub max_duration_us: u64,
}

#[derive(serde::Deserialize)]
pub struct HookMetricsResult {
    pub is_enabled: bool,
    pub total_events_processed: u64,
    pub handlers: Vec<HookHandlerMetricsInfo>,
}

#[derive(serde::Deserialize)]
pub struct HookTriggerResult {
    pub is_success: bool,
    pub dispatched_count: u32,
    pub error: Option<String>,
    pub handler_failures: Vec<Vec<String>>,
}

/// List configured hook handlers and their enabled status.
pub fn list_hooks() -> Result<HookListResult, String> {
    let c = to_cstr("");
    let result = unsafe { read_cstr_return(hook_list(c.as_ptr())) };
    decode_tagged_json_result(&result)
}

/// Get execution metrics for hook handlers.
pub fn get_hook_metrics(handler_name: &str) -> Result<HookMetricsResult, String> {
    let c = to_cstr(handler_name);
    let result = unsafe { read_cstr_return(hook_metrics(c.as_ptr())) };
    decode_tagged_json_result(&result)
}

/// Manually trigger a hook event.
pub fn trigger_hook(
    event_type: &str,
    payload: &serde_json::Value,
) -> Result<HookTriggerResult, String> {
    let request = serde_json::json!({
        "event_type": event_type,
        "payload": payload,
    });
    let request_json =
        serde_json::to_string(&request).map_err(|e| format!("serialize failed: {e}"))?;
    let c = to_cstr(&request_json);
    let result = unsafe { read_cstr_return(hook_trigger(c.as_ptr())) };
    decode_tagged_json_result(&result)
}

// ---------------------------------------------------------------------------
// SQL query
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct SqlQueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub row_count: u32,
    pub is_truncated: bool,
    pub execution_time_ms: u64,
}

/// Execute a read-only SQL query against the node's state machine.
pub fn execute_sql(
    query: &str,
    params_json: &str,
    consistency: &str,
    limit: Option<u32>,
    timeout_ms: Option<u32>,
) -> Result<SqlQueryResult, String> {
    let request = serde_json::json!({
        "query": query,
        "params_json": params_json,
        "consistency": consistency,
        "limit": limit,
        "timeout_ms": timeout_ms,
    });
    let request_json =
        serde_json::to_string(&request).map_err(|e| format!("failed to serialize SQL request: {e}"))?;
    let c = to_cstr(&request_json);
    let result = unsafe { read_cstr_return(sql_query(c.as_ptr())) };

    if let Some(json) = result.strip_prefix('\x01') {
        serde_json::from_str(json).map_err(|e| format!("failed to parse SQL result: {e}"))
    } else if let Some(msg) = result.strip_prefix('\x02') {
        Err(msg.to_string())
    } else {
        Err(result)
    }
}

// ---------------------------------------------------------------------------
// Full-fidelity KV operations (for handler plugins)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct KvReadResult {
    pub value: Option<String>,
    pub was_found: bool,
    pub error: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct KvWriteResult {
    pub is_success: bool,
    pub error: Option<String>,
    pub error_code: Option<String>,
    pub leader_id: Option<u64>,
}

#[derive(serde::Deserialize)]
pub struct KvDeleteResult {
    pub key: String,
    pub was_deleted: bool,
    pub error: Option<String>,
    pub error_code: Option<String>,
    pub leader_id: Option<u64>,
}

#[derive(serde::Deserialize)]
pub struct KvScanEntry {
    pub key: String,
    pub value: String,
    pub version: u64,
    pub create_revision: u64,
    pub mod_revision: u64,
}

#[derive(serde::Deserialize)]
pub struct KvScanResult {
    pub entries: Vec<KvScanEntry>,
    pub count: u32,
    pub is_truncated: bool,
    pub continuation_token: Option<String>,
    pub error: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct KvBatchReadResult {
    pub is_success: bool,
    pub values: Option<Vec<Option<String>>>,
    pub error: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct KvBatchWriteResult {
    pub is_success: bool,
    pub operations_applied: Option<u32>,
    pub error: Option<String>,
    pub error_code: Option<String>,
    pub leader_id: Option<u64>,
}

#[derive(serde::Deserialize)]
pub struct KvCasResult {
    pub is_success: bool,
    pub actual_value: Option<String>,
    pub error: Option<String>,
    pub error_code: Option<String>,
    pub leader_id: Option<u64>,
}

#[derive(serde::Deserialize)]
pub struct KvConditionalBatchResult {
    pub is_success: bool,
    pub conditions_met: bool,
    pub operations_applied: Option<u32>,
    pub failed_condition_index: Option<u32>,
    pub failed_condition_reason: Option<String>,
    pub error: Option<String>,
    pub error_code: Option<String>,
    pub leader_id: Option<u64>,
}

/// Execute a full-fidelity KV operation via the host (JSON-based).
fn kv_execute_raw(request_json: &str) -> Result<serde_json::Value, String> {
    let c = to_cstr(request_json);
    let result = unsafe { read_cstr_return(kv_execute(c.as_ptr())) };
    if let Some(json_str) = result.strip_prefix('\x01') {
        serde_json::from_str(json_str).map_err(|e| format!("failed to parse kv_execute result: {e}"))
    } else if let Some(err) = result.strip_prefix('\x02') {
        Err(err.to_string())
    } else {
        Err(result)
    }
}

pub fn kv_read_full(key: &str) -> KvReadResult {
    let req = serde_json::json!({"op": "read", "key": key});
    match kv_execute_raw(&req.to_string()) {
        Ok(v) => serde_json::from_value(v).unwrap_or(KvReadResult {
            value: None,
            was_found: false,
            error: Some("failed to parse read result".to_string()),
        }),
        Err(e) => KvReadResult {
            value: None,
            was_found: false,
            error: Some(e),
        },
    }
}

pub fn kv_write_full(key: &str, value_b64: &str) -> KvWriteResult {
    let req = serde_json::json!({"op": "write", "key": key, "value": value_b64});
    match kv_execute_raw(&req.to_string()) {
        Ok(v) => serde_json::from_value(v).unwrap_or(KvWriteResult {
            is_success: false,
            error: Some("failed to parse write result".to_string()),
            error_code: None,
            leader_id: None,
        }),
        Err(e) => KvWriteResult {
            is_success: false,
            error: Some(e),
            error_code: None,
            leader_id: None,
        },
    }
}

pub fn kv_delete_full(key: &str) -> KvDeleteResult {
    let req = serde_json::json!({"op": "delete", "key": key});
    match kv_execute_raw(&req.to_string()) {
        Ok(v) => serde_json::from_value(v).unwrap_or(KvDeleteResult {
            key: key.to_string(),
            was_deleted: false,
            error: Some("failed to parse delete result".to_string()),
            error_code: None,
            leader_id: None,
        }),
        Err(e) => KvDeleteResult {
            key: key.to_string(),
            was_deleted: false,
            error: Some(e),
            error_code: None,
            leader_id: None,
        },
    }
}

pub fn kv_scan_full(
    prefix: &str,
    limit: Option<u32>,
    continuation_token: Option<&str>,
) -> KvScanResult {
    let req = serde_json::json!({
        "op": "scan",
        "prefix": prefix,
        "limit": limit,
        "continuation_token": continuation_token,
    });
    match kv_execute_raw(&req.to_string()) {
        Ok(v) => serde_json::from_value(v).unwrap_or(KvScanResult {
            entries: vec![],
            count: 0,
            is_truncated: false,
            continuation_token: None,
            error: Some("failed to parse scan result".to_string()),
        }),
        Err(e) => KvScanResult {
            entries: vec![],
            count: 0,
            is_truncated: false,
            continuation_token: None,
            error: Some(e),
        },
    }
}

pub fn kv_batch_read_full(keys: &[String]) -> KvBatchReadResult {
    let req = serde_json::json!({"op": "batch_read", "keys": keys});
    match kv_execute_raw(&req.to_string()) {
        Ok(v) => serde_json::from_value(v).unwrap_or(KvBatchReadResult {
            is_success: false,
            values: None,
            error: Some("failed to parse batch read result".to_string()),
        }),
        Err(e) => KvBatchReadResult {
            is_success: false,
            values: None,
            error: Some(e),
        },
    }
}

pub fn kv_batch_write_full(operations: &serde_json::Value) -> KvBatchWriteResult {
    let req = serde_json::json!({"op": "batch_write", "operations": operations});
    match kv_execute_raw(&req.to_string()) {
        Ok(v) => serde_json::from_value(v).unwrap_or(KvBatchWriteResult {
            is_success: false,
            operations_applied: None,
            error: Some("failed to parse batch write result".to_string()),
            error_code: None,
            leader_id: None,
        }),
        Err(e) => KvBatchWriteResult {
            is_success: false,
            operations_applied: None,
            error: Some(e),
            error_code: None,
            leader_id: None,
        },
    }
}

pub fn kv_cas_full(key: &str, expected: Option<&str>, new_value: &str) -> KvCasResult {
    let req = serde_json::json!({
        "op": "cas",
        "key": key,
        "expected": expected,
        "new_value": new_value,
    });
    match kv_execute_raw(&req.to_string()) {
        Ok(v) => serde_json::from_value(v).unwrap_or(KvCasResult {
            is_success: false,
            actual_value: None,
            error: Some("failed to parse CAS result".to_string()),
            error_code: None,
            leader_id: None,
        }),
        Err(e) => KvCasResult {
            is_success: false,
            actual_value: None,
            error: Some(e),
            error_code: None,
            leader_id: None,
        },
    }
}

pub fn kv_cad_full(key: &str, expected: &str) -> KvCasResult {
    let req = serde_json::json!({
        "op": "cad",
        "key": key,
        "expected": expected,
    });
    match kv_execute_raw(&req.to_string()) {
        Ok(v) => serde_json::from_value(v).unwrap_or(KvCasResult {
            is_success: false,
            actual_value: None,
            error: Some("failed to parse CAD result".to_string()),
            error_code: None,
            leader_id: None,
        }),
        Err(e) => KvCasResult {
            is_success: false,
            actual_value: None,
            error: Some(e),
            error_code: None,
            leader_id: None,
        },
    }
}

pub fn kv_conditional_batch_full(
    conditions: &serde_json::Value,
    operations: &serde_json::Value,
) -> KvConditionalBatchResult {
    let req = serde_json::json!({
        "op": "conditional_batch",
        "conditions": conditions,
        "operations": operations,
    });
    match kv_execute_raw(&req.to_string()) {
        Ok(v) => serde_json::from_value(v).unwrap_or(KvConditionalBatchResult {
            is_success: false,
            conditions_met: false,
            operations_applied: None,
            failed_condition_index: None,
            failed_condition_reason: None,
            error: Some("failed to parse conditional batch result".to_string()),
            error_code: None,
            leader_id: None,
        }),
        Err(e) => KvConditionalBatchResult {
            is_success: false,
            conditions_met: false,
            operations_applied: None,
            failed_condition_index: None,
            failed_condition_reason: None,
            error: Some(e),
            error_code: None,
            leader_id: None,
        },
    }
}

// ---------------------------------------------------------------------------
// Generic service executor
// ---------------------------------------------------------------------------

/// Execute a domain-specific service operation via the host.
pub fn execute_service(
    service: &str,
    op: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let mut request = params.clone();
    if let Some(obj) = request.as_object_mut() {
        obj.insert("service".to_string(), serde_json::Value::String(service.to_string()));
        obj.insert("op".to_string(), serde_json::Value::String(op.to_string()));
    } else {
        return Err("params must be a JSON object".to_string());
    }

    let request_str =
        serde_json::to_string(&request).map_err(|e| format!("serialize failed: {e}"))?;
    let c = to_cstr(&request_str);
    let result = unsafe { read_cstr_return(service_execute(c.as_ptr())) };
    decode_tagged_json_result::<serde_json::Value>(&result)
}

/// Execute a raw service call with a pre-built JSON request string.
pub fn execute_service_raw(request_json: &str) -> String {
    let c = to_cstr(request_json);
    unsafe { read_cstr_return(service_execute(c.as_ptr())) }
}

// ---------------------------------------------------------------------------
// API Version & Capabilities
// ---------------------------------------------------------------------------

/// Query the host's plugin API version.
///
/// Returns a semver version string (e.g., "0.2.0"). Plugins can use this
/// at init time to adapt behavior for different host versions or log a
/// warning if the host is older than expected.
///
/// # Example
///
/// ```no_run
/// let version = aspen_wasm_guest_sdk::host::get_host_api_version();
/// if version != "0.2.0" {
///     aspen_wasm_guest_sdk::host::warn(&format!("expected API 0.2.0, got {version}"));
/// }
/// ```
pub fn get_host_api_version() -> String {
    unsafe { read_cstr_return(query_host_api_version()) }
}

/// Query the host's available capabilities (host function names).
///
/// Returns a list of host function names that are registered and available
/// for this plugin to call. Plugins can use this to probe for optional
/// capabilities (e.g., `sql_query`, `hook_list`) before attempting to call
/// them, avoiding runtime errors.
///
/// # Example
///
/// ```no_run
/// let caps = aspen_wasm_guest_sdk::host::get_host_capabilities();
/// if caps.contains(&"sql_query".to_string()) {
///     // SQL queries are available on this node
/// }
/// ```
pub fn get_host_capabilities() -> Vec<String> {
    let json = unsafe { read_cstr_return(host_capabilities()) };
    serde_json::from_str(&json).unwrap_or_default()
}

/// Check if a specific host capability is available.
///
/// Convenience wrapper around [`get_host_capabilities`]. Queries the host
/// once and searches the result. For checking multiple capabilities, prefer
/// calling `get_host_capabilities()` once and searching the list.
pub fn has_capability(name: &str) -> bool {
    get_host_capabilities().iter().any(|c| c == name)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Pack two byte slices into a single `Vec<u8>` with a 4-byte LE length prefix.
/// Format: `[4-byte first_len (LE)] ++ first ++ second`
fn pack_two_vecs(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(4 + first.len() + second.len());
    packed.extend_from_slice(&(first.len() as u32).to_le_bytes());
    packed.extend_from_slice(first);
    packed.extend_from_slice(second);
    packed
}

/// Decode a tagged JSON result string. `\0{json}` = success, `\x01{error}` = error.
fn decode_tagged_json_result<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, String> {
    if let Some(json) = s.strip_prefix('\x01') {
        serde_json::from_str(json).map_err(|e| format!("parse result failed: {e}"))
    } else if let Some(err) = s.strip_prefix('\x02') {
        Err(err.to_string())
    } else {
        Err("unexpected host response format".to_string())
    }
}

/// Decode a tagged `Result<(), String>` from a host function.
/// `\x01` = success, `\x02` + msg = error, empty = success.
fn decode_tagged_unit_result(result: &str) -> Result<(), String> {
    if result.is_empty() || result.starts_with('\x01') {
        Ok(())
    } else if let Some(msg) = result.strip_prefix('\x02') {
        Err(msg.to_string())
    } else {
        Err(result.to_string())
    }
}

/// Decode a tagged option result where binary data is base64-encoded.
///
/// Host encoding: `\x01` + base64(value) = found, `\x02` = not-found,
/// `\x03` + error_msg = error, empty = not-found.
fn decode_tagged_b64_option_result(result: &str) -> Result<Option<Vec<u8>>, String> {
    if result.is_empty() {
        return Ok(None);
    }
    match result.as_bytes()[0] {
        b'\x01' => {
            let b64 = &result[1..];
            if b64.is_empty() {
                return Ok(Some(Vec::new()));
            }
            let bytes = base64_decode(b64).map_err(|e| format!("base64 decode: {e}"))?;
            Ok(Some(bytes))
        }
        b'\x02' => Ok(None),
        b'\x03' => {
            let msg = &result[1..];
            Err(msg.to_string())
        }
        _ => {
            // Backwards compat: no tag byte, try base64 decode of entire string
            match base64_decode(result) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(_) => Ok(Some(result.as_bytes().to_vec())),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal base64 codec (no extra dependencies for wasm32 guest)
// ---------------------------------------------------------------------------

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as base64 string.
pub fn base64_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(B64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(B64_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(B64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(B64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Decode base64 string to bytes.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim_end_matches('=');
    let mut result = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in input.bytes() {
        let val = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'\n' | b'\r' | b' ' => continue,
            _ => return Err(format!("invalid base64 char: {}", c as char)),
        };
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_two_vecs_roundtrip() {
        let first = b"hello";
        let second = b"world";
        let packed = pack_two_vecs(first, second);
        assert_eq!(packed.len(), 4 + first.len() + second.len());
        let first_len = u32::from_le_bytes(packed[..4].try_into().unwrap()) as usize;
        assert_eq!(first_len, first.len());
        assert_eq!(&packed[4..4 + first_len], first);
        assert_eq!(&packed[4 + first_len..], second);
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ==");
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_empty() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_base64_binary() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = base64_encode(&data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_tagged_unit_result_success() {
        assert!(decode_tagged_unit_result("").is_ok());
        assert!(decode_tagged_unit_result("\x01ok").is_ok());
    }

    #[test]
    fn test_decode_tagged_unit_result_error() {
        assert_eq!(decode_tagged_unit_result("\x02oops").unwrap_err(), "oops");
    }

    #[test]
    fn test_decode_tagged_b64_option_found() {
        // \x01 + base64("value") = found
        let input = format!("\x01{}", base64_encode(b"value"));
        let result = decode_tagged_b64_option_result(&input);
        assert_eq!(result.unwrap().unwrap(), b"value");
    }

    #[test]
    fn test_decode_tagged_b64_option_not_found() {
        let result = decode_tagged_b64_option_result("\x02");
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_decode_tagged_b64_option_error() {
        let result = decode_tagged_b64_option_result("\x03something broke");
        assert_eq!(result.unwrap_err(), "something broke");
    }

    #[test]
    fn test_decode_tagged_b64_option_empty() {
        let result = decode_tagged_b64_option_result("");
        assert!(result.unwrap().is_none());
    }
}
