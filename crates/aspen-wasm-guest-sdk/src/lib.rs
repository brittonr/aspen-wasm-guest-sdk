//! Guest SDK for building Aspen WASM handler plugins.
//!
//! Plugin authors depend on this crate to implement request handlers that
//! run inside the Aspen WASM sandbox. The typical workflow:
//!
//! 1. Implement the [`AspenPlugin`] trait.
//! 2. Call [`register_plugin!`] with your type to generate the required FFI exports
//!    (`handle_request` and `plugin_info`).
//! 3. Compile to `wasm32-unknown-unknown` and deploy via the plugin manifest.
//!
//! # Example
//!
//! ```rust,ignore
//! use aspen_wasm_guest_sdk::{AspenPlugin, ClientRpcRequest, ClientRpcResponse, PluginInfo};
//!
//! struct Echo;
//!
//! impl AspenPlugin for Echo {
//!     fn info() -> PluginInfo {
//!         PluginInfo {
//!             name: "echo".into(),
//!             version: "0.1.0".into(),
//!             description: Some("Echo plugin for testing".into()),
//!             handles: vec!["Echo".into()],
//!             priority: 900,
//!             app_id: None,
//!             kv_prefixes: vec![],
//!             permissions: PluginPermissions::default(),
//!         }
//!     }
//!
//!     fn handle(request: ClientRpcRequest) -> ClientRpcResponse {
//!         ClientRpcResponse::error("ECHO", &format!("{request:?}"))
//!     }
//! }
//!
//! aspen_wasm_guest_sdk::register_plugin!(Echo);
//! ```
//!
//! The [`AspenPlugin`] trait also provides lifecycle hooks (`init`, `shutdown`, `health`)
//! with default implementations.

pub mod host;
pub mod response;

// Re-export types that plugin authors need.
// KV response types for handler plugins.
// Docs response types for handler plugins.
pub use aspen_client_api::AddPeerClusterResultResponse;
pub use aspen_client_api::BatchCondition;
pub use aspen_client_api::BatchReadResultResponse;
pub use aspen_client_api::BatchWriteOperation;
pub use aspen_client_api::BatchWriteResultResponse;
pub use aspen_client_api::ClientRpcRequest;
pub use aspen_client_api::ClientRpcResponse;
pub use aspen_client_api::CompareAndSwapResultResponse;
pub use aspen_client_api::ConditionalBatchWriteResultResponse;
pub use aspen_client_api::DeleteResultResponse;
pub use aspen_client_api::DocsDeleteResultResponse;
pub use aspen_client_api::DocsGetResultResponse;
pub use aspen_client_api::DocsListEntry;
pub use aspen_client_api::DocsListResultResponse;
pub use aspen_client_api::DocsSetResultResponse;
pub use aspen_client_api::DocsStatusResultResponse;
pub use aspen_client_api::ErrorResponse;
// Hook response types for handler plugins.
pub use aspen_client_api::HookHandlerInfo;
pub use aspen_client_api::HookHandlerMetrics;
pub use aspen_client_api::HookListResultResponse;
pub use aspen_client_api::HookMetricsResultResponse;
pub use aspen_client_api::HookTriggerResultResponse;
// Job/Worker response types for handler plugins.
pub use aspen_client_api::JobCancelResultResponse;
pub use aspen_client_api::JobDetails;
pub use aspen_client_api::JobGetResultResponse;
pub use aspen_client_api::JobListResultResponse;
pub use aspen_client_api::JobQueueStatsResultResponse;
pub use aspen_client_api::JobSubmitResultResponse;
pub use aspen_client_api::JobUpdateProgressResultResponse;
pub use aspen_client_api::KeyOriginResultResponse;
pub use aspen_client_api::ListPeerClustersResultResponse;
pub use aspen_client_api::PeerClusterInfo;
pub use aspen_client_api::PeerClusterStatusResponse;
pub use aspen_client_api::ReadResultResponse;
pub use aspen_client_api::RemovePeerClusterResultResponse;
pub use aspen_client_api::ScanEntry;
pub use aspen_client_api::ScanResultResponse;
pub use aspen_client_api::SetPeerClusterEnabledResultResponse;
// SQL response types for handler plugins.
pub use aspen_client_api::SqlCellValue;
pub use aspen_client_api::SqlResultResponse;
pub use aspen_client_api::UpdatePeerClusterFilterResultResponse;
pub use aspen_client_api::UpdatePeerClusterPriorityResultResponse;
pub use aspen_client_api::WorkerDeregisterResultResponse;
pub use aspen_client_api::WorkerHeartbeatResultResponse;
pub use aspen_client_api::WorkerInfo;
pub use aspen_client_api::WorkerRegisterResultResponse;
pub use aspen_client_api::WorkerStatusResultResponse;
pub use aspen_client_api::WriteResultResponse;
pub use aspen_plugin_api::KvBatchOp;
pub use aspen_plugin_api::PluginHealth;
pub use aspen_plugin_api::PluginInfo;
pub use aspen_plugin_api::PluginPermissions;
pub use aspen_plugin_api::PluginState;
pub use aspen_plugin_api::TimerConfig;

/// Trait that WASM plugin authors implement to handle requests.
pub trait AspenPlugin {
    /// Return metadata describing this plugin.
    fn info() -> PluginInfo;

    /// Handle an incoming client RPC request and produce a response.
    fn handle(request: ClientRpcRequest) -> ClientRpcResponse;

    /// Called once after the plugin is loaded. Perform initialization here.
    ///
    /// Return `Ok(())` to signal readiness, or `Err(message)` to indicate
    /// initialization failure. The default implementation succeeds immediately.
    fn init() -> Result<(), String> {
        Ok(())
    }

    /// Called when the plugin is being unloaded. Release resources here.
    ///
    /// The default implementation does nothing.
    fn shutdown() {}

    /// Called periodically by the host to check plugin health.
    ///
    /// Return `Ok(())` if the plugin is healthy, or `Err(message)` if it is
    /// degraded. The default implementation always reports healthy.
    fn health() -> Result<(), String> {
        Ok(())
    }

    /// Called by the host when a scheduled timer fires.
    ///
    /// The `name` parameter identifies which timer fired. Schedule timers
    /// via [`host::schedule_timer_on_host`].
    ///
    /// The default implementation does nothing.
    fn on_timer(_name: &str) {}

    /// Called by the host when a subscribed hook event fires.
    ///
    /// Subscribe to events via [`host::subscribe_hook_events`] (typically
    /// in your `init` method). The `topic` is the full event topic
    /// (e.g., `hooks.kv.write_committed`) and `event` is the JSON-serialized
    /// hook event payload.
    ///
    /// The default implementation does nothing.
    fn on_hook_event(_topic: &str, _event: &[u8]) {}
}

/// Register a plugin type by generating the FFI exports that the host expects.
///
/// # ABI Contract
///
/// Hyperlight calls guest functions with parameters marshalled through guest memory.
/// For VecBytes params: hyperlight calls guest `malloc`, writes bytes, passes
/// `(ptr: i32, len: i32)`. The guest reads the data and must `free` the allocation.
/// For VecBytes returns: the guest allocates `[4-byte LE size] + data`, returns the
/// pointer as i32. Hyperlight reads it and tracks it for later freeing.
///
/// The guest MUST export `malloc`, `free`, and `memory` for this to work.
#[macro_export]
macro_rules! register_plugin {
    ($plugin_type:ty) => {
        // -----------------------------------------------------------------
        // Memory management exports required by hyperlight-wasm
        // -----------------------------------------------------------------

        /// Export malloc for hyperlight to allocate in guest memory.
        #[unsafe(no_mangle)]
        pub extern "C" fn malloc(size: i32) -> i32 {
            let layout = std::alloc::Layout::from_size_align(size as usize, 8).unwrap();
            let ptr = unsafe { std::alloc::alloc(layout) };
            ptr as i32
        }

        /// Export free for hyperlight to deallocate guest memory.
        #[unsafe(no_mangle)]
        pub extern "C" fn free(ptr: i32) {
            // We can't know the exact size, but for wasm32 linear memory
            // the allocator tracks sizes internally. Use a minimal layout.
            if ptr != 0 {
                let layout = std::alloc::Layout::from_size_align(1, 1).unwrap();
                unsafe { std::alloc::dealloc(ptr as *mut u8, layout) };
            }
        }

        // -----------------------------------------------------------------
        // Guest function exports
        // -----------------------------------------------------------------

        /// Helper: read VecBytes from hyperlight's (ptr, len) pair.
        fn _read_vecbytes(ptr: i32, len: i32) -> Vec<u8> {
            if len <= 0 || ptr == 0 {
                return Vec::new();
            }
            unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize).to_vec() }
        }

        /// Helper: return VecBytes to hyperlight.
        /// Format: [4-byte LE size] + data, returns pointer.
        fn _return_vecbytes(data: &[u8]) -> i32 {
            let total = 4 + data.len();
            let layout = std::alloc::Layout::from_size_align(total, 8).unwrap();
            let ptr = unsafe { std::alloc::alloc(layout) };
            if ptr.is_null() {
                return 0;
            }
            unsafe {
                // Write 4-byte LE length prefix
                let len_bytes = (data.len() as i32).to_le_bytes();
                std::ptr::copy_nonoverlapping(len_bytes.as_ptr(), ptr, 4);
                // Write data
                std::ptr::copy_nonoverlapping(data.as_ptr(), ptr.add(4), data.len());
            }
            ptr as i32
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn handle_request(input_ptr: i32, input_len: i32) -> i32 {
            let input = _read_vecbytes(input_ptr, input_len);
            let request: $crate::ClientRpcRequest = match serde_json::from_slice(&input) {
                Ok(r) => r,
                Err(e) => {
                    let err = $crate::ClientRpcResponse::Error($crate::response::error_response(
                        "PLUGIN_DESERIALIZE_ERROR",
                        &format!("failed to deserialize request: {e}"),
                    ));
                    let out = serde_json::to_vec(&err).unwrap_or_default();
                    return _return_vecbytes(&out);
                }
            };
            let response = <$plugin_type as $crate::AspenPlugin>::handle(request);
            let out = serde_json::to_vec(&response).unwrap_or_default();
            _return_vecbytes(&out)
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn plugin_info(input_ptr: i32, input_len: i32) -> i32 {
            let _ = (input_ptr, input_len);
            let info = <$plugin_type as $crate::AspenPlugin>::info();
            let out = serde_json::to_vec(&info).unwrap_or_default();
            _return_vecbytes(&out)
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn plugin_init(input_ptr: i32, input_len: i32) -> i32 {
            let _ = (input_ptr, input_len);
            let out = match <$plugin_type as $crate::AspenPlugin>::init() {
                Ok(()) => serde_json::to_vec(&serde_json::json!({"ok": true})).unwrap_or_default(),
                Err(e) => serde_json::to_vec(&serde_json::json!({"ok": false, "error": e})).unwrap_or_default(),
            };
            _return_vecbytes(&out)
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn plugin_shutdown(input_ptr: i32, input_len: i32) -> i32 {
            let _ = (input_ptr, input_len);
            <$plugin_type as $crate::AspenPlugin>::shutdown();
            let out = serde_json::to_vec(&serde_json::json!({"ok": true})).unwrap_or_default();
            _return_vecbytes(&out)
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn plugin_health(input_ptr: i32, input_len: i32) -> i32 {
            let _ = (input_ptr, input_len);
            let out = match <$plugin_type as $crate::AspenPlugin>::health() {
                Ok(()) => serde_json::to_vec(&serde_json::json!({"ok": true})).unwrap_or_default(),
                Err(e) => serde_json::to_vec(&serde_json::json!({"ok": false, "error": e})).unwrap_or_default(),
            };
            _return_vecbytes(&out)
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn plugin_on_timer(input_ptr: i32, input_len: i32) -> i32 {
            let input = _read_vecbytes(input_ptr, input_len);
            let name: String = serde_json::from_slice(&input).unwrap_or_default();
            <$plugin_type as $crate::AspenPlugin>::on_timer(&name);
            let out = serde_json::to_vec(&serde_json::json!({"ok": true})).unwrap_or_default();
            _return_vecbytes(&out)
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn plugin_on_hook_event(input_ptr: i32, input_len: i32) -> i32 {
            let input = _read_vecbytes(input_ptr, input_len);
            let parsed: serde_json::Value = serde_json::from_slice(&input).unwrap_or_default();
            let topic = parsed["topic"].as_str().unwrap_or("");
            let event_bytes = serde_json::to_vec(&parsed["event"]).unwrap_or_default();
            <$plugin_type as $crate::AspenPlugin>::on_hook_event(topic, &event_bytes);
            let out = serde_json::to_vec(&serde_json::json!({"ok": true})).unwrap_or_default();
            _return_vecbytes(&out)
        }
    };
}
