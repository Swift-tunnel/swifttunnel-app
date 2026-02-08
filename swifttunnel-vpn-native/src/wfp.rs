//! Windows Filtering Platform (WFP) Integration - STUB
//!
//! This module is a STUB for backward compatibility.
//! Split tunnel functionality is not implemented in the native DLL.

use crate::error::VpnError;

/// WFP Engine handle wrapper - STUB for compatibility
pub struct WfpEngine {
    _private: (),
}

unsafe impl Send for WfpEngine {}
unsafe impl Sync for WfpEngine {}

impl WfpEngine {
    /// Open a new WFP engine session - STUB
    pub fn open() -> Result<Self, VpnError> {
        log::debug!("WFP not implemented");
        Ok(Self { _private: () })
    }

    /// Register as a WFP provider - STUB
    pub fn register_provider(&mut self) -> Result<(), VpnError> {
        Ok(())
    }

    /// Create the split tunnel sublayer - STUB
    pub fn create_sublayer(&mut self) -> Result<(), VpnError> {
        Ok(())
    }

    /// Close the WFP engine - STUB
    pub fn close(&mut self) {
        // No-op
    }

    pub fn is_ready(&self) -> bool {
        true
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        self.close();
    }
}

/// WFP filter layers - kept for API compatibility
#[derive(Debug, Clone, Copy)]
pub enum FilterLayer {
    AleConnectV4,
    AleConnectV6,
    AleRecvAcceptV4,
    AleRecvAcceptV6,
}

/// Setup WFP for split tunneling - STUB
pub fn setup_wfp_for_split_tunnel(_interface_luid: u64) -> Result<WfpEngine, VpnError> {
    log::info!("WFP not implemented");
    WfpEngine::open()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wfp_engine_open_returns_ok() {
        let result = WfpEngine::open();
        assert!(result.is_ok());
    }

    #[test]
    fn test_wfp_engine_register_provider_returns_ok() {
        let mut engine = WfpEngine::open().unwrap();
        assert!(engine.register_provider().is_ok());
    }

    #[test]
    fn test_wfp_engine_create_sublayer_returns_ok() {
        let mut engine = WfpEngine::open().unwrap();
        assert!(engine.create_sublayer().is_ok());
    }

    #[test]
    fn test_wfp_engine_is_ready() {
        let engine = WfpEngine::open().unwrap();
        assert!(engine.is_ready());
    }

    #[test]
    fn test_wfp_engine_close_no_panic() {
        let mut engine = WfpEngine::open().unwrap();
        engine.close();
    }

    #[test]
    fn test_wfp_engine_drop_no_panic() {
        let engine = WfpEngine::open().unwrap();
        drop(engine);
    }

    #[test]
    fn test_wfp_engine_full_lifecycle() {
        let mut engine = WfpEngine::open().unwrap();
        engine.register_provider().unwrap();
        engine.create_sublayer().unwrap();
        assert!(engine.is_ready());
        engine.close();
        drop(engine);
    }

    #[test]
    fn test_setup_wfp_for_split_tunnel_returns_ok() {
        let result = setup_wfp_for_split_tunnel(0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_filter_layer_debug() {
        let layer = FilterLayer::AleConnectV4;
        let debug_str = format!("{:?}", layer);
        assert_eq!(debug_str, "AleConnectV4");
    }

    #[test]
    fn test_filter_layer_clone_and_copy() {
        let layer = FilterLayer::AleConnectV6;
        let cloned = layer.clone();
        let copied = layer;
        assert!(matches!(cloned, FilterLayer::AleConnectV6));
        assert!(matches!(copied, FilterLayer::AleConnectV6));
    }

    #[test]
    fn test_filter_layer_all_variants() {
        let variants = [
            FilterLayer::AleConnectV4,
            FilterLayer::AleConnectV6,
            FilterLayer::AleRecvAcceptV4,
            FilterLayer::AleRecvAcceptV6,
        ];
        assert_eq!(variants.len(), 4);
        assert!(matches!(variants[0], FilterLayer::AleConnectV4));
        assert!(matches!(variants[1], FilterLayer::AleConnectV6));
        assert!(matches!(variants[2], FilterLayer::AleRecvAcceptV4));
        assert!(matches!(variants[3], FilterLayer::AleRecvAcceptV6));
    }
}
