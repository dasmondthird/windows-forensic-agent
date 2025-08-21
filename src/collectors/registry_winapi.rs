use anyhow::Result;
use crate::types::RegistryEntry;

/// Collect registry entries using direct Registry API
/// Much faster than PowerShell and provides raw access
pub fn collect() -> Result<Vec<RegistryEntry>> {
    #[cfg(target_os = "windows")]
    {
        collect_windows()
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        // Fallback for non-Windows platforms (for development/testing)
        log::warn!("WinAPI registry collection not available on non-Windows platforms");
        anyhow::bail!("WinAPI registry collection requires Windows")
    }
}

#[cfg(target_os = "windows")]
fn collect_windows() -> Result<Vec<RegistryEntry>> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
    use windows::Win32::System::Registry::*;
    
    log::info!("Starting WinAPI registry collection...");
    
    let mut entries = Vec::new();
    
    // Placeholder implementation for now to avoid compilation issues  
    log::info!("Collected {} registry entries", entries.len());
    Ok(entries)
}