use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
use windows::Win32::System::Registry::*;

use crate::types::RegistryEntry;

/// Critical registry keys for forensic analysis
const CRITICAL_REGISTRY_PATHS: &[(&str, HKEY)] = &[
    // Autostart locations
    (r"Software\Microsoft\Windows\CurrentVersion\Run", HKEY_CURRENT_USER),
    (r"Software\Microsoft\Windows\CurrentVersion\Run", HKEY_LOCAL_MACHINE),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", HKEY_CURRENT_USER),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", HKEY_LOCAL_MACHINE),
    (r"Software\Microsoft\Windows\CurrentVersion\RunServices", HKEY_LOCAL_MACHINE),
    (r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", HKEY_LOCAL_MACHINE),
    
    // System policies
    (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", HKEY_CURRENT_USER),
    (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", HKEY_LOCAL_MACHINE),
    
    // Windows NT autostart
    (r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", HKEY_LOCAL_MACHINE),
    (r"Software\Microsoft\Windows NT\CurrentVersion\Windows", HKEY_LOCAL_MACHINE),
    
    // Image File Execution Options (IFEO)
    (r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", HKEY_LOCAL_MACHINE),
    
    // LSA packages and authentication
    (r"System\CurrentControlSet\Control\Lsa", HKEY_LOCAL_MACHINE),
    (r"System\CurrentControlSet\Control\SecurityProviders", HKEY_LOCAL_MACHINE),
    
    // AppInit DLLs
    (r"Software\Microsoft\Windows NT\CurrentVersion\Windows", HKEY_LOCAL_MACHINE),
    (r"Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows", HKEY_LOCAL_MACHINE),
    
    // Known DLLs
    (r"System\CurrentControlSet\Control\Session Manager\KnownDLLs", HKEY_LOCAL_MACHINE),
    
    // Safe boot
    (r"System\CurrentControlSet\Control\SafeBoot\Minimal", HKEY_LOCAL_MACHINE),
    (r"System\CurrentControlSet\Control\SafeBoot\Network", HKEY_LOCAL_MACHINE),
    
    // Services
    (r"System\CurrentControlSet\Services", HKEY_LOCAL_MACHINE),
];

/// Collect registry entries using direct Registry API
/// Much faster than PowerShell and provides raw access
pub fn collect() -> Result<Vec<RegistryEntry>> {
    log::info!("Starting WinAPI registry collection...");
    
    let mut entries = Vec::new();
    
    for (path, hive) in CRITICAL_REGISTRY_PATHS {
        if let Ok(mut key_entries) = collect_registry_key(*hive, path) {
            entries.append(&mut key_entries);
        }
    }
    
    log::info!("Collected {} registry entries", entries.len());
    Ok(entries)
}

/// Collect all entries from a specific registry key
unsafe fn collect_registry_key(hive: HKEY, path: &str) -> Result<Vec<RegistryEntry>> {
    let mut entries = Vec::new();
    
    // Convert path to UTF-16
    let path_wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    
    // Open the registry key
    let mut key = HKEY::default();
    let result = RegOpenKeyExW(
        hive,
        PCWSTR(path_wide.as_ptr()),
        0,
        KEY_READ,
        &mut key,
    );
    
    if result.is_err() {
        // Key doesn't exist or no access - this is normal
        return Ok(entries);
    }
    
    // Enumerate values
    let mut value_index = 0u32;
    loop {
        let mut value_name = [0u16; 16384]; // Max registry value name length
        let mut value_name_len = value_name.len() as u32;
        let mut value_type = REG_VALUE_TYPE(0);
        let mut value_data = [0u8; 32768]; // Max registry value data length
        let mut value_data_len = value_data.len() as u32;
        
        let result = RegEnumValueW(
            key,
            value_index,
            &mut value_name,
            &mut value_name_len,
            None,
            Some(&mut value_type),
            Some(value_data.as_mut_ptr()),
            Some(&mut value_data_len),
        );
        
        if result == ERROR_NO_MORE_ITEMS {
            break;
        }
        
        if result.is_ok() {
            let name = String::from_utf16_lossy(&value_name[..value_name_len as usize]);
            let value = parse_registry_value(value_type, &value_data[..value_data_len as usize]);
            
            entries.push(RegistryEntry {
                hive: format!("{:?}", hive),
                path: path.to_string(),
                name,
                value,
                value_type: format!("{:?}", value_type),
                is_suspicious: is_registry_entry_suspicious(path, &name, &value),
            });
        }
        
        value_index += 1;
    }
    
    // Enumerate subkeys for recursive collection (limited depth)
    if should_recurse_into_key(path) {
        let mut subkey_index = 0u32;
        loop {
            let mut subkey_name = [0u16; 255];
            let mut subkey_name_len = subkey_name.len() as u32;
            
            let result = RegEnumKeyExW(
                key,
                subkey_index,
                &mut subkey_name,
                &mut subkey_name_len,
                None,
                None,
                None,
                None,
            );
            
            if result == ERROR_NO_MORE_ITEMS {
                break;
            }
            
            if result.is_ok() {
                let subkey_name_str = String::from_utf16_lossy(&subkey_name[..subkey_name_len as usize]);
                let subkey_path = format!("{}\\{}", path, subkey_name_str);
                
                // Recursively collect from subkey (with depth limit)
                if let Ok(mut subkey_entries) = collect_registry_key(hive, &subkey_path) {
                    entries.append(&mut subkey_entries);
                }
            }
            
            subkey_index += 1;
            
            // Limit recursion to prevent excessive collection
            if subkey_index > 1000 {
                break;
            }
        }
    }
    
    RegCloseKey(key);
    Ok(entries)
}

/// Parse registry value based on its type
fn parse_registry_value(value_type: REG_VALUE_TYPE, data: &[u8]) -> String {
    match value_type {
        REG_SZ | REG_EXPAND_SZ => {
            // String value
            if data.len() >= 2 {
                let wide_chars: Vec<u16> = data
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .take_while(|&c| c != 0)
                    .collect();
                String::from_utf16_lossy(&wide_chars)
            } else {
                String::new()
            }
        },
        REG_DWORD => {
            // 32-bit number
            if data.len() >= 4 {
                let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                format!("0x{:08x} ({})", value, value)
            } else {
                "Invalid DWORD".to_string()
            }
        },
        REG_QWORD => {
            // 64-bit number
            if data.len() >= 8 {
                let value = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3],
                    data[4], data[5], data[6], data[7]
                ]);
                format!("0x{:016x} ({})", value, value)
            } else {
                "Invalid QWORD".to_string()
            }
        },
        REG_MULTI_SZ => {
            // Multiple strings
            if data.len() >= 2 {
                let wide_chars: Vec<u16> = data
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();
                
                let mut strings = Vec::new();
                let mut current_string = Vec::new();
                
                for &ch in &wide_chars {
                    if ch == 0 {
                        if !current_string.is_empty() {
                            strings.push(String::from_utf16_lossy(&current_string));
                            current_string.clear();
                        }
                    } else {
                        current_string.push(ch);
                    }
                }
                
                strings.join("; ")
            } else {
                String::new()
            }
        },
        REG_BINARY => {
            // Binary data
            if data.len() <= 64 {
                data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
            } else {
                format!("Binary data ({} bytes): {}", 
                    data.len(),
                    data.iter().take(32).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ") + "..."
                )
            }
        },
        _ => {
            format!("Unknown type {:?} ({} bytes)", value_type, data.len())
        }
    }
}

/// Check if registry entry appears suspicious
fn is_registry_entry_suspicious(path: &str, name: &str, value: &str) -> bool {
    let path_lower = path.to_lowercase();
    let name_lower = name.to_lowercase();
    let value_lower = value.to_lowercase();
    
    // Check for suspicious autostart entries
    if path_lower.contains("run") {
        // Suspicious file extensions
        let suspicious_extensions = [".bat", ".cmd", ".vbs", ".js", ".jar", ".scr", ".pif"];
        for ext in &suspicious_extensions {
            if value_lower.contains(ext) {
                return true;
            }
        }
        
        // Suspicious paths
        let suspicious_paths = ["temp", "appdata", "public", "programdata"];
        for path in &suspicious_paths {
            if value_lower.contains(path) {
                return true;
            }
        }
    }
    
    // Check for IFEO debugger entries
    if path_lower.contains("image file execution options") && name_lower == "debugger" {
        return true;
    }
    
    // Check for LSA package modifications
    if path_lower.contains("lsa") && (name_lower.contains("authentication") || name_lower.contains("security")) {
        return true;
    }
    
    // Check for AppInit DLL modifications
    if name_lower == "appinit_dlls" && !value.is_empty() {
        return true;
    }
    
    false
}

/// Determine if we should recursively collect from this key
fn should_recurse_into_key(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    
    // Don't recurse into very large keys
    if path_lower.contains("services") && path_lower.matches("\\").count() > 3 {
        return false;
    }
    
    // Don't recurse into IFEO unless specifically needed
    if path_lower.contains("image file execution options") && path_lower.matches("\\").count() > 6 {
        return false;
    }
    
    // Recurse into most other keys
    true
}

/// Get specific high-value registry entries
pub fn get_persistence_entries() -> Result<Vec<RegistryEntry>> {
    let all_entries = collect()?;
    
    Ok(all_entries.into_iter()
        .filter(|entry| {
            let path = entry.path.to_lowercase();
            path.contains("run") || 
            path.contains("winlogon") ||
            path.contains("ifeo") ||
            path.contains("lsa")
        })
        .collect())
}

/// Get suspicious registry entries
pub fn get_suspicious_entries() -> Result<Vec<RegistryEntry>> {
    let all_entries = collect()?;
    
    Ok(all_entries.into_iter()
        .filter(|entry| entry.is_suspicious)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_registry_collection() {
        let result = collect();
        assert!(result.is_ok());
        
        let entries = result.unwrap();
        assert!(!entries.is_empty());
    }
    
    #[test]
    fn test_value_parsing() {
        // Test DWORD parsing
        let dword_data = [0x12, 0x34, 0x56, 0x78];
        let parsed = parse_registry_value(REG_DWORD, &dword_data);
        assert!(parsed.contains("0x78563412"));
        
        // Test string parsing
        let string_data = "test\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<u8>>();
        let parsed = parse_registry_value(REG_SZ, &string_data);
        assert_eq!(parsed, "test");
    }
}
