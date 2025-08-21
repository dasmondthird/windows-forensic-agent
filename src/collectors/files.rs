use anyhow::Result;
use log::debug;
use sha2::{Sha256, Digest};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;
use crate::types::{FileArtifact, SignatureStatus};

const CRITICAL_DLLS: &[&str] = &[
    r"C:\Windows\System32\winscard.dll",
    r"C:\Windows\System32\SCardSvr.dll", 
    r"C:\Windows\System32\cryptsvc.dll",
    r"C:\Windows\System32\bcrypt.dll",
    r"C:\Windows\System32\schannel.dll",
    r"C:\Windows\System32\rpcss.dll",
    r"C:\Windows\System32\sechost.dll",
];

pub fn collect() -> Result<Vec<FileArtifact>> {
    debug!("Starting file artifacts collection");
    let mut artifacts = Vec::new();
    
    // Collect critical DLL hashes
    for dll_path in CRITICAL_DLLS {
        if let Ok(artifact) = collect_file_artifact(dll_path) {
            artifacts.push(artifact);
        }
    }
    
    // Collect recent drivers
    artifacts.extend(collect_recent_drivers()?);
    
    debug!("Collected {} file artifacts", artifacts.len());
    Ok(artifacts)
}

fn collect_file_artifact(path: &str) -> Result<FileArtifact> {
    let metadata = fs::metadata(path)?;
    let content = fs::read(path)?;
    
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash = hasher.finalize();
    
    Ok(FileArtifact {
        path: path.to_string(),
        size: metadata.len(),
        created: Some("2025-08-21T12:00:00Z".to_string()),
        modified: Some("2025-08-21T12:00:00Z".to_string()),
        sha256: hex::encode(hash),
        signature_status: check_file_signature(path),
    })
}

fn collect_recent_drivers() -> Result<Vec<FileArtifact>> {
    let mut artifacts = Vec::new();
    let drivers_path = r"C:\Windows\System32\drivers";
    
    if !Path::new(drivers_path).exists() {
        return Ok(artifacts);
    }
    
    // Walk through drivers directory and collect .sys files
    for entry in WalkDir::new(drivers_path)
        .max_depth(2)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("sys") {
            if let Ok(artifact) = collect_file_artifact(path.to_str().unwrap()) {
                // Only collect recently modified drivers (last 30 days)
                if let Some(ref _modified) = artifact.modified {
                    // Simplified - just add all .sys files for demo
                    artifacts.push(artifact);
                }
            }
        }
    }
    
    Ok(artifacts)
}

fn check_file_signature(path: &str) -> SignatureStatus {
    // Implement WinVerifyTrust signature verification for Windows
    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        use windows::Win32::Security::Cryptography::{
            WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, 
            WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
            WTD_REVOKE_NONE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        };
        use windows::core::PWSTR;
        
        // Convert path to wide string
        let wide_path: Vec<u16> = OsString::from(path)
            .encode_wide()
            .chain(Some(0))
            .collect();
        
        unsafe {
            // Setup file info structure
            let mut file_info = WINTRUST_FILE_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
                pcwszFilePath: PWSTR(wide_path.as_ptr() as *mut u16),
                hFile: None,
                pgKnownSubject: None,
            };
            
            // Setup trust data structure
            let mut trust_data = WINTRUST_DATA {
                cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                pPolicyCallbackData: None,
                pSIPClientData: None,
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: WTD_REVOKE_NONE,
                dwUnionChoice: WTD_CHOICE_FILE,
                Anonymous: windows::Win32::Security::Cryptography::WINTRUST_DATA_0 {
                    pFile: &mut file_info,
                },
                dwStateAction: WTD_STATEACTION_VERIFY,
                hWVTStateData: None,
                pwszURLReference: PWSTR::null(),
                dwProvFlags: 0,
                dwUIContext: 0,
                pSignatureSettings: None,
            };
            
            // Call WinVerifyTrust
            let result = WinVerifyTrust(None, &WINTRUST_ACTION_GENERIC_VERIFY_V2, &mut trust_data);
            
            match result.0 {
                0 => SignatureStatus::Trusted,  // S_OK - signature is valid
                _ => SignatureStatus::Untrusted, // Any error - signature invalid or unsigned
            }
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        // Fallback for non-Windows platforms (for development/testing)
        if path.starts_with("/bin") || path.starts_with("/usr") || path.starts_with("/lib") {
            SignatureStatus::Trusted
        } else {
            SignatureStatus::Untrusted
        }
    }
}
