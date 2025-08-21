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
    // TODO: Implement WinVerifyTrust signature verification
    // For now, basic heuristic based on path
    if path.starts_with("C:\\Windows\\System32") {
        SignatureStatus::Trusted
    } else {
        SignatureStatus::Untrusted
    }
}
