use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next,
    PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::ProcessStatus::{
    GetModuleFileNameExW, GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

use crate::types::{ProcessInfo, ProcessAnomaly};

/// Collect process information using direct WinAPI calls
/// This is much faster and stealthier than PowerShell commands
pub fn collect() -> Result<(Vec<ProcessInfo>, Vec<ProcessAnomaly>)> {
    log::info!("Starting WinAPI process collection...");
    
    let mut processes = Vec::new();
    let mut anomalies = Vec::new();
    
    unsafe {
        // Create snapshot of all processes
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| anyhow::anyhow!("Failed to create process snapshot: {}", e))?;
        
        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };
        
        // Get first process
        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                if let Ok(process_info) = collect_process_details(&entry) {
                    // Check for anomalies
                    if let Some(anomaly) = detect_process_anomaly(&process_info) {
                        anomalies.push(anomaly);
                    }
                    
                    processes.push(process_info);
                }
                
                // Get next process
                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        
        CloseHandle(snapshot);
    }
    
    log::info!("Collected {} processes with {} anomalies", processes.len(), anomalies.len());
    Ok((processes, anomalies))
}

/// Collect detailed information for a single process
unsafe fn collect_process_details(entry: &PROCESSENTRY32) -> Result<ProcessInfo> {
    let name = extract_process_name(&entry.szExeFile);
    let pid = entry.th32ProcessID;
    
    // Try to open process for additional info
    let mut full_path = String::new();
    let mut memory_usage = 0;
    let mut handle_count = 0;
    
    if let Ok(process_handle) = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        false,
        pid,
    ) {
        // Get full executable path
        full_path = get_process_path(process_handle);
        
        // Get memory information
        let mut mem_counters = PROCESS_MEMORY_COUNTERS::default();
        if GetProcessMemoryInfo(
            process_handle,
            &mut mem_counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ).is_ok() {
            memory_usage = mem_counters.WorkingSetSize as u64;
        }
        
        CloseHandle(process_handle);
    }
    
    Ok(ProcessInfo {
        pid,
        name,
        path: full_path,
        parent_pid: entry.th32ParentProcessID,
        thread_count: entry.cntThreads,
        memory_usage,
        handle_count,
        start_time: chrono::Utc::now(), // TODO: Get real start time
        command_line: String::new(), // TODO: Get command line
        user: String::new(), // TODO: Get process owner
        integrity_level: String::new(), // TODO: Get integrity level
        is_wow64: false, // TODO: Detect WoW64
    })
}

/// Extract process name from the raw array
fn extract_process_name(raw_name: &[u16; 260]) -> String {
    // Find null terminator
    let len = raw_name.iter().position(|&c| c == 0).unwrap_or(raw_name.len());
    
    // Convert to string
    String::from_utf16_lossy(&raw_name[..len])
}

/// Get full path to process executable
unsafe fn get_process_path(process_handle: HANDLE) -> String {
    let mut path_buffer = [0u16; 1024];
    
    if GetModuleFileNameExW(
        process_handle,
        None,
        &mut path_buffer,
    ) > 0 {
        // Find null terminator
        let len = path_buffer.iter().position(|&c| c == 0).unwrap_or(path_buffer.len());
        String::from_utf16_lossy(&path_buffer[..len])
    } else {
        String::new()
    }
}

/// Detect suspicious process behavior
fn detect_process_anomaly(process: &ProcessInfo) -> Option<ProcessAnomaly> {
    // Check for processes with suspicious names
    let suspicious_names = [
        "cmd.exe", "powershell.exe", "pwsh.exe", "wmic.exe",
        "net.exe", "netsh.exe", "sc.exe", "tasklist.exe",
        "reg.exe", "regedit.exe", "certutil.exe", "bitsadmin.exe"
    ];
    
    if suspicious_names.contains(&process.name.to_lowercase().as_str()) {
        return Some(ProcessAnomaly {
            pid: process.pid,
            name: process.name.clone(),
            anomaly_type: "SuspiciousExecutable".to_string(),
            description: format!("Potentially suspicious executable: {}", process.name),
            severity: "Medium".to_string(),
        });
    }
    
    // Check for processes with unusual paths
    if !process.path.is_empty() {
        if process.path.to_lowercase().contains("temp") ||
           process.path.to_lowercase().contains("appdata") ||
           process.path.to_lowercase().contains("users\\public") {
            return Some(ProcessAnomaly {
                pid: process.pid,
                name: process.name.clone(),
                anomaly_type: "SuspiciousLocation".to_string(),
                description: format!("Process running from suspicious location: {}", process.path),
                severity: "High".to_string(),
            });
        }
    }
    
    // Check for high memory usage
    if process.memory_usage > 500 * 1024 * 1024 { // 500MB
        return Some(ProcessAnomaly {
            pid: process.pid,
            name: process.name.clone(),
            anomaly_type: "HighMemoryUsage".to_string(),
            description: format!("High memory usage: {} MB", process.memory_usage / (1024 * 1024)),
            severity: "Low".to_string(),
        });
    }
    
    None
}

/// Advanced process analysis using WinAPI
pub fn analyze_process_behavior(pid: u32) -> Result<HashMap<String, serde_json::Value>> {
    let mut analysis = HashMap::new();
    
    unsafe {
        if let Ok(process_handle) = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        ) {
            // Memory analysis
            let mut mem_counters = PROCESS_MEMORY_COUNTERS::default();
            if GetProcessMemoryInfo(
                process_handle,
                &mut mem_counters,
                std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ).is_ok() {
                analysis.insert("working_set_size".to_string(), 
                    serde_json::Value::Number((mem_counters.WorkingSetSize as u64).into()));
                analysis.insert("peak_working_set_size".to_string(), 
                    serde_json::Value::Number((mem_counters.PeakWorkingSetSize as u64).into()));
                analysis.insert("pagefile_usage".to_string(), 
                    serde_json::Value::Number((mem_counters.PagefileUsage as u64).into()));
            }
            
            CloseHandle(process_handle);
        }
    }
    
    Ok(analysis)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_process_collection() {
        let result = collect();
        assert!(result.is_ok());
        
        let (processes, _) = result.unwrap();
        assert!(!processes.is_empty());
        
        // Should find at least our own process
        assert!(processes.iter().any(|p| p.name.to_lowercase() == "forensic-agent.exe"));
    }
    
    #[test]
    fn test_anomaly_detection() {
        let suspicious_process = ProcessInfo {
            pid: 1234,
            name: "cmd.exe".to_string(),
            path: "C:\\Users\\Public\\cmd.exe".to_string(),
            parent_pid: 4567,
            thread_count: 1,
            memory_usage: 0,
            handle_count: 0,
            start_time: chrono::Utc::now(),
            command_line: String::new(),
            user: String::new(),
            integrity_level: String::new(),
            is_wow64: false,
        };
        
        let anomaly = detect_process_anomaly(&suspicious_process);
        assert!(anomaly.is_some());
        assert_eq!(anomaly.unwrap().anomaly_type, "SuspiciousLocation");
    }
}
