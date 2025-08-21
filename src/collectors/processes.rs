use anyhow::Result;
use log::{debug, warn};
use std::process::Command;
use regex::Regex;
use crate::types::{ProcessInfo, ProcessAnomaly, SignatureStatus, TimelineEvent, Severity};

pub fn collect() -> Result<(Vec<ProcessInfo>, Vec<ProcessAnomaly>)> {
    debug!("Starting process collection via PowerShell");
    
    let powershell_script = r#"
    Get-WmiObject -Class Win32_Process | ForEach-Object {
        $process = $_
        $owner = $null
        $domain = $null
        $process.GetOwner([ref]$domain, [ref]$owner) | Out-Null
        
        $creationDate = "Unknown"
        if ($process.CreationDate) {
            $creationDate = ([WMI]"").ConvertToDateTime($process.CreationDate).ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
        
        $processObj = @{
            ProcessId = $process.ProcessId
            Name = $process.Name
            ExecutablePath = if ($process.ExecutablePath) { $process.ExecutablePath } else { "Unknown" }
            CommandLine = if ($process.CommandLine) { $process.CommandLine } else { "" }
            ParentProcessId = if ($process.ParentProcessId) { $process.ParentProcessId } else { 0 }
            Owner = if ($owner) { "$domain\$owner" } else { "Unknown" }
            CreationDate = $creationDate
            SessionId = if ($process.SessionId) { $process.SessionId } else { 0 }
            WorkingSetSize = if ($process.WorkingSetSize) { $process.WorkingSetSize } else { 0 }
            PageFileUsage = if ($process.PageFileUsage) { $process.PageFileUsage } else { 0 }
        }
        
        $processObj | ConvertTo-Json -Compress
    }
    "#;
    
    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", powershell_script])
        .output()?;
    
    if !output.status.success() {
        return Err(anyhow::anyhow!("PowerShell command failed: {}", 
            String::from_utf8_lossy(&output.stderr)));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut processes = Vec::new();
    let mut anomalies = Vec::new();
    
    // Parse JSON output line by line
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(process_data) => {
                if let Some(process) = parse_process_data(&process_data) {
                    // Detect anomalies for this process
                    let mut process_anomalies = detect_process_anomalies(&process);
                    anomalies.append(&mut process_anomalies);
                    
                    processes.push(process);
                }
            }
            Err(e) => {
                warn!("Failed to parse process JSON: {}", e);
            }
        }
    }
    
    debug!("Collected {} processes, {} anomalies", processes.len(), anomalies.len());
    Ok((processes, anomalies))
}

pub fn collect_with_timeline() -> Result<(Vec<ProcessInfo>, Vec<ProcessAnomaly>, Vec<TimelineEvent>)> {
    let (processes, anomalies) = collect()?;
    let mut timeline_events = Vec::new();
    
    // Generate timeline events for processes
    for process in &processes {
        if process.creation_time != "Unknown" && !process.creation_time.is_empty() {
            let event = TimelineEvent::new(
                process.creation_time.clone(),
                "Process Created".to_string(),
                "Process Collector".to_string(),
                format!("Process '{}' started", process.name),
                format!("PID {}: {} started with command line: {}", 
                    process.pid, process.name, process.command_line),
            )
            .with_process(process.pid, process.name.clone())
            .with_file(process.executable_path.clone())
            .with_user(process.user.clone().unwrap_or_else(|| "Unknown".to_string()));
            
            timeline_events.push(event);
        }
    }
    
    // Generate timeline events for anomalies
    for anomaly in &anomalies {
        let event = TimelineEvent::new(
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "Process Anomaly Detected".to_string(),
            "Process Collector".to_string(),
            format!("Anomaly: {}", anomaly.anomaly_type),
            anomaly.description.clone(),
        )
        .with_process(anomaly.pid, "Unknown".to_string())
        .with_severity(match anomaly.severity.as_str() {
            "High" => Severity::High,
            "Critical" => Severity::Critical,
            "Medium" => Severity::Medium,
            _ => Severity::Low,
        })
        .add_data("anomaly_type".to_string(), anomaly.anomaly_type.clone());
        
        timeline_events.push(event);
    }
    
    debug!("Generated {} timeline events for processes", timeline_events.len());
    Ok((processes, anomalies, timeline_events))
}

fn parse_process_data(data: &serde_json::Value) -> Option<ProcessInfo> {
    let pid = data.get("ProcessId")?.as_u64()? as u32;
    let name = data.get("Name")?.as_str()?.to_string();
    let executable_path = data.get("ExecutablePath")?.as_str().unwrap_or("Unknown").to_string();
    let command_line = data.get("CommandLine")?.as_str().unwrap_or("").to_string();
    let parent_pid = data.get("ParentProcessId")?.as_u64().unwrap_or(0) as u32;
    let owner = data.get("Owner")?.as_str().unwrap_or("Unknown").to_string();
    let creation_time = data.get("CreationDate")?.as_str().unwrap_or("Unknown").to_string();
    let session_id = data.get("SessionId")?.as_u64().unwrap_or(0) as u32;
    let working_set_size = data.get("WorkingSetSize")?.as_u64().unwrap_or(0);
    let page_file_usage = data.get("PageFileUsage")?.as_u64().unwrap_or(0);
    
    // Simplified signature status detection
    let signature_status = if executable_path.contains("System32") 
        || executable_path.contains("Program Files") {
        SignatureStatus::Trusted
    } else {
        SignatureStatus::Unknown
    };
    
    Some(ProcessInfo {
        pid,
        parent_pid: Some(parent_pid),
        name,
        executable_path,
        command_line,
        user: Some(owner),
        cpu_usage: 0.0,
        memory_usage: working_set_size,
        signature_status,
        creation_time,
        session_id,
        working_set_size,
        page_file_usage,
        cpu_time: 0, // Not available via WMI easily
        handle_count: 0, // Not available via WMI easily
        thread_count: 0, // Not available via WMI easily
    })
}

fn detect_process_anomalies(process: &ProcessInfo) -> Vec<ProcessAnomaly> {
    let mut anomalies = Vec::new();
    
    // Check for suspicious executable locations
    let suspicious_paths = [
        "AppData",
        "Temp", 
        "Users\\Public",
        "ProgramData",
    ];
    
    for suspicious_path in &suspicious_paths {
        if process.executable_path.contains(suspicious_path) {
            anomalies.push(ProcessAnomaly {
                pid: process.pid,
                anomaly_type: "SuspiciousLocation".to_string(),
                description: format!("Process executable in suspicious location: {}", suspicious_path),
                severity: "High".to_string(),
            });
        }
    }
    
    // Check for LOLBAS (Living Off The Land Binaries and Scripts) abuse patterns
    let lolbas_patterns = [
        (r"powershell.*-enc", "PowerShell encoded command"),
        (r"powershell.*-nop", "PowerShell no profile"),
        (r"powershell.*-w\s+hidden", "PowerShell hidden window"),
        (r"mshta.*http", "MSHTA with HTTP URL"),
        (r"rundll32.*#1", "Rundll32 suspicious export"),
        (r"regsvr32.*/s.*http", "Regsvr32 silent with HTTP"),
        (r"wmic.*process.*call.*create", "WMIC process creation"),
        (r"certutil.*-urlcache", "Certutil download"),
    ];
    
    for (pattern, description) in &lolbas_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(&process.command_line.to_lowercase()) {
                anomalies.push(ProcessAnomaly {
                    pid: process.pid,
                    anomaly_type: "LOLBAS".to_string(),
                    description: description.to_string(),
                    severity: "High".to_string(),
                });
            }
        }
    }
    
    // Check for unsigned executables in user directories
    if matches!(process.signature_status, SignatureStatus::Untrusted) 
        && (process.executable_path.contains("Users\\") 
            || process.executable_path.contains("AppData")) {
        anomalies.push(ProcessAnomaly {
            pid: process.pid,
            anomaly_type: "UnsignedUserDir".to_string(),
            description: "Unsigned executable in user directory".to_string(),
            severity: "Medium".to_string(),
        });
    }
    
    // Check for unusually long command lines with base64
    if process.command_line.len() > 500 
        && (process.command_line.contains("base64") 
            || process.command_line.chars().filter(|c| c.is_ascii_alphanumeric()).count() as f32 / process.command_line.len() as f32 > 0.8) {
        anomalies.push(ProcessAnomaly {
            pid: process.pid,
            anomaly_type: "SuspiciousCommandLine".to_string(),
            description: "Long command line with potential base64 encoding".to_string(),
            severity: "Medium".to_string(),
        });
    }
    
    anomalies
}
