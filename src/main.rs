use anyhow::Result;
use clap::Parser;
use log::{error, info};
use serde_json;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

mod collectors;
mod types;
mod utils;
mod output;
mod detect;

use types::{SystemArtifacts, Finding, TimelineEvent};
use collectors::*;
use detect::engine::DetectionEngine;
use rayon::prelude::*;

#[derive(Parser)]
#[command(name = "forensic-agent")]
#[command(about = "Advanced Windows Forensic Collection Agent")]
struct Args {
    #[arg(short, long, default_value = "forensic-collect")]
    output: PathBuf,
    
    #[arg(long, help = "Enable debug logging")]
    debug: bool,
    
    #[arg(long, help = "Perform only rapid snapshot collection")]
    snapshot: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Initialize logging
    let log_level = if args.debug { 
        log::LevelFilter::Debug 
    } else { 
        log::LevelFilter::Info 
    };
    
    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .init();

    info!("🚀 Starting Windows Forensic Agent v0.1.0");
    let start_time = Instant::now();
    
    // Create output directory
    fs::create_dir_all(&args.output)?;
    
    let artifacts = if args.snapshot {
        collect_snapshot(&args)?
    } else {
        collect_artifacts(&args)?
    };
    
    write_single_report(&args.output, &artifacts)?;
    
    let duration = start_time.elapsed();
    info!("✅ Collection completed in {:.2}s", duration.as_secs_f64());
    
    Ok(())
}

fn collect_artifacts(_args: &Args) -> Result<SystemArtifacts> {
    let mut artifacts = SystemArtifacts::default();
    
    info!("Starting comprehensive forensic collection...");
    
    // Collect services
    match services::collect() {
        Ok(services_data) => artifacts.services = services_data,
        Err(e) => error!("Services collection failed: {}", e),
    }
    
    // Collect registry
    match registry::collect() {
        Ok(registry_data) => artifacts.registry_entries = registry_data,
        Err(e) => error!("Registry collection failed: {}", e),
    }
    
    // Collect processes
    match processes::collect() {
        Ok((processes_data, anomalies_data)) => {
            artifacts.processes = processes_data;
            artifacts.process_anomalies = anomalies_data;
        }
        Err(e) => error!("Processes collection failed: {}", e),
    }
    
    // Continue with other collectors
    collect_remaining_artifacts(&mut artifacts)?;
    
    // Stage 2: Run threat detection
    let detection_engine = DetectionEngine::new();
    match detection_engine.analyze(&artifacts) {
        Ok(findings) => {
            info!("Threat detection completed: {} findings", findings.len());
            write_findings_report(&findings)?;
        }
        Err(e) => error!("Threat detection failed: {}", e),
    }
    
    // Stage 3: Generate unified timeline
    generate_timeline(&mut artifacts);
    
    Ok(artifacts)
}

/// Generate unified timeline from all collected artifacts
fn generate_timeline(artifacts: &mut SystemArtifacts) {
    info!("Generating unified timeline...");
    let mut timeline = Vec::new();
    
    // Add process events to timeline
    for process in &artifacts.processes {
        timeline.push(TimelineEvent {
            timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(), // Placeholder
            source: "Process".to_string(),
            event_type: "Process Started".to_string(),
            description: format!("{} (PID {})", process.name, process.pid),
            details: Some(process.command_line.clone()),
            severity: None,
        });
    }
    
    // Add scheduled task events to timeline
    for task in &artifacts.scheduled_tasks {
        if let Some(last_run) = &task.last_run {
            timeline.push(TimelineEvent {
                timestamp: last_run.clone(),
                source: "Task".to_string(),
                event_type: "Task Executed".to_string(),
                description: task.name.clone(),
                details: Some(format!("Author: {}", task.author.as_ref().unwrap_or(&"Unknown".to_string()))),
                severity: if task.hidden { Some(crate::types::Severity::Medium) } else { None },
            });
        }
    }
    
    // Add file events to timeline
    for file in &artifacts.file_artifacts {
        if let Some(created) = &file.created {
            timeline.push(TimelineEvent {
                timestamp: created.clone(),
                source: "Filesystem".to_string(),
                event_type: "File Created".to_string(),
                description: file.path.clone(),
                details: Some(format!("Size: {} bytes, SHA256: {}", file.size, file.sha256)),
                severity: match file.signature_status {
                    crate::types::SignatureStatus::Untrusted => Some(crate::types::Severity::Low),
                    _ => None,
                },
            });
        }
    }
    
    // Sort timeline by timestamp
    timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    
    artifacts.timeline_events = timeline;
    info!("Generated timeline with {} events", artifacts.timeline_events.len());
}

fn collect_remaining_artifacts(artifacts: &mut SystemArtifacts) -> Result<()> {
    // Collect scheduled tasks
    match tasks::collect() {
        Ok(tasks_data) => artifacts.scheduled_tasks = tasks_data,
        Err(e) => error!("Tasks collection failed: {}", e),
    }
    
    // Collect WMI subscriptions
    match wmi_subs::collect() {
        Ok((filters, consumers, bindings)) => {
            artifacts.wmi_filters = filters;
            artifacts.wmi_consumers = consumers;
            artifacts.wmi_bindings = bindings;
        }
        Err(e) => error!("WMI subscriptions collection failed: {}", e),
    }
    
    // Collect network information
    match network::collect() {
        Ok((network_data, proxy_config, winsock_providers)) => {
            artifacts.network_connections = network_data;
            artifacts.proxy_config = proxy_config;
            artifacts.winsock_providers = winsock_providers;
        }
        Err(e) => error!("Network collection failed: {}", e),
    }
    
    // Collect certificates
    match certificates::collect() {
        Ok(certs_data) => artifacts.certificates = certs_data,
        Err(e) => error!("Certificates collection failed: {}", e),
    }
    
    // Collect files with enhanced signature verification  
    match collectors::files::collect() {
        Ok(files_data) => artifacts.file_artifacts = files_data,
        Err(e) => error!("Files collection failed: {}", e),
    }
    
    // Collect events (placeholder for now)
    match events::collect() {
        Ok(_) => {}, // events collector currently returns () not data
        Err(e) => error!("Events collection failed: {}", e),
    }
    
    // Collect browsers
    match browsers::collect() {
        Ok((extensions, settings, downloads)) => {
            artifacts.browser_extensions = extensions;
            artifacts.browser_settings = settings;
            artifacts.browser_downloads = downloads;
        }
        Err(e) => error!("Browsers collection failed: {}", e),
    }
    
    // Collect crypto theft artifacts
    match crypto_theft::collect() {
        Ok((theft_artifacts, wallet_files, session_files)) => {
            artifacts.crypto_theft_artifacts = theft_artifacts;
            artifacts.wallet_files = wallet_files;
            artifacts.session_files = session_files;
        }
        Err(e) => error!("Crypto theft collection failed: {}", e),
    }
    
    Ok(())
}

fn write_findings_report(findings: &[Finding]) -> Result<()> {
    info!("Writing threat detection findings...");
    let findings_json = serde_json::to_string_pretty(findings)?;
    fs::write("forensic-collect/findings.json", findings_json)?;
    Ok(())
}

fn collect_snapshot(_args: &Args) -> Result<SystemArtifacts> {
    let mut artifacts = SystemArtifacts::default();
    
    info!("Starting rapid snapshot collection...");
    
    // Rapid collection - only essential data
    if let Ok(services_data) = services::collect() {
        artifacts.services = services_data;
    }
    
    if let Ok((network_data, _, _)) = network::collect() {
        artifacts.network_connections = network_data;
    }
    
    if let Ok((processes_data, anomalies_data)) = processes::collect() {
        artifacts.processes = processes_data;
        artifacts.process_anomalies = anomalies_data;
    }
    
    Ok(artifacts)
}

fn write_single_report(output_dir: &PathBuf, artifacts: &SystemArtifacts) -> Result<()> {
    // Write JSON report
    let json_output = serde_json::to_string_pretty(artifacts)?;
    let json_file = output_dir.join("reconnaissance.json");
    fs::write(&json_file, json_output)?;
    
    // Stage 3: Write Markdown report (Perfect Report)
    let markdown_output = generate_markdown_report(artifacts)?;
    let markdown_file = output_dir.join("system_snapshot.md");
    fs::write(&markdown_file, markdown_output)?;
    
    info!("✅ JSON report written to: {}", json_file.display());
    info!("✅ Markdown report written to: {}", markdown_file.display());
    Ok(())
}

/// Generate comprehensive Markdown report
fn generate_markdown_report(artifacts: &SystemArtifacts) -> Result<String> {
    let mut report = String::new();
    
    // Header
    report.push_str(&format!("# Forensic Snapshot: {} ({})\n\n", 
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".to_string()),
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
    ));
    
    // Suspicious Indicators section (most important first)
    report.push_str("## 🚨 Suspicious Indicators\n\n");
    if artifacts.processes.iter().any(|p| crate::detect::rules::find_telegram_c2(&p.command_line)) {
        report.push_str("* **CRITICAL:** Potential Telegram C2 communication detected in process command lines\n");
    }
    if artifacts.scheduled_tasks.iter().any(|t| t.hidden) {
        report.push_str("* **HIGH:** Hidden scheduled tasks detected\n");
    }
    report.push_str("\n");
    
    // Unified Timeline section
    report.push_str("## 📊 Unified Timeline\n\n");
    report.push_str("| Timestamp | Source | Event | Description | Details |\n");
    report.push_str("|-----------|--------|-------|-------------|----------|\n");
    
    for event in artifacts.timeline_events.iter().take(20) { // Show top 20 events
        let severity_marker = match &event.severity {
            Some(crate::types::Severity::Critical) => "🔴",
            Some(crate::types::Severity::High) => "🟠", 
            Some(crate::types::Severity::Medium) => "🟡",
            _ => "⚪",
        };
        
        report.push_str(&format!("| {} | {} {} | {} | {} | {} |\n",
            event.timestamp,
            severity_marker,
            event.source,
            event.event_type,
            event.description,
            event.details.as_ref().unwrap_or(&"".to_string())
        ));
    }
    report.push_str("\n");
    
    // Collected Artifacts section
    report.push_str("## 🔍 Collected Artifacts\n\n");
    
    // Services
    report.push_str("### Services\n\n");
    report.push_str("| Name | State | Path | Account |\n");
    report.push_str("|------|-------|------|---------|\n");
    for service in artifacts.services.iter().take(10) {
        report.push_str(&format!("| {} | {} | {} | {} |\n",
            service.name,
            service.current_state,
            service.binary_path,
            service.service_account
        ));
    }
    report.push_str("\n");
    
    // Processes
    report.push_str("### Processes\n\n");
    report.push_str("| PID | Name | User | Command Line |\n");
    report.push_str("|-----|------|------|-------------|\n");
    for process in artifacts.processes.iter().take(15) {
        let cmd_short = if process.command_line.len() > 50 {
            format!("{}...", &process.command_line[..50])
        } else {
            process.command_line.clone()
        };
        report.push_str(&format!("| {} | {} | {} | `{}` |\n",
            process.pid,
            process.name,
            process.user.as_ref().unwrap_or(&"Unknown".to_string()),
            cmd_short.replace("|", "\\|")
        ));
    }
    report.push_str("\n");
    
    // Registry Entries
    if !artifacts.registry_entries.is_empty() {
        report.push_str("### Registry Entries\n\n");
        report.push_str("| Key Path | Value Name | Value Data |\n");
        report.push_str("|----------|------------|------------|\n");
        for entry in artifacts.registry_entries.iter().take(10) {
            report.push_str(&format!("| {} | {} | {} |\n",
                entry.key_path.replace("|", "\\|"),
                entry.value_name,
                entry.value_data.replace("|", "\\|")
            ));
        }
        report.push_str("\n");
    }
    
    // Statistics
    report.push_str("## 📈 Collection Statistics\n\n");
    report.push_str(&format!("* **Services:** {}\n", artifacts.services.len()));
    report.push_str(&format!("* **Processes:** {}\n", artifacts.processes.len()));
    report.push_str(&format!("* **Registry Entries:** {}\n", artifacts.registry_entries.len()));
    report.push_str(&format!("* **Scheduled Tasks:** {}\n", artifacts.scheduled_tasks.len()));
    report.push_str(&format!("* **Network Connections:** {}\n", artifacts.network_connections.len()));
    report.push_str(&format!("* **Timeline Events:** {}\n", artifacts.timeline_events.len()));
    report.push_str("\n");
    
    report.push_str("---\n");
    report.push_str("*Report generated by Windows Forensic Agent v0.1.0*\n");
    
    Ok(report)
}
