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

use types::SystemArtifacts;
use collectors::*;

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

fn collect_artifacts(args: &Args) -> Result<SystemArtifacts> {
    let mut artifacts = SystemArtifacts::default();
    
    info!("Starting comprehensive forensic collection...");
    
    // Collect services
    match services::collect() {
        Ok(services_data) => artifacts.services = services_data,
        Err(e) => error!("Services collection failed: {}", e),
    }
    
    // Collect registry data
    match registry::collect() {
        Ok(registry_data) => artifacts.registry_entries = registry_data,
        Err(e) => error!("Registry collection failed: {}", e),
    }
    
    // Collect scheduled tasks
    match tasks::collect() {
        Ok(tasks_data) => artifacts.scheduled_tasks = tasks_data,
        Err(e) => error!("Tasks collection failed: {}", e),
    }
    
    // Collect WMI subscriptions
    match wmi_subs::collect() {
        Ok((filters, consumers)) => {
            artifacts.wmi_filters = filters;
            artifacts.wmi_consumers = consumers;
        }
        Err(e) => error!("WMI subscriptions collection failed: {}", e),
    }
    
    // Collect network information
    match network::collect() {
        Ok(network_data) => artifacts.network_connections = network_data,
        Err(e) => error!("Network collection failed: {}", e),
    }
    
    // Collect certificates
    match certificates::collect() {
        Ok(certs_data) => artifacts.certificates = certs_data,
        Err(e) => error!("Certificates collection failed: {}", e),
    }
    
    // Collect files
    match files::collect() {
        Ok(files_data) => artifacts.interesting_files = files_data,
        Err(e) => error!("Files collection failed: {}", e),
    }
    
    // Collect processes
    match processes::collect() {
        Ok((processes_data, anomalies_data)) => {
            artifacts.processes = processes_data;
            artifacts.process_anomalies = anomalies_data;
        }
        Err(e) => error!("Processes collection failed: {}", e),
    }
    
    // Collect events
    match events::collect() {
        Ok(events_data) => artifacts.security_events = events_data,
        Err(e) => error!("Events collection failed: {}", e),
    }
    
    // Collect browsers
    match browsers::collect() {
        Ok((history, credentials, downloads, addons)) => {
            artifacts.browser_history = history;
            artifacts.browser_credentials = credentials;
            artifacts.browser_downloads = downloads;
            artifacts.browser_addons = addons;
        }
        Err(e) => error!("Browsers collection failed: {}", e),
    }
    
    // Collect crypto theft artifacts
    match crypto_theft::collect() {
        Ok((wallet_files, session_files)) => {
            artifacts.wallet_files = wallet_files;
            artifacts.session_files = session_files;
        }
        Err(e) => error!("Crypto theft collection failed: {}", e),
    }
    
    Ok(artifacts)
}

fn collect_snapshot(_args: &Args) -> Result<SystemArtifacts> {
    let mut artifacts = SystemArtifacts::default();
    
    info!("Starting rapid snapshot collection...");
    
    // Rapid collection - only essential data
    if let Ok(services_data) = services::collect() {
        artifacts.services = services_data;
    }
    
    if let Ok(network_data) = network::collect() {
        artifacts.network_connections = network_data;
    }
    
    if let Ok((processes_data, anomalies_data)) = processes::collect() {
        artifacts.processes = processes_data;
        artifacts.process_anomalies = anomalies_data;
    }
    
    Ok(artifacts)
}

fn write_single_report(output_dir: &PathBuf, artifacts: &SystemArtifacts) -> Result<()> {
    let json_output = serde_json::to_string_pretty(artifacts)?;
    let json_file = output_dir.join("reconnaissance.json");
    fs::write(&json_file, json_output)?;
    
    info!("✅ Report written to: {}", json_file.display());
    Ok(())
}
