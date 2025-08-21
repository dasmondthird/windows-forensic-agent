use anyhow::Result;
use clap::Parser;
use log::{error, info, warn};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

mod collectors;
mod detect;
mod output;
mod types;

use crate::collectors::*;
use output::OutputManager;
use types::*;

#[derive(Parser)]
#[command(name = "forensic-agent")]
#[command(about = "Windows forensic agent for system reconnaissance")]
struct Args {
    /// Skip event log collection
    #[arg(long)]
    no_events: bool,

    /// Skip certificate collection  
    #[arg(long)]
    no_certs: bool,

    /// Fast collection mode (skip some heavy operations)
    #[arg(long)]
    fast: bool,

    /// Create ZIP archive of results
    #[arg(long)]
    zip: bool,

    /// Snapshot mode - collect data only, text format
    #[arg(long)]
    snapshot_only: bool,

    /// Output directory
    #[arg(short, long, default_value = "forensic-collect")]
    output: PathBuf,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    
    info!("Starting forensic agent collection...");
    let start_time = Instant::now();
    
    // Use output directory directly without timestamp subfolder
    let output_dir = args.output.clone();
    fs::create_dir_all(&output_dir)?;
    
    // Collect artifacts in parallel
    info!("Collecting system artifacts...");
    
    let artifacts = collect_artifacts(&args)?;
    
    if args.snapshot_only {
        // Snapshot mode - write simple text report
        write_snapshot_report(&output_dir, &artifacts)?;
    } else {
        // Full mode - write everything to single JSON file (no threat analysis)
        write_single_report(&output_dir, &artifacts)?;
    }
    
    let duration = start_time.elapsed();
    info!("Collection completed in {:.2}s", duration.as_secs_f64());
    
    // Create ZIP if requested
    if args.zip && !args.snapshot_only {
        #[cfg(feature = "zip-output")]
        {
            info!("Creating ZIP archive...");
            output_manager.create_zip()?;
        }
        #[cfg(not(feature = "zip-output"))]
        {
            warn!("ZIP feature not enabled in build");
        }
    }
    
    if args.snapshot_only {
        println!("System snapshot completed successfully!");
        println!("Report file: {}", output_dir.join("system_snapshot.txt").display());
        println!("Duration: {:.2}s", duration.as_secs_f64());
        println!("Mode: Pure reconnaissance (no threat analysis)");
    } else {
        println!("Reconnaissance completed successfully!");
        println!("Report file: {}", output_dir.join("reconnaissance.json").display());
        println!("Duration: {:.2}s", duration.as_secs_f64());
        println!("Mode: Pure data collection (no analysis)");
    }
    
    Ok(())
}

fn collect_artifacts(args: &Args) -> Result<SystemArtifacts> {
    let mut artifacts = SystemArtifacts::default();
    
    // Extended system reconnaissance
    // println!("📊 Собираем пользователей и группы...");
    // let (users_list, groups_list, user_profiles) = collect_users().unwrap_or_default();
    // artifacts.users = users_list;
    // artifacts.groups = groups_list;
    // artifacts.user_profiles = user_profiles;
    
    println!("🌐 Собираем полную сетевую конфигурацию...");
    let (network_adapters, routes, arp_table, network_shares, wifi_profiles, network_connections) = collect_network_full().unwrap_or_default();
    artifacts.network_adapters = network_adapters;
    artifacts.network_routes = routes;
    artifacts.arp_table = arp_table;
    artifacts.network_shares = network_shares;
    artifacts.wifi_profiles = wifi_profiles;
    artifacts.extended_network_connections = network_connections;
    
    println!("💾 Собираем установленное ПО...");
    let (installed_software, msi_packages, store_apps) = collect_software().unwrap_or_default();
    artifacts.installed_software = installed_software;
    artifacts.msi_packages = msi_packages;
    artifacts.store_apps = store_apps;
    
    println!("🔧 Собираем переменные окружения...");
    let environment_variables = collect_environment().unwrap_or_default();
    artifacts.environment_variables = environment_variables;
    
    println!("🖥️ Собираем информацию о железе...");
    let (hardware_info, usb_devices, disk_devices, tpm_info, virtualization_info) = collect_hardware().unwrap_or_default();
    artifacts.hardware_info = hardware_info;
    artifacts.usb_devices = usb_devices;
    artifacts.disk_devices = disk_devices;
    // artifacts.tpm_info = tmp_info;
    artifacts.virtualization_info = virtualization_info;

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
        Ok((filters, consumers, bindings)) => {
            artifacts.wmi_filters = filters;
            artifacts.wmi_consumers = consumers;
            artifacts.wmi_bindings = bindings;
        }
        Err(e) => error!("WMI collection failed: {}", e),
    }
    
    // Collect network data
    match network::collect() {
        Ok((connections, proxy, providers)) => {
            artifacts.network_connections = connections;
            artifacts.proxy_config = proxy;
            artifacts.winsock_providers = providers;
        }
        Err(e) => error!("Network collection failed: {}", e),
    }
    
    // Collect file artifacts
    match files::collect() {
        Ok(files_data) => artifacts.file_artifacts = files_data,
        Err(e) => error!("Files collection failed: {}", e),
    }
    
    // Collect process data
    match processes::collect() {
        Ok((processes_data, anomalies)) => {
            artifacts.processes = processes_data;
            artifacts.process_anomalies = anomalies;
        }
        Err(e) => error!("Processes collection failed: {}", e),
    }
    
    // Collect certificates if not disabled
    if !args.no_certs {
        match certificates::collect() {
            Ok(certs_data) => artifacts.certificates = certs_data,
            Err(e) => error!("Certificate collection failed: {}", e),
        }
    }
    
    // Collect events if not disabled
    if !args.no_events {
        if let Err(e) = events::collect() {
            error!("Event collection failed: {}", e);
        }
    }

    // Collect browser data
    match browsers::collect() {
        Ok((extensions, settings, downloads)) => {
            artifacts.browser_extensions = extensions;
            artifacts.browser_settings = settings;
            artifacts.browser_downloads = downloads;
        }
        Err(e) => error!("Browser collection failed: {}", e),
    }

    // Collect crypto theft artifacts
    match crypto_theft::collect() {
        Ok((crypto_artifacts, wallet_files, session_files)) => {
            artifacts.crypto_theft_artifacts = crypto_artifacts;
            artifacts.wallet_files = wallet_files;
            artifacts.session_files = session_files;
        }
        Err(e) => error!("Crypto theft collection failed: {}", e),
    }

    // Collect users and groups
    info!("Collecting users and groups...");
    match users::collect() {
        Ok((users_data, groups_data, profiles_data)) => {
            artifacts.users = users_data;
            artifacts.groups = groups_data;
            artifacts.user_profiles = profiles_data;
            info!("Users collection completed successfully");
        }
        Err(e) => error!("Users collection failed: {}", e),
    }

    // Collect comprehensive network data
    info!("Collecting network data...");
    match network_full::collect() {
        Ok((adapters, routes, arp_entries, netbios_names, shares, wifi_profiles)) => {
            artifacts.network_adapters = adapters;
            artifacts.network_routes = routes;
            artifacts.arp_entries = arp_entries;
            artifacts.netbios_names = netbios_names;
            artifacts.network_shares = shares;
            artifacts.wifi_profiles = wifi_profiles;
            info!("Network collection completed successfully");
        }
        Err(e) => error!("Network full collection failed: {}", e),
    }

    // Collect installed software (temporarily disabled)
    /*
    info!("Collecting software...");
    match software::collect() {
        Ok((software_data, msi_data, store_data)) => {
            artifacts.installed_software = software_data;
            artifacts.msi_installs = msi_data;
            artifacts.store_apps = store_data;
            info!("Software collection completed successfully");
        }
        Err(e) => error!("Software collection failed: {}", e),
    }
    */

    // Collect environment variables
    info!("Collecting environment variables...");
    match environment::collect() {
        Ok(env_vars) => {
            artifacts.environment_variables = env_vars;
            info!("Environment collection completed successfully");
        }
        Err(e) => error!("Environment collection failed: {}", e),
    }

    // Collect hardware information
    info!("Collecting hardware information...");
    match hardware::collect() {
        Ok((hw_info, usb_devices, disk_devices, tpm_info, virt_info)) => {
            artifacts.hardware_info = hw_info;
            artifacts.usb_devices = usb_devices;
            artifacts.disk_devices = disk_devices;
            // TODO: Enable once fixed
            // artifacts.tmp_info = tmp_info;
            artifacts.virtualization_info = virt_info;
            info!("Hardware collection completed successfully");
        }
        Err(e) => error!("Hardware collection failed: {}", e),
    }
    
    Ok(artifacts)
}

fn write_single_report(output_dir: &PathBuf, artifacts: &SystemArtifacts) -> Result<()> {
    use std::fs::File;
    use std::io::Write;
    
    info!("Writing comprehensive report to single file...");
    
    let report_path = output_dir.join("reconnaissance.json");
    let mut report_file = File::create(&report_path)?;
    
    // Create comprehensive report structure
    let comprehensive_report = serde_json::json!({
        "metadata": {
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            "hostname": std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".to_string()),
            "username": std::env::var("USERNAME").unwrap_or_else(|_| "Unknown".to_string()),
            "collection_mode": "pure_reconnaissance"
        },
        "system_artifacts": {
            "services": artifacts.services,
            "registry_entries": artifacts.registry_entries,
            "scheduled_tasks": artifacts.scheduled_tasks,
            "wmi_filters": artifacts.wmi_filters,
            "wmi_consumers": artifacts.wmi_consumers,
            "wmi_bindings": artifacts.wmi_bindings,
            "network_connections": artifacts.network_connections,
            "winsock_providers": artifacts.winsock_providers,
            "proxy_config": artifacts.proxy_config,
            "certificates": artifacts.certificates,
            "file_artifacts": artifacts.file_artifacts,
            "processes": artifacts.processes,
            "process_anomalies": artifacts.process_anomalies,
            "browser_extensions": artifacts.browser_extensions,
            "browser_settings": artifacts.browser_settings,
            "browser_downloads": artifacts.browser_downloads,
            "crypto_theft_artifacts": artifacts.crypto_theft_artifacts,
            "wallet_files": artifacts.wallet_files,
            "session_files": artifacts.session_files
        }
    });
    
    // Write pretty-printed JSON
    let json_string = serde_json::to_string_pretty(&comprehensive_report)?;
    report_file.write_all(json_string.as_bytes())?;
    
    info!("Comprehensive report written to: {}", report_path.display());
    Ok(())
}

fn write_snapshot_report(output_dir: &PathBuf, artifacts: &SystemArtifacts) -> Result<()> {
    use std::fs::File;
    use std::io::Write;
    
    info!("Writing snapshot report...");
    
    let report_path = output_dir.join("system_snapshot.txt");
    let mut report_file = File::create(&report_path)?;
    
    writeln!(report_file, "==========================================")?;
    writeln!(report_file, "       SYSTEM RECONNAISSANCE SNAPSHOT")?;
    writeln!(report_file, "==========================================")?;
    writeln!(report_file, "Timestamp: {}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs())?;
    writeln!(report_file, "Hostname: {}", std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".to_string()))?;
    writeln!(report_file, "Username: {}", std::env::var("USERNAME").unwrap_or_else(|_| "Unknown".to_string()))?;
    writeln!(report_file, "==========================================")?;
    
    // Services
    writeln!(report_file, "\n--- RUNNING SERVICES ({}) ---", artifacts.services.len())?;
    for service in &artifacts.services {
        writeln!(report_file, "Name: {}", service.name)?;
        writeln!(report_file, "  Display: {}", service.display_name)?;
        writeln!(report_file, "  Binary: {}", service.binary_path)?;
        writeln!(report_file, "  State: {} | Start: {} | Account: {}", 
                service.current_state, service.start_type, service.service_account)?;
        if let Some(pid) = service.process_id {
            writeln!(report_file, "  PID: {}", pid)?;
        }
        writeln!(report_file, "")?;
    }
    
    // Processes
    writeln!(report_file, "\n--- ACTIVE PROCESSES ({}) ---", artifacts.processes.len())?;
    for process in &artifacts.processes {
        writeln!(report_file, "PID: {} | PPID: {} | Name: {}", 
                process.pid, 
                process.parent_pid.unwrap_or(0), 
                process.name)?;
        writeln!(report_file, "  Path: {}", process.executable_path)?;
        if !process.command_line.is_empty() {
            writeln!(report_file, "  Command: {}", process.command_line)?;
        }
        if let Some(user) = &process.user {
            writeln!(report_file, "  User: {}", user)?;
        }
        writeln!(report_file, "")?;
    }
    
    // Network connections
    writeln!(report_file, "\n--- NETWORK CONNECTIONS ({}) ---", artifacts.network_connections.len())?;
    for conn in &artifacts.network_connections {
        writeln!(report_file, "{}:{} -> {}:{} [{}] PID: {}", 
                conn.local_address, conn.local_port,
                conn.remote_address, conn.remote_port,
                conn.state, conn.process_id)?;
    }
    
    // Scheduled tasks
    writeln!(report_file, "\n--- SCHEDULED TASKS ({}) ---", artifacts.scheduled_tasks.len())?;
    for task in &artifacts.scheduled_tasks {
        writeln!(report_file, "Task: {}", task.name)?;
        writeln!(report_file, "  Path: {}", task.path)?;
        writeln!(report_file, "  Enabled: {} | Hidden: {}", task.enabled, task.hidden)?;
        if let Some(author) = &task.author {
            writeln!(report_file, "  Author: {}", author)?;
        }
        for action in &task.actions {
            writeln!(report_file, "  Action: {} {}", action.execute, 
                    action.arguments.as_ref().unwrap_or(&String::new()))?;
        }
        writeln!(report_file, "")?;
    }
    
    // Registry entries  
    writeln!(report_file, "\n--- REGISTRY PERSISTENCE ({}) ---", artifacts.registry_entries.len())?;
    for entry in &artifacts.registry_entries {
        writeln!(report_file, "Key: {}", entry.key_path)?;
        writeln!(report_file, "  {}: {} ({})", entry.value_name, entry.value_data, entry.value_type)?;
        writeln!(report_file, "")?;
    }
    
    // Browser extensions
    writeln!(report_file, "\n--- BROWSER EXTENSIONS ({}) ---", artifacts.browser_extensions.len())?;
    for ext in &artifacts.browser_extensions {
        writeln!(report_file, "Browser: {} | Extension: {} ({})", 
                ext.browser, ext.name, ext.id)?;
        writeln!(report_file, "  Version: {} | Permissions: {}", 
                ext.version, ext.permissions.len())?;
        if !ext.permissions.is_empty() {
            writeln!(report_file, "  Perms: {}", ext.permissions.join(", "))?;
        }
        writeln!(report_file, "")?;
    }
    
    // Crypto wallets
    if !artifacts.wallet_files.is_empty() {
        writeln!(report_file, "\n--- CRYPTOCURRENCY WALLETS ({}) ---", artifacts.wallet_files.len())?;
        for wallet in &artifacts.wallet_files {
            writeln!(report_file, "Type: {} | Size: {} bytes", wallet.wallet_type, wallet.file_size)?;
            writeln!(report_file, "  Path: {}", wallet.file_path)?;
            writeln!(report_file, "  Encrypted: {} | Risk: {}", wallet.is_encrypted, wallet.risk_level)?;
            writeln!(report_file, "")?;
        }
    }
    
    // Session files
    if !artifacts.session_files.is_empty() {
        writeln!(report_file, "\n--- APPLICATION SESSIONS ({}) ---", artifacts.session_files.len())?;
        for session in &artifacts.session_files {
            writeln!(report_file, "App: {} | Type: {} | Size: {} bytes", 
                    session.application, session.file_type, session.data_size)?;
            writeln!(report_file, "  Path: {}", session.file_path)?;
            writeln!(report_file, "  Tokens: {}", session.contains_tokens)?;
            writeln!(report_file, "")?;
        }
    }

    // Users
    writeln!(report_file, "\n--- LOCAL USERS ({}) ---", artifacts.users.len())?;
    for user in &artifacts.users {
        writeln!(report_file, "User: {} ({}) | Enabled: {} | SID: {}", 
                user.name, user.full_name, user.enabled, user.sid)?;
        if let Some(last_logon) = &user.last_logon {
            writeln!(report_file, "  Last Logon: {}", last_logon)?;
        }
        if let Some(profile_path) = &user.profile_path {
            writeln!(report_file, "  Profile: {} ({} bytes)", profile_path, user.profile_size)?;
        }
        writeln!(report_file, "")?;
    }

    // Groups
    writeln!(report_file, "\n--- LOCAL GROUPS ({}) ---", artifacts.groups.len())?;
    for group in &artifacts.groups {
        writeln!(report_file, "Group: {} | Members: {}", group.name, group.members.len())?;
        writeln!(report_file, "  Description: {}", group.description)?;
        writeln!(report_file, "  Members: {}", group.members.join(", "))?;
        writeln!(report_file, "")?;
    }

    // Network adapters
    writeln!(report_file, "\n--- NETWORK ADAPTERS ({}) ---", artifacts.network_adapters.len())?;
    for adapter in &artifacts.network_adapters {
        writeln!(report_file, "Adapter: {} [{}] | Status: {} | MAC: {}", 
                adapter.name, adapter.interface_description, adapter.status, adapter.mac_address)?;
        writeln!(report_file, "  IPv4: {}", adapter.ipv4_addresses.join(", "))?;
        writeln!(report_file, "  IPv6: {}", adapter.ipv6_addresses.join(", "))?;
        if let Some(gateway) = &adapter.gateway {
            writeln!(report_file, "  Gateway: {}", gateway)?;
        }
        writeln!(report_file, "  DNS: {}", adapter.dns_servers.join(", "))?;
        writeln!(report_file, "")?;
    }

    // WiFi profiles
    if !artifacts.wifi_profiles.is_empty() {
        writeln!(report_file, "\n--- WIFI PROFILES ({}) ---", artifacts.wifi_profiles.len())?;
        for wifi in &artifacts.wifi_profiles {
            writeln!(report_file, "SSID: {} | Auth: {} | Encryption: {}", 
                    wifi.ssid, wifi.authentication, wifi.encryption)?;
            writeln!(report_file, "  Profile: {} | Auto-connect: {}", wifi.name, wifi.auto_connect)?;
            if wifi.password.is_some() {
                writeln!(report_file, "  Password: [PROTECTED]")?;
            }
            writeln!(report_file, "")?;
        }
    }

    // Network shares
    if !artifacts.network_shares.is_empty() {
        writeln!(report_file, "\n--- NETWORK SHARES ({}) ---", artifacts.network_shares.len())?;
        for share in &artifacts.network_shares {
            writeln!(report_file, "Share: {} -> {} [{}]", share.name, share.path, share.share_type)?;
            writeln!(report_file, "  Description: {}", share.description)?;
            writeln!(report_file, "  Users: {}/{} | Special: {}", 
                    share.current_users, share.concurrent_user_limit, share.special)?;
            writeln!(report_file, "")?;
        }
    }

    // Installed software (top 20)
    writeln!(report_file, "\n--- INSTALLED SOFTWARE (Top 20 of {}) ---", artifacts.installed_software.len())?;
    for (i, software) in artifacts.installed_software.iter().take(20).enumerate() {
        writeln!(report_file, "{}. {} ({})", i+1, software.display_name, 
                software.display_version.as_ref().unwrap_or(&"Unknown".to_string()))?;
        if let Some(publisher) = &software.publisher {
            writeln!(report_file, "   Publisher: {}", publisher)?;
        }
        if let Some(install_date) = &software.install_date {
            writeln!(report_file, "   Installed: {}", install_date)?;
        }
        writeln!(report_file, "")?;
    }

    // Store apps (top 10)
    if !artifacts.store_apps.is_empty() {
        writeln!(report_file, "\n--- WINDOWS STORE APPS (Top 10 of {}) ---", artifacts.store_apps.len())?;
        for (i, app) in artifacts.store_apps.iter().take(10).enumerate() {
            writeln!(report_file, "{}. {} ({})", i+1, app.name, app.version)?;
            writeln!(report_file, "   Publisher: {} | Architecture: {}", app.publisher, app.architecture)?;
            writeln!(report_file, "   Framework: {} | Bundle: {} | Removable: {}", 
                    app.is_framework, app.is_bundle, !app.non_removable)?;
            writeln!(report_file, "")?;
        }
    }
    
    // File artifacts
    if !artifacts.file_artifacts.is_empty() {
        writeln!(report_file, "\n--- FILE ARTIFACTS ({}) ---", artifacts.file_artifacts.len())?;
        for file in &artifacts.file_artifacts {
            writeln!(report_file, "File: {} | Size: {} bytes", file.path, file.size)?;
            if let Some(created) = &file.created {
                writeln!(report_file, "  Created: {}", created)?;
            }
            if let Some(modified) = &file.modified {
                writeln!(report_file, "  Modified: {}", modified)?;
            }
            writeln!(report_file, "  SHA256: {}", file.sha256)?;
            writeln!(report_file, "")?;
        }
    }
    
    writeln!(report_file, "\n==========================================")?;
    writeln!(report_file, "           SNAPSHOT COMPLETE")?;
    writeln!(report_file, "==========================================")?;
    
    info!("Snapshot report written to: {}", report_path.display());
    Ok(())
}
