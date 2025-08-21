use anyhow::Result;
use log::debug;
use std::fs;
use std::path::Path;
use regex::Regex;
use crate::types::{CryptoTheftArtifact, WalletFile, ClipboardMonitor, SessionFile};

/// Критический модуль для детекции кражи криптовалют и сессий
/// Покрывает основные векторы современных crypto-stealer атак
pub fn collect() -> Result<(Vec<CryptoTheftArtifact>, Vec<WalletFile>, Vec<SessionFile>)> {
    debug!("Starting critical crypto theft detection analysis");
    
    let mut artifacts = Vec::new();
    let mut wallet_files = Vec::new();
    let mut session_files = Vec::new();
    
    // Собираем данные по кошелькам
    collect_wallet_files(&mut wallet_files)?;
    
    // Ищем сессионные файлы
    collect_session_files(&mut session_files)?;
    
    // Анализируем буфер обмена на предмет мониторинга
    collect_clipboard_monitors(&mut artifacts)?;
    
    // Ищем следы stealer-ов
    collect_stealer_artifacts(&mut artifacts)?;
    
    debug!("Crypto theft analysis: {} artifacts, {} wallets, {} sessions", 
           artifacts.len(), wallet_files.len(), session_files.len());
    
    Ok((artifacts, wallet_files, session_files))
}

fn collect_wallet_files(wallet_files: &mut Vec<WalletFile>) -> Result<()> {
    let wallet_paths = [
        // MetaMask
        (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask Chrome"),
        (r"%APPDATA%\Mozilla\Firefox\Profiles\*\storage\default\moz-extension+++*\idb", "MetaMask Firefox"),
        
        // Ethereum wallets
        (r"%APPDATA%\Ethereum\keystore", "Ethereum Keystore"),
        (r"%LOCALAPPDATA%\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalState\keystore", "Ethereum Mobile"),
        
        // Desktop wallets
        (r"%APPDATA%\Electrum\wallets", "Electrum"),
        (r"%APPDATA%\Bitcoin\wallet.dat", "Bitcoin Core"),
        (r"%APPDATA%\Litecoin\wallet.dat", "Litecoin Core"),
        (r"%APPDATA%\Dogecoin\wallet.dat", "Dogecoin Core"),
        (r"%APPDATA%\Exodus\exodus.wallet", "Exodus"),
        (r"%APPDATA%\atomic\Local Storage\leveldb", "Atomic Wallet"),
        
        // Hardware wallet software
        (r"%APPDATA%\Ledger Live", "Ledger Live"),
        (r"%LOCALAPPDATA%\Trezor Suite", "Trezor Suite"),
        
        // Other browsers extensions
        (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\fhbohimaelbohpjbbldcngcnapndodjp", "Binance Chain Wallet"),
        (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase Wallet"),
        (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\ibnejdfjmmkpcnlpebklmnkoeoihofec", "TronLink"),
    ];
    
    for (path_pattern, wallet_type) in &wallet_paths {
        let expanded_path = expand_env_vars(path_pattern);
        
        if let Ok(metadata) = fs::metadata(&expanded_path) {
            let is_suspicious = check_recent_access(&expanded_path);
            
            wallet_files.push(WalletFile {
                wallet_type: wallet_type.to_string(),
                file_path: expanded_path.clone(),
                file_size: metadata.len(),
                last_modified: get_file_time(&metadata),
                is_encrypted: check_if_encrypted(&expanded_path),
                is_suspicious,
                risk_level: if is_suspicious { "High" } else { "Medium" }.to_string(),
            });
        }
        
        // Также ищем файлы с wildcard'ами
        if path_pattern.contains('*') {
            scan_wildcard_paths(path_pattern, wallet_type, wallet_files)?;
        }
    }
    
    Ok(())
}

fn collect_session_files(session_files: &mut Vec<SessionFile>) -> Result<()> {
    let session_paths = [
        // Discord
        (r"%APPDATA%\discord\Local Storage\leveldb", "Discord", "leveldb"),
        (r"%APPDATA%\discordcanary\Local Storage\leveldb", "Discord Canary", "leveldb"),
        (r"%APPDATA%\discordptb\Local Storage\leveldb", "Discord PTB", "leveldb"),
        
        // Telegram
        (r"%APPDATA%\Telegram Desktop\tdata", "Telegram", "tdata"),
        
        // Steam
        (r"%PROGRAMFILES(X86)%\Steam\config\loginusers.vdf", "Steam", "vdf"),
        (r"%LOCALAPPDATA%\Steam\config", "Steam Local", "config"),
        
        // Gaming clients
        (r"%LOCALAPPDATA%\Battle.net", "Battle.net", "config"),
        (r"%APPDATA%\Origin", "Origin", "config"),
        
        // Browsers session storage
        (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Sessions", "Chrome Sessions", "session"),
        (r"%APPDATA%\Mozilla\Firefox\Profiles\*\sessionstore-backups", "Firefox Sessions", "session"),
        
        // Email clients
        (r"%APPDATA%\Thunderbird\Profiles", "Thunderbird", "profile"),
        (r"%LOCALAPPDATA%\Microsoft\Outlook", "Outlook", "ost"),
        
        // VPN clients
        (r"%APPDATA%\NordVPN", "NordVPN", "config"),
        (r"%LOCALAPPDATA%\ProtonVPN", "ProtonVPN", "config"),
    ];
    
    for (path_pattern, app_name, file_type) in &session_paths {
        let expanded_path = expand_env_vars(path_pattern);
        
        if Path::new(&expanded_path).exists() {
            let is_suspicious = check_recent_access(&expanded_path);
            
            session_files.push(SessionFile {
                application: app_name.to_string(),
                file_path: expanded_path.clone(),
                file_type: file_type.to_string(),
                last_accessed: get_current_time(),
                contains_tokens: check_for_tokens(&expanded_path),
                is_suspicious,
                data_size: get_directory_size(&expanded_path).unwrap_or(0),
            });
        }
    }
    
    Ok(())
}

fn collect_clipboard_monitors(artifacts: &mut Vec<CryptoTheftArtifact>) -> Result<()> {
    // Ищем процессы, которые могут мониторить буфер обмена
    let clipboard_suspicious_processes = [
        "clipboardmanager.exe",
        "cbmonitor.exe", 
        "clipspy.exe",
        "clipstealer.exe",
    ];
    
    // Проверяем запущенные процессы
    if let Ok(output) = std::process::Command::new("powershell")
        .arg("-Command")
        .arg("Get-Process | Select-Object ProcessName,Id,Path | ConvertTo-Json")
        .output() {
        
        if let Ok(json_str) = String::from_utf8(output.stdout) {
            if let Ok(processes) = serde_json::from_str::<serde_json::Value>(&json_str) {
                if let Some(proc_array) = processes.as_array() {
                    for process in proc_array {
                        if let Some(name) = process.get("ProcessName").and_then(|v| v.as_str()) {
                            for suspicious_name in &clipboard_suspicious_processes {
                                if name.to_lowercase().contains(&suspicious_name.to_lowercase()) {
                                    artifacts.push(CryptoTheftArtifact {
                                        artifact_type: "ClipboardMonitor".to_string(),
                                        description: format!("Suspicious clipboard monitoring process: {}", name),
                                        file_path: process.get("Path")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Unknown").to_string(),
                                        threat_level: "High".to_string(),
                                        indicators: vec![
                                            format!("Process: {}", name),
                                            format!("PID: {}", process.get("Id").unwrap_or(&serde_json::Value::Null)),
                                        ],
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(())
}

fn collect_stealer_artifacts(artifacts: &mut Vec<CryptoTheftArtifact>) -> Result<()> {
    // Известные stealer семейства и их индикаторы
    let stealer_indicators = [
        ("RedLine", vec![r"C:\Users\Public\", "winlogon.exe", "svchost.exe"]),
        ("Raccoon", vec![r"AppData\Local\Temp\", ".raccoon", "sqlite"]),
        ("Mars", vec![r"marsstealer", "mars.exe", "mars_"]),
        ("Vidar", vec![r"vidar", "soft.txt", "information.txt"]),
        ("AZORult", vec![r"azorult", "1.txt", "2.txt"]),
        ("Amadey", vec![r"amadey", "cred.txt", "install.cmd"]),
        ("AsyncRAT", vec![r"AsyncRAT", "Stub.exe", "Client.exe"]),
        ("LummaC2", vec![r"lumma", "C2Stealer", "LummaC2"]),
        ("WhiteSnake", vec![r"WhiteSnake", "snake.exe", "ws_"]),
        ("StealC", vec![r"stealc", "passwords.txt", "wallets.txt"]),
    ];
    
    for (stealer_name, indicators) in &stealer_indicators {
        for indicator in indicators {
            // Ищем файлы по индикаторам
            let search_paths = [
                format!(r"C:\Users\{}\AppData\Local\Temp\*{}", get_username(), indicator),
                format!(r"C:\Users\Public\*{}", indicator),
                format!(r"C:\Windows\Temp\*{}", indicator),
            ];
            
            for search_path in &search_paths {
                if let Ok(paths) = glob::glob(search_path) {
                    for path in paths.flatten() {
                        artifacts.push(CryptoTheftArtifact {
                            artifact_type: "StealerArtifact".to_string(),
                            description: format!("Potential {} stealer artifact detected", stealer_name),
                            file_path: path.to_string_lossy().to_string(),
                            threat_level: "Critical".to_string(),
                            indicators: vec![
                                format!("Stealer: {}", stealer_name),
                                format!("Indicator: {}", indicator),
                                format!("Path: {}", path.display()),
                            ],
                        });
                    }
                }
            }
        }
    }
    
    Ok(())
}

// Утилиты
fn expand_env_vars(path: &str) -> String {
    path.replace("%LOCALAPPDATA%", &std::env::var("LOCALAPPDATA").unwrap_or_default())
        .replace("%APPDATA%", &std::env::var("APPDATA").unwrap_or_default())
        .replace("%PROGRAMFILES(X86)%", &std::env::var("PROGRAMFILES(X86)").unwrap_or_default())
}

fn check_recent_access(path: &str) -> bool {
    // Проверяем, был ли файл изменен за последние 7 дней
    if let Ok(metadata) = fs::metadata(path) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(duration) = modified.elapsed() {
                return duration.as_secs() < 7 * 24 * 3600; // 7 дней
            }
        }
    }
    false
}

fn get_file_time(metadata: &fs::Metadata) -> String {
    if let Ok(modified) = metadata.modified() {
        if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
            return format!("{}", duration.as_secs());
        }
    }
    "Unknown".to_string()
}

fn check_if_encrypted(path: &str) -> bool {
    // Упрощенная проверка - ищем расширения зашифрованных файлов
    path.ends_with(".dat") || path.ends_with(".wallet") || path.ends_with(".aes")
}

fn scan_wildcard_paths(pattern: &str, wallet_type: &str, wallet_files: &mut Vec<WalletFile>) -> Result<()> {
    // Упрощенная реализация для wildcard поиска
    Ok(())
}

fn check_for_tokens(path: &str) -> bool {
    // Проверяем, содержит ли директория токены
    let token_patterns = [
        r"[mM][fF][aA][0-9a-zA-Z]{23}\.[0-9a-zA-Z]{6}\.[0-9a-zA-Z_\-]{27}|[mM][fF][aA][0-9a-zA-Z]{24}\.[0-9a-zA-Z]{6}\.[0-9a-zA-Z_\-]{38}",  // Discord
        r"xox[baprs]-([0-9a-zA-Z]{10,48})?", // Slack
        r"ya29\.[0-9A-Za-z\-_]+", // Google OAuth
    ];
    
    if let Ok(dir) = fs::read_dir(path) {
        for entry in dir.flatten() {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                for pattern in &token_patterns {
                    if let Ok(regex) = Regex::new(pattern) {
                        if regex.is_match(&content) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    
    false
}

fn get_current_time() -> String {
    "2025-08-21T12:00:00Z".to_string() // Упрощенная временная метка
}

fn get_directory_size(path: &str) -> Result<u64> {
    let mut total_size = 0;
    
    if let Ok(dir) = fs::read_dir(path) {
        for entry in dir.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    total_size += metadata.len();
                } else if metadata.is_dir() {
                    if let Ok(subdir_size) = get_directory_size(&entry.path().to_string_lossy()) {
                        total_size += subdir_size;
                    }
                }
            }
        }
    }
    
    Ok(total_size)
}

fn get_username() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string())
}
