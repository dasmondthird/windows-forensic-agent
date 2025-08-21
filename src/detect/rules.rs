use anyhow::Result;
use crate::types::{Finding, SystemArtifacts, Severity, Category, SignatureStatus};
use super::engine::DetectionRule;

// High/Critical Rules

pub struct ServiceBinaryInUserDirRule;

impl DetectionRule for ServiceBinaryInUserDirRule {
    fn rule_id(&self) -> &'static str { "service_binary_in_user_dir" }
    
    fn evaluate(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        let suspicious_paths = ["AppData", "Temp", "Users\\Public"];
        
        for service in &artifacts.services {
            for suspicious_path in &suspicious_paths {
                if service.binary_path.contains(suspicious_path) {
                    findings.push(Finding {
                        id: format!("{}_{}", self.rule_id(), service.name),
                        title: format!("Service '{}' has binary in suspicious location", service.name),
                        severity: Severity::High,
                        category: Category::Service,
                        indicators: vec![
                            format!("Service: {}", service.name),
                            format!("Binary path: {}", service.binary_path),
                        ],
                        rationale: "Services should typically be located in system directories, not user-accessible locations".to_string(),
                        suggested_action: Some("Investigate the service and its origin".to_string()),
                        artifacts: vec![format!("Service: {}", service.name)],
                    });
                }
            }
        }
        
        Ok(findings)
    }
}

pub struct ServiceUnsignedOutsideSystemRule;

impl DetectionRule for ServiceUnsignedOutsideSystemRule {
    fn rule_id(&self) -> &'static str { "service_unsigned_outside_system" }
    
    fn evaluate(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for service in &artifacts.services {
            if matches!(service.signature_status, SignatureStatus::Untrusted) 
                && !service.binary_path.starts_with("C:\\Windows\\System32") {
                findings.push(Finding {
                    id: format!("{}_{}", self.rule_id(), service.name),
                    title: format!("Unsigned service '{}' outside system directory", service.name),
                    severity: Severity::High,
                    category: Category::Service,
                    indicators: vec![
                        format!("Service: {}", service.name),
                        format!("Binary path: {}", service.binary_path),
                        "Signature: Untrusted".to_string(),
                    ],
                    rationale: "System services should be digitally signed and located in trusted directories".to_string(),
                    suggested_action: Some("Verify service legitimacy and check for malware".to_string()),
                    artifacts: vec![format!("Service: {}", service.name)],
                });
            }
        }
        
        Ok(findings)
    }
}

pub struct TaskHiddenLolbasRule;

impl DetectionRule for TaskHiddenLolbasRule {
    fn rule_id(&self) -> &'static str { "task_hidden_lolbas_logon" }
    
    fn evaluate(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        let lolbas_patterns = [
            "powershell -enc",
            "powershell -nop", 
            "powershell -w hidden",
            "mshta http",
            "rundll32",
            "regsvr32 /s http",
        ];
        
        for task in &artifacts.scheduled_tasks {
            if task.hidden {
                for action in &task.actions {
                    for pattern in &lolbas_patterns {
                        if action.execute.to_lowercase().contains(pattern) 
                            || action.arguments.as_ref().map_or(false, |args| args.to_lowercase().contains(pattern)) {
                            findings.push(Finding {
                                id: format!("{}_{}", self.rule_id(), task.name.replace("\\", "_")),
                                title: format!("Hidden task '{}' uses LOLBAS technique", task.name),
                                severity: Severity::Critical,
                                category: Category::Task,
                                indicators: vec![
                                    format!("Task: {}", task.name),
                                    format!("Execute: {}", action.execute),
                                    format!("Pattern: {}", pattern),
                                    "Hidden: true".to_string(),
                                ],
                                rationale: "Hidden scheduled tasks using living-off-the-land binaries are commonly used by attackers".to_string(),
                                suggested_action: Some("Immediately investigate and consider disabling the task".to_string()),
                                artifacts: vec![format!("Task: {}", task.name)],
                            });
                        }
                    }
                }
            }
        }
        
        Ok(findings)
    }
}

pub struct LsaPackagesOutsideSystem32Rule;

impl DetectionRule for LsaPackagesOutsideSystem32Rule {
    fn rule_id(&self) -> &'static str { "lsa_packages_dll_outside_system32" }
    
    fn evaluate(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        let lsa_keys = [
            "Security Packages",
            "Authentication Packages", 
            "Notification Packages",
        ];
        
        for entry in &artifacts.registry_entries {
            if entry.key_path.contains("Control\\Lsa") {
                for lsa_key in &lsa_keys {
                    if entry.value_name.eq_ignore_ascii_case(lsa_key) 
                        && !entry.value_data.is_empty()
                        && !entry.value_data.to_lowercase().contains("system32") {
                        findings.push(Finding {
                            id: format!("{}_{}", self.rule_id(), entry.value_name.replace(" ", "_")),
                            title: format!("LSA {} contains DLL outside System32", entry.value_name),
                            severity: Severity::Critical,
                            category: Category::Registry,
                            indicators: vec![
                                format!("Key: {}", entry.key_path),
                                format!("Value: {}", entry.value_name),
                                format!("Data: {}", entry.value_data),
                            ],
                            rationale: "LSA security packages should only load trusted DLLs from System32".to_string(),
                            suggested_action: Some("Immediately investigate potential credential theft malware".to_string()),
                            artifacts: vec![format!("Registry: {}\\{}", entry.key_path, entry.value_name)],
                        });
                    }
                }
            }
        }
        
        Ok(findings)
    }
}

pub struct ProcessLolbasRule;

impl DetectionRule for ProcessLolbasRule {
    fn rule_id(&self) -> &'static str { "process_lolbas_or_userdir_unsigned" }
    
    fn evaluate(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check process anomalies for LOLBAS and unsigned user directory processes
        for anomaly in &artifacts.process_anomalies {
            if anomaly.anomaly_type == "LOLBAS" || anomaly.anomaly_type == "UnsignedUserDir" {
                findings.push(Finding {
                    id: format!("{}_{}", self.rule_id(), anomaly.pid),
                    title: format!("Suspicious process detected: {}", anomaly.description),
                    severity: Severity::High,
                    category: Category::Process,
                    indicators: vec![
                        format!("PID: {}", anomaly.pid),
                        format!("Type: {}", anomaly.anomaly_type),
                        format!("Description: {}", anomaly.description),
                    ],
                    rationale: "LOLBAS techniques and unsigned executables in user directories are common attack vectors".to_string(),
                    suggested_action: Some("Investigate process and consider termination if malicious".to_string()),
                    artifacts: vec![format!("Process: {}", anomaly.pid)],
                });
            }
        }
        
        Ok(findings)
    }
}

pub struct IfeoDebuggerRule;

impl DetectionRule for IfeoDebuggerRule {
    fn rule_id(&self) -> &'static str { "ifeo_debugger_system_proc" }
    
    fn evaluate(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        let system_processes = [
            "chrome.exe", "edge.exe", "explorer.exe", "lsass.exe",
            "services.exe", "powershell.exe", "svchost.exe",
        ];
        
        for entry in &artifacts.registry_entries {
            if entry.key_path.contains("Image File Execution Options") 
                && entry.value_name.eq_ignore_ascii_case("debugger") {
                
                // Extract executable name from key path
                let path_parts: Vec<&str> = entry.key_path.split('\\').collect();
                if let Some(exe_name) = path_parts.last() {
                    for sys_proc in &system_processes {
                        if exe_name.eq_ignore_ascii_case(sys_proc) {
                            findings.push(Finding {
                                id: format!("{}_{}", self.rule_id(), exe_name.replace(".", "_")),
                                title: format!("IFEO debugger set for system process: {}", exe_name),
                                severity: Severity::High,
                                category: Category::Registry,
                                indicators: vec![
                                    format!("Target: {}", exe_name),
                                    format!("Debugger: {}", entry.value_data),
                                    format!("Key: {}", entry.key_path),
                                ],
                                rationale: "IFEO debuggers for system processes can be used for persistence or process hijacking".to_string(),
                                suggested_action: Some("Remove the debugger entry unless legitimately needed".to_string()),
                                artifacts: vec![format!("Registry: {}\\{}", entry.key_path, entry.value_name)],
                            });
                        }
                    }
                }
            }
        }
        
        Ok(findings)
    }
}

// Medium severity rules

pub struct AppInitDllsRule;

impl DetectionRule for AppInitDllsRule {
    fn rule_id(&self) -> &'static str { "appinit_nonempty_unsigned_allowed" }
    
    fn evaluate(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        let mut appinit_dlls = None;
        let mut load_appinit = false;
        let mut require_signed = true;
        
        for entry in &artifacts.registry_entries {
            if entry.key_path.contains("Windows NT\\CurrentVersion\\Windows") {
                match entry.value_name.as_str() {
                    "AppInit_DLLs" if !entry.value_data.trim().is_empty() => {
                        appinit_dlls = Some(entry.value_data.clone());
                    }
                    "LoadAppInit_DLLs" => {
                        load_appinit = entry.value_data != "0";
                    }
                    "RequireSignedAppInit_DLLs" => {
                        require_signed = entry.value_data != "0";
                    }
                    _ => {}
                }
            }
        }
        
        if let Some(dlls) = appinit_dlls {
            if load_appinit && !require_signed {
                findings.push(Finding {
                    id: self.rule_id().to_string(),
                    title: "AppInit_DLLs enabled without signature requirement".to_string(),
                    severity: Severity::Medium,
                    category: Category::Registry,
                    indicators: vec![
                        format!("AppInit_DLLs: {}", dlls),
                        format!("LoadAppInit_DLLs: {}", load_appinit),
                        format!("RequireSignedAppInit_DLLs: {}", require_signed),
                    ],
                    rationale: "AppInit_DLLs without signature requirements can be abused for DLL injection".to_string(),
                    suggested_action: Some("Enable RequireSignedAppInit_DLLs or disable AppInit_DLLs loading".to_string()),
                    artifacts: vec!["Registry: AppInit_DLLs configuration".to_string()],
                });
            }
        }
        
        Ok(findings)
    }
}

pub struct RecentUnsignedDriverRule;

impl DetectionRule for RecentUnsignedDriverRule {
    fn rule_id(&self) -> &'static str { "recent_driver_suspicious_name" }
    
    fn evaluate(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for file in &artifacts.file_artifacts {
            if file.path.contains("drivers") 
                && file.path.ends_with(".sys")
                && matches!(file.signature_status, SignatureStatus::Untrusted) {
                
                // Simplified check - just check if modified field exists
                if file.modified.is_some() {
                    findings.push(Finding {
                        id: format!("{}_{}", self.rule_id(), file.path.replace("\\", "_").replace(".", "_")),
                        title: format!("Recent unsigned driver: {}", file.path),
                        severity: Severity::Medium,
                        category: Category::Driver,
                        indicators: vec![
                            format!("Path: {}", file.path),
                            format!("Modified: {}", file.modified.as_ref().unwrap_or(&"Unknown".to_string())),
                            "Signature: Untrusted".to_string(),
                        ],
                        rationale: "Recently installed unsigned drivers may indicate rootkit or malware installation".to_string(),
                        suggested_action: Some("Investigate driver legitimacy and scan for rootkits".to_string()),
                        artifacts: vec![format!("Driver: {}", file.path)],
                    });
                }
            }
        }
        
        Ok(findings)
    }
}

// Browser Security Rules

pub struct SuspiciousBrowserExtensionRule;

impl DetectionRule for SuspiciousBrowserExtensionRule {
    fn rule_id(&self) -> &'static str { "browser_extension_suspicious_permissions" }
    
    fn evaluate(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for extension in &artifacts.browser_extensions {
            if extension.is_suspicious {
                findings.push(Finding {
                    id: format!("{}_{}", self.rule_id(), extension.id),
                    title: format!("Suspicious browser extension detected: {}", extension.name),
                    severity: Severity::High,
                    category: Category::Browser,
                    indicators: vec![
                        format!("Browser: {}", extension.browser),
                        format!("Extension: {} ({})", extension.name, extension.id),
                        format!("Permissions: {:?}", extension.permissions),
                        format!("Install path: {}", extension.install_path),
                    ],
                    rationale: "Extensions with extensive permissions can steal data, inject malicious code, or monitor browsing".to_string(),
                    suggested_action: Some("Review extension permissions and remove if unnecessary".to_string()),
                    artifacts: vec![format!("Browser Extension: {}", extension.name)],
                });
            }
        }
        
        Ok(findings)
    }
}

pub struct CompromisedBrowserSettingsRule;

impl DetectionRule for CompromisedBrowserSettingsRule {
    fn rule_id(&self) -> &'static str { "browser_settings_hijacked" }
    
    fn evaluate(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for setting in &artifacts.browser_settings {
            if setting.is_suspicious {
                let severity = match setting.category.as_str() {
                    "Proxy" => Severity::Critical,
                    "SearchEngine" => Severity::High,
                    "Homepage" => Severity::Medium,
                    _ => Severity::Low,
                };
                
                findings.push(Finding {
                    id: format!("{}_{}", self.rule_id(), setting.setting_name),
                    title: format!("Suspicious browser setting: {} = {}", setting.setting_name, setting.value),
                    severity,
                    category: Category::Browser,
                    indicators: vec![
                        format!("Browser: {}", setting.browser),
                        format!("Category: {}", setting.category),
                        format!("Setting: {}", setting.setting_name),
                        format!("Value: {}", setting.value),
                    ],
                    rationale: "Modified browser settings can redirect traffic, disable security, or compromise user privacy".to_string(),
                    suggested_action: Some("Reset browser settings to defaults and scan for malware".to_string()),
                    artifacts: vec![format!("Browser Setting: {}", setting.setting_name)],
                });
            }
        }
        
        Ok(findings)
    }
}

pub struct SuspiciousDownloadRule;

impl DetectionRule for SuspiciousDownloadRule {
    fn rule_id(&self) -> &'static str { "browser_suspicious_download" }
    
    fn evaluate(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for download in &artifacts.browser_downloads {
            if download.is_suspicious {
                findings.push(Finding {
                    id: format!("{}_{}", self.rule_id(), download.filename),
                    title: format!("Suspicious browser download: {}", download.filename),
                    severity: Severity::Medium,
                    category: Category::Browser,
                    indicators: vec![
                        format!("Browser: {}", download.browser),
                        format!("File: {}", download.filename),
                        format!("URL: {}", download.url),
                        format!("Size: {} bytes", download.file_size),
                        format!("Time: {}", download.download_time),
                    ],
                    rationale: "Downloads from suspicious URLs or with malicious patterns may contain malware".to_string(),
                    suggested_action: Some("Scan downloaded file and verify URL legitimacy".to_string()),
                    artifacts: vec![format!("Download: {}", download.filename)],
                });
            }
        }
        
        Ok(findings)
    }
}

// Crypto Theft Detection Rules

pub struct CryptoWalletTheftRule;

impl DetectionRule for CryptoWalletTheftRule {
    fn rule_id(&self) -> &'static str { "crypto_wallet_theft_detection" }
    
    fn evaluate(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Проверяем подозрительные артефакты кражи криптовалют
        for artifact in &artifacts.crypto_theft_artifacts {
            let severity = match artifact.threat_level.as_str() {
                "Critical" => Severity::Critical,
                "High" => Severity::High,
                "Medium" => Severity::Medium,
                _ => Severity::Low,
            };
            
            findings.push(Finding {
                id: format!("{}_{}", self.rule_id(), artifact.artifact_type),
                title: format!("Crypto theft artifact detected: {}", artifact.description),
                severity,
                category: Category::CryptoTheft,
                indicators: artifact.indicators.clone(),
                rationale: "Detected artifacts associated with cryptocurrency theft malware or stealer operations".to_string(),
                suggested_action: Some("Immediately isolate system and scan for malware. Check all cryptocurrency wallets for unauthorized access".to_string()),
                artifacts: vec![format!("Crypto Theft: {}", artifact.file_path)],
            });
        }
        
        Ok(findings)
    }
}

pub struct SuspiciousWalletAccessRule;

impl DetectionRule for SuspiciousWalletAccessRule {
    fn rule_id(&self) -> &'static str { "suspicious_wallet_file_access" }
    
    fn evaluate(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for wallet in &artifacts.wallet_files {
            if wallet.is_suspicious {
                let severity = match wallet.risk_level.as_str() {
                    "High" => Severity::High,
                    "Medium" => Severity::Medium,
                    _ => Severity::Low,
                };
                
                findings.push(Finding {
                    id: format!("{}_{}", self.rule_id(), wallet.wallet_type.replace(" ", "_")),
                    title: format!("Suspicious access to {} wallet files", wallet.wallet_type),
                    severity,
                    category: Category::CryptoTheft,
                    indicators: vec![
                        format!("Wallet Type: {}", wallet.wallet_type),
                        format!("File Path: {}", wallet.file_path),
                        format!("Last Modified: {}", wallet.last_modified),
                        format!("File Size: {} bytes", wallet.file_size),
                        format!("Encrypted: {}", wallet.is_encrypted),
                    ],
                    rationale: "Recent access to cryptocurrency wallet files may indicate theft attempts".to_string(),
                    suggested_action: Some("Verify wallet integrity and move funds to secure location if necessary".to_string()),
                    artifacts: vec![format!("Wallet File: {}", wallet.file_path)],
                });
            }
        }
        
        Ok(findings)
    }
}

pub struct CompromisedSessionRule;

impl DetectionRule for CompromisedSessionRule {
    fn rule_id(&self) -> &'static str { "compromised_session_files" }
    
    fn evaluate(&self, artifacts: &SystemArtifacts) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for session in &artifacts.session_files {
            if session.is_suspicious || session.contains_tokens {
                let severity = if session.contains_tokens { 
                    Severity::High 
                } else { 
                    Severity::Medium 
                };
                
                findings.push(Finding {
                    id: format!("{}_{}", self.rule_id(), session.application.replace(" ", "_")),
                    title: format!("Suspicious session file access: {}", session.application),
                    severity,
                    category: Category::CryptoTheft,
                    indicators: vec![
                        format!("Application: {}", session.application),
                        format!("File Path: {}", session.file_path),
                        format!("File Type: {}", session.file_type),
                        format!("Contains Tokens: {}", session.contains_tokens),
                        format!("Data Size: {} bytes", session.data_size),
                    ],
                    rationale: "Session files containing authentication tokens may have been accessed by malware".to_string(),
                    suggested_action: Some("Change passwords and revoke active sessions for affected applications".to_string()),
                    artifacts: vec![format!("Session File: {}", session.file_path)],
                });
            }
        }
        
        Ok(findings)
    }
}
