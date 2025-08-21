use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub hostname: String,
    pub username: String,
    pub os_version: String,
    pub agent_version: String,
    pub collection_time: String,
}

impl Manifest {
    pub fn new() -> Self {
        Self {
            hostname: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string()),
            username: std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string()),
            os_version: "Windows".to_string(), // TODO: Get actual version
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            collection_time: "2025-08-21T12:00:00Z".to_string(), // Simple timestamp
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub service_type: String,
    pub start_type: String,
    pub current_state: String,
    pub binary_path: String,
    pub service_account: String,
    pub process_id: Option<u32>,
    pub signature_status: SignatureStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub key_path: String,
    pub value_name: String,
    pub value_data: String,
    pub value_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTask {
    pub name: String,
    pub path: String,
    pub author: Option<String>,
    pub hidden: bool,
    pub enabled: bool,
    pub triggers: Vec<TaskTrigger>,
    pub actions: Vec<TaskAction>,
    pub last_run: Option<String>,
    pub next_run: Option<String>,
    pub last_result: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskTrigger {
    pub trigger_type: String,
    pub conditions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskAction {
    pub action_type: String,
    pub execute: String,
    pub arguments: Option<String>,
    pub working_directory: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiFilter {
    pub name: String,
    pub query: String,
    pub event_namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiConsumer {
    pub name: String,
    pub command_line_template: String,
    pub working_directory: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiBinding {
    pub filter: String,
    pub consumer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
    pub process_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub enabled: bool,
    pub server: Option<String>,
    pub bypass: Option<String>,
    pub auto_config_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinsockProvider {
    pub catalog_id: u32,
    pub address_family: i32,
    pub protocol: i32,
    pub protocol_chain: String,
    pub socket_type: i32,
    pub protocol_name: String,
    pub protocol_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub thumbprint_sha1: String,
    pub thumbprint_sha256: String,
    pub store_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileArtifact {
    pub path: String,
    pub size: u64,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub sha256: String,
    pub signature_status: SignatureStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub executable_path: String,
    pub command_line: String,
    pub user: Option<String>,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub signature_status: SignatureStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAnomaly {
    pub pid: u32,
    pub anomaly_type: String,
    pub description: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureStatus {
    Trusted,
    Untrusted,
    Unknown,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub category: Category,
    pub indicators: Vec<String>,
    pub rationale: String,
    pub suggested_action: Option<String>,
    pub artifacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub source: String,
    pub event_type: String,
    pub description: String,
    pub details: Option<String>,
    pub severity: Option<Severity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Category {
    Service,
    Driver,
    Task,
    WMI,
    Registry,
    Process,
    Network,
    Certificate,
    File,
    Browser,
    CryptoTheft,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SystemArtifacts {
    pub services: Vec<ServiceInfo>,
    pub registry_entries: Vec<RegistryEntry>,
    pub scheduled_tasks: Vec<ScheduledTask>,
    pub wmi_filters: Vec<WmiFilter>,
    pub wmi_consumers: Vec<WmiConsumer>,
    pub wmi_bindings: Vec<WmiBinding>,
    pub network_connections: Vec<NetworkConnection>,
    pub proxy_config: Option<ProxyConfig>,
    pub winsock_providers: Vec<WinsockProvider>,
    pub certificates: Vec<CertificateInfo>,
    pub file_artifacts: Vec<FileArtifact>,
    pub processes: Vec<ProcessInfo>,
    pub process_anomalies: Vec<ProcessAnomaly>,
    pub browser_extensions: Vec<BrowserExtension>,
    pub browser_settings: Vec<BrowserSetting>,
    pub browser_downloads: Vec<BrowserDownload>,
    pub crypto_theft_artifacts: Vec<CryptoTheftArtifact>,
    pub wallet_files: Vec<WalletFile>,
    pub session_files: Vec<SessionFile>,
    
    // Timeline for unified event analysis (Stage 3)
    pub timeline_events: Vec<TimelineEvent>,
    
    // New comprehensive collections
    pub users: Vec<UserInfo>,
    pub groups: Vec<GroupInfo>, 
    pub user_profiles: Vec<UserProfile>,
    pub network_adapters: Vec<NetworkAdapter>,
    pub network_routes: Vec<NetworkRoute>,
    pub arp_entries: Vec<ArpEntry>,
    pub netbios_names: Vec<NetBiosName>,
    pub network_shares: Vec<NetworkShare>,
    pub wifi_profiles: Vec<WifiProfile>,
    pub installed_software: Vec<InstalledSoftware>,
    pub msi_installs: Vec<MsiInstall>,
    pub store_apps: Vec<StoreApp>,
    
    // Environment and hardware
    pub environment_variables: Vec<EnvironmentVariable>,
    pub hardware_info: HardwareInfo,
    pub usb_devices: Vec<UsbDevice>,
    pub disk_devices: Vec<DiskDevice>,
    pub tpm_info: Option<TpmInfo>,
    pub virtualization_info: VirtualizationInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserExtension {
    pub browser: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub permissions: Vec<String>,
    pub is_suspicious: bool,
    pub install_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSetting {
    pub browser: String,
    pub category: String,
    pub setting_name: String,
    pub value: String,
    pub is_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserDownload {
    pub browser: String,
    pub filename: String,
    pub url: String,
    pub download_time: String,
    pub file_size: u64,
    pub is_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoTheftArtifact {
    pub artifact_type: String,
    pub description: String,
    pub file_path: String,
    pub threat_level: String,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletFile {
    pub wallet_type: String,
    pub file_path: String,
    pub file_size: u64,
    pub last_modified: String,
    pub is_encrypted: bool,
    pub is_suspicious: bool,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFile {
    pub application: String,
    pub file_path: String,
    pub file_type: String,
    pub last_accessed: String,
    pub contains_tokens: bool,
    pub is_suspicious: bool,
    pub data_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardMonitor {
    pub process_name: String,
    pub process_id: u32,
    pub executable_path: String,
    pub is_suspicious: bool,
}

// New comprehensive data structures

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub name: String,
    pub full_name: String,
    pub description: String,
    pub enabled: bool,
    pub account_expires: Option<String>,
    pub last_logon: Option<String>,
    pub password_last_set: Option<String>,
    pub password_required: bool,
    pub user_may_change_password: bool,
    pub password_changeable_date: Option<String>,
    pub password_expires: Option<String>,
    pub sid: String,
    pub principal_source: String,
    pub profile_path: Option<String>,
    pub profile_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub name: String,
    pub description: String,
    pub sid: String,
    pub principal_source: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub sid: String,
    pub local_path: String,
    pub loaded: bool,
    pub special: bool,
    pub last_use_time: Option<String>,
    pub last_used: Option<String>,
    pub size: u64,
    pub roaming_configured: bool,
    pub roaming_path: Option<String>,
    pub roaming_preference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAdapter {
    pub name: String,
    pub interface_description: String,
    pub interface_index: u32,
    pub status: String,
    pub link_speed: u64,
    pub media_type: String,
    pub physical_media_type: String,
    pub mac_address: String,
    pub is_virtual: bool,
    pub is_hidden: bool,
    pub not_user_removable: bool,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub gateway: Option<String>,
    pub dhcp_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRoute {
    pub destination_prefix: String,
    pub next_hop: String,
    pub interface_index: u32,
    pub interface_alias: String,
    pub address_family: String,
    pub protocol: String,
    pub publish: String,
    pub route_metric: u32,
    pub interface_metric: u32,
    pub policy_store: String,
    pub preferred_lifetime: Option<String>,
    pub valid_lifetime: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip_address: String,
    pub mac_address: String,
    pub interface_index: u32,
    pub interface_alias: String,
    pub state: String,
    pub address_family: String,
    pub policy_store: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetBiosName {
    pub name: String,
    pub name_type: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkShare {
    pub name: String,
    pub path: String,
    pub description: String,
    pub share_type: String,
    pub share_state: String,
    pub scope_name: String,
    pub folder_enumeration_mode: String,
    pub caching_mode: String,
    pub ca_timeout: u32,
    pub concurrent_user_limit: u32,
    pub continuously_available: bool,
    pub current_users: u32,
    pub encrypt_data: bool,
    pub security_descriptor: Option<String>,
    pub special: bool,
    pub temporary: bool,
    pub volume: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiProfile {
    pub name: String,
    pub ssid: String,
    pub authentication: String,
    pub encryption: String,
    pub password: Option<String>,
    pub connection_mode: String,
    pub network_type: String,
    pub auto_connect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledSoftware {
    pub display_name: String,
    pub display_version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
    pub install_location: Option<String>,
    pub install_source: Option<String>,
    pub uninstall_string: Option<String>,
    pub modify_path: Option<String>,
    pub estimated_size: u64,
    pub system_component: bool,
    pub parent_key_name: Option<String>,
    pub release_type: Option<String>,
    pub major_version: Option<u32>,
    pub minor_version: Option<u32>,
    pub version_major: Option<u32>,
    pub version_minor: Option<u32>,
    pub language: Option<String>,
    pub comments: Option<String>,
    pub contact: Option<String>,
    pub help_link: Option<String>,
    pub help_telephone: Option<String>,
    pub no_modify: bool,
    pub no_repair: bool,
    pub no_remove: bool,
    pub url_info_about: Option<String>,
    pub url_update_info: Option<String>,
    pub windows_installer: bool,
    pub registry_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsiInstall {
    pub name: String,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub install_date: Option<String>,
    pub install_location: Option<String>,
    pub install_state: Option<u32>,
    pub package_cache: Option<String>,
    pub package_code: Option<String>,
    pub package_name: Option<String>,
    pub product_id: Option<String>,
    pub reg_company: Option<String>,
    pub reg_owner: Option<String>,
    pub sku_number: Option<String>,
    pub transforms: Option<String>,
    pub url_info_about: Option<String>,
    pub url_update_info: Option<String>,
    pub word_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreApp {
    pub name: String,
    pub package_full_name: String,
    pub version: String,
    pub architecture: String,
    pub resource_id: Option<String>,
    pub publisher: String,
    pub publisher_id: String,
    pub install_location: Option<String>,
    pub is_framework: bool,
    pub package_family_name: String,
    pub publisher_display_name: Option<String>,
    pub signature_kind: String,
    pub status: String,
    pub is_bundle: bool,
    pub is_development_mode: bool,
    pub non_removable: bool,
    pub is_resource_package: bool,
    pub is_stub: bool,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentVariable {
    pub name: String,
    pub value: String,
    pub scope: String, // System, User, Process
    pub var_type: String, // Registry, Runtime
    pub is_path_variable: bool,
    pub path_entries: Vec<String>, // Split PATH entries if applicable
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HardwareInfo {
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
    pub bios_version: String,
    pub bios_date: Option<String>,
    pub processor_name: String,
    pub processor_cores: u32,
    pub processor_logical_processors: u32,
    pub total_memory: u64,
    pub system_type: String,
    pub domain: Option<String>,
    pub workgroup: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDevice {
    pub device_id: String,
    pub name: String,
    pub description: String,
    pub manufacturer: Option<String>,
    pub status: String,
    pub present: bool,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskDevice {
    pub device_id: String,
    pub model: String,
    pub serial_number: Option<String>,
    pub size: u64,
    pub media_type: String,
    pub interface_type: String,
    pub manufacturer: Option<String>,
    pub firmware_revision: Option<String>,
    pub status: String,
    pub partition_count: u32,
    pub smart_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmInfo {
    pub tpm_present: bool,
    pub tpm_ready: bool,
    pub tpm_enabled: bool,
    pub tpm_activated: bool,
    pub tpm_owned: bool,
    pub manufacturer_id: Option<String>,
    pub manufacturer_version: Option<String>,
    pub managed_auth_level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VirtualizationInfo {
    pub is_virtual: bool,
    pub vm_type: Option<String>, // VMware, VirtualBox, Hyper-V, etc.
    pub host_manufacturer: Option<String>,
    pub host_model: Option<String>,
    pub bios_version: Option<String>,
    pub vm_indicators: Vec<String>,
}
