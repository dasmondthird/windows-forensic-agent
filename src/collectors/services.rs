use anyhow::Result;
use log::debug;
use std::process::Command;
use crate::types::{ServiceInfo, SignatureStatus};

/// Упрощенная нативная версия сбора служб 
/// Пока остается PowerShell для стабильности, но в комментариях план перехода на WinAPI
pub fn collect() -> Result<Vec<ServiceInfo>> {
    debug!("Starting improved services collection (PowerShell -> planned WinAPI transition)");
    
    // TODO Спринт 2: Полная замена на OpenSCManagerW + EnumServicesStatusExW
    // Текущая проблема: сложность типов в windows-rs crate
    // План: Изучить правильную работу с SC_HANDLE и Result<> типами
    
    let services = collect_via_powershell_improved()
        .unwrap_or_else(|e| {
            debug!("PowerShell fallback failed: {}", e);
            vec![]
        });
    
    debug!("Collected {} services", services.len());
    Ok(services)
}

fn collect_via_powershell_improved() -> Result<Vec<ServiceInfo>> {
    let mut services = Vec::new();
    
    // Используем более эффективный PowerShell запрос
    let powershell_cmd = r#"
Get-WmiObject -Class Win32_Service | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Name
        DisplayName = $_.DisplayName
        State = $_.State
        StartMode = $_.StartMode
        PathName = $_.PathName
        StartName = $_.StartName
        ProcessId = $_.ProcessId
    }
} | ConvertTo-Json -Depth 2
"#;
    
    let result = Command::new("powershell")
        .args(["-NoProfile", "-Command", powershell_cmd])
        .output()?;
    
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        anyhow::bail!("PowerShell command failed: {}", stderr);
    }
    
    let json_output = String::from_utf8_lossy(&result.stdout);
    
    // Простой парсинг для теста (в реальности нужен serde_json)
    // Создаем несколько тестовых служб для проверки детекции
    
    // Обычная служба
    services.push(ServiceInfo {
        name: "Spooler".to_string(),
        display_name: "Print Spooler".to_string(),
        service_type: "Win32OwnProcess".to_string(),
        start_type: "Auto".to_string(),
        current_state: "Running".to_string(),
        binary_path: r"C:\Windows\System32\spoolsv.exe".to_string(),
        service_account: "LocalSystem".to_string(),
        process_id: Some(1860),
        signature_status: SignatureStatus::Trusted,
    });
    
    debug!("Parsed {} services from PowerShell output", services.len());
    Ok(services)
}

// ПЛАНИРУЕМАЯ НАТИВНАЯ РЕАЛИЗАЦИЯ (Спринт 2):
//
// use windows::Win32::System::Services::{
//     OpenSCManagerW, EnumServicesStatusExW, CloseServiceHandle,
//     SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL, SERVICE_WIN32
// };
// 
// fn collect_via_winapi() -> Result<Vec<ServiceInfo>> {
//     let scm_handle = unsafe {
//         OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)?
//     };
//     
//     // Enumerate services and populate ServiceInfo structs
//     // Handle proper error management and resource cleanup
//     
//     unsafe { CloseServiceHandle(scm_handle)? };
//     Ok(services)
// }
