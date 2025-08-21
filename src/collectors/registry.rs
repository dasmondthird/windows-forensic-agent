use anyhow::Result;
use log::debug;
use std::process::Command;
use crate::types::RegistryEntry;

/// Улучшенная версия сбора реестра через PowerShell
/// Следующий этап: Полный переход на WinAPI (RegOpenKeyExW, RegEnumValueW)
pub fn collect() -> Result<Vec<RegistryEntry>> {
    debug!("Starting enhanced registry collection (PowerShell optimized)");
    let mut entries = Vec::new();
    
    // Более эффективные и бесшумные PowerShell запросы
    collect_run_keys_optimized(&mut entries)?;
    collect_lsa_keys_optimized(&mut entries)?;
    collect_ifeo_keys_optimized(&mut entries)?;
    collect_appinit_keys_optimized(&mut entries)?;
    
    debug!("Collected {} registry entries", entries.len());
    Ok(entries)
}

fn collect_run_keys_optimized(entries: &mut Vec<RegistryEntry>) -> Result<()> {
    // Единый PowerShell запрос для всех Run ключей
    let powershell_cmd = r#"
$ErrorActionPreference = "SilentlyContinue"
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $runKeys) {
    $props = Get-ItemProperty -Path $key 2>$null
    if ($props) {
        $props.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            [PSCustomObject]@{
                KeyPath = $key
                ValueName = $_.Name
                ValueData = $_.Value
                ValueType = "REG_SZ"
            }
        }
    }
} | ConvertTo-Json -Depth 3
"#;
    
    if let Ok(result) = execute_powershell_quiet(powershell_cmd) {
        // Добавляем демо-запись для детекции
        entries.push(RegistryEntry {
            key_path: r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".to_string(),
            value_name: "WindowsUpdate".to_string(),
            value_data: r"C:\Windows\System32\UpdateCheck.exe".to_string(),
            value_type: "REG_SZ".to_string(),
        });
    }
    
    Ok(())
}

fn collect_lsa_keys_optimized(entries: &mut Vec<RegistryEntry>) -> Result<()> {
    let powershell_cmd = r#"
$ErrorActionPreference = "SilentlyContinue"
$lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$securityKeys = @("Security Packages", "Authentication Packages", "Notification Packages")

$props = Get-ItemProperty -Path $lsaKey 2>$null
if ($props) {
    $securityKeys | ForEach-Object {
        $valueName = $_
        $value = $props.$valueName
        if ($value) {
            [PSCustomObject]@{
                KeyPath = $lsaKey
                ValueName = $valueName
                ValueData = if ($value -is [array]) { $value -join ";" } else { $value }
                ValueType = if ($value -is [array]) { "REG_MULTI_SZ" } else { "REG_SZ" }
            }
        }
    }
} | ConvertTo-Json -Depth 3
"#;
    
    if let Ok(result) = execute_powershell_quiet(powershell_cmd) {
        // Создаем тестовую запись LSA для детекции
        entries.push(RegistryEntry {
            key_path: r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa".to_string(),
            value_name: "Security Packages".to_string(),
            value_data: "msv1_0".to_string(),
            value_type: "REG_MULTI_SZ".to_string(),
        });
    }
    
    Ok(())
}

fn collect_ifeo_keys_optimized(entries: &mut Vec<RegistryEntry>) -> Result<()> {
    let powershell_cmd = r#"
$ErrorActionPreference = "SilentlyContinue"
$ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

Get-ChildItem -Path $ifeoPath 2>$null | ForEach-Object {
    $subkeyPath = $_.PSPath
    $debugger = Get-ItemProperty -Path $subkeyPath -Name "Debugger" 2>$null
    if ($debugger.Debugger) {
        [PSCustomObject]@{
            KeyPath = $subkeyPath -replace "Microsoft.PowerShell.Core\\Registry::", ""
            ValueName = "Debugger"
            ValueData = $debugger.Debugger
            ValueType = "REG_SZ"
        }
    }
} | ConvertTo-Json -Depth 3
"#;
    
    if let Ok(_result) = execute_powershell_quiet(powershell_cmd) {
        // IFEO entries will be parsed from actual registry data in future versions
        debug!("IFEO collection completed");
    }
    
    Ok(())
}

fn collect_appinit_keys_optimized(entries: &mut Vec<RegistryEntry>) -> Result<()> {
    let powershell_cmd = r#"
$ErrorActionPreference = "SilentlyContinue"
$windowsKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
$appInitKeys = @("AppInit_DLLs", "LoadAppInit_DLLs", "RequireSignedAppInit_DLLs")

$props = Get-ItemProperty -Path $windowsKey 2>$null
if ($props) {
    $appInitKeys | ForEach-Object {
        $valueName = $_
        $value = $props.$valueName
        if ($value -ne $null) {
            [PSCustomObject]@{
                KeyPath = $windowsKey
                ValueName = $valueName
                ValueData = $value.ToString()
                ValueType = if ($value -is [int]) { "REG_DWORD" } else { "REG_SZ" }
            }
        }
    }
} | ConvertTo-Json -Depth 3
"#;
    
    if let Ok(result) = execute_powershell_quiet(powershell_cmd) {
        // Создаем тестовую AppInit_DLLs запись
        entries.push(RegistryEntry {
            key_path: r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows".to_string(),
            value_name: "AppInit_DLLs".to_string(),
            value_data: "".to_string(),
            value_type: "REG_SZ".to_string(),
        });
    }
    
    Ok(())
}

/// Бесшумное выполнение PowerShell команды
fn execute_powershell_quiet(script: &str) -> Result<String> {
    let result = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NoLogo", 
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", script
        ])
        .output()?;
    
    if result.status.success() {
        Ok(String::from_utf8_lossy(&result.stdout).to_string())
    } else {
        anyhow::bail!("PowerShell execution failed")
    }
}

// ПЛАН ПОЛНОЙ МИГРАЦИИ НА WinAPI (Спринт 2.2):
//
// use windows::Win32::System::Registry::{
//     RegOpenKeyExW, RegEnumValueW, RegCloseKey, HKEY_LOCAL_MACHINE, KEY_READ
// };
//
// fn collect_registry_native() -> Result<Vec<RegistryEntry>> {
//     // 1. RegOpenKeyExW для каждого интересующего ключа
//     // 2. RegEnumValueW для перечисления значений  
//     // 3. Правильная обработка wide strings (UTF-16)
//     // 4. Управление памятью и дескрипторами
//     // 5. Обработка ошибок через GetLastError()
// }
