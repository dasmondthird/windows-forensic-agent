# 🕵️ Windows Forensic Agent

**Comprehensive Windows System Reconnaissance Tool**

## 🎯 Overview

A powerful forensic agent for Windows system reconnaissance that collects comprehensive system intelligence without threat analysis. Pure data collection mode for incident response and security assessment.

## ✅ Features

- **16+ Specialized Collectors** for complete system mapping
- **Pure Reconnaissance Mode** - clean data without analysis
- **JSON Output Format** for easy integration
- **PowerShell-Based Collection** for maximum compatibility
- **Comprehensive Coverage** of Windows components
- **Error Handling & Logging** for reliable operation

## 📊 Data Collection Areas

- Windows Services & Registry
- Running Processes & Network Connections  
- Browser Data & Extensions
- Crypto Wallet Detection
- System Configuration & Events
- File Artifacts & Certificates
- WMI Subscriptions & Scheduled Tasks

## 🚀 Quick Start

```powershell
# Build the project
cargo build --release

# Run full reconnaissance
.\target\release\forensic-agent.exe --output my-reconnaissance

# View results
Get-Content .\my-reconnaissance\reconnaissance.json
```

## 📈 Sample Results

- **Data Volume**: 185KB (4,745 lines) of system intelligence
- **Execution Time**: ~10-11 seconds for complete scan
- **Output Format**: Structured JSON for analysis tools

## 🔧 Requirements

- Windows 10/11
- Rust 2021 Edition
- PowerShell 5.0+
- Administrator privileges (recommended)

## 📝 Output Structure

```json
{
  "metadata": {
    "collection_mode": "pure_reconnaissance",
    "hostname": "...",
    "timestamp": "...",
    "username": "..."
  },
  "system_artifacts": {
    "services": [...],
    "registry_entries": [...],
    "network_connections": [...],
    "browser_extensions": [...],
    "crypto_wallets": [...],
    ...
  }
}
```

## 🛡️ Security

This tool operates in **pure reconnaissance mode** - it only collects and reports system data without performing any analysis or generating threat indicators. Perfect for forensic investigation and system auditing.

---

**Built with Rust 🦀 | Windows-focused 🪟 | Forensics-ready 🔍**
