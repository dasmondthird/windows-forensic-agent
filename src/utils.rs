use anyhow::Result;
use std::process::Command;

pub fn execute_powershell(command: &str) -> Result<String> {
    let output = Command::new("powershell")
        .args(["-Command", command])
        .output()?;
    
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        anyhow::bail!("PowerShell command failed: {}", String::from_utf8_lossy(&output.stderr))
    }
}

pub fn execute_powershell_quiet(command: &str) -> Result<std::process::Output> {
    Command::new("powershell")
        .args(["-Command", command])
        .output()
        .map_err(Into::into)
}
