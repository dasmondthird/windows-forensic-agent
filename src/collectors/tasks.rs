use crate::types::ScheduledTask;
use crate::utils::execute_powershell_quiet;
use anyhow::Result;

pub fn collect() -> Result<Vec<ScheduledTask>> {
    // Use PowerShell for now - more reliable than COM in Windows 0.52
    collect_via_powershell()
}

fn collect_via_powershell() -> Result<Vec<ScheduledTask>> {
    let powershell_cmd = r#"
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | ForEach-Object {
    $task = $_
    $taskInfo = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Name = $task.TaskName
        Path = $task.TaskPath
        Author = $task.Author
        Hidden = $task.State -eq "Hidden"
        Enabled = $task.State -ne "Disabled"
        LastRunTime = if($taskInfo) { $taskInfo.LastRunTime.ToString() } else { "Never" }
        NextRunTime = if($taskInfo) { $taskInfo.NextRunTime.ToString() } else { "Unknown" }
        LastResult = if($taskInfo) { $taskInfo.LastTaskResult } else { 0 }
        State = $task.State
        Actions = @($task.Actions | ForEach-Object { $_.Execute })
    }
} | ConvertTo-Json -Depth 3
"#;

    let output = execute_powershell_quiet(powershell_cmd)?;
    let output_str = String::from_utf8_lossy(&output.stdout);
    let tasks_data: serde_json::Value = serde_json::from_str(&output_str)?;
    
    let mut tasks = Vec::new();
    
    if let Some(tasks_array) = tasks_data.as_array() {
        for task_data in tasks_array {
            if let Some(task) = parse_task_data(task_data) {
                tasks.push(task);
            }
        }
    } else if let Some(task) = parse_task_data(&tasks_data) {
        tasks.push(task);
    }
    
    Ok(tasks)
}

fn parse_task_data(data: &serde_json::Value) -> Option<ScheduledTask> {
    let name = data.get("Name")?.as_str()?.to_string();
    let path = data.get("Path")?.as_str()?.to_string();
    let author = data.get("Author").and_then(|a| a.as_str()).map(|s| s.to_string());
    let hidden = data.get("Hidden")?.as_bool().unwrap_or(false);
    let enabled = data.get("Enabled")?.as_bool().unwrap_or(false);
    let last_run_time = data.get("LastRunTime")?.as_str()?.to_string();
    let next_run_time = data.get("NextRunTime")?.as_str()?.to_string();
    let last_result = data.get("LastResult")?.as_i64().unwrap_or(0) as i32;
    let state = data.get("State")?.as_str()?.to_string();
    
    // Parse actions array
    let mut actions = Vec::new();
    if let Some(actions_array) = data.get("Actions").and_then(|a| a.as_array()) {
        for action_path in actions_array {
            if let Some(path_str) = action_path.as_str() {
                actions.push(crate::types::TaskAction {
                    action_type: "Execute".to_string(),
                    execute: path_str.to_string(),
                    arguments: None,
                    working_directory: None,
                });
            }
        }
    }
    
    Some(ScheduledTask {
        name,
        path,
        author,
        hidden,
        enabled,
        triggers: vec![], // Simplified for now
        actions,
        last_run: if last_run_time == "Never" { None } else { Some(last_run_time.clone()) },
        next_run: if next_run_time == "Unknown" { None } else { Some(next_run_time.clone()) },
        last_result: Some(last_result),
        user_context: "Unknown".to_string(), // Not easily available via PowerShell
        run_level: "Unknown".to_string(), // Not easily available via PowerShell
        last_run_time,
        next_run_time,
        state,
    })
}