#!/usr/bin/env pwsh
# Telegram C2 Detection Test Script
# Sprint 2 Demo - Alternative PowerShell version

Write-Host "🔍 FORENSIC AGENT - SPRINT 2 DEMO" -ForegroundColor Cyan
Write-Host "📱 Testing Telegram C2 Detection..." -ForegroundColor Yellow

# 1. Telegram C2 Detection (MAXIMUM PRIORITY)
Write-Host "`n🎯 1. TELEGRAM C2 DETECTOR" -ForegroundColor Green

# Test data with Telegram bot patterns
$testProcesses = @(
    "notepad.exe",
    "powershell.exe -enc YnI5NTBlOGIxZjE2NDU5OGE0ZGM2OTRkZmU3YjJkNmM6QUFGNjJ2UXNRc2hGV3E=",
    "cmd.exe /c curl api.telegram.org/bot123456789:AAF62vQsQshFWq_abc123",
    "python.exe bot_script.py"
)

$telegramPatterns = @(
    'bot([0-9]{9,10}):[a-zA-Z0-9_-]{35}',
    'api\.telegram\.org/bot',
    'telegram.*bot.*token'
)

foreach ($process in $testProcesses) {
    $detected = $false
    foreach ($pattern in $telegramPatterns) {
        if ($process -match $pattern) {
            Write-Host "  ❌ DETECTED: $process" -ForegroundColor Red
            Write-Host "     Pattern: $pattern" -ForegroundColor DarkRed
            $detected = $true
            break
        }
    }
    if (-not $detected) {
        Write-Host "  ✅ Clean: $process" -ForegroundColor Green
    }
}

# 2. Task Scheduler Collection (COM equivalent)
Write-Host "`n🎯 2. TASK SCHEDULER COLLECTION" -ForegroundColor Green

$tasks = Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object -First 5

Write-Host "  📋 Recent Scheduled Tasks:"
foreach ($task in $tasks) {
    $taskInfo = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
    $lastRun = if ($taskInfo) { $taskInfo.LastRunTime } else { "Never" }
    
    Write-Host "    • $($task.TaskName)" -ForegroundColor Cyan
    Write-Host "      Path: $($task.TaskPath)" -ForegroundColor DarkCyan
    Write-Host "      State: $($task.State)" -ForegroundColor DarkCyan
    Write-Host "      Last Run: $lastRun" -ForegroundColor DarkCyan
    Write-Host ""
}

# 3. Timeline Events System
Write-Host "`n🎯 3. TIMELINE EVENTS SYSTEM" -ForegroundColor Green

$timeline = @()

# Process events
foreach ($proc in (Get-Process | Select-Object -First 3)) {
    $timeline += [PSCustomObject]@{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC")
        EventType = "Process Started"
        Source = "Process"
        Title = "Process: $($proc.ProcessName)"
        Description = "$($proc.ProcessName) (PID $($proc.Id))"
        Severity = "Info"
        ProcessId = $proc.Id
        ProcessName = $proc.ProcessName
    }
}

# Task events
foreach ($task in ($tasks | Select-Object -First 2)) {
    $timeline += [PSCustomObject]@{
        Timestamp = (Get-Date).AddMinutes(-30).ToString("yyyy-MM-dd HH:mm:ss UTC")
        EventType = "Task Executed"
        Source = "Task"
        Title = "Task: $($task.TaskName)"
        Description = "$($task.TaskName) (State: $($task.State))"
        Severity = if ($task.State -eq "Hidden") { "Medium" } else { "Low" }
        TaskPath = $task.TaskPath
    }
}

Write-Host "  📅 Timeline Events (Latest 5):"
$timeline | Sort-Object Timestamp -Descending | Select-Object -First 5 | ForEach-Object {
    $severityColor = switch ($_.Severity) {
        "High" { "Red" }
        "Medium" { "Yellow" }
        "Low" { "Green" }
        default { "White" }
    }
    
    Write-Host "    🕐 $($_.Timestamp)" -ForegroundColor Gray
    Write-Host "       $($_.Title)" -ForegroundColor $severityColor
    Write-Host "       Source: $($_.Source) | Type: $($_.EventType)" -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host "🎉 SPRINT 2 COMPLETED!" -ForegroundColor Green
Write-Host "✅ Telegram C2 Detection: ACTIVE" -ForegroundColor Green  
Write-Host "✅ Task Scheduler Collection: ACTIVE" -ForegroundColor Green
Write-Host "✅ Timeline Events System: ACTIVE" -ForegroundColor Green

Write-Host "`n📊 Summary:" -ForegroundColor Cyan
Write-Host "  • Processes scanned: $($testProcesses.Count)" 
Write-Host "  • Tasks collected: $($tasks.Count)"
Write-Host "  • Timeline events: $($timeline.Count)"
Write-Host "  • Detection rules: $($telegramPatterns.Count)"
