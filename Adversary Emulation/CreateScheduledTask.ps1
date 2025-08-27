$taskName = "Print Spooler"

$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -w hidden -c start-process C:\Windows\System32\calc.exe"

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force

Start-Sleep -Seconds 5

Start-ScheduledTask -TaskName $taskName
