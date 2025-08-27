$taskName = "Print Spooler"

$action = New-ScheduleTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -w hidden -c 'calc.exe'"

$trigger = New-ScheduleTaskTrigger -Once -At (Get-Date)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force

Start-Sleep -Seconds 5

Start-ScheduleTask -TaskName $taskName
