$taskName = "Print Spooler"

$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -w hidden -c start-process calc.exe"

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force

Start-Sleep -Seconds 5

Start-ScheduledTask -TaskName $taskName
