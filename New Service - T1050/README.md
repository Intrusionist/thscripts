# **New Service - T1050**
---
### 1. Service Installation
Syntax
```
sc.exe create #{service_name} binPath= #{binary_path}
sc.exe start #{service_name}
sc.exe stop #{service_name}
sc.exe delete #{service_name}
```
Command Execution
```
sc.exe create antivirus binPath=C:\Windows\System32\calc.exe
sc.exe start antivirus
sc.exe stop antivirus
sc.exe delete antivirus
```
regex for detection
```
(?i).*sc.*create.*binpath.*
(?i).*sc.*(start|stop|delete).*
```
DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*sc.*create.*binpath.*)i limit 100
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*sc.*(start|stop|delete).*)i limit 100
```
---
### 2. Service Installation PowerShell Installs A Local Service using PowerShell
Syntax
```
New-Service -Name "#{service_name}" -BinaryPathName "#{binary_path}"
Start-Service -Name "#{service_name}"
Stop-Service -Name "#{service_name}"
(Get-WmiObject Win32_Service -filter "name='#{service_name}'").Delete()
```
Command Execution
```
powershell.exe New-Service -Name antivirus -BinaryPathName "C:\Windows\System32\calc.exe"
powershell.exe Start-Service -Name "antivirus"
powershell.exe Stop-Service -Name "antivirus"
```
regex for detection
```
(?i)*powershell.*new\-Service.*\-binarypathname.*
(?i).*powershell.*(Start\-Service|Stop\-Service).*\-Name.*
```
DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*powershell.*new\-Service.*\-binarypathname.*)i limit 100
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*powershell.*(Start\-Service|Stop\-Service).*\-Name.*)i limit 100
```
