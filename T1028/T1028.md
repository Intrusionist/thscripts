
# **T1028 - Windows Remote Management**
---

### 1.  Enable Windows Remote Management
 Command Execution
```
powershell.exe Enable-PSRemoting -SkipNetworkProfileCheck -Force
```

```
powershell.exe Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -RemoteAddress Any
```

regex for detection
```
(?i).*powershell.*Enable-PSRemoting.*-Force.*
```

DNIF QUERY
```
_fetch * from event where $Duration=1h AND $Process=regex(.*powershell.*Enable-PSRemoting.*-Force.*)i group count_unique $Process, $ParentProcess, $App limit 100
```
---
### 2. PowerShell Lateral Movement
Syntax
```
powershell.exe [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.application","#{computer_name}")).Document.ActiveView.ExecuteShellCommand("c:\windows\system32\calc.exe", $null, $null, "7")

```
 Command Execution
```
powershell.exe [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.application","DESKTOP-CBP7A7L")).Document.ActiveView.ExecuteShellCommand("c:\windows\system32\calc.exe", $null, $null, "7")
```
regex for detection

```
(?i).*powershell.exe.*CreateInstance.*MMC20.*Document\.ActiveView\.ExecuteShellCommand.*
```

DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(powershell.exe.*CreateInstance.*MMC20.*Document\.ActiveView\.ExecuteShellCommand.*)i group count_unique $Process, $ParentProcess, $App limit 100
```
---
### 3. WMIC Process Call Create
Syntax
```
wmic /user:usename /password:password /node:"#{computer_name}" process call create "C:\Windows\system32\reg.exe add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe\" /v \"Debugger\" /t REG_SZ /d \"cmd.exe\" /f"
```

> Enter username password and node = computername
please use double quotes in node if you have - in your computername

Command Execution

```
wmic /user:administrator /password:password /node:"DESKTOP-CBP7A7L" process call create "C:\Windows\system32\reg.exe add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe\" /v \"Debugger\" /t REG_SZ /d \"cmd.exe\" /f"

```

regex for detection

```
(?i).*wmic.*\/user.*\/password.*\/node.*process call create.*
```

DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*wmic.*\/user.*\/password.*\/node.*process call create.*)i group count_unique $Process, $ParentProcess, $App limit 100
```
---

### 4. Psexec
Syntax
```
psexec \\host -u domain\user -p password -s cmd.exe
```

> **Note : Download psExec from sysinternal website.**

Command Execution
```
cd C:\Users\Test\Downloads\PsExec\
.\PsExec.exe \\DESKTOP-CBP7A7L -u administrator -p password -s cmd.exe
```
regex for detection

```
(?i).*psexec.*\-u.*\-s.*
```

DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*psexec.*\-u.*\-s.*)i group count_unique $Process, $ParentProcess, $App limit 100
```
---
### 5. Powershell Invoke-Command
Syntax
```
invoke-command -computer_name #{host_name} -scriptblock {#{remote_command}}
```
Command Execution
```
 powershell.exe invoke-command -ComputerName "DESKTOP-CBP7A7L" -scriptblock {calc.exe}
```

> Computername should we your hostname

regex for detection
```
(?i).*powershell.*invoke\-command.*\-ComputerName.*scriptblock.*
```

DNIF QUERY
```
 _fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*powershell.*invoke\-command.*\-ComputerName.*scriptblock.*)i AND $Duration=1h group count_unique $Process, $ParentProcess, $App limit 1000
 ```
