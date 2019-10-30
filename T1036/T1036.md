
# **T1036**
---
### 1. Masquerading as Windows LSASS process
Command Execution
```
cmd.exe /c copy %SystemRoot%\System32\cmd.exe %SystemRoot%\Temp\lsass.exe
cmd.exe /c %SystemRoot%\Temp\lsass.exe
```
regex for detection
```
(?i).*cmd.*system32.*cmd.exe.*temp.*
(?i).*c\:\\\\windows\\\\temp\\\\lsass\.exe.*
```

DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*cmd.*system32.*cmd.exe.*temp.*)i group count_unique $App, $Process, $ParentProcess limit 100

_fetch * from event where $Process=regex(c\:\\\\windows\\\\temp\\\\lsass\.exe.*)i limit 100
```
---
### 2. Masquerading - cscript.exe running as notepad.exe
Command Execution
```
cmd.exe copy %SystemRoot%\System32\cscript.exe %APPDATA%\notepad.exe /Y
cmd.exe /c %APPDATA%\notepad.exe /B
```
regex for detection
```
(?i).*copy.*system32.*cscript.exe.*appdata.*\/Y.*
(?i)*cmd.*appdata.*notepad.exe.*\/B.*
```
DNIF QUERY
```
_fetch * from event where $Process=regex(.*copy.*system32.*cscript.exe.*appdata.*\/Y.*)i limit 100

_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*cmd.*appdata.*notepad.exe.*\/B.*)i limit 100
```
---
### 3. Masquerading - wscript.exe running as svchost.exe
Command Execution
```
cmd.exe copy %SystemRoot%\System32\wscript.exe %APPDATA%\svchost.exe /Y
cmd.exe /c %APPDATA%\svchost.exe /B
```
regex for detection
```
(?i).*cmd.*copy.*system32.*wscript\.exe.*appdata.*svchost.*\/Y.*
(?i).*cmd.*appdata.*svchost.*\/B.*
```
DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*cmd.*copy.*system32.*wscript\.exe.*appdata.*svchost.*\/Y.*)i limit 100

_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*cmd.*appdata.*svchost.*\/B.*)i limit 100
```
---
### 4. Masquerading - powershell.exe running as taskhostw.exe
Command Execution
```
copy %windir%\System32\windowspowershell\v1.0\powershell.exe %APPDATA%\taskhostw.exe /Y
cmd.exe /K %APPDATA%\taskhostw.exe
```
regex for detection
```
(?i).*copy.*system32.*powershell\.exe.*appdata.*taskhostw\.exe.*\/Y.*
(?i).*cmd.*\/k.*appdata.*taskhostw\.exe.*
```
DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*copy.*system32.*powershell\.exe.*appdata.*taskhostw\.exe.*\/Y.*)i limit 100

_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*cmd.*\/k.*appdata.*taskhostw\.exe.*)i limit 100
```
