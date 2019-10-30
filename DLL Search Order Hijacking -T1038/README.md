# **DLL Search Order Hijacking - T1038**
### 1. DLL Search Order Hijacking - amsi.dll

Command Execution
```
cmd.exe copy %windir%\System32\windowspowershell\v1.0\powershell.exe %APPDATA%\updater.exe
cmd.exe copy %windir%\System32\amsi.dll %APPDATA%\amsi.dll
cmd.exe /k %APPDATA%\updater.exe
```
regex for detection
```
(?i).*copy.*system32.*powershell.*appdata.*updater.*
(?i).*copy.*system32.*amsi\.dll.*appdata.*amsi.*
(?i).*cmd.*appdata.*updater\.exe.*
```
DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*copy.*system32.*powershell.*appdata.*updater.*)i limit 100
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*copy.*system32.*amsi\.dll.*appdata.*amsi.*)i limit 100
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*cmd.*appdata.*updater\.exe.*)i limit 100
```
