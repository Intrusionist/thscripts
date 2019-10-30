# **Process Injection - T1055**
---
### 1. Process Injection via mavinject.exe
Syntax
```
mavinject #{process_id} /INJECTRUNNING #{dll_payload}
```
> Don't test with malicious dll.

> You can use already available dll payload from file system.

> use dumpmon to get pid and process

Command Execution
```
mavinject 4700 /INJECTRUNNING C:\Users\DNIF\Downloads\T1055.dll
```
regex for detection
```
(?i).*mavinject.*\.dll.*
```
DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*mavinject.*\.dll.*)i limit 100
```
---
### 2. Process Injection via PowerSploit
Syntax
```
Invoke-DllInjection.ps1 -ProcessID #{process_id} -Dll #{dll_payload}
```
Command Execution
```
powershell.exe -exec bypass C:\Users\DNIF\Downloads\PowerSploit-master\PowerSploit-master\CodeExecution\Invoke-DllInjection.ps1 -ProcessID 4700 C:\Users\DNIF\Downloads\T1055.dll
```
regex for detection
```
(?i).*powershell.*\-exec.*bypass.*\.ps1.*\-processid.*\-dll.*
```
DNIF QUERY
```
_fetch * from event where $Duration=1h AND $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*powershell.*\-exec.*bypass.*\.ps1.*\-processid.*\-dll.*)i group count_unique $App, $Process, $ParentProcess, $DevSrcIP limit 100
```
