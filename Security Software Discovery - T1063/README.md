#  **Security Software Discovery - T1063**
---
### 1. Security Software Discovery
Command Execution
```
netsh.exe advfirewall firewall show all profiles
tasklist.exe
tasklist.exe | findstr /i virus
tasklist.exe | findstr /i cb
tasklist.exe | findstr /i defender
tasklist.exe | findstr /i cylance
```
> can't detect piped event as a part of 1 event.

regex for detection
```
(?i).*netsh\.exe.*advfirewall.*show.*all.*profile.*
```
DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*netsh\.exe.*advfirewall.*show.*all.*profile.*)i limit 100
```
---
### 2. Security Software Discovery - Sysmon Service
Command Execution
```
fltmc.exe | findstr.exe 385201
```
regex for detection
```
(?i).*385201.*
(?i).*fltmc.exe.*
```
> both log detected by regex pattern should have same parent process.

DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*385201.*)i group count_unique $DevSrcIP, $CPID, $PPID as #A limit 100
>>_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*fltmc.exe.*)i group count_unique $DevSrcIP, $CPID, $PPID as #B limit 100
>>_agg count_unique $DevSrcIP, $PPID
>>_checkif int_compare count_unique > 1 include
```
