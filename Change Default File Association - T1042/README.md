# **Change Default File Association - T1042**
---
### 1. Change Default File Association
Syntax
```
cmd.exe /c assoc #{extension_to_change}="#{target_exenstion_handler}"
```
Command Execution
```
cmd.exe /c assoc .xml="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
```
regex for detection
```
(?i).*cmd.*\/c.*assoc.*\=.*
```
DNIF QUERY
```
_fetch * from event where $DevSrcIP=183.87.137.18 AND $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*cmd.*\/c.*assoc.*\=.*)i limit 100
```
