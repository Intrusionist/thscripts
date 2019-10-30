# **Windows Management Instrumentation - T1047**
---
### 1. WMI Reconnaissance Users
Command Execution
```
wmic useraccount get /ALL
```
regex for detection
```
(?i).*wmic.*useraccount.*get.*\/ALL.*
```
DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*wmic.*useraccount.*get.*\/ALL.*)i limit 100
```
---
### 2. WMI Reconnaissance Processes
Command Execution
```
wmic process get caption,executablepath,commandline
```
regex for detection
```
(?i).*wmic.*proces.*get.*caption.*executablepath.*commandline.*
```
DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*wmic.*proces.*get.*caption.*executablepath.*commandline.*)i limit 100
```
---
### 3. WMI Reconnaissance Software
Command Execution
```
wmic qfe get description,installedOn /format:csv
```
regex for detection
```
(?i).*wmic.*qfe.*get.*description.*installedon.*
```
DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*wmic.*qfe.*get.*description.*installedon.*)i limit 100
```
---
### 4. WMI Reconnaissance List Remote Services
Syntax
```
wmic /node:"#{node}" service where (caption like "%#{service_search_string} (%")
```
Command Execution
```
wmic /node:"IP" service where (caption like "%mssql%")
```
regex for detection
```
(?i).*wmic.*node.*service.*where.*
```
DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*wmic.*node.*service.*where.*)i limit 100
```
