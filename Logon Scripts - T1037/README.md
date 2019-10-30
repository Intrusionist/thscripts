# **Logon Scripts - T1037**
---
### 1. Logon Scripts Windows
Syntax
```
REG.exe ADD HKCU\Environment /v UserInitMprLogonScript /t REG_MULTI_SZ /d "#{script_command}"
REG.exe DELETE HKCU\Environment /v UserInitMprLogonScript /f
```
Command Execution
```
REG.exe ADD HKCU\Environment /v UserInitMprLogonScript /t REG_MULTI_SZ /d "C:\Windows\System32\calc.exe"
REG.exe DELETE HKCU\Environment /v UserInitMprLogonScript /f
```
regex for detection
```
(?i).*reg.exe.*add.*hkcu\\\\environment.*\/v.*userinitmprlogonscript.*reg\_multi\_sz.*
(?i).*reg.*delete.*hkcu\\\\environment.*\/v.*userinitmprlogonscript.*\/f.*
```
DNIF QUERY
```
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*reg.exe.*add.*hkcu\\\\environment.*\/v.*userinitmprlogonscript.*reg\_multi\_sz.*)i limit 100
_fetch * from event where $LogName=WINDOWS-SYSMON AND $EventID=1 AND $Process=regex(.*reg.*delete.*hkcu\\\\environment.*\/v.*userinitmprlogonscript.*\/f.*)i limit 100
```
