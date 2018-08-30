# Powershell Execution Bypass

What is Powershell ?
-------------------
PowerShell is an object-oriented automation engine and scripting language with an interactive command-line shell that Microsoft developed to help IT professionals configure systems and automate administrative tasks.

What is Powershell Execution Policy ?
---------------------------------------
The PowerShell execution policy is the setting that determines which type of PowerShell scripts (if any) can be run on the system.
There are 4 type of Execution policy
1. RemoteSigned
2. AllSigned
3. Undefined
4. Restricted

To check the Execution Policy Fire this command.

Get-ExecutionPolicy

 ```Proof of Concept```


![poweshellpolicy](https://user-images.githubusercontent.com/42810123/44849436-bdc9ba00-ac77-11e8-8b35-828839ba0a49.JPG)

### Ways to bypass Execution Policies

1. PowerShell.exe -noprofile -
2. powershell -nop
3. Powershell -command "Command"
4. Powershell -c
5. powershell.exe -EncodedCommand $EncodedCommand
6. invoke-command -scriptblock {Command}
7. invoke-command -computername Computername -scriptblock {get-executionpolicy} | set-executionpolicy -force
8. Get-Content .powershellfile.ps1 | Invoke-Expression
9. GC .powershellfile.ps1 | iex
10. PowerShell.exe -ExecutionPolicy Bypass
11. PowerShell.exe -ExecutionPolicy UnRestricted
12. PowerShell.exe -ExecutionPolicy Remote-signed
13. Disable-ExecutionPolicy
14. Powershell.exe Set-ExecutionPolicy Bypass
15. Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
16. Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
17. Powershell.exe -Exec Bypass
17. Changing the Registry : HKEY_CURRENT_USER\Software\MicrosoftPowerShell\1\ShellIds\Microsoft.PowerShell
