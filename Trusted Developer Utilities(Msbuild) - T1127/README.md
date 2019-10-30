# Msbuild Execution
---
What is MsBuild
-----
Microsoft has released a lot of binaries within the .NET framework that have the ability to compile and execute code. Originally MSBuild was introduced in order to enable developers to build products in environments where Visual Studio is not installed. Specifically this binary can compile XML C# project files since it has a method called Tasks that can execute a task which is written in a managed code. However since this method can take code and the MSBuild is a trusted Microsoft binary that can execute this code it can be abused by an attacker in order to bypass security and execute an application.

 How to Execute The Script
 ----------------------
 #### ```Run it in Command Prompt```
 C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe **file**

 ```Note```
 Replace **file** with **runcac.csproj** file path



 How The Script Works
 ----------------------
 This Script creates the temporary bat file and runs the calculator from that file
