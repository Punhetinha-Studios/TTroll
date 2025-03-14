# VS.VULN

**VS.VULN** exploits vulnerabilities in Visual Studio events, targeting project files like `.vcxproj`, `.csproj`, etc.

## Features

### 1. **Using Events**

Executes arbitrary commands when the specified input trigger is activated (ex: `GetFrameworkPaths`, `Compile`, `BeforeBuild`)

#### WARNING: Deleting the lines which contains the modified XML will break it.

(CLI) Example of **Module 1 (Project)** usage: 
```
vsvuln --module=1 --path=C:\Anywhere\Project.csproj --trigger=Compile --command="start calc.exe" --ps=false
```
Opens calc.exe when the user compiles project.

### 2. **Using compiled .suo**
Executes arbitrary commands when user opens project.

#### WARNING: Deleting the .vs folder/.suo file will break it.

(CLI) Example of **Module 2 (Compiled Suo)** usage:
```
vsvuln --module=2 --path=C:\Anywhere\.suo --command="cmd /c start calc.exe"
```
Opens calc.exe when the user opens project.

## Credits
The vulnerability has been discovered by cjm00n (https://github.com/cjm00n) & edwardzpeng (https://x.com/edwardzpeng)

VS.DE Visual Studio .suo Deserialization Exploit - https://github.com/moom825/visualstudio-suo-exploit
