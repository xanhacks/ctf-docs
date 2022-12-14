---
title: Introduction to C#
description: Introduction to C#
---

# Introduction to C\#

## Definition

C# (pronounced "C-sharp") is a modern, object-oriented programming language developed by Microsoft. It was first released in 2000 as part of the .NET framework, and it is designed to be used for building a wide range of applications, from simple command-line programs to complex, enterprise-level applications. C# is a type-safe, managed language, meaning that the runtime environment automatically handles memory management and other low-level details, allowing developers to focus on writing code. C# is a statically-typed language, meaning that types are checked at compile-time rather than at runtime. This makes C# programs more efficient and less prone to runtime errors.

## Build

### Windows

To build dotnet project you need to install [Visual Studio](https://visualstudio.microsoft.com/).

MSDN :

- [Single-file deployment and executable](https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview?tabs=cli)
- [Trimming options](https://learn.microsoft.com/en-us/dotnet/core/deploying/trimming/trimming-options)

Command to generate a [self-contained](https://learn.microsoft.com/en-us/dotnet/core/deploying/deploy-with-cli#self-contained-deployment) PE without symbols.

```powershell
dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:DebugType=none -p:DebugSymbols=false -p:PublishTrimmed=true
```

### Linux

On Linux you can install `mono` which is a .NET compiler and runtime.

Arch : `sudo pacman -S mono`

Compilation :

```bash
$ vim Main.cs
$ mcs Main.cs
$ file Main.exe
Main.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```
