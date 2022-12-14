---
title: Sandbox evasion
description: Introduction to C# sandbox evasion
---

# Sandbox Evasion

## Sleep

```csharp
/**
* Sleep for a certain amounts of seconds.
*/
private void Sleep(int seconds)
{
    Thread.Sleep(seconds * 1000);
}
```

## Mouse is moving

```csharp
using System.Runtime.InteropServices;

// ...

[DllImport("user32.dll")]
static extern bool GetCursorPos(out Point lpPoint);

public Point GetMousePosition()
{
    GetCursorPos(out Point lpPoint);
    return lpPoint;
}

[StructLayout(LayoutKind.Sequential)]
public struct Point
{
    public int X;
    public int Y;
}

/**
* Exit the program if the position of the mouse has not changed in 30 seconds.
*/
public void CheckMouseIsMoving()
{
    Point mousePosition = this.GetMousePosition();
    this.Sleep(30);
    Point newMousePosition = this.GetMousePosition();

    if (mousePosition.X == newMousePosition.X &&
        mousePosition.Y == newMousePosition.Y) Environment.Exit(1337);
}
```

## Numbers of CPUs

```csharp
/**
* Exit the program if the number of CPU is below or equals to 2.
*/
public void CheckCPUCount()
{
    if (Environment.ProcessorCount <= 2) Environment.Exit(1337);
}
```


## Presence of Debugger

```csharp
using System.Diagnostics;

// ...

/**
* Exit the program if a debugger is attached to the process.
*/
public void CheckDebugger()
{
    if (Debugger.IsAttached) Environment.Exit(1337);
}
```

## Uptime

```csharp
/**
*  Exit the program if the uptime is less than 15 minutes.
*/
public void CheckUptime()
{
    int uptime = (Environment.TickCount & Int32.MaxValue) / 1000;
    if (uptime / 60 < 15) Environment.Exit(1337);
}
```
