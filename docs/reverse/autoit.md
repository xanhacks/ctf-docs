# AutoIt

## Definition

AutoIt is a free, open-source programming language designed for automating the Windows graphical user interface (GUI). It was developed in 1999 as a way for non-programmers to create simple automation scripts for tasks such as clicking buttons, filling out forms, and performing other repetitive tasks. It has been used by some malware developers to create malicious scripts and executables because it is relatively easy to learn and use.

AutoIt uses a BASIC-like syntax and includes a number of built-in functions for interacting with the Windows GUI, such as sending mouse clicks and keystrokes, controlling windows and processes, and reading and writing to the clipboard. AutoIt scripts can be compiled into standalone executables, making it easy to distribute automation scripts to other users.

You can install `AutoIt` on [www.autoitscript.com](https://www.autoitscript.com/site/autoit/downloads/).

## Compiler

You can use the `Aut2exe.exe` to compile AutoIt scripts (`.au3`).

```
Aut2exe.exe /in <infile.au3> [/out <outfile.exe>] [/icon <iconfile.ico>] [/comp 0-4] [/nopack] [/x64] [/bin <binfile.bin>]
```

Example of usage :

```
"C:\Program Files (x86)\AutoIt3\Aut2Exe\Aut2exe.exe" /in debug.au3 /out debug.exe /console
```

## Decompiler

You can use the [Exe2Aut](https://github.com/JacobPimental/exe2aut) decompiler.

Simply drag & drop your AutoIt executable on this application to obtain the `.au3` source code.

## Language

Here is some useful AutoIt functions :

- [ConsoleWrite ( "data" )]() : Writes data to the STDOUT stream (only for console application).
- [MsgBox ( flag, "title", "text" [, timeout = 0 [, hwnd]] )](https://www.autoitscript.com/autoit3/docs/functions/MsgBox.htm) : Displays a simple message box with optional timeout.
- [StringMid ( "string", start [, count = -1] )](https://www.autoitscript.com/autoit3/docs/functions/StringMid.htm) : Extracts a number of characters from a string.
- [DllStructCreate ( Struct [, Pointer] )](https://www.autoitscript.com/autoit3/docs/functions/DllStructCreate.htm) : Creates a C/C++ style structure to be used in DllCall.
- [DllStructSetData ( Struct, Element, value [, index] )](https://www.autoitscript.com/autoit3/docs/functions/DllStructSetData.htm) : Sets the data of an element in the struct.
- [DllCall ( "dll", "return type", "function" [, type1, param1 [, type n, param n]] )](https://www.autoitscript.com/autoit3/docs/functions/DllCall.htm) : Dynamically calls a function in a DLL.

Most used AutoIt functions according to ChatGPT :

- `ControlClick`: Simulates a mouse click on a control.
- `ControlSend`: Sends keystrokes to a control.
- `ControlSetText`: Sets the text of a control.
- `WinActivate`: Activates a window.
- `WinWait`: Waits for a window to appear.
- `ProcessClose`: Closes a process.
- `Run`: Launches a program or opens a file.
- `Send`: Sends keystrokes to the active window.
- `Sleep`: Pauses the script for a specified number of milliseconds.
- `FileRead`: Reads a file and returns its contents as a string.
- `FileWrite`: Writes a string to a file.

Make a comment :

```autoit
; This is a comment !
```