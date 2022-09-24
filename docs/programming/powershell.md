---
title: Powershell
description: Powershell cheatsheet for pentester.
---

# Powershell

## Host discovery

### Ping scanner

```powershell
PS C:\Windows\system32> for($i=0;$i -lt 30;$i++){ echo "172.16.2.$i :"; (New-Object System.Net.Networkinformation.ping).Send("172.16.2.$i").Status }
172.16.2.0 :
DestinationHostUnreachable
172.16.2.1 :
TimedOut
172.16.2.2 :
DestinationHostUnreachable
172.16.2.3 :
DestinationHostUnreachable
172.16.2.4 :
DestinationHostUnreachable
172.16.2.5 :
Success
[...]
```