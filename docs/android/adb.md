---
title: adb cheatsheet
description: adb cheatsheet with examples.
---

# adb (Android Debug Bridge)

[Android Debug Bridge](https://developer.android.com/studio/command-line/adb) (adb) is a versatile command-line tool that lets you communicate with a device. The adb command facilitates a variety of device actions, such as installing and debugging apps, and it provides access to a Unix shell that you can use to run a variety of commands on a device.

It is a client-server program that includes three components:
* A **client**, which sends commands. The client runs on your development machine. You can invoke a client from a command-line terminal by issuing an adb command.
* A **daemon** (adbd), which runs commands on a device. The daemon runs as a background process on each device.
* A **server**, which manages communication between the client and the daemon. The server runs as a background process on your development machine.

adb is included in the Android SDK Platform-Tools package.

## Disable APK verification (verifier_verify_adb_installs)

```shell
$ adb install de.lotum.whatsinthefoto.fr.apk 
Performing Streamed Install
adb: failed to install de.lotum.whatsinthefoto.fr.apk: Failure [INSTALL_FAILED_VERIFICATION_FAILURE]
$ adb shell settings put global verifier_verify_adb_installs 0
$ adb install de.lotum.whatsinthefoto.fr.apk 
Performing Streamed Install
Success
```