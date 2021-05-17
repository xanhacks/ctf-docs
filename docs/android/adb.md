---
title: adb cheatsheet
description: adb cheatsheet with examples.
---

Disable APK verification

```shell
$ adb install de.lotum.whatsinthefoto.fr.apk 
Performing Streamed Install
adb: failed to install de.lotum.whatsinthefoto.fr.apk: Failure [INSTALL_FAILED_VERIFICATION_FAILURE]
$ adb shell settings put global verifier_verify_adb_installs 0
$ adb install de.lotum.whatsinthefoto.fr.apk 
Performing Streamed Install
Success
```