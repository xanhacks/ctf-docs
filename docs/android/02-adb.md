---
title: adb cheatsheet
description: adb cheatsheet with examples.
---

# adb (Android Debug Bridge)

[adb](https://developer.android.com/studio/command-line/adb) is a versatile command-line tool that lets you communicate with a device. The adb command facilitates a variety of device actions, such as installing and debugging apps, and it provides access to a Unix shell that you can use to run a variety of commands on a device.

It is a client-server program that includes three components:

- A **client**, which sends commands. The client runs on your development machine. You can invoke a client from a command-line terminal by issuing an adb command.

- A **daemon** (adbd), which runs commands on a device. The daemon runs as a background process on each device.

- A **server**, which manages communication between the client and the daemon. The server runs as a background process on your development machine.

**adb** is included in the Android SDK Platform-Tools package.

## Basic commands

```shell
$ adb devices 
List of devices attached
192.168.56.103:5555     device

$ adb devices -l
List of devices attached
192.168.56.103:5555    device product:vbox86p model:Google_Pixel_3 device:vbox86p transport_id:3

$ adb -s 192.168.56.103:5555 shell
$ adb –d shell                        # only attached USB device
$ adb –e shell                        # only attached emulator
```

## Install / Run an application

```shell
$ adb install sieve.apk
Performing Push Install
sieve.apk: 1 file pushed, 0 skipped. 179.8 MB/s (367886 bytes in 0.002s)
        pkg: /data/local/tmp/sieve.apk
Success
$ adb shell am start -n com.mwr.example.sieve/com.mwr.example.sieve.MainLoginActivity
Starting: Intent { cmp=com.mwr.example.sieve/.MainLoginActivity }

$ adb shell am start -a com.example.ACTION_NAME -n com.package.name/com.package.name.ActivityName
```

## Logs (logcat)

[Official logcat docs](https://developer.android.com/studio/command-line/logcat)

```shell
adb logcat
adb logcat -c               # clear current logs
adb logcat -d > output      # Save the logcat output to a file on the local system.
adb bugreport > output      # Dump the whole device information like dumpstate, dumpsys and logcat output.
```

Display all log messages on a specific **pid** (process id) :

```shell
$ adb shell ps | grep gallery
u0_a100       3319   287 1385884 115136 ep_poll      f277dbb9 S com.android.gallery3d
$ adb logcat --pid 3319
--------- beginning of main
05-17 05:26:06.685  3319  3319 I Zygote  : seccomp disabled by setenforce 0
05-17 05:26:06.689  3319  3319 W droid.gallery3: Unexpected CPU variant for X86 using defaults: x86
05-17 05:26:06.854  3319  3319 D ApplicationLoaders: Returning zygote-cached class loader: /system/framework/android.hidl.base-V1.0-java.jar
05-17 05:26:06.854  3319  3319 D ApplicationLoaders: Returning zygote-cached class loader: /system/framework/android.hidl.manager-V1.0-java.jar
05-17 05:26:06.854  3319  3319 D ApplicationLoaders: Returning zygote-cached class loader: /system/framework/android.hidl.base-V1.0-java.jar
05-17 05:26:06.859  3319  3319 I droid.gallery3: The ClassLoaderContext is a special shared library.
```

Display all log messages with priority level *warning* and higher, on all tags :

```shell
$ adb logcat "*:W"
```

## Android version

```shell
$ adb shell getprop ro.build.version.release
11
```

## Files Push / Pull

```shell
adb push <computer_src> <device_dst>
adb pull <device_src> <computer_dst>
```

## List packages

```shell
$ adb shell pm list packages
...
$ adb -s emulator-5554 shell pm list packages | grep "chrome"
package:com.android.chrome
```

## Disable APK verification

- Set *verifier_verify_adb_installs* to 0.

```shell
$ adb install de.lotum.whatsinthefoto.fr.apk 
Performing Streamed Install
adb: failed to install de.lotum.whatsinthefoto.fr.apk: Failure [INSTALL_FAILED_VERIFICATION_FAILURE]
$ adb shell settings put global verifier_verify_adb_installs 0
$ adb install de.lotum.whatsinthefoto.fr.apk 
Performing Streamed Install
Success
```

### References

- https://developer.android.com/studio/command-line/adb
- https://www.automatetheplanet.com/adb-cheat-sheet/
- https://gist.github.com/Pulimet/5013acf2cd5b28e55036c82c91bd56d8
