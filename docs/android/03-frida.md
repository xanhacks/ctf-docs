---
title: Frida cheatsheet
description: Frida cheatsheet with examples.
---

# Frida

[Frida](https://frida.re/) is a dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.
This tool allows you to inject your own scripts into black box processes. Hook any function, spy on crypto APIs or trace private application code, no source code needed.

![frida logo](https://frida.re/img/logotype.svg)

## Setup

**Prerequisite** : An emulator / physical Android device with root access.

1. Install frida on your computer.

```shell
$ python3 -m pip install frida-tools
$ frida --version
14.2.18
```

2. Download frida-server from [releases](https://github.com/frida/frida/releases) according to your device processor architecture.<br>
Example : frida-server-14.2.18-android-x86.xz

3. Extract it.

```shell
$ xz -d frida-server-14.2.18-android-x86.xz
$ file frida-server-14.2.18-android-x86
frida-server-14.2.18-android-x86: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /system/bin/linker, stripped
```

4. Push it to your device using [adb](https://developer.android.com/studio/command-line/adb).

```shell
$ adb push frida-server-14.2.18-android-x86 /data/local/tmp
frida-server-14.2.18-android-x86: 1 file pushed, 0 skipped. 8.6 MB/s (42958488 bytes in 4.766s)
```

5. Run the frida-server binary in background.

```
$ adb shell
generic_x86_arm:/ $ id
uid=2000(shell) gid=2000(shell) ...
generic_x86_arm:/ $ su
generic_x86_arm:/ # id
uid=0(root) gid=0(root) ...
generic_x86_arm:/ # cd /data/local/tmp
generic_x86_arm:/data/local/tmp # chmod 755 frida-server-14.2.18-android-x86
generic_x86_arm:/data/local/tmp # ./frida-server-14.2.18-android-x86 &
[1] 9162
generic_x86_arm:/data/local/tmp #
```

## frida-trace

[frida-trace](https://frida.re/docs/frida-trace/) is a tool for dynamically tracing function calls. 

```shell
$ adb devices
List of devices attached
192.168.119.88:5555     device
emulator-5554   device

$ frida-ps -D emulator-5554 -a | grep chrome
9214  Chrome                                 com.android.chrome
$ frida-trace -D emulator-5554 --attach-pid=9214 -i "Java_*"
Instrumenting...
Java_sun_nio_fs_LinuxWatchService_poll: Auto-generated handler at ".../Java_sun_nio_fs_LinuxWatchService_poll.js"
Java_java_io_ObjectOutputStream_doublesToBytes: Auto-generated handler at ".../Java_java_io_ObjectOutputStream__ae2f5089.js"
Java_java_io_UnixFileSystem_list0: Auto-generated handler at ".../Java_java_io_UnixFileSystem_list0.js"
Java_sun_nio_ch_EPoll_eventsOffset: Auto-generated handler at ".../Java_sun_nio_ch_EPoll_eventsOffset.js"
...
```