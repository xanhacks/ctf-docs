---
title: Frida cheatsheet
description: Frida cheatsheet with examples.
---

# Frida

[Frida](https://frida.re/) is a dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.
This tool allows you to inject your own scripts into black box processes. Hook any function, spy on crypto APIs or trace private application code, no source code needed.

![frida logo](https://frida.re/img/logotype.svg)

## Frida setup

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

## Functions Hooking

### Java functions

> Challenge `frida-me` from `404CTF`.

Example with PIN Bruteforce :

```js
let mainActivityName = "de.hallebar.secretz.MainActivity";
let min = 0;
let max = 99999999;

console.log("Hook loaded !");

Java.perform(function() {
    let mainActivity = Java.use(mainActivityName);

    mainActivity.complicatedCheckerPleaseDontReverse.overload("int").implementation = function (arg) {
        console.log("\n[*] call complicatedCheckerPleaseDontReverse(" + arg + ")");

        for (let i = min; i < max; i++) {
            try {
                this.complicatedCheckerPleaseDontReverse(i);
            } catch (e) {
                if (e == "Error: invalid string") {
                    console.log("PIN Found : " + i);
                    break;
                }
            }
        }

        return "hooked!";
    };
});
```

```bash
$ frida -D emulator-5554 -l brute_pin.js -f de.hallebar.secretz --no-pause
     ____
    / _  |   Frida 15.1.24 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Android Emulator 5554 (id=emulator-5554)
Spawning `de.hallebar.secretz`...
Hook loaded !
Spawned `de.hallebar.secretz`. Resuming main thread!
[Android Emulator 5554::de.hallebar.secretz ]->
[*] call complicatedCheckerPleaseDontReverse(1234)
PIN Found : 1474560
```

### Native functions

Find the function name in the native library :

```bash
$ nm -C --dynamic HallebardeSecretz/lib/x86/libsecretz.so | grep DecryptCBC
0001b770 T AES::DecryptCBC(unsigned char const*, unsigned int, unsigned char const*, unsigned char const*)
...

$ nm --dynamic HallebardeSecretz/lib/x86/libsecretz.so | grep '0001b770'
0001b770 T _ZN3AES10DecryptCBCEPKhjS1_S1_
```

hook.js :

```js
Interceptor.attach(Module.getExportByName(libName, '_ZN3AES10DecryptCBCEPKhjS1_S1_'), {
    onEnter: function(args) {
        console.log("[*] libsecretz.so: AES::DecryptCBC()");
        console.log("args[0] : " + args[0]);
        console.log(hexdump(args[0]));

        console.log("args[1] : " + args[1]);
        console.log(hexdump(args[1]));

        console.log("args[2] (int32) : " + args[2].toInt32());
        // ...
    },
    onLeave: function(retval) {
        console.log("retval : " + retval);
        console.log(hexdump(retval));
    }
});
```

More examples on this [blog](https://x3tb3t.github.io/2018/08/03/Frida-for-Android/).


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