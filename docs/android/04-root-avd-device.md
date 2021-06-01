---
title: Root an AVD Device
description: How to root an emulator from AVD (Android Virtual Device).
---

1. Create a new virtual device on AVD.

!!! warning
    Pick any image that does NOT say **Google Play** in the target column.

![Your virtual devices](/assets/img/android/your_virtual_devices.png)

You can now close *android-studio*.

2. Run the emulator.

```bash
$ $ANDROID_SDK_ROOT/emulator/emulator -list-avds
Pixel_4a_API_30
$ $ANDROID_SDK_ROOT/emulator/emulator -avd Pixel_4a_API_30

or

$ $ANDROID_SDK_ROOT/emulator/emulator @Pixel_4a_API_30
```

Wait for the device to boot, it should appear in *adb devices*.

```bash
$ $ANDROID_SDK_ROOT/platform-tools/adb devices
List of devices attached
emulator-5554   device
```

3. Restart **adbd** as root and enjoy !

```bash
$ $ANDROID_SDK_ROOT/platform-tools/adb root
restarting adbd as root
$ $ANDROID_SDK_ROOT/platform-tools/adb shell
generic_x86_arm:/ # id
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:su:s0
```