---
title: Android - All in one
description: Android must-known.
---

# Android

## APK file structure

`AndroidManifest.xml`
:   Manifest file in binary XML format which contains essential information about the application. This information is consumed by the Android operating system, Google Play and Android build environment.

    This file contains the package name, permissions, android api version, activities, services, broadcast receivers, content providers, ... It can be useful to find the entrypoint of the application.

`META-INF/`
:   This folder typically contains **MANIFEST.MF**, **CERT.RSA** and **CERT.SF** files.

    CERT.RSA and CERT.SF files contain security certificates for Android application. More specifically CERT.SF contains the list of all files inside the APK with their SHA-1 digests. CERT.RSA contains public certificate of the app.

`resources.arsc`
:   File containing precompiled application resources, in binary XML.

`res/`
:   Folder containing resources not compiled into **resources.arsc**. Resources may include XML files, images, string files, icons, user interface layouts, fonts and many more. 

`assets/`
:   Optional folder containing applications assets, which can be retrieved by AssetManager.

`classes.dex`
:   Application code compiled in the dex format.

`lib/`
:   Optional folder containing compiled code - i.e. native code libraries (C/C++).

    **armeabi:** compiled code for ARM based processors<br>
    **armeabi-v7a**: compiled code for ARMv7 and above processors<br>
    **arm64-v8a**: compiled code for ARMv8 arm64 and above processors<br>
    **x86**: compiled code for x86 processors<br>
    **x86_64**: compiled code for x86_64 processors<br>
    **mips**: compiled code for MIPS processors<br>


### References

- https://openapkfile.com/structure.html
- https://www.javatpoint.com/AndroidManifest-xml-file-in-android