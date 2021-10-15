---
title: Arch Linux installation
description: Arch Linux installation with i3 and disk encryption.
---

# Arch Linux installation (i3 & disk encryption)

## Create a bootable USB stick

1. Download the ISO at https://archlinux.org/download/.
2. Verify the integrity of the ISO using a checksum.
3. Burn the ISO to a USB Stick.

## Installation

Official wiki : https://wiki.archlinux.org/title/Installation_guide

### Keyboard & fonts

Setup the keymap :
```
root@archiso ~ # localectl list-keymaps | grep fr
fr
fr_CH
fr_CH-latin1
...
root@archiso ~ # loadkeys fr
```

Zoom the font (optional) :
```
root@archiso ~ # setfont ter-120n
```

### Wifi connection

Connect to wifi (you can skip this step if you are using an internet cable) :
```
root@archiso ~ # iwctl
[iwd]# device list
                           Devices
   Name
   wlan0
[iwd]# station wlan0 scan
[iwd]# station wlan0 get-networks
                           Available networks
   Network name
   wifi-13975935
[iwd]# station wlan0 connect wifi-13975935
Type the network passphrase for wifi-13975935 psk.
Passphrase: ****************
[iwd]# exit
root@archiso ~ # ip a
...
4: wlan0: ...
```

### Clock

Set the system clock :
```
root@archiso ~ # timedatectl set-ntp true
```

### Mirrors

Use the fastest mirror :
```
root@archiso ~ # reflector -c France -a 6 --sort rate --save /etc/pacman.d/mirrorlist
```

Update package databases :
```
root@archiso ~ # pacman -Syy
```

### Partitions

List all the disks (computer disk : _nvme0n1_) :
```
root@archiso ~ # lsblk
NAME    ...   MOUNTPOINTS
loop0   ...   /run/archiso/airootfs
sda     ...   /run/archiso/bootmnt
nvme0n1 ...
```

Partitions :
1. EFI system partition (size : 260M, code: ef00)
2. Linux swap (size: 4G, code: 8200)
3. Linux filesystem (size: the rest of the disk, code: 8300)

```
root@archiso ~ # gdisk /dev/nvme0n1

Command (? for help): n
Partition number (1-128, default 1): <press enter to use default>
First sector : <press enter to use default>
Last sector : +260M
Hex code or GUID : ef00

Command (? for help): n
Partition number (1-128, default 1): <press enter to use default>
First sector : <press enter to use default>
Last sector : +4G
Hex code or GUID : 8200

Command (? for help): n
Partition number (1-128, default 1): <press enter to use default>
First sector : <press enter to use default>
Last sector : <press enter to use default>
Hex code or GUID : <press enter to use default>

Command (? for help): w

Do you want to proceed? (Y/N): Y
The operation has completed successfully.
```

Format partitions :

```
root@archiso ~ # lsblk
NAME    ...   MOUNTPOINTS
loop0   ...   /run/archiso/airootfs
sda     ...   /run/archiso/bootmnt
nvme0n1
-> nvme0n1p1 260M part
-> nvme0n1p1   4G part
-> nvme0n1p1 500G part
```

Fat 32 for EFI :
```
root@archiso ~ # mkfs.fat -F32 /dev/nvme0n1p1
mkfs.fat 4.2 (2021-01-32)
```

Swap :
```
root@archiso ~ # mkswap /dev/nvme0n1p2
Setting up ...
root@archiso ~ # swapon /dev/nvme0n1p2
```

Encryption of linux FS (mapper name : cryptlinuxfs, use whatever you want):
```
root@archiso ~ # cryptsetup -y -v luksFormat /dev/nvme0n1p3

Are you sure ? YES
Enter passphrase: ...
Verify passphrase: ...
Command successful.
root@archiso ~ # cryptsetup open /dev/nvme0n1p3 cryptlinuxfs
cryptsetup open
root@archiso ~ # mkfs.ext4 /dev/mapper/cryptlinuxfs
...
root@archiso ~ # mount /dev/mapper/cryptlinuxfs /mnt
root@archiso ~ # mkdir /mnt/boot
root@archiso ~ # mount /dev/nvme0n1p1 /mnt/boot
```

You can replace `intel-ucode` by `amd-ucode`.
```
root@archiso ~ # pacstrap /mnt base linux linix-firmware vim intel-ucode
```