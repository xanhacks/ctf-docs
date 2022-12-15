# Reverse Engineering

Reverse engineering is the process of analyzing a product, system, or piece of software in order to understand how it works.

## Disable ASLR

### Linux

Disable ASLR on the whole system :

```bash
# Turn OFF
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
# Turn ON
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

### Windows

The value is stored on [IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics) at offset 0x40.

Disable ASLR on a binary (2 options) :

1. Open the binary with [PEStudio](https://pestudio.en.lo4d.com/windows), go to `optional-header` and set `address-space-layout-randomization (ASLR)` to `false`.
2. Open the binary with [CFFExplorer](https://ntcore.com/?tag=cff-explorer), go to `Optional Header`, click on `DllCharateristics` and uncheck `DLL can move`.
