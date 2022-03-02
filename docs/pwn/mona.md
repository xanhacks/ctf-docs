

```
bp 0x62501203
!mona config -set workingfolder c:\mona\%p


!mona bytearray -b "\x00"
!mona compare -f C:\mona\oscp\bytearray.txt -a <address>

!mona jmp -r esp -cpb "\x00\xa9\xcd\xd4"
```