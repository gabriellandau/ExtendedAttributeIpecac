# Extended Attribute Ipecac

By [Gabriel Landau](https://twitter.com/GabrielLandau) @ [Elastic Security Labs](https://www.elastic.co/security-labs/).

Removes [`$Kernel.Purge` Extended Attributes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/kernel-extended-attributes#auto-deletion-of-kernel-extended-attributes) from the given file.  Attempts to use TxF to reduce the consequence of failure, but falls back to YOLO mode.

## Credit
Idea courtesy of [@sixtyvividtails](https://twitter.com/sixtyvividtails) and inspired by [BBQ master @jonasLyk](https://twitter.com/jonasLyk) in this [conversation](https://twitter.com/GabrielLandau/status/1678813817545826305).

## Example Usage

```
C:\Users\user\Desktop>fsutil file queryEA C:\Windows\System32\ntdll.dll

Extended Attributes (EA) information for file C:\Windows\System32\ntdll.dll:

Total Ea Size: 0x10b

Ea Buffer Offset: 0
Ea Name: $CI.CATALOGHINT
Ea Value Length: 65
0000:  01 00 61 00 4d 69 63 72  6f 73 6f 66 74 2d 57 69  ..a.Microsoft-Wi
0010:  6e 64 6f 77 73 2d 43 6c  69 65 6e 74 2d 44 65 73  ndows-Client-Des
0020:  6b 74 6f 70 2d 52 65 71  75 69 72 65 64 2d 50 61  ktop-Required-Pa
0030:  63 6b 61 67 65 30 35 31  36 7e 33 31 62 66 33 38  ckage0516~31bf38
0040:  35 36 61 64 33 36 34 65  33 35 7e 61 6d 64 36 34  56ad364e35~amd64
0050:  7e 7e 31 30 2e 30 2e 32  32 36 32 31 2e 31 39 39  ~~10.0.22621.199
0060:  32 2e 63 61 74                                    2.cat

Ea Buffer Offset: 80
Ea Name: $KERNEL.PURGE.ESBCACHE
Ea Value Length: 6c
0000:  6c 00 00 00 03 00 02 0c  95 8b 45 ad 5d 21 d9 01  l.........E.]!..
0010:  80 65 80 f3 ae 35 d9 01  42 00 00 00 4e 00 27 01  .e...5..B...N.'.
0020:  0c 80 00 00 20 3b d5 f1  a3 bf cc 98 c9 4e 5c 6f  .... ;.......N\o
0030:  06 df c9 b4 e3 e3 47 94  b1 0a 1d 71 61 83 c2 bf  ......G....qa...
0040:  38 1e 70 17 fa 27 00 0c  80 00 00 20 34 db f2 3f  8.p..'..... 4..?
0050:  a4 a9 12 46 9a 99 26 89  00 46 44 7e 55 4b d7 44  ...F..&..FD~UK.D
0060:  fa dc 41 ea 6c 16 92 fb  8b b6 6e b7              ..A.l.....n.

C:\Users\user\Desktop>ExtendedAttributeIpecac.exe 
Removes $Kernel.Purge EAs from the given file.

Usage: C:\git\ExtendedAttributeIpecac\x64\Release\ExtendedAttributeIpecac.exe <FILE> [--no-yolo]
        --no-yolo       Fail if the operation cannot be done with TxF.

C:\Users\user\Desktop>ExtendedAttributeIpecac.exe C:\Windows\System32\ntdll.dll
 [+] Created stream in TxF: C:\Windows\System32\ntdll.dll:RemoveKernelPurgeEAs
 [+] Reparse point created.
 [+] Reparse point removed.
 [+] Stream removed.
 [+] Transaction committed.
 [+] Operation successful.

C:\Users\user\Desktop>fsutil file queryEA C:\Windows\System32\ntdll.dll

Extended Attributes (EA) information for file C:\Windows\System32\ntdll.dll:

Total Ea Size: 0x7d

Ea Buffer Offset: 0
Ea Name: $CI.CATALOGHINT
Ea Value Length: 65
0000:  01 00 61 00 4d 69 63 72  6f 73 6f 66 74 2d 57 69  ..a.Microsoft-Wi
0010:  6e 64 6f 77 73 2d 43 6c  69 65 6e 74 2d 44 65 73  ndows-Client-Des
0020:  6b 74 6f 70 2d 52 65 71  75 69 72 65 64 2d 50 61  ktop-Required-Pa
0030:  63 6b 61 67 65 30 35 31  36 7e 33 31 62 66 33 38  ckage0516~31bf38
0040:  35 36 61 64 33 36 34 65  33 35 7e 61 6d 64 36 34  56ad364e35~amd64
0050:  7e 7e 31 30 2e 30 2e 32  32 36 32 31 2e 31 39 39  ~~10.0.22621.199
0060:  32 2e 63 61 74                                    2.cat
```
