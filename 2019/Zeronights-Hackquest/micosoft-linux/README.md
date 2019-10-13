# Micosoft Linux

```
When we were in a bar with friends, a strange homeless-looking man came up to us and handed us two worn floppy disks. He muttered about some friend who was a time traveler. We did not understand anything, but one thing was clear to us that we needed to look at the contents of these diskettes. There was an image of the secret development of the operating system from Micosoft from 1998! When we launched this image, it required an activation code... We are asking for help to bypass the activation code. Because we are completely drunk now and don’t know where to start.
```

## Challenge analysis

After extracting the archice we get a file named `task_2.is`, let's check the type of the file:
```bash
$ file task2.iso
jD74nd8_task2.iso: ISO 9660 CD-ROM filesystem data (DOS/MBR boot sector) 'ISOIMAGE' (bootable)
```

As we could have guessed with the `.iso` extension, this file seems to be an `ISO image` of a filesystem. We can thus try to mount it and see what we found inside:
```bash
$ mount -o loop jD74nd8_task2.iso /tmp/task_2
$ tree -p /tmp/task_2
.
|-- [drwxr-xr-x]  EFI
|   `-- [drwxr-xr-x]  BOOT
|       `-- [-rw-r--r--]  startup.nsh
|-- [drwxr-xr-x]  boot
|   |-- [-rw-r--r--]  kernel.xz
|   |-- [-rw-r--r--]  rootfs.xz
|   `-- [drwxr-xr-x]  syslinux
|       |-- [-r--r--r--]  boot.cat
|       |-- [-rw-r--r--]  isolinux.bin
|       |-- [-rwxr-xr-x]  ldlinux.c32
|       `-- [-rw-r--r--]  syslinux.cfg
`-- [drwxr-xr-x]  minimal
    |-- [drwxr-xr-x]  rootfs
    |   |-- [-rw-r--r--]  README
    |   |-- [drwxr-xr-x]  bin
    |   |   `-- [-rwxr-xr-x]  activator
    |   `-- [drwxr-xr-x]  usr
    |       `-- [drwxr-xr-x]  bin
    |           `-- [-rwxr-xr-x]  2048
    `-- [drwxr-xr-x]  work

10 directories, 10 files
```

It looks like we have an image of a minimal Linux filesystem:
- `EFI`: contains a boot script
- `boot`: contains the Linux kernel and files related to the Linux kernel setup.
- `minimal`: contains a minimal `rootfs` with on interesting `bash script`:
```bash
$ cat minimal/rootfs/bin/activator
#!/bin/sh
while true; do
  status=$(cat /dev/activate 2>/dev/null)
  if [[ "$status" == "ACTIVATED" ]]; then
    echo "Your license key is activated, $email!"
    echo "Now you can play your favorite game!"
    echo "Press any key to continue..."
    read
    exec 2048
  fi
  echo -n "Enter your email: "
  read email
  echo -n "Enter license key ( XXXX-XXXX-XXXX-XXXX ): "
  read key
  echo "Trying to activate your license...."
  echo -n "$email|$key" > /dev/activate
  sleep 1
done 
```

A quick look at this script allows to understand how the challenge works; first, the activation status is read in `/dev/activate`, if the status is `ACTIVATED` then the player is allowed to play `2048`. If the status isn't `ACTIVATED` the user is prompted for an email and a password which are then written to `/dev/activate`. 

## Driver research

Assuming this hypothesis is valid, we have to deal with a Linux driver and understand how it works. To do that, we need to extract the Linux kernel (the driver isn't in the filesystem) and find the driver inside.

The Linux kernel can be easily found by looking at the file named `kernel.xz`, however, this file does not only contains the kernel:
- The beginning of the file contains the bootloader:
```bash
$ r2 -a x86 -b 16 kernel.xz
[0000:0000]> pd 30
0000:0000      ea0500c007     ljmp 0x7c0:5
0000:0005      8cc8           mov ax, cs
0000:0007      8ed8           mov ds, ax
0000:0009      8ec0           mov es, ax
0000:000b      8ed0           mov ss, ax
0000:000d      31e4           xor sp, sp
0000:000f      fb             sti
0000:0010      fc             cld
```

By analysing the bootloader we finally find that the kernel is compressed and start at offset `0x42E9` as shown in the disassembly:
```
$ r2 -a x86 -b 64 kernel.xz
[0x00000000]> s 0x22A85A
[0x0022a85a]> pd 20
            0x0022a85a      56             push rsi
            0x0022a85b      4889f7         mov rdi, rsi
            0x0022a85e      488d35db6500.  lea rsi, [0x00230e40]
            0x0022a865      488d157d9add.  lea rdx, [0x000042e9]
            0x0022a86c      b954652200     mov ecx, 0x226554
            0x0022a871      4989e8         mov r8, rbp
            0x0022a874      49c7c11c9108.  mov r9, 0x108911c
            0x0022a87b      e8c02c0000     call xz_decompress
[0x000042e9]> px
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x000042e9  fd37 7a58 5a00 0001 6922 de36 0201 0400  .7zXZ...i".6....
0x000042f9  2101 1a00 01c9 80b3 ffff 5101 e25d 003f  !.........Q..].?
0x00004309  9145 8468 3d89 a6da 8acc 93e2 4ef1 e9e1  .E.h=.......N...
0x00004319  e8ef f5f6 99aa f0c5 9b06 eb5b 20b3 62b0  ...........[ .b.
0x00004329  0dc7 8245 f046 0493 cae8 4be3 1274 1167  ...E.F....K..t.g
0x00004339  d817 7879 34c0 4136 d8af 974a f457 5917  ..xy4.A6...J.WY.
0x00004349  00bf 19c5 fa45 4d76 92ac db3b 9c41 ff25  .....EMv...;.A.%
0x00004359  fd6d a7dd 5082 3822 66e7 f950 d304 3240  .m..P.8"f..P..2@
0x00004369  e35e f41e eaef 77a4 adb6 a7e3 4b2c 9b3c  .^....w.....K,.<
0x00004379  9238 8353 a2c5 1839 0ecc 07ef 5fae 931b  .8.S...9...._...
0x00004389  443f 6aba 96cc 2a1a 9757 c584 d33b de5a  D?j...*..W...;.Z
0x00004399  3e83 493f 6a3c a7ac 3864 a7fe ae29 8597  >.I?j<..8d...)..
0x000043a9  2547 4507 34cd 7869 b321 837b b70e d4c1  %GE.4.xi.!.{....
0x000043b9  ca2c be06 2c7d 0e3e dcec ae3b 04a6 9127  .,..,}.>...;...'
0x000043c9  e080 02f0 6ef8 ff99 48ff c180 273f 8043  ....n...H...'?.C
0x000043d9  97bc 1c80 a5c6 3e94 2866 75ce b1e7 2623  ......>.(fu...&#
```

To get the kernel we need to extract the `xz` archive:
```bash
$ dd if=kernel.xz of=tail.tmp bs=0x42e9 skip=1
$ dd if=tail.tmp of=xz-kernel.xz bs=0x226554 count=1
$ 7z e xz-kernel.xz
```

Now that we have the Kernel let's try to find the driver. To be able to quickly identify the functions, the first thing I checked was the version of the kernel in order to download the source:
```
[0xffffffff81c00000]> / Linux version
0xffffffff81800080 hit3_0 .Linux version 5.0.11 (billy@m.
[0xffffffff81c00000]> ps @ 0xffffffff81800080
Linux version 5.0.11 (billy@micosoft.com) (gcc version 9.1.0 (GCC)) #1 SMP Sat Aug 25 13:37:00 CEST 2019
```

Now, we have to find the functions related to the driver operation. To do that, we start by looking at the strings:
```
[0xffffffff81c00000]> iz~devices
1758  0x00a62904 0xffffffff81862904  36  37 (.rodata) ascii Multiple peripheral devices selected
5042  0x00a86c4f 0xffffffff81886c4f   7   8 (.rodata) ascii devices
5043  0x00a86c57 0xffffffff81886c57  19  20 (.rodata) ascii Character devices:\n
5044  0x00a86c6b 0xffffffff81886c6b  16  17 (.rodata) ascii \nBlock devices:\n
6200  0x00a8b7b3 0xffffffff8188b7b3  54  55 (.rodata) ascii Show clockevent devices & pending hrtimers (no others)
8146  0x00a97b87 0xffffffff81897b87  58  59 (.rodata) ascii No general definition block is found, no devices defined.\n
8734  0x00a9ca52 0xffffffff8189ca52  40  41 (.rodata) ascii HDCP is enabled (%d downstream devices)\n
10683 0x00aa833a 0xffffffff818a833a  18  19 (.rodata) ascii Attached devices:\n
10949 0x00aa9b5d 0xffffffff818a9b5d  43  44 (.rodata) ascii host indicates ignore ATA devices, ignored\n
11327 0x00aab873 0xffffffff818ab873  51  52 (.rodata) ascii link online but %d devices misclassified, retrying\n
11328 0x00aab8a7 0xffffffff818ab8a7  70  71 (.rodata) ascii link online but %d devices misclassified, device detection might fail\n
091   0x0103758f 0xffffffff81c3758f  13  14 (.init.data) ascii reset_devices
```

Then by following the cross-reference to the string it is easy to identify some of the functions so we end up by finding `_register_chrdev` which is the function in charge of registering the drivers. Looking for the cross-reference to this function then allow to identify the `init` function for `activate` device at address 0xFFFFFFFF81BC7B98 and the associated `file_operations` structure at address 0xFFFFFFFF81A4DAC0.

## Reversing the driver operations

Once we have found the `file_operations` structure associated with `activate` device we can start to reverse the operations handler:
- `Read` handler: 
  - Returns "Write email key first" if no write operation has been performed yet.
  - Return "FAILED" if the success variable (0xFFFFFFFF81C82F60) is 0.
  - Return "ACTIVATED" if the success variable (0xFFFFFFFF81C82F60) is 1.
- `Write` handler: perform some operations with the email and check if the password validate the conditions.

Finally, here is the code to generate valid key from an email:
```python
#!/usr/bin/env python
from Crypto.Hash import SHA256
import sys

def keygen(mail):
    """Keygen function"""

    SBOX = list(map(
        lambda x: x ^ 0x55,
        [
            0x49, 0x48, 0x51, 0x54, 0x4D, 0x4C, 0x5D, 0x50,
            0x41, 0x40, 0x59, 0x5C, 0x45, 0x44, 0x55, 0x58,
            0x46, 0x47, 0x5B, 0x5A, 0x42, 0x43, 0x5F, 0x5E,
            0x4E, 0x4F, 0x53, 0x52, 0x4A, 0x4B, 0x57, 0x56
        ]
    ))

    global_hash = [0] * 32
    passcode =    [0] * 16

    for c in mail:
        hash_sha256 = SHA256.new(bytes(c, 'utf-8')).digest()
        for i in range(32):
            global_hash[i] = (global_hash[i] + hash_sha256[i]) % 0xEC

    index = 0x0E
    for i in range(16):

        I = SBOX[index]
        X = global_hash[I]
        index = SBOX[I]
        Y = global_hash[index]

        passcode[i] = (X*Y) % 9

    print("{}: {}{}{}{}-{}{}{}{}-{}{}{}{}-{}{}{}{}".format(mail, *passcode))

def main():
    """Main function"""

    if len(sys.argv) < 2:
        print("Usage: {} <mail>".format(sys.argv[0]))
        return -1

    mail = sys.argv[1]
    keygen(mail)

if __name__:
    main()
```

Resources:
- https://github.com/intel/mainline-tracking/tree/4b972a01a7da614b4796475f933094751a295a2f/arch/x86/boot
- https://elixir.bootlin.com/linux/v5.0.11/source