Crashmode
=========

When the Android<sup>TM</sup> boot image is corrupted or a crash
occurs during the device initialization, the watchdogs or the kernel
panic handle, reset the device.

Crashmode goal is to:

1. Catch such a situation and inform the end-user.
2. Avoid an endless reboot loop and battery drain.
3. Give a chance to the engineer to retrieve some debug information
   for post-mortem analysis.

Any type of watchdog is taken into account: kernel, security, PMC, EC
and platform watchdog.  Note that the watchdog reset reason is
reported by Intel BIOS within the non-standard `RSCI` ACPI table while
Kernel panic is reported in the `LoaderEntryRebootReason` EFI variable
by the `drivers/staging/android/efibc.c` kernel driver.

This menu informs the user of the situation and lets him choose which
boot target he wants.

*"WARNING: Multiple crash events have been reported. Use the above menu
to select the next boot option. If the problem persists, please
contact the technical assistance."*

Crashmode automatically powers off the device after five minutes
of inactivity.

With `userdebug` and `eng` builds, Crashmode provides a way to
retrieve some data from the device (Cf.
[ADB support in Crashmode](#adb-support-in-crashmode)) and also
perform some basic interaction with the device.

*Important*: transitions between `Fastboot` and `Crashmode` with
`fastboot oem reboot crashmode` and `adb reboot bootloader` do not
reset the device in order to avoid any memory corruption.  However,
notice that any `fastboot flash` can result in big memory allocation
and RAM corruption.

Crashmode configuration
-----------------------------------------------------

By default, Crashmode is enabled on watchdog and kernel panic events.
To disable it:

```bash
$ fastboot oem crash-event-menu 0
```

To re-enable it:

```bash
$ fastboot oem crash-event-menu 1
```

By default, Kernelflinger displays Crashmode when three crash events
occur in less than ten minutes.  The number of crashes before entering
Crashmode can be configured:

```bash
$ fastboot oem set-watchdog-counter-max 0
```

It makes Kernelflinger display Crashmode each time a crash event is
detected.

See [fastboot documentation](./fastboot.md) for details.

Manually enter crashmode
------------------------

With `userdebug` and `eng` builds, Crashmode can be be entered
manually:

* from Android<sup>TM</sup> or Recovery using the `adb reboot
  crashmode` command
* from Fastboot:

1. using the `fastboot oem reboot crashmode` command
2. using the Fastboot graphical menu

ADB support in Crashmode
------------------------

In `userdebug` and `eng` builds, Crashmode also provide a way to
retrieve data from the device and interact with the device.

Crashmode adb implementation enumerates as `bootloader`.  It allows
any script to detect that the device entered crashmode and use adb
commands to retrieve some data before continuing the boot using the
usual `adb reboot [TARGET]` command.

Example:
```bash
$ adb devices
List of devices attached
INV144900553    bootloader
```

Crashmode adb implementation is limited to the following commands:

```bash
- reboot [TARGET]: reboot to TARGET.  If TARGET parameter is not
  supplied it reboots to Android<sup>TM</sup>.
- pull ram:[:START[:LENGTH]]: retrieve RAM content.
- pull vmcore:[:START[:LENGTH]]: retrieve crash dump vmcore.
- pull acpi:TABLE_NAME: retrieve TABLE_NAME ACPI table.
- pull part:PART_NAME[:START[:LENGTH]]: retrieve PART_NAME partition
  content.
- pull factory-part:PART_NAME[:START[:LENGTH]]: dump the PART_NAME
  factory partition.
- pull mbr: retrieve the Master Boot Record.
- pull gpt-header: retrieve the GPT header.
- pull gpt-parts: retrieve the GPT partition table.
- pull gpt-factory-header: retrieve the factory GPT header.
- pull gpt-factory-parts: retrieve the factory GPT partition table.
- pull efivar:VAR_NAME[:GUID]: retrieve VAR_NAME EFI variable content.
- pull bert-region: retrieve BERT region, prepended by "BERR" magic.
- shell list: list all the shell commands
- shell help COMMAND: print the help for COMMAND
- shell devmem ADDRESS [WIDTH [VALUE]]: read/write from physical address
- shell lsacpi: list the ACPI tables
- shell lspci: list the PCI devices
- shell hexdump ADDRESS LENGTH: Hexdump a memory region
- shell inb | inw | inl IOPORT: Perform a read operation on the given I/O port
- shell outb | outw | outl IOPORT DATA: Perform a write operation on the given I/O port
- shell lspartition: List the GPT partitions
```

The optional `START` and `LENGTH` parameters allow to perform a
partial dump of the data.  They are expressed in hexadecimal with or
without the "0x" prefix.

### ACPI tables

The `pull acpi:TABLE_NAME` command retrieves any ACPI tables.  If
several ACPI tables share the same signature, the first occurrence can
be retrieved with:

```bash
$ adb pull ACPI:TABLE_NAME
```

or

```bash
$ adb pull ACPI:TABLE_NAME1
```

While the other instances tables can be retrieved with:

```bash
$ adb pull ACPI:TABLE_NAME<N>
```

with `<N>` going from 1 to the occurrence number of `TABLE_NAME` ACPI
tables.

### EFI variables

The `pull efivar:VAR_NAME[:GUID]` command retrieves `VAR_NAME` EFI
variable. If several instances of `VAR_NAME` exist, the `GUID`
argument must be supplied.

### RAM and VMCORE

* `ram` dump generates an
  [Android<sup>TM</sup> sparse file](http://www.2net.co.uk/tutorial/android-sparse-image-format)
  with `DONT_CARE` chunk for non conventional memory regions.  Use the
  `simg2img` command from the AOSP tree (`make simg2img-host`) to
  obtain the flat file you are looking for manual analysis.

* `vmcore` dump generates an image of the main memory, exported as
  [Executable and Linkable Format (ELF)](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
  object. This `vmcore` file can be loaded into the
  [RedHat<sup>TM</sup> Linux crash utility](http://people.redhat.com/anderson/crash_whitepaper/)
  to perform a crash analysis.  This `vmcore` file is a 64-bits ELF,
  it only works with a 64-bits Linux kernel.

*Memory flush and preservation*

Crashmode runs after the system has crashed, rebooted and the IAFW has
fully re-initialized.  Hence:

1. The platform must preserve the memory accross reboot due to crash.
2. The system should flush the CPU cache before rebooting.
3. The memory regions used by the IAFW must not be released to the OS.
   The Linux kernel `memmap` command line parameter can be used to
   prevent it to use some memory regions
   (cf. [kernel-parameters.txt](https://www.kernel.org/doc/Documentation/kernel-parameters.txt)).

*Note*:

* `ram` and `vmcore` commands are limited to one `pull` command at a
  time.
* The `START` parameter is a physical address.

### BERT region

The `pull bert-region` command retrieves the
[APEI](https://firmware.intel.com/sites/default/files/resources/A_Tour_beyond_BIOS_Implementing_APEI_with_UEFI_White_Paper.pdf)
(ACPI Platform Error Interface, see
[ACPI specification](http://uefi.org/specifications)) BERT (Boot Error
Record Table) region prepended by `BERR` magic.

### shell devmem Command

The `shell devmem ADDRESS [WIDTH [VALUE]]` command perform a
read/write access from physical `ADDRESS`.  It is designed to allow
read/write accessed to and from registers.

`ADDRESS` is the physical address to interact with.  `WIDTH` is the
size of the transaction to use (8, 16, 32 or 64 bits).  If `WIDTH` is
not set, `devmem` assumes a 32 bits width.  If the value `VALUE`
parameter is supplied `devmem` writes this value to `ADDRESS`.

```bash
$ adb shell devmem 0x7aed6c60 32 0xdeadbeef
$ adb shell devmem 0x7aed6c60
0xDEADBEEF
```

### shell lsacpi command

The `shell lsacpi` list all the ACPI table, their location in RAM and
their size.

```bash
$ adb shell lsacpi
Name   Address    Size
-
DSDT  0x7AED6C60  25218
XSDT  0x7AEDCF30    100
FACP  0x7AED6B50    268
APIC  0x7AED6AC0    132
MCFG  0x7AED6A80     60
HPET  0x7AED6A40     56
NHLT  0x7AED3AD0   1323
TPM2  0x7AED6420     52
```

### shell lspci command

The `shell lspci` lists all the PCI devices.

```bash
$ adb shell lspci
00:00.0 Host bridge: 8086:5AF0 (rev 0B)
00:00.1 Signal processing controller: 8086:5A8C (rev 0B)
00:00.2 Non-Essential Instrumentation: 8086:5A8E (rev 0B)
00:02.0 VGA compatible controller: 8086:5A84 (rev 0B)
00:03.0 Multimedia controller: 8086:5A88 (rev 0B)
00:0D.1 8086:5A94 (rev 0B)
00:0D.2 Serial bus controllers: 8086:5A96 (rev 0B)
00:0D.3 RAM memory: 8086:5AEC (rev 0B)
00:0E.0 Audio device: 8086:5A98 (rev 0B)
00:0F.0 Communication controller: 8086:5A9A (rev 0B)
00:0F.1 Communication controller: 8086:5A9C (rev 0B)
[...]
```

### shell hexdump command

The `shell hexdump ADDRESS LENGTH` dumps memory bytes per bytes and
print it in hexdump and ASCII.

```bash
$ adb shell hexdump 0x7aed6b50 0x40
7AED6B50  46 41 43 50 0C 01 00 00  05 93 49 4E 54 45 4C 20  |FACP......INTEL |
7AED6B60  45 44 4B 32 20 20 20 20  05 00 00 00 49 4E 54 4C  |EDK2    ....INTL|
7AED6B70  0D 00 00 01 F0 CE ED 7A  60 6C ED 7A 01 02 09 00  |.......z`l.z....|
7AED6B80  00 00 00 00 00 00 00 00  00 04 00 00 00 00 00 00  |................|
```

### shell inb, inw, inl, outb, outw and outl commands

These commands proves direct access to I/O ports on the device.

The `inb`, `inw` and `inl` commands perform a read operation on the
given I/O port and print the result.

The `outb`, `outw` and `outl` commands perform write operation to the
given I/O port.

```bash
$ Usage:
  inb|inw|inl IOPORT
  outb|outw|outl IOPORT DATA
$ adb shell outb 0xcf9 0x6
```

### shell lspartition

The `shell lspartition` partition lists all the GPT partition with
their offset on the disk and their size.

```bash
$ adb shell lspartition
#   Name          Offset        Size (MB)
-
1   bootloader_a  0x0000100000        30
2   bootloader_b  0x0001F00000        30
3   boot_a        0x0003D00000        30
4   boot_b        0x0005B00000        30
[...]
```

### Example:

```bash
$ adb pull acpi:DSDT DSDT
580 KB/s (131324 bytes in 0.220s)

$ adb pull efivar:OEMLock OEMLock
0 KB/s (4 bytes in 0.50s)

$ adb pull ram:9F000:0F0000 ram.simg
947 KB/s (585792 bytes in 0.603s)

$ simg2img ram.sparse.bin ram.bin

$ adb pull part:boot boot.img
1189 KB/s (31457280 bytes in 25.832s)

$ adb pull factory-part:modem1_cal
1088 KB/s (1048576 bytes in 0.941s)
```
