#
# Copyright (c) 2018, Intel Corporation
# All rights reserved.
#
# Author: Meng Xianglin <xianglinx.meng@intel.com>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer
#      in the documentation and/or other materials provided with the
#      distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
#
# This file defines bootlogic data structures, try to keep it without
# any external definitions in order to ease export of it.
#

set(DEPENDENCIES external-gnu-efi
	efiwrapper
	coreboot
	bionic
	)

set(external-gnu-efi-repo
	https://github.com/projectceladon/external-gnu-efi.git
	)
set(efiwrapper-repo
	https://github.com/intel/efiwrapper.git
	)
set(coreboot-repo
	https://github.com/coreboot/coreboot.git
	)
set(bionic-repo
	https://android.googlesource.com/platform/bionic
	)

set(LIB_EFI_SOURCES
	${LIB_EFI_SOURCE}/lib/boxdraw.c
	${LIB_EFI_SOURCE}/lib/hand.c
	${LIB_EFI_SOURCE}/lib/guid.c
	${LIB_EFI_SOURCE}/lib/debug.c
	${LIB_EFI_SOURCE}/lib/error.c
	${LIB_EFI_SOURCE}/lib/console.c
	${LIB_EFI_SOURCE}/lib/init.c
	${LIB_EFI_SOURCE}/lib/runtime/efirtlib.c
	${LIB_EFI_SOURCE}/lib/runtime/rtlock.c
	${LIB_EFI_SOURCE}/lib/runtime/rtstr.c
	${LIB_EFI_SOURCE}/lib/runtime/rtdata.c
	${LIB_EFI_SOURCE}/lib/runtime/vm.c
	${LIB_EFI_SOURCE}/lib/hw.c
	${LIB_EFI_SOURCE}/lib/data.c
	${LIB_EFI_SOURCE}/lib/misc.c
	${LIB_EFI_SOURCE}/lib/lock.c
	${LIB_EFI_SOURCE}/lib/smbios.c
	${LIB_EFI_SOURCE}/lib/crc.c
	${LIB_EFI_SOURCE}/lib/event.c
	${LIB_EFI_SOURCE}/lib/sread.c
	${LIB_EFI_SOURCE}/lib/str.c
	${LIB_EFI_SOURCE}/lib/cmdline.c
	${LIB_EFI_SOURCE}/lib/print.c
	${LIB_EFI_SOURCE}/lib/dpath.c
	${LIB_EFI_SOURCE}/lib/${TARGET_EFI_ARCH_NAME}/initplat.c
	${LIB_EFI_SOURCE}/lib/${TARGET_EFI_ARCH_NAME}/efi_stub.S
	${LIB_EFI_SOURCE}/lib/${TARGET_EFI_ARCH_NAME}/math.c
	)

set(LIB_PAYLOAD_SOURCES
	${LIB_PAYLOAD_SOURCE}/libpci/libpci.c
	${LIB_PAYLOAD_SOURCE}/arch/x86/main.c
	${LIB_PAYLOAD_SOURCE}/arch/x86/sysinfo.c
	${LIB_PAYLOAD_SOURCE}/arch/x86/timer.c
	${LIB_PAYLOAD_SOURCE}/arch/x86/coreboot.c
	${LIB_PAYLOAD_SOURCE}/arch/x86/util.S
	${LIB_PAYLOAD_SOURCE}/arch/x86/virtual.c
	${LIB_PAYLOAD_SOURCE}/arch/x86/selfboot.c
	${LIB_PAYLOAD_SOURCE}/arch/x86/exception.c
	${LIB_PAYLOAD_SOURCE}/arch/x86/multiboot.c
	${LIB_PAYLOAD_SOURCE}/arch/x86/rom_media.c
	${LIB_PAYLOAD_SOURCE}/crypto/sha1.c
	${LIB_PAYLOAD_SOURCE}/libc/malloc.c
	${LIB_PAYLOAD_SOURCE}/libc/printf.c
	${LIB_PAYLOAD_SOURCE}/libc/console.c
	${LIB_PAYLOAD_SOURCE}/libc/string.c
	${LIB_PAYLOAD_SOURCE}/libc/memory.c
	${LIB_PAYLOAD_SOURCE}/libc/ctype.c
	${LIB_PAYLOAD_SOURCE}/libc/ipchecksum.c
	${LIB_PAYLOAD_SOURCE}/libc/lib.c
	${LIB_PAYLOAD_SOURCE}/libc/rand.c
	${LIB_PAYLOAD_SOURCE}/libc/time.c
	${LIB_PAYLOAD_SOURCE}/libc/exec.c
	${LIB_PAYLOAD_SOURCE}/libc/readline.c
	${LIB_PAYLOAD_SOURCE}/libc/getopt_long.c
	${LIB_PAYLOAD_SOURCE}/libc/sysinfo.c
	${LIB_PAYLOAD_SOURCE}/libc/args.c
	${LIB_PAYLOAD_SOURCE}/libc/strlcpy.c
	${LIB_PAYLOAD_SOURCE}/libc/qsort.c
	${LIB_PAYLOAD_SOURCE}/libc/hexdump.c
	${LIB_PAYLOAD_SOURCE}/libc/die.c
	${LIB_PAYLOAD_SOURCE}/libc/coreboot.c
	${LIB_PAYLOAD_SOURCE}/libc/64bit_div.c
	${LIB_PAYLOAD_SOURCE}/drivers/pci.c
	${LIB_PAYLOAD_SOURCE}/drivers/serial/8250.c
	${LIB_PAYLOAD_SOURCE}/drivers/serial/serial.c
	${LIB_PAYLOAD_SOURCE}/drivers/i8042/i8042.c
	${LIB_PAYLOAD_SOURCE}/drivers/i8042/keyboard.c
	${LIB_PAYLOAD_SOURCE}/drivers/nvram.c
	${LIB_PAYLOAD_SOURCE}/drivers/options.c
	${LIB_PAYLOAD_SOURCE}/drivers/timer/rdtsc.c
	${LIB_PAYLOAD_SOURCE}/drivers/hid.c
	)

set(EFIWRAPPER_LIB_SOURCES
	${EFIWRAPPER_LIB_SOURCE}/ewvar.c
	${EFIWRAPPER_LIB_SOURCE}/ewdrv.c
	${EFIWRAPPER_LIB_SOURCE}/protocol.c
	${EFIWRAPPER_LIB_SOURCE}/core.c
	${EFIWRAPPER_LIB_SOURCE}/lib.c
	${EFIWRAPPER_LIB_SOURCE}/bs.c
	${EFIWRAPPER_LIB_SOURCE}/rs.c
	${EFIWRAPPER_LIB_SOURCE}/conin.c
	${EFIWRAPPER_LIB_SOURCE}/conout.c
	${EFIWRAPPER_LIB_SOURCE}/serialio.c
	${EFIWRAPPER_LIB_SOURCE}/storage.c
	${EFIWRAPPER_LIB_SOURCE}/blockio.c
	${EFIWRAPPER_LIB_SOURCE}/diskio.c
	${EFIWRAPPER_LIB_SOURCE}/interface.c
	${EFIWRAPPER_LIB_SOURCE}/media.c
	${EFIWRAPPER_LIB_SOURCE}/conf_table.c
	${EFIWRAPPER_LIB_SOURCE}/smbios.c
	${EFIWRAPPER_LIB_SOURCE}/ewacpi.c
	${EFIWRAPPER_LIB_SOURCE}/ewarg.c
	${EFIWRAPPER_LIB_SOURCE}/sdio.c
	${EFIWRAPPER_LIB_SOURCE}/ewlib.c
	${EFIWRAPPER_LIB_SOURCE}/eraseblk.c
	)

set(LIB_ADB_SOURCES
	${LIB_ADB_SOURCE}/adb.c
	${LIB_ADB_SOURCE}/adb_socket.c
	${LIB_ADB_SOURCE}/reboot_service.c
	${LIB_ADB_SOURCE}/sync_service.c
	${LIB_ADB_SOURCE}/reader.c
	)

set(LIB_ELFLOADER_SOURCES
	${LIB_ELFLOADER_SOURCE}/elf32_ld.c
	${LIB_ELFLOADER_SOURCE}/elf64_ld.c
	${LIB_ELFLOADER_SOURCE}/elf_ld.c
	)

set(LIB_FASTBOOT_SOURCES
	${LIB_FASTBOOT_SOURCE}/fastboot.c
	#${LIB_FASTBOOT_SOURCE}/fastboot_oem.c
	${LIB_FASTBOOT_SOURCE}/fastboot_flashing.c
	${LIB_FASTBOOT_SOURCE}/flash.c
	${LIB_FASTBOOT_SOURCE}/sparse.c
	${LIB_FASTBOOT_SOURCE}/info.c
	${LIB_FASTBOOT_SOURCE}/intel_variables.c
	${LIB_FASTBOOT_SOURCE}/bootmgr.c
	${LIB_FASTBOOT_SOURCE}/hashes.c
	${LIB_FASTBOOT_SOURCE}/bootloader.c
	${LIB_FASTBOOT_SOURCE}/fastboot_transport.c
	${LIB_FASTBOOT_SOURCE}/fastboot_ui.c
	)

set(LIB_KERNELFLINGER_SOURCES
	${LIB_KERNELFLINGER_SOURCE}/android.c
	${LIB_KERNELFLINGER_SOURCE}/efilinux.c
	${LIB_KERNELFLINGER_SOURCE}/acpi.c
	${LIB_KERNELFLINGER_SOURCE}/acpi_image.c
	${LIB_KERNELFLINGER_SOURCE}/lib.c
	${LIB_KERNELFLINGER_SOURCE}/options.c
	${LIB_KERNELFLINGER_SOURCE}/vars.c
	${LIB_KERNELFLINGER_SOURCE}/log.c
	${LIB_KERNELFLINGER_SOURCE}/em.c
	${LIB_KERNELFLINGER_SOURCE}/gpt.c
	${LIB_KERNELFLINGER_SOURCE}/storage.c
	${LIB_KERNELFLINGER_SOURCE}/pci.c
	${LIB_KERNELFLINGER_SOURCE}/mmc.c
	${LIB_KERNELFLINGER_SOURCE}/ufs.c
	${LIB_KERNELFLINGER_SOURCE}/sdcard.c
	${LIB_KERNELFLINGER_SOURCE}/sdio.c
	${LIB_KERNELFLINGER_SOURCE}/sata.c
	${LIB_KERNELFLINGER_SOURCE}/uefi_utils.c
	${LIB_KERNELFLINGER_SOURCE}/targets.c
	${LIB_KERNELFLINGER_SOURCE}/smbios.c
	${LIB_KERNELFLINGER_SOURCE}/oemvars.c
	${LIB_KERNELFLINGER_SOURCE}/text_parser.c
	${LIB_KERNELFLINGER_SOURCE}/watchdog.c
	${LIB_KERNELFLINGER_SOURCE}/life_cycle.c
	${LIB_KERNELFLINGER_SOURCE}/qsort.c
	${LIB_KERNELFLINGER_SOURCE}/nvme.c
	${LIB_KERNELFLINGER_SOURCE}/timer.c
	${LIB_KERNELFLINGER_SOURCE}/virtual_media.c
	${LIB_KERNELFLINGER_SOURCE}/general_block.c
	${LIB_KERNELFLINGER_SOURCE}/slot.c
	${LIB_KERNELFLINGER_SOURCE}/pae.c
	${LIB_KERNELFLINGER_SOURCE}/signature.c
	${LIB_KERNELFLINGER_SOURCE}/ias_sig.c
	${LIB_KERNELFLINGER_SOURCE}/no_ui.c
	${LIB_KERNELFLINGER_SOURCE}/ui_color.c
	)
