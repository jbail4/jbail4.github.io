---
title: Dumping QEMU Guest Memory & Analysis with volatility
date: 2026-08-27 12:00:00 +0100
tags: [qemu, memory, volatility, C, memory introspection]
---

# Dumping QEMU Guest Memory & Analysis with volatility

At around the end of 2025 i had created a proof of concept memory introspection library written in C.  
  
This library provides an API to read the virtual memory of windows executables (both user space & kernel space) whilst dealing with the complex translations of virtual memory to the "physical memory" of a windows guest running under a qemu hypervisor. I intend to rewrite this library and create hopefully interesting blog posts about this project.

## **The Plan**

To begin this project i will write a program that dumps the "physical" memory of the virtual machine to a file. I will then use Volatility3 to ensure this dump has successfully captured the memory contents of our virtual machine. For now we will assume that hugepages are not being used, i will only target the Intel Q35 virtual chipset and i will make an assumption that the largest memory map is our target memory region.  
  
Effectively the steps to achieve this are as follows:

1. Find the QEMU PID
2. Read `/proc/<QEMU PID>/maps`
3. Find the memory mapping which corresponds to pc.ram
4. Read both the low & high memory regions to a file
5. Validate the dump using Volatility3

This step will help later on when putting the library together by ensuring any memory reads are being targeted to our virtual machine's memory.

## How to find our QEMU guest RAM mapping

By default QEMU creates a memory map for guest RAM and backs it with memory allocated in the host address space.  
  
On Linux you can view the memory mappings of any process in plain text as follows: `cat /proc/&lt;pid&gt;/maps`. An example entry within this file is as follows:  
  
`7f1fb00aa000-7f1fb00bf000 r--p 00034000 00:24 1437171&nbsp;/usr/lib64/libduktape.so.207.20700`  
  
For now we only care about the first part - the given virtual address range. To find the largest memory map we will need to check each line and do the following:  
`&lt;end virtual address&gt; - &lt;start virtual address&gt; = &lt;map size&gt;.`  
  
We will then need to compare the result of each line until we're left with the largest map size.  
  
We can also find this with the below:

```bash
sudo awk '{split($1,a,"-"); size=strtonum("0x"a[2])-strtonum("0x"a[1]); print size, $0}' /proc/<QEMU PID>/maps | sort -nr | numfmt --field=1 --to=iec
16G 7f14abe00000-7f18abe00000 rw-p 00000000 00:00 0 
256M 7f1430000000-7f1440000000 rw-s 10000000000 00:11 3101&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;anon_inode:[vfio-device]
64M 7f14a7dff000-7f14abdff000 rw-s 00000000 00:07 239&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/dev/kvmfr0
64M 7f144c000000-7f1450000000 rw-s 00000000 00:11 3101&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;anon_inode:[vfio-device]
64M 7f18b4021000-7f18b8000000 ---p 00000000 00:00 0 
64M 7f18ac021000-7f18b0000000 ---p 00000000 00:00 0 
64M 7f14a0021000-7f14a4000000 ---p 00000000 00:00 0 
64M 7f148c021000-7f1490000000 ---p 00000000 00:00 0 
64M 7f1484021000-7f1488000000 ---p 00000000 00:00 0 
64M 7f1480021000-7f1484000000 ---p 00000000 00:00 0 
64M 7f142c021000-7f1430000000 ---p 00000000 00:00 0 
64M 7f1494022000-7f1498000000 ---p 00000000 00:00 0 
64M 7f1490024000-7f1494000000 ---p 00000000 00:00 0 
64M 7f148802e000-7f148c000000 ---p 00000000 00:00 0 
59M 7f14645ad000-7f1468000000 ---p 00000000 00:00 0 
56M 7f1474852000-7f1478000000 ---p 00000000 00:00 0 
55M 7f149c9b3000-7f14a0000000 ---p 00000000 00:00 0 
53M 7f1453f00000-7f1457325000 rw-p 00000000 00:00 0
```

We can see `7f14abe00000-7f18abe00000` is our guest "physical" RAM map as we had allocated 16GiB of memory to the virtual machine.

## How is our RAM content structured

We can use the [RAMMap sysinternals tool](<https://learn.microsoft.com/en-us/sysinternals/downloads/rammap> "RAMMap sysinternals tool") to view our memory layout on our guest. The below screenshot was taken within the context of the target virtual machine.  




![image.png](<./assets/17232f8d9ee5057c-image.png>)

As default behavior on systems with greater than 2816MiB of memory assigned, physical ranges are split into both a low & high memory region. This is due to memory addresses between 2GiB-4GiB being reserved for MMIO (memory mapped input/output).

To target low region we will read from `0x100000`to `0x7FF00000`.

To target high region we will read from `0x100000000` to `0x480000000`.

An important note - the hexadecimal value of `0x480000000` equates to 18GiB. As such when we create our dump we will have to include our MMIO region but given this does not contain any pages used by the OS it is safe to just zero this region.

This also means that our QEMU guest RAM mapping is not the same as what's visible in the context of the virtual machine. Using libvirt we can use `virsh qemu-monitor-command &lt;Guest Name&gt; --hmp "info mtree -f"` in the terminal to check how this has been addressed. Towards the top of the output we can see the below:

```bash
Root memory region: system
  0000000000000000-000000000002ffff (prio 0, ram): pc.ram KVM
  0000000000030000-000000000004ffff (prio 1, i/o): smbase-blackhole
  0000000000050000-00000000000bffff (prio 0, ram): pc.ram @0000000000050000 KVM
  00000000000c0000-00000000000dffff (prio 1, rom): pc.rom KVM
  00000000000e0000-00000000000fffff (prio 0, rom): system.flash0 @000000000035c000 KVM
  0000000000100000-000000007effffff (prio 0, ram): pc.ram @0000000000100000 KVM
  000000007f000000-000000007fffffff (prio 1, i/o): tseg-blackhole
  0000000080000000-0000000080087fff (prio 0, ramd): 0000:01:00.0 BAR 0 mmaps[0] KVM
  0000000080088000-0000000080088fff (prio 1, i/o): vfio-nvidia-bar0-88000-mirror-quirk
  0000000080089000-0000000080b8ffff (prio 0, ramd): 0000:01:00.0 BAR 0 mmaps[0] @0000000000089000 KVM
  0000000080b90000-0000000080b9008f (prio 0, i/o): msix-table
  0000000080b90090-0000000083ffffff (prio 0, ramd): 0000:01:00.0 BAR 0 mmaps[0] @0000000000b90090
  0000000084000000-0000000084003fff (prio 0, ramd): 0000:01:00.1 BAR 0 mmaps[0] KVM
  0000000084200000-00000000842000ff (prio 1, i/o): ivshmem-mmio
  0000000085420000-000000008543ffff (prio 1, i/o): e1000e-mmio
  0000000085440000-000000008544004f (prio 0, i/o): msix-table
  0000000085442000-0000000085442007 (prio 0, i/o): msix-pba
  0000000085a00000-0000000085a0001f (prio 0, i/o): msix-table
  0000000085a00800-0000000085a00807 (prio 0, i/o): msix-pba
  0000000085c00000-0000000085c0003f (prio 0, i/o): capabilities
  0000000085c00040-0000000085c0043f (prio 0, i/o): operational
  0000000085c00440-0000000085c0044f (prio 0, i/o): usb3 port #1
  0000000085c00450-0000000085c0045f (prio 0, i/o): usb3 port #2
  0000000085c00460-0000000085c0046f (prio 0, i/o): usb3 port #3
  0000000085c00470-0000000085c0047f (prio 0, i/o): usb3 port #4
  0000000085c00480-0000000085c0048f (prio 0, i/o): usb3 port #5
  0000000085c00490-0000000085c0049f (prio 0, i/o): usb3 port #6
  0000000085c004a0-0000000085c004af (prio 0, i/o): usb3 port #7
  0000000085c004b0-0000000085c004bf (prio 0, i/o): usb3 port #8
  0000000085c004c0-0000000085c004cf (prio 0, i/o): usb3 port #9
  0000000085c004d0-0000000085c004df (prio 0, i/o): usb3 port #10
  0000000085c004e0-0000000085c004ef (prio 0, i/o): usb3 port #11
  0000000085c004f0-0000000085c004ff (prio 0, i/o): usb3 port #12
  0000000085c00500-0000000085c0050f (prio 0, i/o): usb3 port #13
  0000000085c00510-0000000085c0051f (prio 0, i/o): usb3 port #14
  0000000085c00520-0000000085c0052f (prio 0, i/o): usb3 port #15
  0000000085c00530-0000000085c0053f (prio 0, i/o): usb2 port #1
  0000000085c00540-0000000085c0054f (prio 0, i/o): usb2 port #2
  0000000085c00550-0000000085c0055f (prio 0, i/o): usb2 port #3
  0000000085c00560-0000000085c0056f (prio 0, i/o): usb2 port #4
  0000000085c00570-0000000085c0057f (prio 0, i/o): usb2 port #5
  0000000085c00580-0000000085c0058f (prio 0, i/o): usb2 port #6
  0000000085c00590-0000000085c0059f (prio 0, i/o): usb2 port #7
  0000000085c005a0-0000000085c005af (prio 0, i/o): usb2 port #8
  0000000085c005b0-0000000085c005bf (prio 0, i/o): usb2 port #9
  0000000085c005c0-0000000085c005cf (prio 0, i/o): usb2 port #10
  0000000085c005d0-0000000085c005df (prio 0, i/o): usb2 port #11
  0000000085c005e0-0000000085c005ef (prio 0, i/o): usb2 port #12
  0000000085c005f0-0000000085c005ff (prio 0, i/o): usb2 port #13
  0000000085c00600-0000000085c0060f (prio 0, i/o): usb2 port #14
  0000000085c00610-0000000085c0061f (prio 0, i/o): usb2 port #15
  0000000085c01000-0000000085c0121f (prio 0, i/o): runtime
  0000000085c02000-0000000085c0281f (prio 0, i/o): doorbell
  0000000085c03000-0000000085c030ff (prio 0, i/o): msix-table
  0000000085c03800-0000000085c03807 (prio 0, i/o): msix-pba
  0000000086000000-0000000086001fff (prio 0, i/o): intel-hda
  0000000086002000-0000000086003fff (prio 0, i/o): intel-hda
  0000000086004000-0000000086004fff (prio 1, i/o): ahci
  0000000086005000-000000008600500f (prio 0, i/o): msix-table
  0000000086005800-0000000086005807 (prio 0, i/o): msix-pba
  0000000086006000-000000008600600f (prio 0, i/o): msix-table
  0000000086006800-0000000086006807 (prio 0, i/o): msix-pba
  0000000086007000-000000008600700f (prio 0, i/o): msix-table
  0000000086007800-0000000086007807 (prio 0, i/o): msix-pba
  0000000086008000-000000008600800f (prio 0, i/o): msix-table
  0000000086008800-0000000086008807 (prio 0, i/o): msix-pba
  0000000086009000-000000008600900f (prio 0, i/o): msix-table
  0000000086009800-0000000086009807 (prio 0, i/o): msix-pba
  000000008600a000-000000008600a00f (prio 0, i/o): msix-table
  000000008600a800-000000008600a807 (prio 0, i/o): msix-pba
  000000008600b000-000000008600b00f (prio 0, i/o): msix-table
  000000008600b800-000000008600b807 (prio 0, i/o): msix-pba
  000000008600c000-000000008600c00f (prio 0, i/o): msix-table
  000000008600c800-000000008600c807 (prio 0, i/o): msix-pba
  000000008600d000-000000008600d00f (prio 0, i/o): msix-table
  000000008600d800-000000008600d807 (prio 0, i/o): msix-pba
  000000008600e000-000000008600e00f (prio 0, i/o): msix-table
  000000008600e800-000000008600e807 (prio 0, i/o): msix-pba
  000000008600f000-000000008600f00f (prio 0, i/o): msix-table
  000000008600f800-000000008600f807 (prio 0, i/o): msix-pba
  0000000086010000-000000008601000f (prio 0, i/o): msix-table
  0000000086010800-0000000086010807 (prio 0, i/o): msix-pba
  0000000086011000-000000008601100f (prio 0, i/o): msix-table
  0000000086011800-0000000086011807 (prio 0, i/o): msix-pba
  0000000086012000-000000008601200f (prio 0, i/o): msix-table
  0000000086012800-0000000086012807 (prio 0, i/o): msix-pba
  0000000086013000-000000008601300f (prio 0, i/o): msix-table
  0000000086013800-0000000086013807 (prio 0, i/o): msix-pba
  00000000e0000000-00000000efffffff (prio 0, i/o): pcie-mmcfg-mmio
  00000000fec00000-00000000fec00fff (prio 0, i/o): kvm-ioapic
  00000000fed1c000-00000000fed1ffff (prio 1, i/o): lpc-rcrb-mmio
  00000000fed40000-00000000fed4007f (prio 0, i/o): tpm-crb-mmio
  00000000fed40080-00000000fed40fff (prio 0, ram): tpm-crb-cmd
  00000000fed45000-00000000fed453ff (prio 0, ramd): tpm-ppi
  00000000fee00000-00000000feefffff (prio 4096, i/o): kvm-apic-msi
  00000000ffc00000-00000000ffc83fff (prio 0, romd): system.flash1 KVM
  00000000ffc84000-00000000ffffffff (prio 0, romd): system.flash0 KVM
  0000000100000000-000000047fffffff (prio 0, ram): pc.ram @0000000080000000 KVM
  0000007010000000-0000007010000fff (prio 0, i/o): virtio-pci-common-virtio-serial
  0000007010001000-0000007010001fff (prio 0, i/o): virtio-pci-isr-virtio-serial
  0000007010002000-0000007010002fff (prio 0, i/o): virtio-pci-device-virtio-serial
  0000007010003000-0000007010003fff (prio 0, i/o): virtio-pci-notify-virtio-serial
  0000007030000000-000000703fffffff (prio 0, ramd): 0000:01:00.0 BAR 1 mmaps[0] KVM
  0000007040000000-0000007041ffffff (prio 0, ramd): 0000:01:00.0 BAR 3 mmaps[0] KVM
  00000070f0000000-00000070f3ffffff (prio 1, ram): looking-glass KVM
```

From the above we only care about the address ranges labelled `pc.ram` and that contain the memory regions listed previously which corresponds to the below.

- `0000000000100000-000000007effffff (prio 0, ram): pc.ram @0000000000100000 KVM` \- low region

- `0000000100000000-000000047fffffff (prio 0, ram): pc.ram @0000000080000000 KVM`\- high region

From the above this tells us where our low & high region start within our guest RAM map. Our low region starts at offset `0x100000` . Our high region starts at offset `0x80000000`.

## Finally creating the dumper in C

```c
#define _GNU_SOURCE
#include <dirent.h>
#include <linux/limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>

static uint32_t qemu_pid = 117948;
static char dump_target_path[PATH_MAX] = "/tmp/qemu.dump";

typedef struct map_descriptor {
  uint64_t start;
  uint64_t end;
  uint64_t size;
} map_descriptor;

void locate_pcram_map(map_descriptor *pcram_map, uint32_t qemu_pid) {
  pcram_map->size = 0;

  map_descriptor candidate_map = {0};

  char maps_path[PATH_MAX];
  sprintf(maps_path, "/proc/%i/maps", qemu_pid);
  FILE *maps_file = fopen(maps_path, "r");

  char buffer[128];
  while (fgets(buffer, sizeof(buffer), maps_file)) {
    struct map_descriptor current_map;
    sscanf(buffer, "%llx-%llx", &current_map.start, &current_map.end);

    current_map.size = current_map.end - current_map.start;

    if (current_map.size > candidate_map.size)
      candidate_map = current_map;
  }

  fclose(maps_file);
  *pcram_map = candidate_map;
}

#define CHUNK_SIZE                                                             \
  0x800000 // 8MiB size for incremental process_vm_readv & fwrite calls

#define LOW_MEM_MAP_START 0x100000
#define LOW_MEM_SIZE 0x80000000
#define LOW_MEM_PCRAM_START 0x100000

#define HIGH_MEM_MAP_START 0x80000000
#define HIGH_MEM_PCRAM_START 0x100000000

void write_dump_to_file(map_descriptor *pcram_map, uint32_t qemu_pid,
                        char dump_path[PATH_MAX]) {
  size_t buffer_size = pcram_map->size + 0x80000000;
  void *buffer = malloc(buffer_size);

  // dump low memory region
  for (size_t i = 0; i < LOW_MEM_SIZE / CHUNK_SIZE; i++) {
    struct iovec local = {
        (void *)((uint64_t)buffer + LOW_MEM_PCRAM_START + (i * CHUNK_SIZE)),
        CHUNK_SIZE};
    struct iovec remote = {(void *)((uint64_t)pcram_map->start +
                                    LOW_MEM_MAP_START + (i * CHUNK_SIZE)),
                           CHUNK_SIZE};

    process_vm_readv(qemu_pid, &local, 1, &remote, 1, 0);
  }

  // dump high memory region
  for (size_t i = 0; i < buffer_size / CHUNK_SIZE; i++) {
    struct iovec local = {
        (void *)((uint64_t)buffer + HIGH_MEM_PCRAM_START + (i * CHUNK_SIZE)),
        CHUNK_SIZE};
    struct iovec remote = {(void *)((uint64_t)pcram_map->start +
                                    HIGH_MEM_MAP_START + (i * CHUNK_SIZE)),
                           CHUNK_SIZE};
    process_vm_readv(qemu_pid, &local, 1, &remote, 1, 0);
  }

  FILE *dump_file = fopen(dump_path, "w");
  for (size_t i = 0; i < buffer_size / CHUNK_SIZE; i++) {
    fwrite((void *)((uint64_t)buffer + (i * CHUNK_SIZE)), 1, CHUNK_SIZE,
           dump_file);
  }

  fclose(dump_file);
  free(buffer);
}

int main(int argc, char *argv[]) {
  map_descriptor pcram_map;
  locate_pcram_map(&pcram_map, qemu_pid);

  printf("pc.ram mapping:\nstart: %llx\nend:%lx\nsize: %i(MiB)\n",
         pcram_map.start, pcram_map.end, pcram_map.size / 1024 / 1024);

  write_dump_to_file(&pcram_map, qemu_pid, dump_target_path);
}
```

Compile: `gcc dumper.c -o dumper`

## Using our dump

```bash
sudo ./dumper
pc.ram mapping:
  start: 7ff1f7e00000
  end:   7ff5f7e00000
  size:  16384 MiB
  
ls -l /tmp/qemu.dump 
-rw-r--r--. 1 root root 19327352832 Aug 27 14:12 /tmp/qemu.dump
```

We can see that our pc.ram mapping has been found and the correct memory ranges have been dumped to /tmp/qemu.dump.

## Testing our dump with volatility

```bash
vol -f /tmp/qemu.dump windows.info
Volatility 3 Framework 2.28.0
Progress:  100.00		PDB scanning finished                        
Variable	Value

Kernel Base	0xf807e0e00000
DTB	0x1ae000
Symbols	file:///~/.local/lib/python3.14/site-packages/volatility3/symbols/windows/ntkrnlmp.pdb/72C69E726C648BC18257AF38FA78A2F2-1.json.xz
Is64Bit	True
IsPAE	False
layer_name	0 WindowsIntel32e
memory_layer	1 FileLayer
KdVersionBlock	0xf807e1c0aa20
Major/Minor	15.26100
MachineType	34404
KeNumberProcessors	16
SystemTime	2026-08-27 13:12:36+00:00
NtSystemRoot	C:\WINDOWS
NtProductType	NtProductWinNt
NtMajorVersion	10
NtMinorVersion	0
PE MajorOperatingSystemVersion	10
PE MinorOperatingSystemVersion	0
PE Machine	34404
PE TimeDateStamp	Wed Feb 13 20:47:57 2069
```

We can see that volatility has successfully extracted version information from our dump. We can also view what processes were running on our system at the time of the dump.

```bash
vol -f /tmp/qemu.dump windows.pslist                            
Volatility 3 Framework 2.28.0
Progress:  100.00		PDB scanning finished                        
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output

4	0	System	0xd60137695040	345	-	N/A	False	2026-08-27 13:08:06.000000 UTC	N/A	Disabled
268	4	Registry	0xd60137de4040	4	-	N/A	False	2026-08-27 13:07:59.000000 UTC	N/A	Disabled
1000	4	smss.exe	0xd60145505040	2	-	N/A	False	2026-08-27 13:08:06.000000 UTC	N/A	Disabled
1120	1104	csrss.exe	0xd601401ad080	14	-	0	False	2026-08-27 13:08:22.000000 UTC	N/A	Disabled
1208	1104	wininit.exe	0xd6014596c0c0	2	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1216	1200	csrss.exe	0xd60145a4f140	14	-	1	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1304	1200	winlogon.exe	0xd60145b18080	4	-	1	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1328	1208	services.exe	0xd60145b1e180	8	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1364	1208	lsass.exe	0xd60145b5a180	11	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1504	1328	svchost.exe	0xd60145b9a0c0	17	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1536	1208	fontdrvhost.ex	0xd60145ba3080	5	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1544	1304	fontdrvhost.ex	0xd60145372080	5	-	1	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1632	1328	svchost.exe	0xd60145bba080	9	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1684	1328	svchost.exe	0xd60145bf9080	7	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1740	1304	dwm.exe	0xd60145c0c080	110	-	1	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1892	1328	svchost.exe	0xd60145374080	6	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1900	1328	svchost.exe	0xd60145d56080	6	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2008	1328	svchost.exe	0xd60145dd3080	3	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2012	1328	svchost.exe	0xd60145dee0c0	3	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1068	1328	svchost.exe	0xd60145369080	15	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1440	1328	svchost.exe	0xd6014536b080	4	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1376	1328	svchost.exe	0xd6014536e080	4	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1384	1328	svchost.exe	0xd60145f450c0	3	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2116	1328	svchost.exe	0xd60145f7e080	8	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2128	1328	svchost.exe	0xd60145371080	5	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2168	1328	svchost.exe	0xd6014536d080	2	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2300	1328	svchost.exe	0xd60145fa0080	8	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2460	1328	NVDisplay.Cont	0xd60146749080	39	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2548	1328	svchost.exe	0xd60146760080	10	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2588	1328	svchost.exe	0xd601467ac080	9	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2632	1328	svchost.exe	0xd601467e5080	4	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2640	1328	svchost.exe	0xd60146759200	5	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2648	1328	svchost.exe	0xd601467eb0c0	7	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2800	1328	svchost.exe	0xd601468de080	7	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2836	4	MemCompression	0xd60146811040	38	-	N/A	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2892	1328	svchost.exe	0xd601468f4080	3	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2972	1328	svchost.exe	0xd601469c6080	7	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2984	1328	svchost.exe	0xd60146969080	5	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
2992	1328	svchost.exe	0xd6014696c080	8	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
1080	1328	svchost.exe	0xd60146967080	3	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
3100	1328	svchost.exe	0xd60146c14080	10	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
3168	1328	svchost.exe	0xd60146a5e080	6	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
3228	1328	svchost.exe	0xd60146ce1080	5	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
3232	1328	svchost.exe	0xd60146a63200	3	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
3420	1328	svchost.exe	0xd60146d860c0	10	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
3428	1328	svchost.exe	0xd60146bf7080	14	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
3436	1328	svchost.exe	0xd60146d57080	14	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
3440	1328	svchost.exe	0xd60146d5a080	16	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
3556	1328	svchost.exe	0xd60146dcc080	5	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
3616	1328	svchost.exe	0xd60146e0d080	6	-	0	False	2026-08-27 13:08:25.000000 UTC	N/A	Disabled
3768	1328	spoolsv.exe	0xd60146e47080	10	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
3804	1328	svchost.exe	0xd60146eaf0c0	2	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
3896	1328	svchost.exe	0xd60146dd4080	4	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
4012	1328	svchost.exe	0xd6014804d080	6	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
4064	1328	Everything.exe	0xd601480c80c0	2	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
4080	1328	GameInputRedis	0xd601480cf080	11	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
4092	1328	svchost.exe	0xd601480d2080	17	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
3160	1328	jhi_service.ex	0xd601480d0080	2	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
3108	1328	looking-glass-	0xd601480db080	2	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
3288	1328	svchost.exe	0xd60146e4c0c0	21	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
4104	1328	nvcontainer.ex	0xd6014806d080	29	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
4116	1328	lghub_updater.	0xd601480f5080	51	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
4148	1328	qemu-ga.exe	0xd601480a3080	3	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
4156	1328	svchost.exe	0xd601480a2080	3	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
4224	1328	MpDefenderCore	0xd6014807d080	10	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
4256	1328	svchost.exe	0xd6014810a080	5	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
4268	1328	WMIRegistratio	0xd60148109080	2	-	0	True	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
4284	1328	logi_lamparray	0xd60146e51080	8	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
4352	1328	MsMpEng.exe	0xd6014811b080	68	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
4444	1328	svchost.exe	0xd60148279080	7	-	0	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
4668	3108	looking-glass-	0xd6014836b080	2	-	1	False	2026-08-27 13:08:26.000000 UTC	N/A	Disabled
```

