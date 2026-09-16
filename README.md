# AmdTools64.sys — arbitrary physical memory access from user mode

Security research on `AmdTools64.sys` ("AMD Tools Driver" 1.7.16.219), an
AMD-signed Windows kernel driver that is not part of any public AMD software
distribution. The driver exposes a rich set of `METHOD_BUFFERED` IOCTLs that
map, read and write **arbitrary attacker-controlled physical memory** from
user mode, which turns the driver into a fully working BYOVD ("bring your own
vulnerable driver") primitive.

To the best of our knowledge the sample is not currently on Microsoft's
recommended vulnerable-driver blocklist.

## Affected component

| Field | Value |
|---|---|
| File | `AmdTools64.sys` |
| Product version | 1.7.16.219 |
| Original name | `amdtools64.sys` |
| SHA-256 | `891007BC9F3B55AE168FA60CCBB831CCDB5DCE4DA4A591D000806D5A2C6115C3` |
| Signature | "Advanced Micro Devices Inc." (Sectigo RSA Code Signing CA, cross-certified via Microsoft Code Verification Root) |
| Build timestamp | 2022-06-22 (PE header) |
| PDB path | `C:\Project\AmdToolsDriver\src\AMD Special Tools Driver\x64\Release\amdtools64.pdb` |

The driver is a PnP driver. Its `AddDevice` creates a device via
`IoCreateDeviceSecure` with SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (SYSTEM and
Administrators only) and registers a device interface with GUID
`{1232175B-1C34-41FD-B101-342D47B828AC}`. Loading the driver therefore only
requires administrator rights, after which the IOCTLs below break the
admin-to-kernel boundary.

## Arbitrary physical memory primitives

### `0xFFF028A4` — map arbitrary physical memory into user mode (RW)

Request layout (`METHOD_BUFFERED`, input and output `>= 0x21` bytes):

```c
struct MmapRequest {
    UINT64 PhysicalAddress; // +0x00 in:  physical base address (unvalidated)
    UINT32 Length;          // +0x08 in:  size in bytes (unvalidated)
    UINT32 Status;          // +0x0C out: driver status
    PVOID  PoolCtx;         // +0x10 out: driver-side allocation (pass to 0xFFF028A8 to unmap)
    PVOID  UserVa;          // +0x18 out: user-mode mapping of the physical memory
    UINT8  CacheType;       // +0x20 in:  0 = NonCached, 1 = Cached, 2 = WriteCombined
};
```

The handler runs `MmMapIoSpace` → `IoAllocateMdl` →
`MmBuildMdlForNonPagedPool` → `MmMapLockedPagesSpecifyCache(Mdl, UserMode, ...)`
and returns the resulting user-mode address. The mapping is readable **and
writable**, so a single call yields full kernel read/write. `0xFFF028A8` frees
a previously returned mapping (`PoolCtx`).

### `0xFFF0281C` / `0xFFF02820` — one-shot block read / block write

Both share the same 0x10C-byte request (input and output `>= 0x10C`):

```c
struct PhysBlockRequest {
    UINT64 PhysicalAddress; // +0x00 in: 64-bit physical address (unvalidated)
    UINT16 Width;           // +0x08 in: byte count, 1..0x100
    UINT16 Status;          // +0x0A out: 0 = ok, 5 = MmMapIoSpace failed, 6 = bad width
    UINT8  Data[0x100];     // +0x0C in (write) / out (read)
};
```

* `0xFFF0281C` (handler `0x1400026e8`): `MmMapIoSpace` → copy `Width` bytes
  from the mapped region into `Data` → `MmUnmapIoSpace` — **arbitrary read**.
* `0xFFF02820` (handler `0x140003050`): `MmMapIoSpace` → copy `Width` bytes
  from `Data` into the mapped region → `MmUnmapIoSpace` — **arbitrary write**.

`MmMapIoSpace` is called with `MmCached`; note that `MmMapIoSpace(0, ...)`
fails, so physical address 0 is the only unusable address.

### Other physical-memory read primitives

| IOCTL | Size | Behaviour |
|---|---|---|
| `0xFFF02888` | 0x20 | `MmMapIoSpace(Phys, Len)` → copy into pool → map pool to user; returns `PoolCtx` + `UserVa`. `Len` is unvalidated. `0xFFF0288C` frees. |
| `0xFFF02824` | 0x2122 | Pattern search over physical memory: maps `[Base, Base+WindowSize)`, probes every `Stride` bytes with `RtlCompareMemory` against `Pattern` (`ChunkSize <= 0x100`), on match copies up to `ReadLength (<= 0x2000)` bytes back and returns the match address. |

### Other arbitrary/near-arbitrary write primitives

| IOCTL | Size | Behaviour |
|---|---|---|
| `0xFFF02894` | 0xC | SMN (AMD System Management Network) register **write**: base address taken from MSR `0xC0010058` masked with `0xFFFFFFF00000`, plus a fully user-controlled offset; byte/word/dword (`WRITE_REGISTER_*`) from the request. |
| `0xFFF02890` | 0xC | SMN register read (same addressing). |
| `0xFFF02884` | 8 | APIC register **write**: maps the APIC base from MSR `0x1B` (enabling the APIC via `WRMSR` first if necessary), offset `WORD[req] < 0x20`, value `DWORD[req+4]`, returns the old value. |
| `0xFFF02880` | 8 | APIC register read (same addressing). |
| `0xFFF02830` | 0xA | PCI configuration space **write** via `HalSetBusDataByOffset`: `{Bus, Func, Dev, Width(1/2/4), Offset, Status, Value}`. Combined with the BAR-mapping IOCTLs below this yields an indirect arbitrary physical mapping primitive (rewrite a BAR, then map it). |
| `0xFFF0282C` | 0xA | PCI configuration space read via `HalGetBusDataByOffset`. |
| `0xFFF02834` / `0xFFF0283C` | 0x16 | Read the BAR of an attacker-chosen PCI device (`Bus/Dev/Func/Offset`) and map it into user mode; `0xFFF02840` / `0xFFF02838` are the matching unmap IOCTLs. |

### Memory allocation primitives

| IOCTL | Size | Behaviour |
|---|---|---|
| `0xFFF028AC` | 0x38 | `MmAllocateContiguousMemorySpecifyCache` + MDL + user-mode mapping of the allocation; `0xFFF028B0` frees. |
| `0xFFF02868` / `0xFFF0289C` | 0x2E | `MmAllocatePagesForMdl` (attacker-controlled physical range) + user-mode mapping; `0xFFF0286C` / `0xFFF028A0` free. |

### Full IOCTL dispatch table

Single dispatcher at `0x140005968`; `0xFFF028C0` selects a batch/command-list
processor instead. Handler addresses are from the 1.7.16.219 build.

| IOCTL | Handler | In/Out min | Function |
|---|---|---|---|
| `0xFFF02800` | inline | 4 | return version `0x010710DA` |
| `0xFFF02804` | `0x1400027BC` | 0x14 | SMU/MP1 command |
| `0xFFF02808` | `0x140003124` | 0x14 | SMU/MP1 command |
| `0xFFF0280C` | `0x140002BD0` | — | SMU/MP1 command |
| `0xFFF02810` | `0x140002BD0` | — | SMU/MP1 command |
| `0xFFF02814` | `0x140002990` | 8 | SMU/MP1 command |
| `0xFFF02818` | `0x1400032F0` | 8 | SMU/MP1 command |
| `0xFFF0281C` | `0x1400026E8` | 0x10C | **physical read (<= 0x100 B)** |
| `0xFFF02820` | `0x140003050` | 0x10C | **physical write (<= 0x100 B)** |
| `0xFFF02824` | `0x140002A38` | 0x2122 | **physical pattern search + bulk read** |
| `0xFFF02828` | `0x140001A44` | 8 | SMU/MP1 command |
| `0xFFF0282C` | `0x140002818` | 0xA | **PCI config read** |
| `0xFFF02830` | `0x140003188` | 0xA | **PCI config write** |
| `0xFFF02834` | `0x1400022FC` | 0x16 | **map PCI BAR to user mode** |
| `0xFFF02838` | `0x140002D70` | 0x16 | unmap |
| `0xFFF0283C` | `0x140001CAC` | 0x16 | map PCI BAR (via pool copy) |
| `0xFFF02840` | `0x140002C34` | 0x16 | unmap |
| `0xFFF02844` | `0x140002504` | 6 | SMU/MP1 command |
| `0xFFF02848` | `0x1400029C0` | 3 | SMU/MP1 command |
| `0xFFF0284C` | `0x140003320` | 3 | SMU/MP1 command |
| `0xFFF02850` | `0x14000269C` | 2 | SMU/MP1 command |
| `0xFFF02854` | `0x140003000` | 2 | SMU/MP1 command |
| `0xFFF02858` | `0x140001C94` | 1 | SMU/MP1 command |
| `0xFFF0285C` | `0x140006504` | 8 | SMU/MP1 command |
| `0xFFF02860` | `0x14000261C` | 0xC | SMU/MP1 command |
| `0xFFF02864` | `0x140002EF0` | 0xC | SMU/MP1 command |
| `0xFFF02868` | `0x14000187C` | 0x2E | **MmAllocatePagesForMdl + user map** |
| `0xFFF0286C` | `0x140001BC0` | 0x2E | free |
| `0xFFF02870` | `0x140002668` | 0xC | SMU/MP1 command |
| `0xFFF02874` | `0x140002F78` | 0xC | SMU/MP1 command |
| `0xFFF0287C` | `0x140002DF8` | — | SMU/MP1 command |
| `0xFFF02880` | `0x140002534` | 8 | APIC register read |
| `0xFFF02884` | `0x140002E00` | 8 | APIC register write |
| `0xFFF02888` | `0x140001EF0` | 0x20 | **snapshot physical range to user map** |
| `0xFFF0288C` | `0x140002CA8` | 0x20 | free snapshot |
| `0xFFF02890` | `0x1400028B0` | 0xC | **SMN register read** |
| `0xFFF02894` | `0x140003210` | 0xC | **SMN register write** |
| `0xFFF02898` | `0x140001C44` | 0xC | SMU/MP1 command |
| `0xFFF0289C` | `0x140001960` | 0x2E | **MmAllocatePagesForMdl + user map** |
| `0xFFF028A0` | `0x140001BC0` | 0x2E | free |
| `0xFFF028A4` | `0x1400020E4` | 0x21 | **map arbitrary physical memory (RW)** |
| `0xFFF028A8` | `0x140002D1C` | 0x21 | unmap |
| `0xFFF028AC` | `0x140001668` | 0x38 | **contiguous memory alloc + user map** |
| `0xFFF028B0` | `0x140001B30` | 0x38 | free |
| `0xFFF028B8` | `0x140001C28` | 8 | SMU/MP1 command |
| `0xFFF028BC` | `0x140002BB0` | 0x10 | SMU/MP1 command |
| `0xFFF028C0` | `0x1400057E0` | — | batch command-list processor |
| `0xFFF028C4` | `0x140002BD0` | 2/0x78 | SMU/MP1 command |
| `0xFFF02900` | `0x140001368` | 0x118/0x14 | forwards request to another device |
| `0xFFF02940` | `0x140002A14` | 0x18 | forwards request to another device |

Entries marked "SMU/MP1 command" pass small fixed-size payloads to the AMD
SMU mailbox and were not audited in depth; several of them also end in
`MmMapIoSpace`-based access.

## Proof-of-concept code

### `poc_amdtools64.cpp` — physical memory read via `0xFFF028A4`

Installs the driver as a kernel service, creates a root-enumerated PnP
devnode, opens the device interface, maps physical `0x53000000`
(`Length = 0x200000`, `MmNonCached`) into user mode and dumps the first
64 bytes.

```
cl /EHsc /W4 poc_amdtools64.cpp cfgmgr32.lib     (MSVC x64)
poc_amdtools64.exe C:\absolute\path\to\AmdTools64.sys
```

### `poc_amdtools64_write.cpp` — physical memory write via `0xFFF02820`

End-to-end, crash-safe demonstration of the **arbitrary write**:

1. installs the driver and binds it to the devnode (see "Loading the driver"
   below);
2. allocates one **AWE page** (`AllocateUserPhysicalPages`, requires
   `SeLockMemoryPrivilege`) — a physical frame *owned by the process*, so the
   test can never corrupt unrelated kernel/device memory;
3. plants a random 32-byte marker in the frame through its user-mode mapping
   and verifies the driver's read primitive (`0xFFF0281C`) sees it at
   `PFN << 12`;
4. writes the payload `"AmdTools64 0xFFF02820 phys write"` to
   `phys + 0x800` with `0xFFF02820` and shows the bytes appear in the
   process' own virtual address;
5. additionally exercises the `Width == 4` (DWORD) path of the handler;
6. stops and deletes the service.

```
x86_64-w64-mingw32-g++ -O2 -static -o poc_amdtools64_write.exe \
    poc_amdtools64_write.cpp -lcfgmgr32 -lnewdev -lpsapi
poc_amdtools64_write.exe C:\absolute\path\to\AmdTools64.sys
```

Verified working output (Windows 10 21H2 x64, KVM/QEMU VM):

```
[+] AWE frame mapped: PFN 0x1B1BAC -> physical 0x1B1BAC000
[+] read-back via 0xFFF0281C matches the marker
[*] writing 32 bytes via IOCTL 0xFFF02820 to physical 0x1B1BAC800...
[+] driver accepted the write (status = 0)
[+] PROOF: bytes appeared in OUR user-mode page @0000000001fb0800:
    AmdTools64 0xFFF02820 phys write
[+] DWORD write path verified (0x44434241 @phys 0x1B1BAC810)
```

## Loading the driver on Windows 10 21H2

The driver is a pure PnP driver (the device is only created in `AddDevice`),
and modern Windows refuses to bind a bare root devnode to a service without a
driver package ("No compatible drivers found"; `UpdateDriverForPlugAndPlayDevices`
fails with `0xE000022F` because the package has no catalog). The PoC uses an
**INF-squat** technique that works without any custom signed package:

1. create the service (`CreateServiceW`);
2. create a root devnode `ROOT\AMDTOOLS64\0000` (`CM_Create_DevNodeW`);
3. give it a hardware ID that matches an *already staged* driver package, e.g.
   `ACPI\QEMU0001` from virtio `pvpanic.inf` (`CM_Add_IDW`) and run
   `CM_Setup_DevNode` — PnP installs that package and creates the class node;
4. rewrite the `Service` value (in both `Enum\ROOT\AMDTOOLS64\0000` and
   `Control\Class\{...}\00NN`) to `AmdTools64`;
5. disable/enable the device — PnP now loads `AmdTools64.sys` and `AddDevice`
   registers the device interface.

Administrative rights are required, matching the standard BYOVD threat model.
`SeLockMemoryPrivilege` ("Lock pages in memory") additionally needs to be
granted to the account for the AWE-based verification in
`poc_amdtools64_write.cpp`.

## Driver quirks worth knowing

* `MmMapIoSpace(0, ...)` fails, and ranges covering non-RAM holes (VGA range,
  MMIO, beyond top of RAM) fail with `STATUS_NO_MEMORY` (`0xC0000017`) —
  relevant when scripting the read/search IOCTLs.
* `MmMapIoSpace` with `MmCached` fails for ranges somewhere between 64 KiB and
  1 MiB (`0xFFF02824` searches were verified working with 64 KiB windows and
  failing with 1 MiB windows); the `MmNonCached` path used by `0xFFF02888`
  handles at least 64 MiB.
* The `0xFFF028A4` mapping returned to user mode is writable — the "read"
  primitive is implicitly a read/write primitive as well.

## Repository layout

| File | Description |
|---|---|
| `AmdTools64.sys` | vulnerable driver sample (AMD-signed) |
| `poc_amdtools64.cpp` | read PoC via `0xFFF028A4` (map physical → user) |
| `poc_amdtools64_write.cpp` | write PoC via `0xFFF02820` (AWE-verified, tested on VM) |
| `amdtools64_loldrivers.yaml` | LOLDrivers submission entry |
| `loldrivers_issue.md` | LOLDrivers issue draft |
| `amd_psirt_report.txt` | AMD PSIRT coordinated disclosure report draft |

## Disclosure

Reported to AMD PSIRT under coordinated disclosure. The finding has not been
publicly disclosed at the time of writing. Do not use this code against
systems you do not own or have explicit permission to test.
