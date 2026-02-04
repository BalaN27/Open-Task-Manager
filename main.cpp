#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <comdef.h>
#include <WbemIdl.h>
#include <comutil.h>
#include <map>
#include <Lmcons.h>
#include <algorithm>
#include <pdh.h>
#include <pdhmsg.h>
#include <iphlpapi.h>

// Link these in your compiler command: -lole32 -lwbemuuid -lpsapi -lgdi32 -lpdh -liphlpapi

// --- FORWARD DECLARATIONS ---
std::string GetRegistryValue(HKEY hKeyRoot, const char* subKey, const char* valueName);
HICON LoadIconFromFile(const char* filePath);

// --- DATA STRUCTURES ---
struct RAMDetails { // Begin RAMDetails struct
    std::string type = "Unknown";
    int slotsUsed = 0;
    std::vector<std::string> sticks;
}; // End RAMDetails struct

struct SystemSpecs { // Begin SystemSpecs struct
    std::string cpu;
    std::string mobo;
    std::string gpu;

    SystemSpecs() { // Begin SystemSpecs constructor
        cpu = GetRegistryValue(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString");
        mobo = GetRegistryValue(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "BaseBoardProduct");
        gpu = "Fetching via DXGI...";
    } // End SystemSpecs constructor
}; // End SystemSpecs struct

struct ProcessInfo { // Begin ProcessInfo struct
    std::wstring name;
    DWORD id;
    std::string location;
    float cpuUsage;
    float memoryMB;
    float diskMBps;
    float netMBps;
}; // End ProcessInfo struct

struct ProcessGroup { // Begin ProcessGroup struct
    std::wstring name;
    std::vector<DWORD> ids;
    std::vector<std::string> locations;
    std::vector<float> cpuUsages;
    std::vector<float> memoryMBs;
    std::vector<float> diskMBpss;
    std::vector<float> netMBpss;
}; // End ProcessGroup struct

struct ProcessCategory { // Begin ProcessCategory struct
    std::string categoryName;
    std::vector<ProcessGroup> groups;
}; // End ProcessCategory struct

struct InstalledProgram { // Begin InstalledProgram struct
    std::string name;
    std::string version;
    std::string publisher;
    std::string uninstallString;
    std::string installDate;
    std::string size;
}; // End InstalledProgram struct

// --- DIRECTX GLOBALS ---
static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

// --- CONTEXT MENU GLOBALS ---
static DWORD g_selectedProcessID = 0;
static std::wstring g_selectedProcessName = L"";

// --- PERFORMANCE MONITORING GLOBALS ---
struct ProcessCPUInfo { // Begin ProcessCPUInfo struct
    ULONGLONG lastCPUTime;
    ULONGLONG lastSystemTime;
    DWORD processID;
}; // End ProcessCPUInfo struct

struct NetworkStats { // Begin NetworkStats struct
    ULONGLONG totalBytesReceived;
    ULONGLONG totalBytesSent;
    ULONGLONG lastUpdateTime;
}; // End NetworkStats struct

static std::map<DWORD, ProcessCPUInfo> g_processCPUData;
static NetworkStats g_lastNetworkStats = {0, 0, 0};

// --- FUNCTION PROTOTYPES ---
std::string GetGPUName(ID3D11Device* device);
RAMDetails GetAdvancedRAMInfo();
float GetRAMUsage();
std::vector<ProcessInfo> GetProcesses();
std::vector<ProcessGroup> GroupProcesses(const std::vector<ProcessInfo>& flatList);
std::vector<ProcessCategory> CategorizeProcesses(const std::vector<ProcessInfo>& flatList);
std::vector<InstalledProgram> GetInstalledPrograms();
bool IsSystemProcess(const std::wstring& processName);
bool KillProcess(DWORD processID, const std::wstring& processName);
float GetProcessCPUUsage(DWORD processID);
void UpdateProcessMetrics(std::vector<ProcessInfo>& processes);
float GetSystemNetworkUsage();

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

void InitializeImGui(HWND hwnd);
void ShutdownImGui();
void RenderFrame();
void RenderTaskManagerTab(std::vector<ProcessInfo>& rawProcesses);
void RenderSystemDetailsTab(const SystemSpecs& specs, const RAMDetails& ramAdv);
void RenderRemoveAppTab();
void RenderBottomBar();
void RenderProcessesSubTab(const std::vector<ProcessGroup>& groups);
void RenderUsersSubTab();

// --- ICON LOADING HELPER ---
HICON LoadIconFromFile(const char* filePath) { // Begin LoadIconFromFile function
    // Try to load as .ico file first
    HICON hIcon = (HICON)LoadImageA(NULL, filePath, IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE);
    
    if (hIcon != NULL) { // Begin if icon loaded successfully
        return hIcon;
    } // End if icon loaded successfully
    
    // If .ico failed, try loading as bitmap (.png, .bmp, etc.)
    HBITMAP hBitmap = (HBITMAP)LoadImageA(NULL, filePath, IMAGE_BITMAP, 32, 32, LR_LOADFROMFILE);
    
    if (hBitmap != NULL) { // Begin if bitmap loaded successfully
        // Convert bitmap to icon
        ICONINFO iconInfo;
        iconInfo.fIcon = TRUE;
        iconInfo.xHotspot = 0;
        iconInfo.yHotspot = 0;
        iconInfo.hbmMask = hBitmap;
        iconInfo.hbmColor = hBitmap;
        
        hIcon = CreateIconIndirect(&iconInfo);
        DeleteObject(hBitmap);
        
        return hIcon;
    } // End if bitmap loaded successfully
    
    return NULL;
} // End LoadIconFromFile function

// --- REGISTRY HELPER ---
std::string GetRegistryValue(HKEY hKeyRoot, const char* subKey, const char* valueName) { // Begin GetRegistryValue function
    char buffer[255];
    DWORD bufferSize = sizeof(buffer);
    if (RegGetValueA(hKeyRoot, subKey, valueName, RRF_RT_REG_SZ, NULL, buffer, &bufferSize) == ERROR_SUCCESS) { // Begin if RegGetValueA success
        return std::string(buffer);
    } // End if RegGetValueA success
    return "Unknown Hardware";
} // End GetRegistryValue function

// --- GPU NAME RETRIEVAL ---
std::string GetGPUName(ID3D11Device* device) { // Begin GetGPUName function
    if (device == nullptr) { // Begin if device is null
        return "N/A";
    } // End if device is null
    
    IDXGIDevice* pDXGIDevice = nullptr;
    device->QueryInterface(__uuidof(IDXGIDevice), (void**)&pDXGIDevice);
    
    IDXGIAdapter* pAdapter = nullptr;
    pDXGIDevice->GetAdapter(&pAdapter);
    
    DXGI_ADAPTER_DESC desc;
    pAdapter->GetDesc(&desc);
    
    std::wstring ws(desc.Description);
    std::string str(ws.begin(), ws.end());
    
    pAdapter->Release();
    pDXGIDevice->Release();
    
    return str;
} // End GetGPUName function

// --- RAM INFORMATION RETRIEVAL ---
RAMDetails GetAdvancedRAMInfo() { // Begin GetAdvancedRAMInfo function
    RAMDetails details;
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) { // Begin if CoInitializeEx failed
        return details;
    } // End if CoInitializeEx failed

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    
    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

    IWbemServices* pSvc = NULL;
    BSTR path = SysAllocString(L"ROOT\\CIMV2");
    hr = pLoc->ConnectServer(path, NULL, NULL, NULL, 0L, NULL, NULL, &pSvc);
    SysFreeString(path);

    if (SUCCEEDED(hr)) { // Begin if ConnectServer succeeded
        IEnumWbemClassObject* pEnumerator = NULL;
        BSTR queryLang = SysAllocString(L"WQL");
        BSTR query = SysAllocString(L"SELECT Capacity, SMBIOSMemoryType FROM Win32_PhysicalMemory");
        
        hr = pSvc->ExecQuery(queryLang, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        
        SysFreeString(queryLang);
        SysFreeString(query);

        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;

        while (pEnumerator) { // Begin while pEnumerator exists
            hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) { // Begin if no more objects
                break;
            } // End if no more objects

            VARIANT vtProp;
            
            if (SUCCEEDED(pclsObj->Get(L"Capacity", 0, &vtProp, 0, 0))) { // Begin if Get Capacity succeeded
                long long gb = 0;
                if (vtProp.vt == VT_BSTR) { // Begin if variant type is BSTR
                    gb = _wtoi64(vtProp.bstrVal) / (1024 * 1024 * 1024);
                } else if (vtProp.vt == VT_I8 || vtProp.vt == VT_UI8) { // Begin else if variant type is integer
                    gb = vtProp.ullVal / (1024 * 1024 * 1024);
                } // End else if variant type is integer
                
                details.sticks.push_back(std::to_string(gb) + " GB Stick");
                details.slotsUsed = details.slotsUsed + 1;
                VariantClear(&vtProp);
            } // End if Get Capacity succeeded

            if (SUCCEEDED(pclsObj->Get(L"SMBIOSMemoryType", 0, &vtProp, 0, 0))) { // Begin if Get SMBIOSMemoryType succeeded
                if (vtProp.vt == VT_I4) { // Begin if variant type is I4
                    if (vtProp.intVal == 26) { // Begin if DDR4
                        details.type = "DDR4";
                    } else if (vtProp.intVal == 34) { // Begin else if DDR5
                        details.type = "DDR5";
                    } else if (vtProp.intVal == 24) { // Begin else if DDR3
                        details.type = "DDR3";
                    } // End else if DDR3
                } // End if variant type is I4
                VariantClear(&vtProp);
            } // End if Get SMBIOSMemoryType succeeded
            pclsObj->Release();
        } // End while pEnumerator exists
        
        if (pEnumerator) { // Begin if pEnumerator exists
            pEnumerator->Release();
        } // End if pEnumerator exists
        pSvc->Release();
    } // End if ConnectServer succeeded
    
    if (pLoc) { // Begin if pLoc exists
        pLoc->Release();
    } // End if pLoc exists
    CoUninitialize();
    return details;
} // End GetAdvancedRAMInfo function

// --- RAM USAGE PERCENTAGE ---
float GetRAMUsage() { // Begin GetRAMUsage function
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    return (float)memInfo.dwMemoryLoad;
} // End GetRAMUsage function

// --- PROCESS CPU USAGE CALCULATION ---
float GetProcessCPUUsage(DWORD processID) { // Begin GetProcessCPUUsage function
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == NULL) { // Begin if process handle failed
        return 0.0f;
    } // End if process handle failed
    
    FILETIME creationTime, exitTime, kernelTime, userTime;
    FILETIME systemTime;
    
    if (GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime) == FALSE) { // Begin if GetProcessTimes failed
        CloseHandle(hProcess);
        return 0.0f;
    } // End if GetProcessTimes failed
    
    GetSystemTimeAsFileTime(&systemTime);
    
    ULARGE_INTEGER nowKernel, nowUser, nowSystem;
    nowKernel.LowPart = kernelTime.dwLowDateTime;
    nowKernel.HighPart = kernelTime.dwHighDateTime;
    nowUser.LowPart = userTime.dwLowDateTime;
    nowUser.HighPart = userTime.dwHighDateTime;
    nowSystem.LowPart = systemTime.dwLowDateTime;
    nowSystem.HighPart = systemTime.dwHighDateTime;
    
    ULONGLONG processCPUTime = nowKernel.QuadPart + nowUser.QuadPart;
    
    float cpuPercent = 0.0f;
    
    if (g_processCPUData.find(processID) != g_processCPUData.end()) { // Begin if previous data exists
        ProcessCPUInfo& prevData = g_processCPUData[processID];
        
        ULONGLONG cpuTimeDelta = processCPUTime - prevData.lastCPUTime;
        ULONGLONG systemTimeDelta = nowSystem.QuadPart - prevData.lastSystemTime;
        
        if (systemTimeDelta > 0) { // Begin if valid time delta
            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);
            
            cpuPercent = (float)(cpuTimeDelta * 100.0) / (float)systemTimeDelta;
            cpuPercent = cpuPercent * sysInfo.dwNumberOfProcessors;
            
            if (cpuPercent > 100.0f) { // Begin if over 100%
                cpuPercent = 100.0f;
            } // End if over 100%
        } // End if valid time delta
    } // End if previous data exists
    
    // Store current data for next calculation
    g_processCPUData[processID].lastCPUTime = processCPUTime;
    g_processCPUData[processID].lastSystemTime = nowSystem.QuadPart;
    g_processCPUData[processID].processID = processID;
    
    CloseHandle(hProcess);
    return cpuPercent;
} // End GetProcessCPUUsage function

// --- PROCESS LIST RETRIEVAL WITH ACCURATE METRICS ---
std::vector<ProcessInfo> GetProcesses() { // Begin GetProcesses function
    std::vector<ProcessInfo> list;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnap, &pe)) { // Begin if Process32FirstW succeeded
        do { // Begin do-while loop
            ProcessInfo info;
            info.name = pe.szExeFile;
            info.id = pe.th32ProcessID;
            info.location = "-";
            info.cpuUsage = 0.0f;
            info.memoryMB = 0.0f;
            info.diskMBps = 0.0f;
            info.netMBps = 0.0f;
            
            // Get process path and metrics
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProcess != NULL) { // Begin if process handle opened
                
                // Get process executable path
                wchar_t processPath[MAX_PATH];
                DWORD pathSize = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, processPath, &pathSize)) { // Begin if QueryFullProcessImageNameW succeeded
                    std::wstring pathWStr(processPath);
                    std::transform(pathWStr.begin(), pathWStr.end(), pathWStr.begin(), ::towlower);
                    
                    // Check location
                    if (pathWStr.find(L"\\system32\\") != std::wstring::npos) { // Begin if in system32
                        info.location = "System32";
                    } else if (pathWStr.find(L"\\windows\\") != std::wstring::npos) { // Begin else if in windows
                        info.location = "Win";
                    } else { // Begin else other location
                        info.location = "-";
                    } // End else other location
                } // End if QueryFullProcessImageNameW succeeded
                
                // Get memory usage
                PROCESS_MEMORY_COUNTERS_EX pmc;
                if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) { // Begin if GetProcessMemoryInfo succeeded
                    info.memoryMB = (float)pmc.WorkingSetSize / (1024.0f * 1024.0f);
                } // End if GetProcessMemoryInfo succeeded
                
                // Get I/O counters for disk activity
                IO_COUNTERS ioCounters;
                if (GetProcessIoCounters(hProcess, &ioCounters)) { // Begin if GetProcessIoCounters succeeded
                    // This gives total I/O bytes, we'll need to calculate rate over time
                    // For now, store the total and we'll calculate delta later
                    static std::map<DWORD, ULONGLONG> lastIOBytes;
                    static std::map<DWORD, ULONGLONG> lastIOTime;
                    
                    ULONGLONG totalIO = ioCounters.ReadTransferCount + ioCounters.WriteTransferCount;
                    ULONGLONG currentTime = GetTickCount64();
                    
                    if (lastIOBytes.find(pe.th32ProcessID) != lastIOBytes.end()) { // Begin if has previous IO data
                        ULONGLONG ioDelta = totalIO - lastIOBytes[pe.th32ProcessID];
                        ULONGLONG timeDelta = currentTime - lastIOTime[pe.th32ProcessID];
                        
                        if (timeDelta > 0) { // Begin if valid time delta
                            // Convert to MB/s
                            info.diskMBps = (float)ioDelta / (1024.0f * 1024.0f) / ((float)timeDelta / 1000.0f);
                        } // End if valid time delta
                    } // End if has previous IO data
                    
                    lastIOBytes[pe.th32ProcessID] = totalIO;
                    lastIOTime[pe.th32ProcessID] = currentTime;
                } // End if GetProcessIoCounters succeeded
                
                CloseHandle(hProcess);
            } // End if process handle opened
            
            // Get CPU usage
            info.cpuUsage = GetProcessCPUUsage(pe.th32ProcessID);
            
            // Note: Per-process network usage requires additional privileges and complex tracking
            // For now, network is calculated at system level - individual process network usage
            // would require packet inspection or ETW (Event Tracing for Windows)
            // We'll display 0.0 for now, but total system network is available
            info.netMBps = 0.0f;
            
            list.push_back(info);
        } while (Process32NextW(hSnap, &pe)); // End do-while loop
    } // End if Process32FirstW succeeded
    CloseHandle(hSnap);
    return list;
} // End GetProcesses function

// --- UPDATE PROCESS METRICS (CALL PERIODICALLY) ---
void UpdateProcessMetrics(std::vector<ProcessInfo>& processes) { // Begin UpdateProcessMetrics function
    for (auto& proc : processes) { // Begin for each process
        proc.cpuUsage = GetProcessCPUUsage(proc.id);
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc.id);
        if (hProcess != NULL) { // Begin if process opened
            // Update memory
            PROCESS_MEMORY_COUNTERS_EX pmc;
            if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) { // Begin if got memory info
                proc.memoryMB = (float)pmc.WorkingSetSize / (1024.0f * 1024.0f);
            } // End if got memory info
            
            CloseHandle(hProcess);
        } // End if process opened
    } // End for each process
} // End UpdateProcessMetrics function

// --- GET SYSTEM NETWORK USAGE ---
float GetSystemNetworkUsage() { // Begin GetSystemNetworkUsage function
    PMIB_IFTABLE pIfTable = NULL;
    DWORD dwSize = 0;
    
    // First call to get buffer size
    if (GetIfTable(NULL, &dwSize, FALSE) != ERROR_INSUFFICIENT_BUFFER) { // Begin if GetIfTable failed
        return 0.0f;
    } // End if GetIfTable failed
    
    pIfTable = (MIB_IFTABLE*)malloc(dwSize);
    if (pIfTable == NULL) { // Begin if malloc failed
        return 0.0f;
    } // End if malloc failed
    
    if (GetIfTable(pIfTable, &dwSize, FALSE) != NO_ERROR) { // Begin if GetIfTable failed
        free(pIfTable);
        return 0.0f;
    } // End if GetIfTable failed
    
    ULONGLONG totalBytesReceived = 0;
    ULONGLONG totalBytesSent = 0;
    
    for (DWORD i = 0; i < pIfTable->dwNumEntries; i = i + 1) { // Begin for each interface
        MIB_IFROW* pIfRow = &pIfTable->table[i];
        
        // Only count active interfaces (up and operational)
        if (pIfRow->dwOperStatus == MIB_IF_OPER_STATUS_OPERATIONAL || 
            pIfRow->dwOperStatus == MIB_IF_OPER_STATUS_CONNECTED) { // Begin if interface is active
            totalBytesReceived = totalBytesReceived + pIfRow->dwInOctets;
            totalBytesSent = totalBytesSent + pIfRow->dwOutOctets;
        } // End if interface is active
    } // End for each interface
    
    ULONGLONG currentTime = GetTickCount64();
    float networkMBps = 0.0f;
    
    if (g_lastNetworkStats.lastUpdateTime > 0) { // Begin if have previous data
        ULONGLONG receivedDelta = totalBytesReceived - g_lastNetworkStats.totalBytesReceived;
        ULONGLONG sentDelta = totalBytesSent - g_lastNetworkStats.totalBytesSent;
        ULONGLONG timeDelta = currentTime - g_lastNetworkStats.lastUpdateTime;
        
        if (timeDelta > 0) { // Begin if valid time delta
            ULONGLONG totalBytesDelta = receivedDelta + sentDelta;
            networkMBps = (float)totalBytesDelta / (1024.0f * 1024.0f) / ((float)timeDelta / 1000.0f);
        } // End if valid time delta
    } // End if have previous data
    
    g_lastNetworkStats.totalBytesReceived = totalBytesReceived;
    g_lastNetworkStats.totalBytesSent = totalBytesSent;
    g_lastNetworkStats.lastUpdateTime = currentTime;
    
    free(pIfTable);
    return networkMBps;
} // End GetSystemNetworkUsage function

// --- GROUP PROCESSES BY NAME ---
std::vector<ProcessGroup> GroupProcesses(const std::vector<ProcessInfo>& flatList) { // Begin GroupProcesses function
    std::map<std::wstring, ProcessGroup> groups;
    for (const auto& p : flatList) { // Begin for each process in flatList
        groups[p.name].name = p.name;
        groups[p.name].ids.push_back(p.id);
    } // End for each process in flatList
    std::vector<ProcessGroup> result;
    for (auto const& [name, group] : groups) { // Begin for each group in groups
        result.push_back(group);
    } // End for each group in groups
    return result;
} // End GroupProcesses function

// --- CHECK IF PROCESS IS SYSTEM PROCESS ---
bool IsSystemProcess(const std::wstring& processName) { // Begin IsSystemProcess function
    // Common Windows system processes
    std::vector<std::wstring> systemProcesses = { // Begin systemProcesses list
        L"System", L"Registry", L"smss.exe", L"csrss.exe", L"wininit.exe",
        L"services.exe", L"lsass.exe", L"svchost.exe", L"winlogon.exe",
        L"explorer.exe", L"dwm.exe", L"taskmgr.exe", L"dllhost.exe",
        L"conhost.exe", L"RuntimeBroker.exe", L"SearchHost.exe",
        L"StartMenuExperienceHost.exe", L"ShellExperienceHost.exe",
        L"TextInputHost.exe", L"SecurityHealthService.exe",
        L"SgrmBroker.exe", L"fontdrvhost.exe", L"WmiPrvSE.exe",
        L"spoolsv.exe", L"dasHost.exe", L"System Idle Process",
        L"audiodg.exe", L"SearchIndexer.exe", L"MsMpEng.exe",
        L"NisSrv.exe", L"SearchApp.exe", L"sihost.exe",
        L"ctfmon.exe", L"taskhostw.exe", L"ApplicationFrameHost.exe"
    }; // End systemProcesses list
    
    for (const auto& sysProc : systemProcesses) { // Begin for each system process
        if (processName == sysProc) { // Begin if process name matches
            return true;
        } // End if process name matches
    } // End for each system process
    
    return false;
} // End IsSystemProcess function

// --- KILL PROCESS FUNCTION ---
bool KillProcess(DWORD processID, const std::wstring& processName) { // Begin KillProcess function
    // Confirmation dialog
    std::wstring confirmMsg = L"Are you sure you want to terminate:\n" + processName + L"\nPID: " + std::to_wstring(processID) + L"?";
    int result = MessageBoxW(NULL, confirmMsg.c_str(), L"Confirm Kill Process", MB_YESNO | MB_ICONWARNING);
    
    if (result == IDYES) { // Begin if user confirmed
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
        
        if (hProcess != NULL) { // Begin if process handle opened
            if (TerminateProcess(hProcess, 0)) { // Begin if TerminateProcess succeeded
                CloseHandle(hProcess);
                
                std::wstring successMsg = L"Process terminated successfully:\n" + processName;
                MessageBoxW(NULL, successMsg.c_str(), L"Success", MB_OK | MB_ICONINFORMATION);
                return true;
            } else { // Begin else TerminateProcess failed
                CloseHandle(hProcess);
                
                std::wstring errorMsg = L"Failed to terminate process:\n" + processName + L"\n\nYou may need administrator privileges.";
                MessageBoxW(NULL, errorMsg.c_str(), L"Error", MB_OK | MB_ICONERROR);
                return false;
            } // End else TerminateProcess failed
        } else { // Begin else process handle failed
            std::wstring errorMsg = L"Failed to open process:\n" + processName + L"\n\nAccess denied or invalid PID.";
            MessageBoxW(NULL, errorMsg.c_str(), L"Error", MB_OK | MB_ICONERROR);
            return false;
        } // End else process handle failed
    } // End if user confirmed
    
    return false;
} // End KillProcess function

// --- CATEGORIZE PROCESSES INTO USER AND OS ---
std::vector<ProcessCategory> CategorizeProcesses(const std::vector<ProcessInfo>& flatList) { // Begin CategorizeProcesses function
    std::map<std::wstring, ProcessGroup> userGroups;
    std::map<std::wstring, ProcessGroup> osGroups;
    
    for (const auto& p : flatList) { // Begin for each process in flatList
        if (IsSystemProcess(p.name)) { // Begin if system process
            osGroups[p.name].name = p.name;
            osGroups[p.name].ids.push_back(p.id);
            osGroups[p.name].locations.push_back(p.location);
            osGroups[p.name].cpuUsages.push_back(p.cpuUsage);
            osGroups[p.name].memoryMBs.push_back(p.memoryMB);
            osGroups[p.name].diskMBpss.push_back(p.diskMBps);
            osGroups[p.name].netMBpss.push_back(p.netMBps);
        } else { // Begin else user process
            userGroups[p.name].name = p.name;
            userGroups[p.name].ids.push_back(p.id);
            userGroups[p.name].locations.push_back(p.location);
            userGroups[p.name].cpuUsages.push_back(p.cpuUsage);
            userGroups[p.name].memoryMBs.push_back(p.memoryMB);
            userGroups[p.name].diskMBpss.push_back(p.diskMBps);
            userGroups[p.name].netMBpss.push_back(p.netMBps);
        } // End else user process
    } // End for each process in flatList
    
    // Get username
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    std::string categoryUserName = "User";
    if (GetUserNameA(username, &username_len)) { // Begin if GetUserNameA succeeded
        categoryUserName = std::string(username);
    } // End if GetUserNameA succeeded
    
    // Create categories
    std::vector<ProcessCategory> categories;
    
    ProcessCategory userCategory;
    userCategory.categoryName = categoryUserName;
    for (auto const& [name, group] : userGroups) { // Begin for each user group
        userCategory.groups.push_back(group);
    } // End for each user group
    categories.push_back(userCategory);
    
    ProcessCategory osCategory;
    osCategory.categoryName = "OS";
    for (auto const& [name, group] : osGroups) { // Begin for each OS group
        osCategory.groups.push_back(group);
    } // End for each OS group
    categories.push_back(osCategory);
    
    return categories;
} // End CategorizeProcesses function

// --- GET INSTALLED PROGRAMS FROM REGISTRY ---
std::vector<InstalledProgram> GetInstalledPrograms() { // Begin GetInstalledPrograms function
    std::vector<InstalledProgram> programs;
    
    // Registry paths to check for installed programs
    const char* registryPaths[] = { // Begin registry paths array
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    }; // End registry paths array
    
    for (int pathIdx = 0; pathIdx < 2; pathIdx = pathIdx + 1) { // Begin for each registry path
        HKEY hUninstKey;
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, registryPaths[pathIdx], 0, KEY_READ, &hUninstKey) == ERROR_SUCCESS) { // Begin if RegOpenKeyExA succeeded
            
            DWORD dwIndex = 0;
            char subKeyName[256];
            DWORD subKeyNameSize = sizeof(subKeyName);
            
            while (RegEnumKeyExA(hUninstKey, dwIndex, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) { // Begin while enumerating subkeys
                
                HKEY hAppKey;
                std::string fullPath = std::string(registryPaths[pathIdx]) + "\\" + std::string(subKeyName);
                
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath.c_str(), 0, KEY_READ, &hAppKey) == ERROR_SUCCESS) { // Begin if opening app key succeeded
                    
                    InstalledProgram program;
                    char buffer[512];
                    DWORD bufferSize;
                    
                    // Get Display Name
                    bufferSize = sizeof(buffer);
                    if (RegQueryValueExA(hAppKey, "DisplayName", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) { // Begin if DisplayName exists
                        program.name = std::string(buffer);
                    } // End if DisplayName exists
                    
                    // Skip if no display name (system component)
                    if (program.name.empty()) { // Begin if name is empty
                        RegCloseKey(hAppKey);
                        subKeyNameSize = sizeof(subKeyName);
                        dwIndex = dwIndex + 1;
                        continue;
                    } // End if name is empty
                    
                    // Get Version
                    bufferSize = sizeof(buffer);
                    if (RegQueryValueExA(hAppKey, "DisplayVersion", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) { // Begin if DisplayVersion exists
                        program.version = std::string(buffer);
                    } else { // Begin else no version
                        program.version = "-";
                    } // End else no version
                    
                    // Get Publisher
                    bufferSize = sizeof(buffer);
                    if (RegQueryValueExA(hAppKey, "Publisher", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) { // Begin if Publisher exists
                        program.publisher = std::string(buffer);
                    } else { // Begin else no publisher
                        program.publisher = "-";
                    } // End else no publisher
                    
                    // Get Uninstall String
                    bufferSize = sizeof(buffer);
                    if (RegQueryValueExA(hAppKey, "UninstallString", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) { // Begin if UninstallString exists
                        program.uninstallString = std::string(buffer);
                    } else { // Begin else no uninstall string
                        program.uninstallString = "";
                    } // End else no uninstall string
                    
                    // Get Install Date
                    bufferSize = sizeof(buffer);
                    if (RegQueryValueExA(hAppKey, "InstallDate", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) { // Begin if InstallDate exists
                        program.installDate = std::string(buffer);
                    } else { // Begin else no install date
                        program.installDate = "-";
                    } // End else no install date
                    
                    // Get Size
                    DWORD size = 0;
                    bufferSize = sizeof(DWORD);
                    if (RegQueryValueExA(hAppKey, "EstimatedSize", NULL, NULL, (LPBYTE)&size, &bufferSize) == ERROR_SUCCESS) { // Begin if EstimatedSize exists
                        if (size > 0) { // Begin if size is valid
                            float sizeMB = (float)size / 1024.0f;
                            char sizeStr[64];
                            sprintf(sizeStr, "%.2f MB", sizeMB);
                            program.size = std::string(sizeStr);
                        } else { // Begin else size is zero
                            program.size = "-";
                        } // End else size is zero
                    } else { // Begin else no size
                        program.size = "-";
                    } // End else no size
                    
                    programs.push_back(program);
                    RegCloseKey(hAppKey);
                } // End if opening app key succeeded
                
                subKeyNameSize = sizeof(subKeyName);
                dwIndex = dwIndex + 1;
            } // End while enumerating subkeys
            
            RegCloseKey(hUninstKey);
        } // End if RegOpenKeyExA succeeded
    } // End for each registry path
    
    // Sort programs alphabetically by name
    std::sort(programs.begin(), programs.end(), [](const InstalledProgram& a, const InstalledProgram& b) { // Begin sort lambda
        return a.name < b.name;
    }); // End sort lambda
    
    return programs;
} // End GetInstalledPrograms function

// --- IMGUI INITIALIZATION ---
void InitializeImGui(HWND hwnd) { // Begin InitializeImGui function
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
    ImGui::StyleColorsDark();
} // End InitializeImGui function

// --- IMGUI SHUTDOWN ---
void ShutdownImGui() { // Begin ShutdownImGui function
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
} // End ShutdownImGui function

// --- RENDER TASK MANAGER TAB ---
void RenderTaskManagerTab(std::vector<ProcessInfo>& rawProcesses) { // Begin RenderTaskManagerTab function
    if (ImGui::BeginTabItem("Task Manager")) { // Begin if BeginTabItem Task Manager
        auto categories = CategorizeProcesses(rawProcesses);

        if (ImGui::BeginChild("ProcessScroll")) { // Begin if BeginChild ProcessScroll
            
            // Create table with columns
            if (ImGui::BeginTable("ProcessTable", 7, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) { // Begin if BeginTable ProcessTable
                
                // Setup columns
                ImGui::TableSetupColumn("Process Name", ImGuiTableColumnFlags_WidthFixed, 250.0f);
                ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                ImGui::TableSetupColumn("Loc", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                ImGui::TableSetupColumn("CPU %", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                ImGui::TableSetupColumn("Memory (MB)", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                ImGui::TableSetupColumn("Disk (MB/s)", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                ImGui::TableSetupColumn("Network (Mbps)", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                ImGui::TableHeadersRow();
                
                for (const auto& category : categories) { // Begin for each category
                    // Category header row
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    
                    if (ImGui::TreeNodeEx(category.categoryName.c_str(), ImGuiTreeNodeFlags_DefaultOpen | ImGuiTreeNodeFlags_SpanFullWidth)) { // Begin if category TreeNode expanded
                        
                        // List all process groups within this category
                        for (const auto& group : category.groups) { // Begin for each group in category
                            std::string nameStr(group.name.begin(), group.name.end());
                            std::string label = nameStr;
                            
                            if (group.ids.size() > 1) { // Begin if group has multiple processes
                                label = nameStr + " (" + std::to_string(group.ids.size()) + ")";
                            } // End if group has multiple processes

                            // Process group row
                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);
                            
                            if (ImGui::TreeNode(label.c_str())) { // Begin if process TreeNode expanded
                                
                                // Individual process instances
                                for (size_t i = 0; i < group.ids.size(); i = i + 1) { // Begin for each process instance
                                    ImGui::TableNextRow();
                                    
                                    // Process name column
                                    ImGui::TableSetColumnIndex(0);
                                    ImGui::Indent();
                                    ImGui::Text("  Instance %zu", i + 1);
                                    
                                    // Right-click context menu for individual instance
                                    char popupID[128];
                                    sprintf(popupID, "ProcessInstanceContext_%zu_%lu", i, group.ids[i]);
                                    if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1)) { // Begin if right-clicked
                                        g_selectedProcessID = group.ids[i];
                                        g_selectedProcessName = group.name;
                                        ImGui::OpenPopup(popupID);
                                    } // End if right-clicked
                                    
                                    if (ImGui::BeginPopup(popupID)) { // Begin if popup opened
                                        ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "PID: %lu", g_selectedProcessID);
                                        ImGui::Separator();
                                        
                                        if (ImGui::MenuItem("Kill Task")) { // Begin if Kill Task clicked
                                            if (KillProcess(g_selectedProcessID, g_selectedProcessName)) { // Begin if process killed
                                                // Refresh process list
                                                rawProcesses = GetProcesses();
                                            } // End if process killed
                                        } // End if Kill Task clicked
                                        
                                        ImGui::EndPopup();
                                    } // End if popup opened
                                    
                                    ImGui::Unindent();
                                    
                                    // PID column
                                    ImGui::TableSetColumnIndex(1);
                                    ImGui::Text("%lu", group.ids[i]);
                                    
                                    // Location column
                                    ImGui::TableSetColumnIndex(2);
                                    ImGui::Text("%s", group.locations[i].c_str());
                                    
                                    // CPU column
                                    ImGui::TableSetColumnIndex(3);
                                    ImGui::Text("%.1f%%", group.cpuUsages[i]);
                                    
                                    // Memory column
                                    ImGui::TableSetColumnIndex(4);
                                    ImGui::Text("%.1f", group.memoryMBs[i]);
                                    
                                    // Disk column
                                    ImGui::TableSetColumnIndex(5);
                                    ImGui::Text("%.2f", group.diskMBpss[i]);
                                    
                                    // Network column
                                    ImGui::TableSetColumnIndex(6);
                                    ImGui::Text("%.2f", group.netMBpss[i]);
                                } // End for each process instance
                                
                                ImGui::TreePop();
                            } else { // Begin else process TreeNode collapsed
                                // Show aggregated data when collapsed
                                float totalCpu = 0.0f;
                                float totalMem = 0.0f;
                                float totalDisk = 0.0f;
                                float totalNet = 0.0f;
                                
                                for (size_t i = 0; i < group.ids.size(); i = i + 1) { // Begin for calculating totals
                                    totalCpu = totalCpu + group.cpuUsages[i];
                                    totalMem = totalMem + group.memoryMBs[i];
                                    totalDisk = totalDisk + group.diskMBpss[i];
                                    totalNet = totalNet + group.netMBpss[i];
                                } // End for calculating totals
                                
                                // Right-click context menu for grouped processes
                                char groupPopupID[128];
                                std::string groupNameStr(group.name.begin(), group.name.end());
                                sprintf(groupPopupID, "ProcessGroupContext_%s", groupNameStr.c_str());
                                
                                if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1)) { // Begin if right-clicked on group
                                    g_selectedProcessName = group.name;
                                    ImGui::OpenPopup(groupPopupID);
                                } // End if right-clicked on group
                                
                                if (ImGui::BeginPopup(groupPopupID)) { // Begin if group popup opened
                                    ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "%s (%zu instances)", groupNameStr.c_str(), group.ids.size());
                                    ImGui::Separator();
                                    
                                    if (ImGui::MenuItem("Kill All Instances")) { // Begin if Kill All clicked
                                        std::wstring confirmMsg = L"Are you sure you want to terminate ALL " + std::to_wstring(group.ids.size()) + L" instances of:\n" + group.name + L"?";
                                        int result = MessageBoxW(NULL, confirmMsg.c_str(), L"Confirm Kill All", MB_YESNO | MB_ICONWARNING);
                                        
                                        if (result == IDYES) { // Begin if confirmed kill all
                                            int killedCount = 0;
                                            int failedCount = 0;
                                            
                                            for (size_t i = 0; i < group.ids.size(); i = i + 1) { // Begin for each instance to kill
                                                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, group.ids[i]);
                                                if (hProcess != NULL) { // Begin if process opened
                                                    if (TerminateProcess(hProcess, 0)) { // Begin if terminated
                                                        killedCount = killedCount + 1;
                                                    } else { // Begin else termination failed
                                                        failedCount = failedCount + 1;
                                                    } // End else termination failed
                                                    CloseHandle(hProcess);
                                                } else { // Begin else open failed
                                                    failedCount = failedCount + 1;
                                                } // End else open failed
                                            } // End for each instance to kill
                                            
                                            // Show result message
                                            char resultMsg[256];
                                            sprintf(resultMsg, "Terminated: %d\nFailed: %d", killedCount, failedCount);
                                            MessageBoxA(NULL, resultMsg, "Kill All Results", MB_OK | MB_ICONINFORMATION);
                                            
                                            // Refresh process list
                                            rawProcesses = GetProcesses();
                                        } // End if confirmed kill all
                                    } // End if Kill All clicked
                                    
                                    ImGui::EndPopup();
                                } // End if group popup opened
                                
                                // PID column - show count
                                ImGui::TableSetColumnIndex(1);
                                ImGui::Text("%zu PIDs", group.ids.size());
                                
                                // Location column - show most common location
                                ImGui::TableSetColumnIndex(2);
                                if (group.locations.size() > 0) { // Begin if has locations
                                    ImGui::Text("%s", group.locations[0].c_str());
                                } else { // Begin else no locations
                                    ImGui::Text("-");
                                } // End else no locations
                                
                                // CPU column
                                ImGui::TableSetColumnIndex(3);
                                ImGui::Text("%.1f%%", totalCpu);
                                
                                // Memory column
                                ImGui::TableSetColumnIndex(4);
                                ImGui::Text("%.1f", totalMem);
                                
                                // Disk column
                                ImGui::TableSetColumnIndex(5);
                                ImGui::Text("%.2f", totalDisk);
                                
                                // Network column
                                ImGui::TableSetColumnIndex(6);
                                ImGui::Text("%.2f", totalNet);
                            } // End else process TreeNode collapsed
                        } // End for each group in category
                        
                        ImGui::TreePop();
                    } // End if category TreeNode expanded
                } // End for each category
                
                ImGui::EndTable();
            } // End if BeginTable ProcessTable
            
            ImGui::EndChild();
        } // End if BeginChild ProcessScroll
        ImGui::EndTabItem();
    } // End if BeginTabItem Task Manager
} // End RenderTaskManagerTab function

// --- RENDER SYSTEM DETAILS TAB ---
void RenderSystemDetailsTab(const SystemSpecs& specs, const RAMDetails& ramAdv) { // Begin RenderSystemDetailsTab function
    if (ImGui::BeginTabItem("System Details")) { // Begin if BeginTabItem System Details
        ImGui::TextColored(ImVec4(0.2f, 0.8f, 1.0f, 1.0f), "Core Hardware");
        ImGui::BulletText("CPU: %s", specs.cpu.c_str());
        ImGui::BulletText("GPU: %s", specs.gpu.c_str());
        ImGui::BulletText("Mobo: %s", specs.mobo.c_str());
        ImGui::Separator();

        ImGui::TextColored(ImVec4(0.2f, 0.8f, 1.0f, 1.0f), "Memory Architecture (%s)", ramAdv.type.c_str());
        if (ImGui::BeginTable("RAM_Table", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) { // Begin if BeginTable RAM_Table
            ImGui::TableSetupColumn("Slot");
            ImGui::TableSetupColumn("Capacity");
            ImGui::TableHeadersRow();
            
            for (int i = 0; i < (int)ramAdv.sticks.size(); i = i + 1) { // Begin for loop i = 0 to sticks size
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("Slot %d", i + 1);
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%s", ramAdv.sticks[i].c_str());
            } // End for loop i = 0 to sticks size
            ImGui::EndTable();
        } // End if BeginTable RAM_Table
        ImGui::Separator();

        ImGui::TextColored(ImVec4(0.2f, 0.8f, 1.0f, 1.0f), "Storage Devices");
        DWORD driveMask = GetLogicalDrives();
        
        for (int i = 0; i < 26; i = i + 1) { // Begin for loop i = 0 to 26 (drive letters)
            if (driveMask & (1 << i)) { // Begin if drive letter exists
                char drivePath[] = { (char)('A' + i), ':', '\\', '\0' };
                ULARGE_INTEGER freeB, totalB, totalFreeB;
                
                if (GetDiskFreeSpaceExA(drivePath, &freeB, &totalB, &totalFreeB)) { // Begin if GetDiskFreeSpaceExA succeeded
                    float totalGB = (float)totalB.QuadPart / (1024 * 1024 * 1024);
                    float freeGB = (float)totalFreeB.QuadPart / (1024 * 1024 * 1024);
                    float usedGB = totalGB - freeGB;
                    
                    ImGui::Text("Drive %c:", drivePath[0]);
                    ImGui::SameLine();
                    
                    char overlay[64];
                    sprintf(overlay, "%.1f / %.1f GB", usedGB, totalGB);
                    ImGui::ProgressBar(usedGB / totalGB, ImVec2(-1.0f, 15.0f), overlay);
                } // End if GetDiskFreeSpaceExA succeeded
            } // End if drive letter exists
        } // End for loop i = 0 to 26 (drive letters)
        ImGui::EndTabItem();
    } // End if BeginTabItem System Details
} // End RenderSystemDetailsTab function

// --- RENDER REMOVE APP TAB ---
void RenderRemoveAppTab() { // Begin RenderRemoveAppTab function
    if (ImGui::BeginTabItem("Remove App")) { // Begin if BeginTabItem Remove App
        
        static std::vector<InstalledProgram> programs;
        static bool programsLoaded = false;
        static bool isLoading = false;
        static char searchBuffer[256] = "";
        
        // Load programs button
        if (programsLoaded == false && isLoading == false) { // Begin if not loaded and not loading
            ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Click 'Load Programs' to view installed applications");
            if (ImGui::Button("Load Programs", ImVec2(200, 40))) { // Begin if Load Programs button clicked
                isLoading = true;
                programs = GetInstalledPrograms();
                programsLoaded = true;
                isLoading = false;
            } // End if Load Programs button clicked
        } else if (isLoading) { // Begin else if loading
            ImGui::Text("Loading installed programs...");
        } else { // Begin else programs loaded
            
            // Search bar
            ImGui::Text("Search:");
            ImGui::SameLine();
            ImGui::InputText("##search", searchBuffer, sizeof(searchBuffer));
            ImGui::SameLine();
            if (ImGui::Button("Refresh List")) { // Begin if Refresh button clicked
                programs = GetInstalledPrograms();
            } // End if Refresh button clicked
            
            ImGui::Separator();
            ImGui::Text("Total Programs: %zu", programs.size());
            ImGui::Separator();
            
            // Create scrollable area for programs
            if (ImGui::BeginChild("ProgramsList", ImVec2(0, 0), true)) { // Begin if BeginChild ProgramsList
                
                // Create table for programs
                if (ImGui::BeginTable("ProgramsTable", 6, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) { // Begin if BeginTable ProgramsTable
                    
                    // Setup columns
                    ImGui::TableSetupColumn("Program Name", ImGuiTableColumnFlags_WidthFixed, 300.0f);
                    ImGui::TableSetupColumn("Version", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableSetupColumn("Publisher", ImGuiTableColumnFlags_WidthFixed, 200.0f);
                    ImGui::TableSetupColumn("Install Date", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableHeadersRow();
                    
                    // Filter and display programs
                    std::string searchStr = std::string(searchBuffer);
                    std::transform(searchStr.begin(), searchStr.end(), searchStr.begin(), ::tolower);
                    
                    for (size_t i = 0; i < programs.size(); i = i + 1) { // Begin for each program
                        
                        // Filter by search
                        if (searchStr.empty() == false) { // Begin if search filter active
                            std::string programNameLower = programs[i].name;
                            std::transform(programNameLower.begin(), programNameLower.end(), programNameLower.begin(), ::tolower);
                            
                            if (programNameLower.find(searchStr) == std::string::npos) { // Begin if not matching search
                                continue;
                            } // End if not matching search
                        } // End if search filter active
                        
                        ImGui::TableNextRow();
                        
                        // Program Name column
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%s", programs[i].name.c_str());
                        
                        // Version column
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%s", programs[i].version.c_str());
                        
                        // Publisher column
                        ImGui::TableSetColumnIndex(2);
                        ImGui::Text("%s", programs[i].publisher.c_str());
                        
                        // Install Date column
                        ImGui::TableSetColumnIndex(3);
                        ImGui::Text("%s", programs[i].installDate.c_str());
                        
                        // Size column
                        ImGui::TableSetColumnIndex(4);
                        ImGui::Text("%s", programs[i].size.c_str());
                        
                        // Action column
                        ImGui::TableSetColumnIndex(5);
                        
                        if (programs[i].uninstallString.empty() == false) { // Begin if has uninstall string
                            char buttonLabel[64];
                            sprintf(buttonLabel, "Uninstall##%zu", i);
                            
                            if (ImGui::Button(buttonLabel, ImVec2(90, 0))) { // Begin if Uninstall button clicked
                                
                                // Confirmation popup
                                std::string confirmMsg = "Are you sure you want to uninstall:\n" + programs[i].name + "?";
                                int result = MessageBoxA(NULL, confirmMsg.c_str(), "Confirm Uninstall", MB_YESNO | MB_ICONWARNING);
                                
                                if (result == IDYES) { // Begin if user confirmed
                                    
                                    // Execute uninstall command
                                    STARTUPINFOA si;
                                    PROCESS_INFORMATION pi;
                                    ZeroMemory(&si, sizeof(si));
                                    si.cb = sizeof(si);
                                    ZeroMemory(&pi, sizeof(pi));
                                    
                                    // Create mutable copy of uninstall string
                                    char* uninstallCmd = new char[programs[i].uninstallString.length() + 1];
                                    strcpy(uninstallCmd, programs[i].uninstallString.c_str());
                                    
                                    if (CreateProcessA(NULL, uninstallCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) { // Begin if CreateProcessA succeeded
                                        // Wait for uninstall process to complete
                                        WaitForSingleObject(pi.hProcess, INFINITE);
                                        CloseHandle(pi.hProcess);
                                        CloseHandle(pi.hThread);
                                        
                                        // Refresh the list after uninstall
                                        programs = GetInstalledPrograms();
                                        
                                        MessageBoxA(NULL, "Uninstall process completed. List refreshed.", "Success", MB_OK | MB_ICONINFORMATION);
                                    } else { // Begin else CreateProcessA failed
                                        MessageBoxA(NULL, "Failed to start uninstaller. You may need administrator privileges.", "Error", MB_OK | MB_ICONERROR);
                                    } // End else CreateProcessA failed
                                    
                                    delete[] uninstallCmd;
                                } // End if user confirmed
                            } // End if Uninstall button clicked
                        } else { // Begin else no uninstall string
                            ImGui::TextDisabled("N/A");
                        } // End else no uninstall string
                    } // End for each program
                    
                    ImGui::EndTable();
                } // End if BeginTable ProgramsTable
                
                ImGui::EndChild();
            } // End if BeginChild ProgramsList
        } // End else programs loaded
        
        ImGui::EndTabItem();
    } // End if BeginTabItem Remove App
} // End RenderRemoveAppTab function

// --- RENDER BOTTOM STATUS BAR ---
void RenderBottomBar() { // Begin RenderBottomBar function
    ImGui::Separator();
    
    // RAM Usage
    float ramPercent = GetRAMUsage();
    ImGui::Text("System RAM Usage: %.1f%%", ramPercent);
    ImGui::ProgressBar(ramPercent / 100.0f, ImVec2(-1, 20));
    
    // Network Usage
    float netUsage = GetSystemNetworkUsage();
    ImGui::Text("System Network Usage: %.2f MB/s", netUsage);
    ImGui::ProgressBar(netUsage / 10.0f, ImVec2(-1, 20)); // Scale to 10 MB/s max for visualization
} // End RenderBottomBar function

// --- RENDER COMPLETE FRAME ---
void RenderFrame() { // Begin RenderFrame function
    const float clear_color[4] = { 0.1f, 0.1f, 0.1f, 1.0f };
    g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
    g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    g_pSwapChain->Present(1, 0);
} // End RenderFrame function

// --- MAIN FUNCTION ---
int main(int, char**) { // Begin main function
    // Setup window class
    WNDCLASSEXW wc = { // Begin WNDCLASSEXW initialization
        sizeof(wc), 
        CS_CLASSDC, 
        WndProc, 
        0L, 
        0L, 
        GetModuleHandle(nullptr), 
        nullptr,  // hIcon - will be set after loading
        nullptr, 
        nullptr, 
        nullptr, 
        L"ImGui App", 
        nullptr 
    }; // End WNDCLASSEXW initialization
    
    // Try to load icon from assets folder
    HICON hIcon = LoadIconFromFile("assets/logo.ico");
    if (hIcon == NULL) { // Begin if .ico failed
        hIcon = LoadIconFromFile("assets/logo.png");
    } // End if .ico failed
    
    // Set icon in window class if loaded successfully
    if (hIcon != NULL) { // Begin if icon loaded
        wc.hIcon = hIcon;
        wc.hIconSm = hIcon;
    } // End if icon loaded
    
    ::RegisterClassExW(&wc);
    
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int windowX = (screenW - 800) / 2;
    int windowY = (screenH - 600) / 2;
    
    HWND hwnd = ::CreateWindowW(
        wc.lpszClassName, 
        L"Task Monitor", 
        WS_OVERLAPPEDWINDOW, 
        windowX, 
        windowY, 
        800, 
        600, 
        nullptr, 
        nullptr, 
        wc.hInstance, 
        nullptr
    );
    
    // Set window icon if loaded successfully
    if (hIcon != NULL) { // Begin if icon loaded for window
        SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
        SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
    } // End if icon loaded for window

    if (CreateDeviceD3D(hwnd) == false) { // Begin if CreateDeviceD3D failed
        if (hIcon != NULL) { // Begin if icon needs cleanup
            DestroyIcon(hIcon);
        } // End if icon needs cleanup
        return 1;
    } // End if CreateDeviceD3D failed

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    // Initialize ImGui
    InitializeImGui(hwnd);

    // Initialize system data once
    SystemSpecs specs;
    specs.gpu = GetGPUName(g_pd3dDevice);
    RAMDetails ramAdv = GetAdvancedRAMInfo();
    std::vector<ProcessInfo> rawProcesses = GetProcesses();
    
    // Timer for process list refresh
    ULONGLONG lastProcessRefresh = GetTickCount64();
    const ULONGLONG PROCESS_REFRESH_INTERVAL = 1000; // Refresh every 1 second

    // Main loop
    bool done = false;
    while (done == false) { // Begin while done is false
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) { // Begin while PeekMessage
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) { // Begin if message is WM_QUIT
                done = true;
            } // End if message is WM_QUIT
        } // End while PeekMessage
        
        if (done) { // Begin if done
            break;
        } // End if done
        
        // Periodically refresh process data
        ULONGLONG currentTime = GetTickCount64();
        if (currentTime - lastProcessRefresh >= PROCESS_REFRESH_INTERVAL) { // Begin if time to refresh
            rawProcesses = GetProcesses();
            lastProcessRefresh = currentTime;
        } // End if time to refresh

        // Start ImGui frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // Main window
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
        
        ImGuiWindowFlags windowFlags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove;
        ImGui::Begin("Master", nullptr, windowFlags);

        if (ImGui::BeginTabBar("MainTabs")) { // Begin if BeginTabBar MainTabs
            RenderTaskManagerTab(rawProcesses);
            RenderSystemDetailsTab(specs, ramAdv);
            RenderRemoveAppTab();
            ImGui::EndTabBar();
        } // End if BeginTabBar MainTabs

        RenderBottomBar();
        ImGui::End();

        // Render frame
        ImGui::Render();
        RenderFrame();
    } // End while done is false

    // Cleanup
    ShutdownImGui();
    CleanupDeviceD3D();
    
    // Clean up icon
    if (hIcon != NULL) { // Begin if icon needs cleanup at end
        DestroyIcon(hIcon);
    } // End if icon needs cleanup at end
    
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
} // End main function

// --- DIRECTX HELPERS ---
bool CreateDeviceD3D(HWND hWnd) { // Begin CreateDeviceD3D function
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    
    HRESULT result = D3D11CreateDeviceAndSwapChain(
        nullptr, 
        D3D_DRIVER_TYPE_HARDWARE, 
        nullptr, 
        0, 
        featureLevelArray, 
        2, 
        D3D11_SDK_VERSION, 
        &sd, 
        &g_pSwapChain, 
        &g_pd3dDevice, 
        &featureLevel, 
        &g_pd3dDeviceContext
    );
    
    if (result != S_OK) { // Begin if D3D11CreateDeviceAndSwapChain failed
        return false;
    } // End if D3D11CreateDeviceAndSwapChain failed

    CreateRenderTarget();
    return true;
} // End CreateDeviceD3D function

void CreateRenderTarget() { // Begin CreateRenderTarget function
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
} // End CreateRenderTarget function

void CleanupRenderTarget() { // Begin CleanupRenderTarget function
    if (g_mainRenderTargetView) { // Begin if g_mainRenderTargetView exists
        g_mainRenderTargetView->Release();
        g_mainRenderTargetView = nullptr;
    } // End if g_mainRenderTargetView exists
} // End CleanupRenderTarget function

void CleanupDeviceD3D() { // Begin CleanupDeviceD3D function
    CleanupRenderTarget();
    
    if (g_pSwapChain) { // Begin if g_pSwapChain exists
        g_pSwapChain->Release();
        g_pSwapChain = nullptr;
    } // End if g_pSwapChain exists
    
    if (g_pd3dDeviceContext) { // Begin if g_pd3dDeviceContext exists
        g_pd3dDeviceContext->Release();
        g_pd3dDeviceContext = nullptr;
    } // End if g_pd3dDeviceContext exists
    
    if (g_pd3dDevice) { // Begin if g_pd3dDevice exists
        g_pd3dDevice->Release();
        g_pd3dDevice = nullptr;
    } // End if g_pd3dDevice exists
} // End CleanupDeviceD3D function

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) { // Begin WndProc function
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) { // Begin if ImGui handled message
        return true;
    } // End if ImGui handled message
    
    switch (msg) { // Begin switch on message type
        case WM_SIZE:
            if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED) { // Begin if window resized and not minimized
                CleanupRenderTarget();
                UINT width = (UINT)LOWORD(lParam);
                UINT height = (UINT)HIWORD(lParam);
                g_pSwapChain->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0);
                CreateRenderTarget();
            } // End if window resized and not minimized
            return 0;
            
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) { // Begin if alt-key menu command
                return 0;
            } // End if alt-key menu command
            break;
            
        case WM_DESTROY:
            ::PostQuitMessage(0);
            return 0;
    } // End switch on message type
    
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
} // End WndProc function