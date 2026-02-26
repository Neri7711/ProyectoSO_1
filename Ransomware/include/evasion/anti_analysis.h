#pragma once

#include <string>
#include <cstdint>
#include <vector>

#ifdef PLATFORM_WINDOWS
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#pragma comment(lib, "ntdll.lib")
#elif PLATFORM_UNIX
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <ifaddrs.h>
#include <net/if.h>
#endif

class AntiAnalysis {
private:
    bool enabled;
    
    // Métodos anti-debug
    bool IsDebuggerPresentClassic();
    bool CheckRemoteDebugger();
    bool CheckNtGlobalFlag();
    bool CheckHeapFlags();
    bool CheckDebugBreakpoints();
    bool CheckTimingAttack();
    bool CheckParentProcess();
    
    // Métodos anti-VM
    bool CheckVMWare();
    bool CheckVirtualBox();
    bool CheckHyperV();
    bool CheckQEMU();
    bool CheckWine();
    bool CheckSandboxie();
    bool CheckDiskSize();
    bool CheckCPUCores();
    bool CheckMACAddress();
    bool CheckRegistryArtifacts();
    bool CheckVMProcesses();
    
    // Métodos anti-sandbox
    bool CheckUserActivity();
    bool CheckMouseMovement();
    bool CheckSystemUptime();
    bool CheckSleepTiming();
    bool CheckHardwareFingerprint();
    
    // Métodos de utilidad
#ifdef PLATFORM_WINDOWS
    std::string GetRegistryValue(HKEY root, const std::string& path, const std::string& value);
#endif
    bool ProcessExists(const std::string& processName);
    uint64_t GetSystemUptime();
    void AntiHooking();
    
public:
    AntiAnalysis();
    ~AntiAnalysis();
    
    // Métodos de detección principales
    bool IsAnalysisEnvironment();
    bool IsVirtualMachine();
    bool IsSandbox();
    bool IsDebugged();
    
    // Configuración
    void EnableAllChecks();
    void DisableAllChecks();
    void SetEnabled(bool enabled) { this->enabled = enabled; }
    
    // Verificaciones específicas
    bool PerformAllChecks();
    
    // Técnicas de evasión
    void HideFromDebugger();
#ifdef PLATFORM_WINDOWS
    void SleepObfuscation(DWORD milliseconds);
#else
    void SleepObfuscation(unsigned int milliseconds);
#endif
    void AntiDumping();
    void AntiEmulation();
    
    // Recopilación de información
    std::string GetSystemInfo();
    std::string GetHardwareFingerprint();
    
    // Constantes
    static const int MIN_DISK_SIZE_GB = 60;
    static const int MIN_CPU_CORES = 2;
    static const int MIN_RAM_SIZE_GB = 2;
    static const int MIN_UPTIME_MINUTES = 10;
};
