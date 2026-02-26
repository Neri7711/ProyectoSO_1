#include "utils/file_utils.h"
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pwd.h>
#include <vector>
#include <string>
#include <cstring>

class UnixFileUtils : public FileUtils {
public:
    static std::vector<std::string> GetUserDirectories() {
        std::vector<std::string> directories;
        
        // Get home directory
        const char* home = getenv("HOME");
        if (home) {
            directories.push_back(std::string(home) + "/Documents");
            directories.push_back(std::string(home) + "/Desktop");
            directories.push_back(std::string(home) + "/Downloads");
            directories.push_back(std::string(home) + "/Pictures");
            directories.push_back(std::string(home) + "/Videos");
            directories.push_back(std::string(home) + "/Music");
        }
        
        // Common system directories
        directories.push_back("/tmp");
        directories.push_back("/var/tmp");
        directories.push_back("/usr/share");
        directories.push_back("/opt");
        
        return directories;
    }
    
    static std::string GetTempPath() {
        return "/tmp/";
    }
    
    static std::string GetAppDataPath() {
        const char* home = getenv("HOME");
        if (home) {
            return std::string(home) + "/.local/share/";
        }
        return "/tmp/";
    }
    
    static std::string GetSystemPath() {
        return "/usr/local/bin/";
    }
    
    static bool SetFilePermissions(const std::string& path, bool readOnly) {
        if (readOnly) {
            return chmod(path.c_str(), S_IRUSR | S_IRGRP | S_IROTH) == 0;
        } else {
            return chmod(path.c_str(), S_IRWXU | S_IRWXG | S_IRWXO) == 0;
        }
    }
    
    static bool HideFile(const std::string& path) {
        // Unix: rename with dot prefix
        std::string hiddenPath = "." + path;
        return rename(path.c_str(), hiddenPath.c_str()) == 0;
    }
    
    static bool DeleteFileSecurely(const std::string& path) {
        // Multi-pass secure deletion
        std::vector<int> patterns = {0x00, 0xFF, 0xAA, 0x55};
        
        for (int pattern : patterns) {
            int fd = open(path.c_str(), O_WRONLY);
            if (fd == -1) continue;
            
            // Get file size
            struct stat st;
            fstat(fd, &st);
            off_t size = st.st_size;
            
            // Overwrite with pattern
            std::vector<uint8_t> buffer(size, pattern);
            write(fd, buffer.data(), size);
            fsync(fd);
            close(fd);
        }
        
        // Finally unlink
        return unlink(path.c_str()) == 0;
    }
    
    static std::vector<std::string> GetMountPoints() {
        std::vector<std::string> mountPoints;
        
        // Parse /proc/mounts
        std::ifstream mounts("/proc/mounts");
        std::string line;
        
        while (std::getline(mounts, line)) {
            std::istringstream iss(line);
            std::string device, mountPoint, fsType;
            
            if (iss >> device >> mountPoint >> fsType) {
                // Skip system mounts
                if (mountPoint.find("/proc") == 0 ||
                    mountPoint.find("/sys") == 0 ||
                    mountPoint.find("/dev") == 0) {
                    continue;
                }
                
                mountPoints.push_back(mountPoint);
            }
        }
        
        return mountPoints;
    }
    
    static bool IsProcessRunning(const std::string& processName) {
        DIR* dir = opendir("/proc");
        if (!dir) return false;
        
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (!isdigit(entry->d_name[0])) continue;
            
            std::string commPath = std::string("/proc/") + entry->d_name + "/comm";
            std::ifstream commFile(commPath);
            std::string comm;
            
            if (commFile >> comm) {
                if (comm == processName) {
                    closedir(dir);
                    return true;
                }
            }
        }
        
        closedir(dir);
        return false;
    }
    
    static uint64_t GetFileSize(const std::string& path) {
        struct stat st;
        if (stat(path.c_str(), &st) == 0) {
            return st.st_size;
        }
        return 0;
    }
};
