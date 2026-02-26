#include "utils/file_utils.h"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <shlobj.h>
#include <AclAPI.h>

namespace fs = std::filesystem;

bool FileUtils::FileExists(const std::string& filePath) {
    return fs::exists(filePath) && fs::is_regular_file(filePath);
}

bool FileUtils::IsFileReadable(const std::string& filePath) {
    std::ifstream file(filePath);
    return file.good();
}

bool FileUtils::IsFileWritable(const std::string& filePath) {
    std::ofstream file(filePath, std::ios::app);
    return file.good();
}

size_t FileUtils::GetFileSize(const std::string& filePath) {
    try {
        return fs::file_size(filePath);
    }
    catch (...) {
        return 0;
    }
}

std::string FileUtils::GetFileExtension(const std::string& filePath) {
    return fs::path(filePath).extension().string();
}

std::string FileUtils::GetFileName(const std::string& filePath) {
    return fs::path(filePath).filename().string();
}

std::string FileUtils::GetDirectoryPath(const std::string& filePath) {
    return fs::path(filePath).parent_path().string();
}

bool FileUtils::DirectoryExists(const std::string& dirPath) {
    return fs::exists(dirPath) && fs::is_directory(dirPath);
}

bool FileUtils::CreateDirectory(const std::string& dirPath) {
    try {
        return fs::create_directories(dirPath);
    }
    catch (...) {
        return false;
    }
}

std::vector<std::string> FileUtils::ListFiles(const std::string& dirPath, const std::string& pattern) {
    std::vector<std::string> files;
    
    try {
        for (const auto& entry : fs::directory_iterator(dirPath)) {
            if (entry.is_regular_file()) {
                if (pattern == "*" || entry.path().extension().string() == pattern) {
                    files.push_back(entry.path().string());
                }
            }
        }
    }
    catch (...) {
        // Ignore errors
    }
    
    return files;
}

std::vector<std::string> FileUtils::ListDirectories(const std::string& dirPath) {
    std::vector<std::string> directories;
    
    try {
        for (const auto& entry : fs::directory_iterator(dirPath)) {
            if (entry.is_directory()) {
                directories.push_back(entry.path().string());
            }
        }
    }
    catch (...) {
        // Ignore errors
    }
    
    return directories;
}

std::string FileUtils::GetTempPath() {
    char tempPath[MAX_PATH];
    DWORD result = ::GetTempPathA(MAX_PATH, tempPath);
    return (result > 0 && result < MAX_PATH) ? std::string(tempPath) : "";
}

std::string FileUtils::GetAppDataPath() {
    char appDataPath[MAX_PATH];
    HRESULT result = SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    return (result == S_OK) ? std::string(appDataPath) : "";
}

std::string FileUtils::GetSystemPath() {
    char systemPath[MAX_PATH];
    UINT result = GetSystemDirectoryA(systemPath, MAX_PATH);
    return (result > 0 && result < MAX_PATH) ? std::string(systemPath) : "";
}

std::string FileUtils::GetCurrentPath() {
    char currentPath[MAX_PATH];
    DWORD result = GetCurrentDirectoryA(MAX_PATH, currentPath);
    return (result > 0 && result < MAX_PATH) ? std::string(currentPath) : "";
}

bool FileUtils::IsAbsolutePath(const std::string& path) {
    return fs::path(path).is_absolute();
}

std::string FileUtils::NormalizePath(const std::string& path) {
    try {
        return fs::path(path).lexically_normal().string();
    }
    catch (...) {
        return path;
    }
}

bool FileUtils::SetFileHidden(const std::string& filePath) {
    DWORD attributes = GetFileAttributesA(filePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return false;
    
    return SetFileAttributesA(filePath.c_str(), attributes | FILE_ATTRIBUTE_HIDDEN);
}

bool FileUtils::SetFileReadOnly(const std::string& filePath) {
    DWORD attributes = GetFileAttributesA(filePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return false;
    
    return SetFileAttributesA(filePath.c_str(), attributes | FILE_ATTRIBUTE_READONLY);
}

bool FileUtils::SetFileSystem(const std::string& filePath) {
    DWORD attributes = GetFileAttributesA(filePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return false;
    
    return SetFileAttributesA(filePath.c_str(), attributes | FILE_ATTRIBUTE_SYSTEM);
}

DWORD FileUtils::GetFileAttributes(const std::string& filePath) {
    return ::GetFileAttributesA(filePath.c_str());
}

bool FileUtils::SetFileAttributes(const std::string& filePath, DWORD attributes) {
    return ::SetFileAttributesA(filePath.c_str(), attributes) != FALSE;
}

bool FileUtils::TakeOwnership(const std::string& filePath) {
    // Esta es una versión simplificada - la implementación completa requiere manipulación de ACL más compleja
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    
    // Habilitar privilegio SeTakeOwnership
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_TAKE_OWNERSHIP_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }
    
    CloseHandle(hToken);
    return true;
}

bool FileUtils::GrantFullAccess(const std::string& filePath) {
    // Versión simplificada - la implementación completa crearía ACL adecuada
    return TakeOwnership(filePath);
}

bool FileUtils::RemoveReadOnly(const std::string& filePath) {
    DWORD attributes = GetFileAttributesA(filePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return false;
    
    return SetFileAttributesA(filePath.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
}

FILETIME FileUtils::GetFileCreationTime(const std::string& filePath) {
    FILETIME creationTime = { 0 };
    
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        GetFileTime(hFile, &creationTime, NULL, NULL);
        CloseHandle(hFile);
    }
    
    return creationTime;
}

FILETIME FileUtils::GetFileModificationTime(const std::string& filePath) {
    FILETIME modificationTime = { 0 };
    
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        GetFileTime(hFile, NULL, NULL, &modificationTime);
        CloseHandle(hFile);
    }
    
    return modificationTime;
}

FILETIME FileUtils::GetFileAccessTime(const std::string& filePath) {
    FILETIME accessTime = { 0 };
    
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        GetFileTime(hFile, NULL, &accessTime, NULL);
        CloseHandle(hFile);
    }
    
    return accessTime;
}

bool FileUtils::SetFileTime(const std::string& filePath, const FILETIME* creation, 
                           const FILETIME* access, const FILETIME* modification) {
    HANDLE hFile = CreateFileA(filePath.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, 
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    BOOL result = ::SetFileTime(hFile, creation, access, modification);
    CloseHandle(hFile);
    
    return result != FALSE;
}

std::string FileUtils::ReadFileToString(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }
    
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

bool FileUtils::WriteStringToFile(const std::string& filePath, const std::string& content) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    file << content;
    return file.good();
}

bool FileUtils::AppendStringToFile(const std::string& filePath, const std::string& content) {
    std::ofstream file(filePath, std::ios::app | std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    file << content;
    return file.good();
}

bool FileUtils::CopyFile(const std::string& sourcePath, const std::string& destPath) {
    return ::CopyFileA(sourcePath.c_str(), destPath.c_str(), FALSE) != FALSE;
}

bool FileUtils::MoveFile(const std::string& sourcePath, const std::string& destPath) {
    return ::MoveFileA(sourcePath.c_str(), destPath.c_str()) != FALSE;
}

bool FileUtils::DeleteFile(const std::string& filePath) {
    return ::DeleteFileA(filePath.c_str()) != FALSE;
}

bool FileUtils::SecureDelete(const std::string& filePath, int passes) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    // Obtener tamaño del archivo
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.close();
    
    // Sobrescribir archivo múltiples veces
    for (int pass = 0; pass < passes; pass++) {
        std::ofstream outFile(filePath, std::ios::binary);
        if (!outFile.is_open()) {
            return false;
        }
        
        // Generar datos aleatorios para este pase
        std::vector<char> randomData(fileSize);
        for (size_t i = 0; i < fileSize; i++) {
            randomData[i] = rand() % 256;
        }
        
        outFile.write(randomData.data(), fileSize);
        outFile.flush();
        outFile.close();
    }
    
    // Eliminar el archivo
    return ::DeleteFileA(filePath.c_str()) != FALSE;
}

bool FileUtils::WipeFreeSpace(const std::string& drivePath, int passes) {
    // Esto es un placeholder - la implementación real sería mucho más compleja
    // e involucraría crear y eliminar archivos grandes para sobrescribir espacio libre
    return true;
}

std::vector<std::string> FileUtils::FindFilesByExtension(const std::string& rootPath, 
                                                        const std::vector<std::string>& extensions) {
    std::vector<std::string> foundFiles;
    
    try {
        for (const auto& entry : fs::recursive_directory_iterator(rootPath)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                for (const auto& targetExt : extensions) {
                    if (ext == targetExt) {
                        foundFiles.push_back(entry.path().string());
                        break;
                    }
                }
            }
        }
    }
    catch (...) {
        // Ignore errors
    }
    
    return foundFiles;
}

std::vector<std::string> FileUtils::FindFilesBySize(const std::string& rootPath, 
                                                    size_t minSize, size_t maxSize) {
    std::vector<std::string> foundFiles;
    
    try {
        for (const auto& entry : fs::recursive_directory_iterator(rootPath)) {
            if (entry.is_regular_file()) {
                size_t fileSize = entry.file_size();
                if (fileSize >= minSize && fileSize <= maxSize) {
                    foundFiles.push_back(entry.path().string());
                }
            }
        }
    }
    catch (...) {
        // Ignore errors
    }
    
    return foundFiles;
}

std::vector<std::string> FileUtils::FindFilesByDate(const std::string& rootPath, 
                                                    const FILETIME& afterDate, const FILETIME& beforeDate) {
    std::vector<std::string> foundFiles;
    
    try {
        for (const auto& entry : fs::recursive_directory_iterator(rootPath)) {
            if (entry.is_regular_file()) {
                FILETIME fileTime = GetFileModificationTime(entry.path().string());
                
                if (CompareFileTime(&fileTime, &afterDate) >= 0 && 
                    CompareFileTime(&fileTime, &beforeDate) <= 0) {
                    foundFiles.push_back(entry.path().string());
                }
            }
        }
    }
    catch (...) {
        // Ignore errors
    }
    
    return foundFiles;
}
