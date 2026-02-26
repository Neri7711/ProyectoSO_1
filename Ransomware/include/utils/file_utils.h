#pragma once

#include <string>
#include <vector>

#ifdef PLATFORM_WINDOWS
#include <windows.h>
#elif PLATFORM_UNIX
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#endif

class FileUtils {
public:
    // Operaciones de archivo
    static bool FileExists(const std::string& filePath);
    static bool IsFileReadable(const std::string& filePath);
    static bool IsFileWritable(const std::string& filePath);
    static size_t GetFileSize(const std::string& filePath);
    static std::string GetFileExtension(const std::string& filePath);
    static std::string GetFileName(const std::string& filePath);
    static std::string GetDirectoryPath(const std::string& filePath);
    
    // Operaciones de directorio
    static bool DirectoryExists(const std::string& dirPath);
    static bool CreateDirectory(const std::string& dirPath);
    static std::vector<std::string> ListFiles(const std::string& dirPath, const std::string& pattern = "*");
    static std::vector<std::string> ListDirectories(const std::string& dirPath);
    
    // Operaciones de ruta
    static std::string GetTempPath();
    static std::string GetAppDataPath();
    static std::string GetSystemPath();
    static std::string GetCurrentPath();
    static bool IsAbsolutePath(const std::string& path);
    static std::string NormalizePath(const std::string& path);
    
    // Atributos de archivo
#ifdef PLATFORM_WINDOWS
    static bool SetFileHidden(const std::string& filePath);
    static bool SetFileReadOnly(const std::string& filePath);
    static bool SetFileSystem(const std::string& filePath);
    static DWORD GetFileAttributes(const std::string& filePath);
    static bool SetFileAttributes(const std::string& filePath, DWORD attributes);
#else
    static bool SetFileHidden(const std::string& filePath);
    static bool SetFileReadOnly(const std::string& filePath);
    static bool SetFileSystem(const std::string& filePath);
    static mode_t GetFileAttributes(const std::string& filePath);
    static bool SetFileAttributes(const std::string& filePath, mode_t attributes);
#endif
    
    // Seguridad de archivo
    static bool TakeOwnership(const std::string& filePath);
    static bool GrantFullAccess(const std::string& filePath);
    static bool RemoveReadOnly(const std::string& filePath);
    
    // Operaciones de tiempo de archivo
#ifdef PLATFORM_WINDOWS
    static FILETIME GetFileCreationTime(const std::string& filePath);
    static FILETIME GetFileModificationTime(const std::string& filePath);
    static FILETIME GetFileAccessTime(const std::string& filePath);
    static bool SetFileTime(const std::string& filePath, const FILETIME* creation, 
                           const FILETIME* access, const FILETIME* modification);
#else
    static time_t GetFileCreationTime(const std::string& filePath);
    static time_t GetFileModificationTime(const std::string& filePath);
    static time_t GetFileAccessTime(const std::string& filePath);
    static bool SetFileTime(const std::string& filePath, const time_t* creation, 
                           const time_t* access, const time_t* modification);
#endif
    
    // Funciones de utilidad
    static std::string ReadFileToString(const std::string& filePath);
    static bool WriteStringToFile(const std::string& filePath, const std::string& content);
    static bool AppendStringToFile(const std::string& filePath, const std::string& content);
    static bool CopyFile(const std::string& sourcePath, const std::string& destPath);
    static bool MoveFile(const std::string& sourcePath, const std::string& destPath);
    static bool DeleteFile(const std::string& filePath);
    
    // Operaciones seguras
    static bool SecureDelete(const std::string& filePath, int passes = 3);
    static bool WipeFreeSpace(const std::string& drivePath, int passes = 1);
    
    // Búsqueda de archivos
    static std::vector<std::string> FindFilesByExtension(const std::string& rootPath, 
                                                        const std::vector<std::string>& extensions);
    static std::vector<std::string> FindFilesBySize(const std::string& rootPath, 
                                                    size_t minSize, size_t maxSize);
#ifdef PLATFORM_WINDOWS
    static std::vector<std::string> FindFilesByDate(const std::string& rootPath, 
                                                    const FILETIME& afterDate, const FILETIME& beforeDate);
#else
    static std::vector<std::string> FindFilesByDate(const std::string& rootPath, 
                                                    const time_t& afterDate, const time_t& beforeDate);
#endif
};
