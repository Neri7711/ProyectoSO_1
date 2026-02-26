#pragma once

#include <string>
#include <fstream>
#include <mutex>

#ifdef PLATFORM_WINDOWS
#include <windows.h>
#elif PLATFORM_UNIX
#include <chrono>
#include <iomanip>
#include <sstream>
#endif

class Logger {
private:
    std::string logFilePath;
    std::ofstream logFile;
    std::mutex logMutex;
    bool enabled;
    
    // Métodos internos
    std::string GetCurrentTimestamp();
    void WriteLog(const std::string& level, const std::string& message);
    
public:
    Logger(const std::string& filePath);
    ~Logger();
    
    // Métodos de logging
    void Log(const std::string& message);
    void Error(const std::string& message);
    void Warning(const std::string& message);
    void Info(const std::string& message);
    void Debug(const std::string& message);
    
    // Configuración
    void SetEnabled(bool enabled) { this->enabled = enabled; }
    void SetLogFile(const std::string& filePath);
    
    // Métodos de utilidad
    void Flush();
    void Clear();
    
    // Constantes
    static const std::string LOG_LEVEL_INFO;
    static const std::string LOG_LEVEL_ERROR;
    static const std::string LOG_LEVEL_WARNING;
    static const std::string LOG_LEVEL_DEBUG;
};
