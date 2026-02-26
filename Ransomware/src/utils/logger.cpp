#include "utils/logger.h"
#include <iostream>
#include <iomanip>
#include <sstream>

const std::string Logger::LOG_LEVEL_INFO = "INFO";
const std::string Logger::LOG_LEVEL_ERROR = "ERROR";
const std::string Logger::LOG_LEVEL_WARNING = "WARNING";
const std::string Logger::LOG_LEVEL_DEBUG = "DEBUG";

Logger::Logger(const std::string& filePath) : logFilePath(filePath), enabled(true) {
    SetLogFile(filePath);
}

Logger::~Logger() {
    if (logFile.is_open()) {
        logFile.close();
    }
}

void Logger::SetLogFile(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (logFile.is_open()) {
        logFile.close();
    }
    
    logFilePath = filePath;
    
    // Expandir variables de entorno
    char expandedPath[MAX_PATH];
    if (ExpandEnvironmentStringsA(filePath.c_str(), expandedPath, MAX_PATH)) {
        logFile.open(expandedPath, std::ios::app);
    } else {
        logFile.open(filePath, std::ios::app);
    }
    
    if (logFile.is_open()) {
        logFile << "\n=== Ransomware Session Started ===\n";
        logFile.flush();
    }
}

std::string Logger::GetCurrentTimestamp() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    
    char buffer[64];
    sprintf_s(buffer, "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    return std::string(buffer);
}

void Logger::WriteLog(const std::string& level, const std::string& message) {
    if (!enabled || !logFile.is_open()) return;
    
    std::lock_guard<std::mutex> lock(logMutex);
    
    logFile << "[" << GetCurrentTimestamp() << "] [" << level << "] " << message << "\n";
    logFile.flush();
}

void Logger::Log(const std::string& message) {
    WriteLog(LOG_LEVEL_INFO, message);
}

void Logger::Error(const std::string& message) {
    WriteLog(LOG_LEVEL_ERROR, message);
}

void Logger::Warning(const std::string& message) {
    WriteLog(LOG_LEVEL_WARNING, message);
}

void Logger::Info(const std::string& message) {
    WriteLog(LOG_LEVEL_INFO, message);
}

void Logger::Debug(const std::string& message) {
    WriteLog(LOG_LEVEL_DEBUG, message);
}

void Logger::Flush() {
    std::lock_guard<std::mutex> lock(logMutex);
    if (logFile.is_open()) {
        logFile.flush();
    }
}

void Logger::Clear() {
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (logFile.is_open()) {
        logFile.close();
    }
    
    logFile.open(logFilePath, std::ios::trunc);
    if (logFile.is_open()) {
        logFile << "\n=== Log Cleared ===\n";
        logFile.flush();
    }
}
