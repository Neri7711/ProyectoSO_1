#pragma once

#include <string>
#include <vector>

#ifdef PLATFORM_WINDOWS
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#elif PLATFORM_UNIX
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <fstream>
#include <sys/stat.h>
#include <pwd.h>
#endif

// Persistencia de clave local basada en DPAPI
// Flujo: RSA private key blob → CryptProtectData (DPAPI + entropy) → archivo %APPDATA% + Registry
class KeyPersistence {
private:
    // Contraseña maestra hardcodeada usada como entropia opcional para CryptProtectData
    static const char* MASTER_PASSWORD;

    // Ubicaciones de almacenamiento
    static const char* STORAGE_SUBDIR;    // subdirectorio dentro de %APPDATA%
    static const char* STORAGE_FILENAME;  // nombre de archivo para el blob encriptado
    static const char* REGISTRY_KEY_PATH; // ruta de registro HKCU
    static const char* REGISTRY_VALUE_NAME;

    // Helpers internos
    static std::string       ExpandAppDataPath();
    static std::vector<BYTE> DeriveEntropy();
    static std::string       Base64Encode(const std::vector<BYTE>& data);
    static std::vector<BYTE> Base64Decode(const std::string& encoded);

public:
    // Encriptar el blob de clave privada con DPAPI y persistirlo
    // Retorna true si al menos un backend de almacenamiento tuvo éxito
    static bool SavePrivateKey(const std::vector<BYTE>& privateKeyBlob);

    // Recuperar blob de clave privada del almacenamiento
    // Retorna true si la clave fue encontrada y desencriptada exitosamente
    static bool LoadPrivateKey(std::vector<BYTE>& privateKeyBlob);

    // Backends individuales (llamados por SavePrivateKey / LoadPrivateKey)
    static bool SaveToFile(const std::vector<BYTE>& dpapiBlobBytes);
    static bool LoadFromFile(std::vector<BYTE>& dpapiBlobBytes);

    static bool SaveToRegistry(const std::vector<BYTE>& dpapiBlobBytes);
    static bool LoadFromRegistry(std::vector<BYTE>& dpapiBlobBytes);

    // Wrappers DPAPI de bajo nivel
    static bool DPAPIProtect(const std::vector<BYTE>& plainData,
                             std::vector<BYTE>&       protectedData);
    static bool DPAPIUnprotect(const std::vector<BYTE>& protectedData,
                               std::vector<BYTE>&       plainData);
};
