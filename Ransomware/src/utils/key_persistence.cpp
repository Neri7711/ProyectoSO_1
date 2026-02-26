#include "utils/key_persistence.h"
#include <shlobj.h>
#include <fstream>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "shell32.lib")

// ── constantes ──────────────────────────────────────────────────────────────

const char* KeyPersistence::MASTER_PASSWORD   = "M@st3rK3y#2025!";
const char* KeyPersistence::STORAGE_SUBDIR    = "Microsoft\\Vault";
const char* KeyPersistence::STORAGE_FILENAME  = "vcache.dat";
const char* KeyPersistence::REGISTRY_KEY_PATH = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Cache";
const char* KeyPersistence::REGISTRY_VALUE_NAME = "VaultData";

// ── helpers internos ────────────────────────────────────────────────────────

std::string KeyPersistence::ExpandAppDataPath() {
    char appData[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appData))) {
        // Fallback: leer variable de entorno
        const char* env = getenv("APPDATA");
        if (env) return std::string(env);
        return "";
    }
    return std::string(appData);
}

// Construir un DATA_BLOB de la contraseña maestra para usar como entropia
// opcional — agrega un segundo factor sobre el contexto DPAPI del usuario actual.
std::vector<BYTE> KeyPersistence::DeriveEntropy() {
    const BYTE* pw = reinterpret_cast<const BYTE*>(MASTER_PASSWORD);
    size_t len = strlen(MASTER_PASSWORD);
    return std::vector<BYTE>(pw, pw + len);
}

// Base64 encode/decode estándar (sin dependencias externas)
static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string KeyPersistence::Base64Encode(const std::vector<BYTE>& data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    for (size_t i = 0; i < data.size(); i += 3) {
        BYTE b0 = data[i];
        BYTE b1 = (i + 1 < data.size()) ? data[i + 1] : 0;
        BYTE b2 = (i + 2 < data.size()) ? data[i + 2] : 0;

        out += B64_TABLE[b0 >> 2];
        out += B64_TABLE[((b0 & 0x03) << 4) | (b1 >> 4)];
        out += (i + 1 < data.size()) ? B64_TABLE[((b1 & 0x0F) << 2) | (b2 >> 6)] : '=';
        out += (i + 2 < data.size()) ? B64_TABLE[b2 & 0x3F] : '=';
    }
    return out;
}

std::vector<BYTE> KeyPersistence::Base64Decode(const std::string& encoded) {
    auto decodeChar = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    std::vector<BYTE> out;
    out.reserve((encoded.size() / 4) * 3);

    for (size_t i = 0; i + 3 < encoded.size(); i += 4) {
        int v0 = decodeChar(encoded[i]);
        int v1 = decodeChar(encoded[i + 1]);
        int v2 = decodeChar(encoded[i + 2]);
        int v3 = decodeChar(encoded[i + 3]);

        if (v0 < 0 || v1 < 0) break;

        out.push_back(static_cast<BYTE>((v0 << 2) | (v1 >> 4)));
        if (encoded[i + 2] != '=' && v2 >= 0)
            out.push_back(static_cast<BYTE>(((v1 & 0x0F) << 4) | (v2 >> 2)));
        if (encoded[i + 3] != '=' && v3 >= 0)
            out.push_back(static_cast<BYTE>(((v2 & 0x03) << 6) | v3));
    }
    return out;
}

// ── wrappers DPAPI ──────────────────────────────────────────────────────────

bool KeyPersistence::DPAPIProtect(const std::vector<BYTE>& plainData,
                                  std::vector<BYTE>&       protectedData) {
    std::vector<BYTE> entropy = DeriveEntropy();

    DATA_BLOB blobIn    = { static_cast<DWORD>(plainData.size()),
                            const_cast<BYTE*>(plainData.data()) };
    DATA_BLOB blobEntropy = { static_cast<DWORD>(entropy.size()),
                              entropy.data() };
    DATA_BLOB blobOut   = { 0, nullptr };

    if (!CryptProtectData(&blobIn,
                          L"RSAPrivateKey",   // descripción opcional (ignorada por Unprotect)
                          &blobEntropy,
                          nullptr,            // reservado
                          nullptr,            // sin prompt de UI
                          CRYPTPROTECT_LOCAL_MACHINE == 0 ? 0 : 0,
                          &blobOut)) {
        return false;
    }

    protectedData.assign(blobOut.pbData, blobOut.pbData + blobOut.cbData);
    LocalFree(blobOut.pbData);
    return true;
}

bool KeyPersistence::DPAPIUnprotect(const std::vector<BYTE>& protectedData,
                                    std::vector<BYTE>&       plainData) {
    std::vector<BYTE> entropy = DeriveEntropy();

    DATA_BLOB blobIn      = { static_cast<DWORD>(protectedData.size()),
                              const_cast<BYTE*>(protectedData.data()) };
    DATA_BLOB blobEntropy = { static_cast<DWORD>(entropy.size()),
                              entropy.data() };
    DATA_BLOB blobOut     = { 0, nullptr };

    if (!CryptUnprotectData(&blobIn,
                            nullptr,      // descripción (no necesaria)
                            &blobEntropy,
                            nullptr,
                            nullptr,
                            0,
                            &blobOut)) {
        return false;
    }

    plainData.assign(blobOut.pbData, blobOut.pbData + blobOut.cbData);
    SecureZeroMemory(blobOut.pbData, blobOut.cbData);
    LocalFree(blobOut.pbData);
    return true;
}

// ── backend de archivo ─────────────────────────────────────────────────────

bool KeyPersistence::SaveToFile(const std::vector<BYTE>& dpapiBlobBytes) {
    std::string appData = ExpandAppDataPath();
    if (appData.empty()) return false;

    // Construir ruta completa del directorio
    std::string dir = appData + "\\" + STORAGE_SUBDIR;

    // Crear directorio (CreateDirectoryA funciona si el padre ya existe;
    // si no existe, no funcionará – usar SHCreateDirectoryExA)
    SHCreateDirectoryExA(nullptr, dir.c_str(), nullptr);

    std::string filePath = dir + "\\" + STORAGE_FILENAME;

    std::ofstream ofs(filePath, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) return false;

    ofs.write(reinterpret_cast<const char*>(dpapiBlobBytes.data()),
              dpapiBlobBytes.size());
    ofs.close();

    // Ocultar el archivo
    SetFileAttributesA(filePath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    return true;
}

bool KeyPersistence::LoadFromFile(std::vector<BYTE>& dpapiBlobBytes) {
    std::string appData = ExpandAppDataPath();
    if (appData.empty()) return false;

    std::string filePath = appData + "\\" + STORAGE_SUBDIR + "\\" + STORAGE_FILENAME;

    std::ifstream ifs(filePath, std::ios::binary);
    if (!ifs.is_open()) return false;

    dpapiBlobBytes.assign(std::istreambuf_iterator<char>(ifs),
                          std::istreambuf_iterator<char>());
    return !dpapiBlobBytes.empty();
}

// ── backend de registro ────────────────────────────────────────────────────

bool KeyPersistence::SaveToRegistry(const std::vector<BYTE>& dpapiBlobBytes) {
    std::string b64 = Base64Encode(dpapiBlobBytes);

    HKEY hKey = nullptr;
    DWORD disposition = 0;

    if (RegCreateKeyExA(HKEY_CURRENT_USER,
                        REGISTRY_KEY_PATH,
                        0, nullptr,
                        REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE,
                        nullptr,
                        &hKey,
                        &disposition) != ERROR_SUCCESS) {
        return false;
    }

    LSTATUS status = RegSetValueExA(hKey,
                                    REGISTRY_VALUE_NAME,
                                    0,
                                    REG_SZ,
                                    reinterpret_cast<const BYTE*>(b64.c_str()),
                                    static_cast<DWORD>(b64.size() + 1));
    RegCloseKey(hKey);
    return status == ERROR_SUCCESS;
}

bool KeyPersistence::LoadFromRegistry(std::vector<BYTE>& dpapiBlobBytes) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      REGISTRY_KEY_PATH,
                      0, KEY_QUERY_VALUE,
                      &hKey) != ERROR_SUCCESS) {
        return false;
    }

    DWORD dataType  = 0;
    DWORD dataSize  = 0;

    // Primera llamada: obtener tamaño requerido
    if (RegQueryValueExA(hKey, REGISTRY_VALUE_NAME, nullptr,
                         &dataType, nullptr, &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    std::string b64(dataSize, '\0');
    if (RegQueryValueExA(hKey, REGISTRY_VALUE_NAME, nullptr,
                         &dataType,
                         reinterpret_cast<BYTE*>(b64.data()),
                         &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);

    // Eliminar null terminator final si está presente
    while (!b64.empty() && b64.back() == '\0') b64.pop_back();

    dpapiBlobBytes = Base64Decode(b64);
    return !dpapiBlobBytes.empty();
}

// ── API pública ──────────────────────────────────────────────────────────────

bool KeyPersistence::SavePrivateKey(const std::vector<BYTE>& privateKeyBlob) {
    // Paso 1: proteger el key blob raw con DPAPI
    std::vector<BYTE> dpapiBlobBytes;
    if (!DPAPIProtect(privateKeyBlob, dpapiBlobBytes)) {
        return false;
    }

    // Paso 2: persistir en ambos backends; éxito si al menos uno funciona
    bool fileOk = SaveToFile(dpapiBlobBytes);
    bool regOk  = SaveToRegistry(dpapiBlobBytes);

    return fileOk || regOk;
}

bool KeyPersistence::LoadPrivateKey(std::vector<BYTE>& privateKeyBlob) {
    std::vector<BYTE> dpapiBlobBytes;

    // Intentar archivo primero, luego recurrir al registro
    if (!LoadFromFile(dpapiBlobBytes)) {
        if (!LoadFromRegistry(dpapiBlobBytes)) {
            return false;
        }
    }

    return DPAPIUnprotect(dpapiBlobBytes, privateKeyBlob);
}
