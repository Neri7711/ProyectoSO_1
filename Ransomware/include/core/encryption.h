#pragma once

#include <string>
#include <vector>
#include <cstdint>

#ifdef PLATFORM_WINDOWS
#include <windows.h>
#include <wincrypt.h>
#include "utils/key_persistence.h"
#pragma comment(lib, "crypt32.lib")
#elif PLATFORM_UNIX
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#endif

class EncryptionEngine {
private:
#ifdef PLATFORM_WINDOWS
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTKEY hPublicKey;
    HCRYPTKEY hPrivateKey;
#elif PLATFORM_UNIX
    EVP_PKEY* rsaKeyPair;
    EVP_CIPHER_CTX* chachaCtx;
#endif
    
    std::string privateKeyData;
    std::string publicKeyData;
        
    // Estado ChaCha20
    struct ChaCha20State {
        uint32_t state[16];
        size_t position;
    };

    // Métodos internos
    bool InitializeCryptoProvider();
    bool GenerateRSAKeyPair();
    bool InitializeChaCha20();
    
    // Implementación ChaCha20
    void ChaCha20Block(uint32_t state[16]);
    void ChaCha20KeyStream(ChaCha20State* state, uint8_t* stream, size_t length);
    void QuarterRound(uint32_t state[16], int a, int b, int c, int d);
    
    // Operaciones de archivo
    bool BackupFile(const std::string& filePath);
    bool SecureDeleteFile(const std::string& filePath);
    
public:
    EncryptionEngine();
    ~EncryptionEngine();
    
    // Inicialización
    bool Initialize();
    std::string GenerateKeyPair();
    
    // Operaciones de encriptación
    bool EncryptFile(const std::string& filePath, const std::string& publicKey);
    bool DecryptFile(const std::string& filePath, const std::string& privateKey);
    
    // Encriptación ChaCha20
    bool EncryptData(const uint8_t* input, size_t inputSize, 
                     uint8_t* output, const uint8_t* key, const uint8_t* nonce);
    bool DecryptData(const uint8_t* input, size_t inputSize, 
                     uint8_t* output, const uint8_t* key, const uint8_t* nonce);
    
    // Operaciones RSA
    std::string EncryptRSA(const std::string& data);
    std::string DecryptRSA(const std::string& encryptedData);
    
    // Gestión de claves
    std::string GetPublicKey() const { return publicKeyData; }
    std::string GetPrivateKey() const { return privateKeyData; }

    // Persistencia de clave local protegida
    bool SaveProtectedPrivateKey();
    bool LoadProtectedPrivateKey();
    
    // Métodos de utilidad
    bool GenerateRandomBytes(uint8_t* buffer, size_t size);
    std::string GenerateRandomString(size_t length);
    
    // Constantes
    static const size_t CHACHA20_KEY_SIZE = 32;
    static const size_t CHACHA20_NONCE_SIZE = 12;
    static const size_t RSA_KEY_SIZE = 4096;
    static const std::string ENCRYPTED_EXTENSION;
};
