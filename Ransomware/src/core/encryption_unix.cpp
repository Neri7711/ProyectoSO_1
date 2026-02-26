#include "core/encryption.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <fstream>
#include <vector>
#include <cstring>

class UnixEncryptionEngine : public EncryptionEngine {
private:
    EVP_PKEY* rsa_key = nullptr;
    EVP_CIPHER_CTX* cipher_ctx = nullptr;
    
public:
    bool Initialize() override {
        // Initialize OpenSSL
        OpenSSL_add_all_algorithms();
        
        // Initialize cipher context
        cipher_ctx = EVP_CIPHER_CTX_new();
        if (!cipher_ctx) return false;
        
        return GenerateRSAKeyPair();
    }
    
    bool GenerateRSAKeyPair() override {
        // Generate RSA-4096 key pair
        rsa_key = EVP_PKEY_new();
        if (!rsa_key) return false;
        
        RSA* rsa = RSA_new();
        if (!rsa) return false;
        
        BIGNUM* bn = BN_new();
        BN_set_word(bn, RSA_F4);
        
        if (RSA_generate_key_ex(rsa, 4096, bn, nullptr) != 1) {
            RSA_free(rsa);
            BN_free(bn);
            return false;
        }
        
        if (EVP_PKEY_assign_RSA(rsa_key, rsa) != 1) {
            RSA_free(rsa);
            BN_free(bn);
            return false;
        }
        
        BN_free(bn);
        return true;
    }
    
    bool EncryptData(const uint8_t* input, size_t inputSize,
                     uint8_t* output, const uint8_t* key, const uint8_t* nonce) override {
        // Initialize ChaCha20 encryption
        if (EVP_EncryptInit_ex(cipher_ctx, EVP_chacha20(), nullptr, key, nonce) != 1) {
            return false;
        }
        
        int len;
        int outputLen = 0;
        
        // Encrypt data
        if (EVP_EncryptUpdate(cipher_ctx, output, &len, input, inputSize) != 1) {
            return false;
        }
        outputLen += len;
        
        // Finalize encryption
        if (EVP_EncryptFinal_ex(cipher_ctx, output + len, &len) != 1) {
            return false;
        }
        outputLen += len;
        
        return true;
    }
    
    bool GenerateRandomBytes(uint8_t* buffer, size_t size) override {
        return RAND_bytes(buffer, size) == 1;
    }
    
    ~UnixEncryptionEngine() {
        if (rsa_key) EVP_PKEY_free(rsa_key);
        if (cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);
        EVP_cleanup();
    }
};
