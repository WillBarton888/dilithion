#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>

int main() {
    std::cout << "Testing OpenSSL..." << std::endl;

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Get cipher
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    if (cipher) {
        std::cout << "EVP_aes_256_cbc found!" << std::endl;
        std::cout << "Block size: " << EVP_CIPHER_block_size(cipher) << std::endl;
    } else {
        std::cout << "EVP_aes_256_cbc NOT found!" << std::endl;
    }

    // Print OpenSSL version
    std::cout << "OpenSSL version: " << SSLeay_version(SSLEAY_VERSION) << std::endl;

    return 0;
}