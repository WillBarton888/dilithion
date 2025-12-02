// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <rpc/ssl_wrapper.h>
#include <fstream>
#include <sstream>
#include <cstring>

// OpenSSL includes
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

// Static initialization flag
static bool s_openssl_initialized = false;

CSSLWrapper::CSSLWrapper() : m_ctx(nullptr) {
    InitializeOpenSSL();
}

CSSLWrapper::~CSSLWrapper() {
    if (m_ctx) {
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
    }
}

void CSSLWrapper::InitializeOpenSSL() {
    if (!s_openssl_initialized) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        s_openssl_initialized = true;
    }
}

void CSSLWrapper::CleanupOpenSSL() {
    if (s_openssl_initialized) {
        EVP_cleanup();
        ERR_free_strings();
        s_openssl_initialized = false;
    }
}

bool CSSLWrapper::VerifyFiles(const std::string& cert_file, const std::string& key_file) {
    // Check certificate file
    std::ifstream cert_stream(cert_file);
    if (!cert_stream.good()) {
        m_last_error = "Certificate file not found or not readable: " + cert_file;
        return false;
    }
    cert_stream.close();
    
    // Check key file
    std::ifstream key_stream(key_file);
    if (!key_stream.good()) {
        m_last_error = "Private key file not found or not readable: " + key_file;
        return false;
    }
    key_stream.close();
    
    return true;
}

void CSSLWrapper::SetSSLOptions() {
    if (!m_ctx) {
        return;
    }
    
    // Require TLS 1.2 or higher (disable SSLv2, SSLv3, TLS 1.0, TLS 1.1)
    // Use version-specific API for compatibility
    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
        // OpenSSL 1.1.0+
        SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);
    #else
        // OpenSSL 1.0.x - use options instead
        SSL_CTX_set_options(m_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | 
                                       SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    #endif
    
    // Set cipher list (HIGH security, exclude weak ciphers)
    const char* ciphers = "HIGH:!aNULL:!MD5:!RC4:!DES:!3DES";
    if (SSL_CTX_set_cipher_list(m_ctx, ciphers) != 1) {
        m_last_error = "Failed to set cipher list";
        return;
    }
    
    // Disable renegotiation for security (SSL_OP_NO_RENEGOTIATION available in OpenSSL 1.1.0h+)
    #ifdef SSL_OP_NO_RENEGOTIATION
        SSL_CTX_set_options(m_ctx, SSL_OP_NO_RENEGOTIATION);
    #endif
    
    // Prefer server cipher order
    SSL_CTX_set_options(m_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
}

std::string CSSLWrapper::GetSSLErrorString(unsigned long err) const {
    char buffer[256];
    ERR_error_string_n(err, buffer, sizeof(buffer));
    return std::string(buffer);
}

bool CSSLWrapper::InitializeServer(const std::string& cert_file,
                                   const std::string& key_file,
                                   const std::string& ca_file) {
    // Verify files exist
    if (!VerifyFiles(cert_file, key_file)) {
        return false;
    }
    
    // Create SSL context
    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
        // OpenSSL 1.1.0+
        m_ctx = SSL_CTX_new(TLS_server_method());
    #else
        // OpenSSL 1.0.x
        m_ctx = SSL_CTX_new(SSLv23_server_method());
    #endif
    if (!m_ctx) {
        unsigned long err = ERR_get_error();
        m_last_error = "Failed to create SSL context: " + GetSSLErrorString(err);
        return false;
    }
    
    // Load certificate
    if (SSL_CTX_use_certificate_file(m_ctx, cert_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        unsigned long err = ERR_get_error();
        m_last_error = "Failed to load certificate: " + GetSSLErrorString(err);
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return false;
    }
    
    // Load private key
    if (SSL_CTX_use_PrivateKey_file(m_ctx, key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        unsigned long err = ERR_get_error();
        m_last_error = "Failed to load private key: " + GetSSLErrorString(err);
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return false;
    }
    
    // Verify private key matches certificate
    if (SSL_CTX_check_private_key(m_ctx) != 1) {
        unsigned long err = ERR_get_error();
        m_last_error = "Private key does not match certificate: " + GetSSLErrorString(err);
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return false;
    }
    
    // Load CA certificate if provided (for client verification)
    if (!ca_file.empty()) {
        if (SSL_CTX_load_verify_locations(m_ctx, ca_file.c_str(), nullptr) != 1) {
            // Warning but not fatal
            m_last_error = "Warning: Failed to load CA certificate: " + ca_file;
        } else {
            // Request client certificate (optional verification)
            SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, nullptr);
        }
    }
    
    // Set SSL options
    SetSSLOptions();
    
    return true;
}

SSL* CSSLWrapper::AcceptSSL(int socket_fd) {
    if (!m_ctx) {
        m_last_error = "SSL context not initialized";
        return nullptr;
    }
    
    // Create SSL connection
    SSL* ssl = SSL_new(m_ctx);
    if (!ssl) {
        unsigned long err = ERR_get_error();
        m_last_error = "Failed to create SSL connection: " + GetSSLErrorString(err);
        return nullptr;
    }
    
    // Attach socket to SSL
    if (SSL_set_fd(ssl, socket_fd) != 1) {
        unsigned long err = ERR_get_error();
        m_last_error = "Failed to set SSL file descriptor: " + GetSSLErrorString(err);
        SSL_free(ssl);
        return nullptr;
    }
    
    // Perform SSL handshake
    int ret = SSL_accept(ssl);
    if (ret != 1) {
        int ssl_error = SSL_get_error(ssl, ret);
        unsigned long err = ERR_get_error();
        std::ostringstream oss;
        oss << "SSL handshake failed (error " << ssl_error << "): " << GetSSLErrorString(err);
        m_last_error = oss.str();
        SSL_free(ssl);
        return nullptr;
    }
    
    return ssl;
}

int CSSLWrapper::SSLRead(SSL* ssl, void* buffer, int size) {
    if (!ssl) {
        m_last_error = "SSL connection is null";
        return -1;
    }
    
    int bytes_read = SSL_read(ssl, buffer, size);
    if (bytes_read < 0) {
        int ssl_error = SSL_get_error(ssl, bytes_read);
        if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
            unsigned long err = ERR_get_error();
            m_last_error = "SSL read error: " + GetSSLErrorString(err);
        }
    }
    
    return bytes_read;
}

int CSSLWrapper::SSLWrite(SSL* ssl, const void* buffer, int size) {
    if (!ssl) {
        m_last_error = "SSL connection is null";
        return -1;
    }
    
    int bytes_written = SSL_write(ssl, buffer, size);
    if (bytes_written < 0) {
        int ssl_error = SSL_get_error(ssl, bytes_written);
        if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
            unsigned long err = ERR_get_error();
            m_last_error = "SSL write error: " + GetSSLErrorString(err);
        }
    }
    
    return bytes_written;
}

void CSSLWrapper::SSLShutdown(SSL* ssl) {
    if (ssl) {
        SSL_shutdown(ssl);
    }
}

void CSSLWrapper::SSLFree(SSL* ssl) {
    if (ssl) {
        SSL_free(ssl);
    }
}

std::string CSSLWrapper::GetLastError() const {
    return m_last_error;
}

