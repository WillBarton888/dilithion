// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_RPC_SSL_WRAPPER_H
#define DILITHION_RPC_SSL_WRAPPER_H

#include <string>
#include <memory>

// Forward declarations for OpenSSL types
struct ssl_st;
struct ssl_ctx_st;
struct bio_st;
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct bio_st BIO;

/**
 * Phase 3: SSL/TLS Wrapper for RPC Server
 * 
 * Provides secure encrypted communication using OpenSSL.
 * Supports both server and client SSL contexts.
 */
class CSSLWrapper {
public:
    /**
     * Constructor
     */
    CSSLWrapper();
    
    /**
     * Destructor
     */
    ~CSSLWrapper();
    
    /**
     * Initialize SSL context for server mode
     * @param cert_file Path to certificate file (PEM format)
     * @param key_file Path to private key file (PEM format)
     * @param ca_file Optional path to CA certificate file (for client verification)
     * @return true if initialization successful, false on error
     */
    bool InitializeServer(const std::string& cert_file,
                         const std::string& key_file,
                         const std::string& ca_file = "");
    
    /**
     * Create SSL connection from accepted socket
     * @param socket_fd Accepted socket file descriptor
     * @return SSL* pointer on success, nullptr on error
     */
    SSL* AcceptSSL(int socket_fd);
    
    /**
     * Read data from SSL connection
     * @param ssl SSL connection
     * @param buffer Buffer to read into
     * @param size Maximum bytes to read
     * @return Number of bytes read, or -1 on error
     */
    int SSLRead(SSL* ssl, void* buffer, int size);
    
    /**
     * Write data to SSL connection
     * @param ssl SSL connection
     * @param buffer Data to write
     * @param size Number of bytes to write
     * @return Number of bytes written, or -1 on error
     */
    int SSLWrite(SSL* ssl, const void* buffer, int size);
    
    /**
     * Shutdown SSL connection gracefully
     * @param ssl SSL connection
     */
    void SSLShutdown(SSL* ssl);
    
    /**
     * Free SSL connection
     * @param ssl SSL connection to free
     */
    void SSLFree(SSL* ssl);
    
    /**
     * Get last SSL error message
     */
    std::string GetLastError() const;
    
    /**
     * Check if SSL is initialized
     */
    bool IsInitialized() const { return m_ctx != nullptr; }
    
    /**
     * Get SSL context (for advanced usage)
     */
    SSL_CTX* GetContext() const { return m_ctx; }

private:
    SSL_CTX* m_ctx;
    std::string m_last_error;
    
    /**
     * Initialize OpenSSL library
     */
    static void InitializeOpenSSL();
    
    /**
     * Cleanup OpenSSL library
     */
    static void CleanupOpenSSL();
    
    /**
     * Verify certificate and key files exist and are readable
     */
    bool VerifyFiles(const std::string& cert_file, const std::string& key_file);
    
    /**
     * Set SSL options (TLS version, cipher suites, etc.)
     */
    void SetSSLOptions();
    
    /**
     * Get SSL error string
     */
    std::string GetSSLErrorString(unsigned long err) const;
};

#endif // DILITHION_RPC_SSL_WRAPPER_H

