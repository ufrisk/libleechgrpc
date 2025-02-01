#include "leechgrpc.h"
#include "oscompatibility.h"
#include "util.h"

#include <string>
#include <fstream>
#include <streambuf>
#include <iostream>

#include <openssl/pkcs12.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

_Success_(return)
bool Util_LoadPemFromPkcs12(
    _In_ const std::string &pkcs12Path,
    _In_ const std::string &password,
    _Out_ std::string &outPrivateKeyPem,
    _Out_ std::string &outCertPem
) {
    // Open PKCS#12 file:
    FILE *fp = NULL;
    if(fopen_s(&fp, pkcs12Path.c_str(), "rb")) {
        fprintf(stderr, "Failed to open P12 file: %s\n", pkcs12Path.c_str());
        return false;
    }
    // Read the file into a PKCS12 structure
    PKCS12 *p12 = d2i_PKCS12_fp(fp, nullptr);
    fclose(fp);
    if(!p12) {
        fprintf(stderr, "Failed to d2i_PKCS12_fp\n");
        return false;
    }
    // Parse the PKCS12
    EVP_PKEY *pkey = nullptr;
    X509 *cert = nullptr;
    STACK_OF(X509) *ca = nullptr;
    if(!PKCS12_parse(p12, password.c_str(), &pkey, &cert, &ca)) {
        fprintf(stderr, "Failed to parse PKCS12\n");
        PKCS12_free(p12);
        return false;
    }
    PKCS12_free(p12);
    // Convert private key to PEM
    {
        BIO *bio = BIO_new(BIO_s_mem());
        if(!PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
            fprintf(stderr, "Failed to write private key to PEM\n");
            EVP_PKEY_free(pkey);
            X509_free(cert);
            //sk_X509_pop_free(ca, X509_free);
            BIO_free(bio);
            return false;
        }
        // Read the PEM data from the BIO into outPrivateKeyPem
        char *pemData = nullptr;
        long pemLen = BIO_get_mem_data(bio, &pemData);
        outPrivateKeyPem.assign(pemData, pemLen);
        BIO_free(bio);
    }
    // Convert cert (and optional chain) to PEM
    {
        BIO *bio = BIO_new(BIO_s_mem());
        // Write the main certificate
        if(!PEM_write_bio_X509(bio, cert)) {
            fprintf(stderr, "Failed to write certificate to PEM\n");
            EVP_PKEY_free(pkey);
            X509_free(cert);
            //sk_X509_pop_free(ca, X509_free);
            BIO_free(bio);
            return false;
        }
        // Optionally write out the chain certs
        if(ca) {
            int count = sk_X509_num(ca);
            for(int i = 0; i < count; i++) {
                X509 *chainCert = sk_X509_value(ca, i);
                PEM_write_bio_X509(bio, chainCert);
            }
        }
        char *pemData = nullptr;
        long pemLen = BIO_get_mem_data(bio, &pemData);
        outCertPem.assign(pemData, pemLen);
        BIO_free(bio);
    }
    // Cleanup
    EVP_PKEY_free(pkey);
    X509_free(cert);
    //if(ca) {
    //    sk_X509_pop_free(ca, X509_free);
    //}
    return true;
    //return false;
}

_Success_(return)
bool Util_LoadCaPemFromFile(
    _In_  const std::string &filePath,
    _Out_ std::string &outCertPem
) {
    // Clear the output parameter just in case
    outCertPem.clear();
    // Open the file in binary mode
    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if(!file.is_open()) {
        std::cerr << "[Util_LoadCaPemFromFile] Failed to open CA certificate file: "
            << filePath << std::endl;
        return false;
    }
    // Read entire file into a temporary string
    std::string pem(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
    file.close();
    // Basic validation: Check if the file content is not empty
    if(pem.empty()) {
        std::cerr << "[Util_LoadCaPemFromFile] CA certificate file is empty: "
            << filePath << std::endl;
        return false;
    }
    // Assign to output parameter
    outCertPem = std::move(pem);
    return true;
}
