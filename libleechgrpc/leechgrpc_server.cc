#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>
#include <openssl/ssl.h>
#include <iostream>
#include <memory>
#include <string>

// Include the generated headers.
#ifdef _WIN32
#include "generated/leechgrpc.grpc.pb.h"
#include "generated/leechgrpc.pb.h"
#else
#include "leechgrpc.grpc.pb.h"
#include "leechgrpc.pb.h"
#endif /* _WIN32 */

#include "leechgrpc.h"
#include "oscompatibility.h"
#include "util.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using leechrpc::LeechRpc;
using leechrpc::SubmitCommandRequest;
using leechrpc::SubmitCommandResponse;

// Implementation of the LeechRpc service.
class LeechRpcServiceImpl final : public LeechRpc::Service {
public:
    explicit LeechRpcServiceImpl(PVOID ctx, PFN_RESERVED_SUBMIT_COMMAND_CB pfnCB) : m_ctx(ctx), m_pfnCB(pfnCB)
    {
    }

    // Handle the ReservedSubmitCommand RPC.
    Status ReservedSubmitCommand(ServerContext *context, const SubmitCommandRequest *request, SubmitCommandResponse *response) override
    {
        // Extract the client’s message (pbIn)        
        const std::string client_data = request->pbin();
        const PBYTE pbIn = reinterpret_cast<PBYTE>(const_cast<char *>(client_data.data()));
        SIZE_T cbIn = client_data.size();

        // Call the callback function
        PBYTE pbOut = NULL;
        SIZE_T cbOut = 0;
        m_pfnCB(m_ctx, pbIn, cbIn, &pbOut, &cbOut);

        // Set the response message & free it.
        response->set_pbout(reinterpret_cast<const char *>(pbOut), cbOut);
        LocalFree(pbOut);

        return Status::OK;
    }

private:
    PVOID m_ctx;
    PFN_RESERVED_SUBMIT_COMMAND_CB m_pfnCB;
};

/*
* Create a gRPC server.
* -- dwPort: Port to listen on.
* -- pfnReservedSubmitCommandCB: Callback function to handle incoming commands.
* -- return: Handle to the gRPC server, or NULL on failure.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
HANDLE leechgrpc_server_create_insecure(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ PVOID ctx,
    _In_ PFN_RESERVED_SUBMIT_COMMAND_CB pfnReservedSubmitCommandCB
) {
    auto *service = new LeechRpcServiceImpl(ctx, pfnReservedSubmitCommandCB);
    // Convert the address/port to a string
    CHAR szAddressAndPort[MAX_PATH] = { 0 };
    _snprintf_s(szAddressAndPort, MAX_PATH, _TRUNCATE, "%s:%d", szAddress, dwPort);
    const std::string server_address(szAddressAndPort);
    // Build the server
    ServerBuilder builder;
    builder.SetMaxReceiveMessageSize(LEECHGRPC_MESSAGE_SIZE_MAX);
    builder.SetMaxSendMessageSize(LEECHGRPC_MESSAGE_SIZE_MAX);
    // Listen on the given address without any authentication mechanism (Insecure)
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    // Register our service
    builder.RegisterService(service);
    // Assemble the server
    std::unique_ptr<Server> server = builder.BuildAndStart();
    if(!server) {
        return NULL;
    }
    // Dynamically allocate a unique_ptr<Server> on the heap
    std::unique_ptr<std::unique_ptr<Server>> ptrOnHeap(new std::unique_ptr<Server>(std::move(server)));
    // Transfer ownership by returning the raw pointer as HANDLE
    // The caller will store this handle and cast it back later.
    return reinterpret_cast<HANDLE>(ptrOnHeap.release());
}

_Success_(return != NULL)
LEECHGRPC_SERVER_HANDLE leechgrpc_server_create_secure_internal(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ PVOID ctx,
    _In_ PFN_RESERVED_SUBMIT_COMMAND_CB pfnReservedSubmitCommandCB,
    _In_ const std::string sTlsClientCert,
    _In_ const std::string sTlsServerCert,
    _In_ const std::string sTlsServerCertPrivateKey
) {
    try {
        if(sTlsClientCert.length() < 8 || sTlsServerCert.length() < 8 || sTlsServerCertPrivateKey.length() < 8) {
            std::cerr << "[Server] Invalid TLS certificate or key provided." << std::endl;
            return NULL;
        }
        auto *service = new LeechRpcServiceImpl(ctx, pfnReservedSubmitCommandCB);
        // address/port -> string:
        CHAR szAddressAndPort[MAX_PATH] = { 0 };
        _snprintf_s(szAddressAndPort, MAX_PATH, _TRUNCATE, "%s:%u", szAddress, dwPort);
        const std::string server_address(szAddressAndPort);
        // mTLS client cert & server cert/key:
        grpc::SslServerCredentialsOptions::PemKeyCertPair keyCertPair;
        keyCertPair.private_key = sTlsServerCertPrivateKey;
        keyCertPair.cert_chain = sTlsServerCert;
        grpc::SslServerCredentialsOptions sslOpts;
        sslOpts.pem_key_cert_pairs.push_back(keyCertPair);
        sslOpts.pem_root_certs = sTlsClientCert;
        sslOpts.client_certificate_request = GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
        // build and configure server:
        auto serverCreds = grpc::SslServerCredentials(sslOpts);
        grpc::ServerBuilder builder;
        builder.SetMaxReceiveMessageSize(LEECHGRPC_MESSAGE_SIZE_MAX);
        builder.SetMaxSendMessageSize(LEECHGRPC_MESSAGE_SIZE_MAX);
        builder.AddListeningPort(server_address, serverCreds);
        builder.RegisterService(service);
        // start the server:
        std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
        if(!server) {
            std::cerr << "[Server] Failed to start secure server on: " << server_address << std::endl;
            return NULL;
        }
        // dynamically allocate a unique_ptr<Server> on the heap:
        std::unique_ptr<std::unique_ptr<grpc::Server>> ptrOnHeap(new std::unique_ptr<grpc::Server>(std::move(server)));
        // return the raw pointer as a LEECHGRPC_SERVER_HANDLE.
        // caller is responsible for cleanup.
        return reinterpret_cast<LEECHGRPC_SERVER_HANDLE>(ptrOnHeap.release());
    } catch(const std::exception &ex) {
        std::cerr << "[Server] Exception in secure server creation: " << ex.what() << std::endl;
        return NULL;
    } catch(...) {
        std::cerr << "[Server] Unknown error in secure server creation." << std::endl;
        return NULL;
    }
}

/*
* Create a gRPC server with mTLS.
* -- szAddress: Address to listen on, e.g., "localhost" or "
* -- dwPort: Port to listen on.
* -- ctx: Optional context to pass to the callback function.
* -- pfnReservedSubmitCommandCB: Callback function to handle incoming commands.
* -- szTlsClientCert: Client CA certificate to trust for mTLS connections.
* -- szTlsServerCert: Server TLS certificate (incl. chain).
* -- szTlsServerCertPrivateKey: Server TLS certificate private key.
* -- return: Handle to the gRPC server, or NULL on failure.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
LEECHGRPC_SERVER_HANDLE leechgrpc_server_create_secure_pemraw(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ PVOID ctx,
    _In_ PFN_RESERVED_SUBMIT_COMMAND_CB pfnReservedSubmitCommandCB,
    _In_ LPCSTR szTlsClientCert,
    _In_ LPCSTR szTlsServerCert,
    _In_ LPCSTR szTlsServerCertPrivateKey
) {
    const std::string sTlsClientCert(szTlsClientCert);
    const std::string sTlsServerCert(szTlsServerCert);
    const std::string sTlsServerCertPrivateKey(szTlsServerCertPrivateKey);
    return leechgrpc_server_create_secure_internal(szAddress, dwPort, ctx, pfnReservedSubmitCommandCB, sTlsClientCert, sTlsServerCert, sTlsServerCertPrivateKey);
}

/*
* Create a gRPC server with mTLS.
* -- szAddress: Address to listen on, e.g., "localhost" or "
* -- dwPort: Port to listen on.
* -- ctx: Optional context to pass to the callback function.
* -- pfnReservedSubmitCommandCB: Callback function to handle incoming commands.
* -- szTlsClientCertPath: Client CA certificate to trust for mTLS connections.
* -- szTlsServerP12Path: Path to the server's TLS certificate & private key (.p12 / .pfx).
* -- szTlsServerP12Password: Password for the server's TLS certificate & private key (.p12 / .pfx).
* -- return: Handle to the gRPC server, or NULL on failure.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
LEECHGRPC_SERVER_HANDLE leechgrpc_server_create_secure_p12(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ PVOID ctx,
    _In_ PFN_RESERVED_SUBMIT_COMMAND_CB pfnReservedSubmitCommandCB,
    _In_ LPCSTR szTlsClientCertPath,
    _In_ LPCSTR szTlsServerP12Path,
    _In_ LPCSTR szTlsServerP12Password
) {
    // server certificate from .p12 file:
    std::string sTlsClientCert;
    std::string sTlsServerCert;
    std::string sTlsServerCertPrivateKey;
    if(!Util_LoadPemFromPkcs12(szTlsServerP12Path, szTlsServerP12Password, sTlsServerCertPrivateKey, sTlsServerCert)) {
        std::cerr << "[Server] Failed to load mTLS server cert/key from .p12 file: " << szTlsServerP12Path << std::endl;
        return NULL;
    }
    // client certificate:
    if(!Util_LoadCaPemFromFile(szTlsClientCertPath, sTlsClientCert)) {
        std::cerr << "[Server] Failed to load mTLS client ca cert from: " << szTlsClientCertPath << std::endl;
        return NULL;
    }
    return leechgrpc_server_create_secure_internal(szAddress, dwPort, ctx, pfnReservedSubmitCommandCB, sTlsClientCert, sTlsServerCert, sTlsServerCertPrivateKey);
}

/*
* Create a gRPC server with mTLS.
* -- szAddress: Address to listen on, e.g., "localhost" or "
* -- dwPort: Port to listen on.
* -- ctx: Optional context to pass to the callback function.
* -- pfnReservedSubmitCommandCB: Callback function to handle incoming commands.
* -- szTlsClientCertPath: Client CA certificate to trust for mTLS connections.
* -- szTlsServerCertPath: Server TLS certificate (incl. chain).
* -- szTlsServerCertPrivateKeyPath: Server TLS certificate private key.
* -- return: Handle to the gRPC server, or NULL on failure.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
LEECHGRPC_SERVER_HANDLE leechgrpc_server_create_secure_pemfile(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ PVOID ctx,
    _In_ PFN_RESERVED_SUBMIT_COMMAND_CB pfnReservedSubmitCommandCB,
    _In_ LPCSTR szTlsClientCertPath,
    _In_ LPCSTR szTlsServerCertPath,
    _In_ LPCSTR szTlsServerCertPrivateKeyPath
) {
    // Load the server's private key and certificate from the .p12 file
    std::string sTlsClientCert;
    std::string sTlsServerCert;
    std::string sTlsServerCertPrivateKey;
    if(!Util_LoadCaPemFromFile(szTlsServerCertPath, sTlsServerCert)) {
        std::cerr << "[Server] Failed to load server ca certificate from: " << szTlsServerCertPath << std::endl;
        return NULL;
    }
    if(!Util_LoadCaPemFromFile(szTlsServerCertPrivateKeyPath, sTlsServerCertPrivateKey)) {
        std::cerr << "[Server] Failed to load server ca certificate private key from: " << szTlsServerCertPrivateKeyPath << std::endl;
        return NULL;
    }
    if(!Util_LoadCaPemFromFile(szTlsClientCertPath, sTlsClientCert)) {
        std::cerr << "[Server] Failed to load client ca certificate from: " << szTlsClientCertPath << std::endl;
        return NULL;
    }
    return leechgrpc_server_create_secure_internal(szAddress, dwPort, ctx, pfnReservedSubmitCommandCB, sTlsClientCert, sTlsServerCert, sTlsServerCertPrivateKey);
}

/*
* Wait for the gRPC server to shutdown.
* -- hGRPC: Handle to the gRPC server.
*/
LEECHGRPC_EXPORTED_FUNCTION
VOID leechgrpc_server_wait(_In_ LEECHGRPC_SERVER_HANDLE hGRPC)
{
    auto pServer = reinterpret_cast<std::unique_ptr<Server>*>(hGRPC);
    (*pServer)->Wait();
}

/*
* Shut down the gRPC server.
* -- hGRPC: Handle to the gRPC server.
*/
LEECHGRPC_EXPORTED_FUNCTION
VOID leechgrpc_server_shutdown(_In_ LEECHGRPC_SERVER_HANDLE hGRPC)
{
    auto pServer = reinterpret_cast<std::unique_ptr<Server>*>(hGRPC);
    (*pServer)->Shutdown();
    delete pServer;
}
