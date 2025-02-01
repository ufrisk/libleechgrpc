#include <grpcpp/grpcpp.h>
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

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using leechrpc::LeechRpc;
using leechrpc::SubmitCommandRequest;
using leechrpc::SubmitCommandResponse;

// A client class that connects to the LeechRpc server
class LeechRpcClient {
public:
    // Constructor: create a new Stub connected to the provided channel
    explicit LeechRpcClient(std::shared_ptr<Channel> channel) : stub_(LeechRpc::NewStub(channel)) {}

    // Calls the ReservedSubmitCommand RPC
    std::string ReservedSubmitCommand(const std::string& message)
    {
        // Container for the request and response
        SubmitCommandRequest request;
        SubmitCommandResponse response;

        // Fill the request with the client data
        request.set_pbin(message);

        // Context for the client (can set metadata, etc.)
        ClientContext context;

        // Set a deadline for the RPC
        auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(LEECHGRPC_CLIENT_TIMEOUT_MS);
        context.set_deadline(deadline);

        // The actual RPC
        Status status = stub_->ReservedSubmitCommand(&context, request, &response);

        // Act upon its status
        if (!status.ok()) {
            //std::cerr << "[Client] RPC failed: " << status.error_message() << std::endl;
            return "";
        }

        // Return the pbOut bytes as a std::string
        return response.pbout();
    }

private:
    // Stub used for making RPC calls
    std::unique_ptr<LeechRpc::Stub> stub_;
};

/*
* Submit a command to the gRPC server.
* -- hGRPC: Handle to the gRPC client.
* -- pbIn: Pointer to the input buffer.
* -- cbIn: Size of the input buffer.
* -- ppbOut: Pointer to receive the output buffer. The caller is responsible for freeing this buffer with LocalFree/free.
* -- pcbOut: Pointer to receive the size of the output buffer.
* -- return: TRUE if the command was successfully submitted; otherwise, FALSE.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return)
BOOL leechgrpc_client_submit_command(
    _In_ LEECHGRPC_CLIENT_HANDLE hGRPC,
    _In_ PBYTE pbIn,
    _In_ SIZE_T cbIn,
    _Out_ PBYTE *ppbOut,
    _Out_ SIZE_T *pcbOut
)
{
    try {
        // Cast the handle to a client
        LeechRpcClient *client = static_cast<LeechRpcClient *>(hGRPC);
        // Call the ReservedSubmitCommand RPC
        std::string message(reinterpret_cast<char *>(pbIn), cbIn);
        std::string reply = client->ReservedSubmitCommand(message);
        // Allocate memory for the response
        *ppbOut = reinterpret_cast<PBYTE>(LocalAlloc(LMEM_ZEROINIT, reply.size()));
        if(*ppbOut == NULL) {
            std::cerr << "[Client] Error allocating memory for response" << std::endl;
            return FALSE;
        }
        if(reply.size() == 0) {
            std::cerr << "[Client] Error submitting command" << std::endl;
            return FALSE;
        }
        // Copy the response to the output buffer
        memcpy(*ppbOut, reply.c_str(), reply.size());
        *pcbOut = reply.size();
        return TRUE;
    } catch(const std::exception &e) {
        std::cerr << "[Client] Error submitting command: " << e.what() << std::endl;
        return FALSE;
    }
}

/*
* Create a gRPC client connection to the gRPC server.
* -- pszAddress: Address of the gRPC server.
* -- dwPort: Port of the gRPC server.
* -- return: Handle to the gRPC client connection, or NULL on failure.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
LEECHGRPC_CLIENT_HANDLE leechgrpc_client_create_insecure(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort
) {
    try {
        std::string address = std::string(szAddress) + ":" + std::to_string(dwPort);
        grpc::ChannelArguments channel_args;
        channel_args.SetMaxReceiveMessageSize(LEECHGRPC_MESSAGE_SIZE_MAX);
        channel_args.SetMaxSendMessageSize(LEECHGRPC_MESSAGE_SIZE_MAX);
        channel_args.SetSslTargetNameOverride("*");
        return reinterpret_cast<LEECHGRPC_CLIENT_HANDLE>(new LeechRpcClient(grpc::CreateCustomChannel(address, grpc::InsecureChannelCredentials(), channel_args)));
    } catch(const std::exception &e) {
        std::cerr << "[Client] Error creating channel: " << e.what() << std::endl;
        return NULL;
    }
}

_Success_(return != NULL)
LEECHGRPC_CLIENT_HANDLE leechgrpc_client_create_secure_internal(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ LPCSTR szTlsServerHostnameOverride,
    _In_ const std::string sTlsServerCert,
    _In_ const std::string sTlsClientCert,
    _In_ const std::string sTlsClientCertPrivateKey
) {
    try {
        if(sTlsClientCert.length() < 8 || sTlsClientCertPrivateKey.length() < 8) {
            std::cerr << "[Client] Invalid TLS certificate or key provided." << std::endl;
            return NULL;
        }
        // address/port -> string:
        CHAR szAddressAndPort[MAX_PATH] = { 0 };
        _snprintf_s(szAddressAndPort, MAX_PATH, _TRUNCATE, "%s:%u", szAddress, dwPort);
        const std::string server_address(szAddressAndPort);
        // mTLS server cert & client cert/key:
        grpc::SslCredentialsOptions sslOpts;
        if(sTlsServerCert.length() > 8) {
            sslOpts.pem_root_certs = sTlsServerCert;
        }
        sslOpts.pem_private_key = sTlsClientCertPrivateKey;
        sslOpts.pem_cert_chain = sTlsClientCert;
        // build and configure server:
        grpc::ChannelArguments channelArgs;
        channelArgs.SetMaxReceiveMessageSize(LEECHGRPC_MESSAGE_SIZE_MAX);
        channelArgs.SetMaxSendMessageSize(LEECHGRPC_MESSAGE_SIZE_MAX);
        if(szTlsServerHostnameOverride) {
            channelArgs.SetSslTargetNameOverride(szTlsServerHostnameOverride);
        }
        auto creds = grpc::SslCredentials(sslOpts);
        auto channel = grpc::CreateCustomChannel(server_address, creds, channelArgs);
        if(!channel) {
            std::cerr << "[Client] Error creating secure channel to: " << server_address << std::endl;
            return NULL;
        }
        // create and return a new LeechRpcClient object, cast to LEECHGRPC_CLIENT_HANDLE:
        // caller is responsible for deleting this pointer.
        return reinterpret_cast<LEECHGRPC_CLIENT_HANDLE>(new LeechRpcClient(channel));
    } catch(const std::exception &e) {
        std::cerr << "[Client] Exception in secure client creation: " << e.what() << std::endl;
        return NULL;
    } catch(...) {
        std::cerr << "[Client] Unknown error in secure client creation." << std::endl;
        return NULL;
    }
}

/*
* Create a gRPC client connection to the gRPC server with mTLS.
* -- pszAddress: Address of the gRPC server.
* -- dwPort: Port of the gRPC server.
* -- szTlsServerHostnameOverride: Optional hostname to verify against the server certificate (if different from address).
* -- szTlsServerCertPath: Server CA certificate to trust for mTLS connections.
* -- szTlsClientP12Path: Path to the client's TLS certificate (incl. chain) & private key (.p12 / .pfx).
* -- szTlsClientP12Password: Password for the client's TLS certificate & private key (.p12 / .pfx).
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
LEECHGRPC_CLIENT_HANDLE leechgrpc_client_create_secure_p12(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ LPCSTR szTlsServerHostnameOverride,
    _In_opt_ LPCSTR szTlsServerCertPath,
    _In_ LPCSTR szTlsClientP12Path,
    _In_ LPCSTR szTlsClientP12Password
) {
    std::string sTlsServerCert("");
    std::string sTlsClientCert;
    std::string sTlsClientCertPrivateKey;
    if(szTlsServerCertPath) {
        if(!Util_LoadCaPemFromFile(szTlsServerCertPath, sTlsServerCert)) {
            std::cerr << "[Client] Failed to load root CA from file: " << szTlsServerCertPath << std::endl;
            return NULL;
        }
    }
    if(!Util_LoadPemFromPkcs12(szTlsClientP12Path, szTlsClientP12Password, sTlsClientCertPrivateKey, sTlsClientCert)) {
        std::cerr << "[Client] Failed to load client cert/key from: " << szTlsClientP12Path << std::endl;
        return NULL;
    }
    return leechgrpc_client_create_secure_internal(szAddress, dwPort, szTlsServerHostnameOverride, sTlsServerCert, sTlsClientCert, sTlsClientCertPrivateKey);
}

/*
* Create a gRPC client connection to the gRPC server with mTLS.
* -- pszAddress: Address of the gRPC server.
* -- dwPort: Port of the gRPC server.
* -- szTlsServerHostnameOverride: Optional hostname to verify against the server certificate (if different from address).
* -- szTlsServerCert: Server CA certificate to trust for mTLS connections.
* -- szTlsClientCert: Cerver TLS certificate.
* -- szTlsClientCertPrivateKey: Client TLS certificate private key.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
LEECHGRPC_CLIENT_HANDLE leechgrpc_client_create_secure_pemraw(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ LPCSTR szTlsServerHostnameOverride,
    _In_opt_ LPCSTR szTlsServerCert,
    _In_ LPCSTR szTlsClientCert,
    _In_ LPCSTR szTlsClientCertPrivateKey
) {
    const std::string sTlsServerCertNull("");
    const std::string sTlsServerCert(szTlsServerCert);
    const std::string sTlsClientCert(szTlsClientCert);
    const std::string sTlsClientCertPrivateKey(szTlsClientCertPrivateKey);
    return leechgrpc_client_create_secure_internal(szAddress, dwPort, szTlsServerHostnameOverride, (szTlsServerCert ? sTlsServerCert : sTlsServerCertNull), sTlsClientCert, sTlsClientCertPrivateKey);
}

/*
* Create a gRPC client connection to the gRPC server with mTLS.
* -- pszAddress: Address of the gRPC server.
* -- dwPort: Port of the gRPC server.
* -- szTlsServerHostnameOverride: Optional hostname to verify against the server certificate (if different from address).
* -- szTlsServerCertPath: Server CA certificate to trust for mTLS connections.
* -- szTlsClientCertPath: Cerver TLS certificate.
* -- szTlsClientCertPrivateKeyPath: Client TLS certificate private key.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
LEECHGRPC_CLIENT_HANDLE leechgrpc_client_create_secure_pemfile(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ LPCSTR szTlsServerHostnameOverride,
    _In_opt_ LPCSTR szTlsServerCertPath,
    _In_ LPCSTR szTlsClientCertPath,
    _In_ LPCSTR szTlsClientCertPrivateKeyPath
) {
    std::string sTlsServerCert("");
    std::string sTlsClientCert;
    std::string sTlsClientCertPrivateKey;
    if(szTlsServerCertPath) {
        if(!Util_LoadCaPemFromFile(szTlsServerCertPath, sTlsServerCert)) {
            std::cerr << "[Client] Failed to load server ca certificate from file: " << szTlsServerCertPath << std::endl;
            return NULL;
        }
    }
    if(!Util_LoadCaPemFromFile(szTlsClientCertPath, sTlsClientCert)) {
        std::cerr << "[Client] Failed to load client certificate from file: " << szTlsClientCertPath << std::endl;
        return NULL;
    }
    if(!Util_LoadCaPemFromFile(szTlsClientCertPrivateKeyPath, sTlsClientCertPrivateKey)) {
        std::cerr << "[Client] Failed to load client certificate private key from file: " << szTlsClientCertPrivateKeyPath << std::endl;
        return NULL;
    }
    return leechgrpc_client_create_secure_internal(szAddress, dwPort, szTlsServerHostnameOverride, sTlsServerCert, sTlsClientCert, sTlsClientCertPrivateKey);
}

/*
* Free the gRPC client connection.
* -- hGRPC: Handle to the gRPC client.
*/
LEECHGRPC_EXPORTED_FUNCTION
VOID leechgrpc_client_free(_In_ LEECHGRPC_CLIENT_HANDLE hGRPC)
{
    try {
        delete static_cast<LeechRpcClient*>(hGRPC);
    } catch(const std::exception &e) {
        std::cerr << "[Client] Error free client: " << e.what() << std::endl;
    }
}
