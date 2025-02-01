#include <Windows.h>
#include <stdio.h>
#include "../libleechgrpc/leechgrpc.h"

#pragma comment(lib, "libleechgrpc.lib")

VOID TestServerCB(_In_ PVOID ctx, _In_ PBYTE pbIn, _In_ SIZE_T cbIn, _Out_ PBYTE *ppbOut, _Out_ SIZE_T *pcbOut)
{
    printf("[Server] Received message: %s\n", pbIn);
    *pcbOut = strlen("MESSAGE FROM TEST SERVER!") + 1;
    *ppbOut = (PBYTE)LocalAlloc(LMEM_FIXED, *pcbOut);
    memcpy(*ppbOut, "MESSAGE FROM TEST SERVER!", *pcbOut);
}

int main_insecure()
{

    DWORD dwPORT = 28474;
    HANDLE hGRPC;

    hGRPC = leechgrpc_server_create_insecure("0.0.0.0", dwPORT, NULL, TestServerCB);
    if(!hGRPC) {
        printf("[Server] Error creating gRPC server.\n");
        return 1;
    }

    printf("[Server] server created!\n");

    printf("[Server] start wait.\n");
    leechgrpc_server_wait(hGRPC);

    printf("[Server] wait completed - shutting down!\n");
    leechgrpc_server_shutdown(hGRPC);
    return 0;
}

int main_secure_tls() {

    DWORD dwPORT = 28474;
    HANDLE hGRPC;

    hGRPC = leechgrpc_server_create_secure_p12("0.0.0.0", dwPORT, NULL, TestServerCB, "..\\..\\cert\\client-tls.cer", "..\\..\\cert\\server-tls.p12", "test");
    if(!hGRPC) {
        printf("[Server] Error creating gRPC server.\n");
        return 1;
    }

    printf("[Server] server created!\n");

    printf("[Server] start wait.\n");
    leechgrpc_server_wait(hGRPC);

    printf("[Server] wait completed - shutting down!\n");
    leechgrpc_server_shutdown(hGRPC);
    return 0;
}



int main()
{
    main_secure_tls();
}
