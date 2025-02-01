#include <Windows.h>
#include <stdio.h>
#include "../libleechgrpc/leechgrpc.h"

#pragma comment(lib, "libleechgrpc.lib")

int main_insecure()
{
    LPCSTR szHOST = "localhost";
    DWORD dwPORT = 28474;
    HANDLE hGRPC;
    PBYTE pbIn = NULL, pbOut = NULL;
    SIZE_T cbIn = 0, cbOut = 0;
    BOOL fResult;

    hGRPC = leechgrpc_client_create_insecure(szHOST, dwPORT);

    if(hGRPC == NULL) {
        printf("[Client] Error creating gRPC client.\n");
        return 1;
    }

    pbIn = (PBYTE)"MESSAGE FROM TEST CLIENT!";
    cbIn = strlen((char *)pbIn);

    fResult = leechgrpc_client_submit_command(hGRPC, pbIn, cbIn, &pbOut, &cbOut);

    if(!fResult) {
        printf("[Client] Error submitting command.\n");
        leechgrpc_client_free(hGRPC);
        return 1;
    }

    printf("[Client] Server responded with: %s\n", pbOut);

    leechgrpc_client_free(hGRPC);

    return 0;
}

int main_secure_tls()
{
    LPCSTR szHOST = "127.0.0.1";
    DWORD dwPORT = 28474;
    HANDLE hGRPC;
    PBYTE pbIn = NULL, pbOut = NULL;
    SIZE_T cbIn = 0, cbOut = 0;
    BOOL fResult;

    hGRPC = leechgrpc_client_create_secure_p12(szHOST, dwPORT, "localhost", "..\\..\\cert\\server-tls.cer", "..\\..\\cert\\client-tls.p12", "test");

    if(hGRPC == NULL) {
        printf("[Client] Error creating gRPC client.\n");
        return 1;
    }

    pbIn = (PBYTE)"MESSAGE FROM TEST CLIENT!";
    cbIn = strlen((char *)pbIn);

    fResult = leechgrpc_client_submit_command(hGRPC, pbIn, cbIn, &pbOut, &cbOut);

    if(!fResult) {
        printf("[Client] Error submitting command.\n");
        leechgrpc_client_free(hGRPC);
        return 1;
    }

    printf("[Client] Server responded with: %s\n", pbOut);

    leechgrpc_client_free(hGRPC);

    return 0;
}

int main()
{
    //main_insecure();
    main_secure_tls();
}
