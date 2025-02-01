#ifndef __UTIL_H__
#define __UTIL_H__

#include "leechgrpc.h"
#include <iostream>
#include <memory>
#include <string>

_Success_(return)
bool Util_LoadPemFromPkcs12(
    _In_ const std::string &pkcs12Path,
    _In_ const std::string &password,
    _Out_ std::string &outPrivateKeyPem,
    _Out_ std::string &outCertPem
);

_Success_(return)
bool Util_LoadCaPemFromFile(
    _In_ const std::string &filePath,
    _Out_ std::string &outCertPem
);

#endif /* __UTIL_H__ */
