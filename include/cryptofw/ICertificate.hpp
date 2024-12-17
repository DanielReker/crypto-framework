#pragma once

#include <string>
#include "cryptofw/Blob.hpp"
#include "cryptofw/CadesType.hpp"

class ICertificate {
public:
    virtual ~ICertificate() = default;

    virtual Blob Encrypt(const Blob& data) const = 0;
    virtual Blob Decrypt(const Blob& encrypted_data) const = 0;
    virtual Blob SignCades(const Blob& data, CadesType type, bool detached, const std::wstring& tsp_server_url = L"") const = 0;

    virtual std::string GetSubjectName() const = 0;
};