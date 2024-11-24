#pragma once

#include <string>
#include "cryptofw/Blob.hpp"
#include "cryptofw/CadesType.hpp"
#include "cryptofw/XadesType.hpp"

class ICertificate {
public:
    virtual ~ICertificate() = default;

    virtual Blob Encrypt(const Blob& data) const = 0;

    virtual Blob Decrypt(const Blob& encrypted_data) const = 0;

    virtual Blob SignCades(const Blob& data, CadesType type) const = 0;
    virtual bool VerifyCades(const Blob& signature, CadesType type) const = 0;

    virtual Blob SignXades(const Blob& data, XadesType type) const = 0;
    virtual bool VerifyXades(const Blob& signature, XadesType type) const = 0;

    virtual std::string GetSubjectName() const = 0;
};