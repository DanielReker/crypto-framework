#pragma once

#include <vector>
#include <memory>

#include "cryptofw/Blob.hpp"
#include "cryptofw/CadesType.hpp"
#include "cryptofw/XadesType.hpp"

class ICertificate;

class ICsp {
public:
    virtual ~ICsp() = default;

    virtual std::vector<std::shared_ptr<ICertificate>> GetCertificates() = 0;

    virtual bool VerifyCadesAttached(const Blob& signature, CadesType type) const = 0;
    virtual bool VerifyCadesDetached(const Blob& signature, const Blob& source, CadesType type) const = 0;
    virtual bool VerifyXades(const Blob& signature, XadesType type) const = 0;
};