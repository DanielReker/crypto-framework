#pragma once

#include <string>

#include "cryptofw/Blob.hpp"

#include "MscapiCsp.hpp"
#include "MscapiCertificate.hpp"


class MscapiCertificate;

class CryptoProCsp : public MscapiCsp {
private:
    std::wstring tsp_server_url_;

public:
    CryptoProCsp(const std::wstring& tsp_server_url);

    Blob SignCadesWithCertificate(const Blob& data, CadesType type, const MscapiCertificate& cert, bool detached) const override;

    bool VerifyCadesAttached(const Blob& signature, CadesType type) const override;
    bool VerifyCadesDetached(const Blob& signature, const Blob& source, CadesType type) const override;
};