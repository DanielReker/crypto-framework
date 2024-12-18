#pragma once

#include <string>

#include "cryptofw/Blob.hpp"

#include "MscapiCsp.hpp"
#include "MscapiCertificate.hpp"


class CryptoProCsp : public MscapiCsp {
private:
    static std::shared_ptr<ICsp> instance_;

    static const std::string mscapi_name_;


public:
    static std::shared_ptr<ICsp> GetInstance();

    CryptoProCsp();

    Blob SignCadesWithCertificate(const Blob& data, CadesType type, const MscapiCertificate& cert, bool detached, const std::wstring& tsp_server_url = L"") const override;

    bool VerifyCadesAttached(const Blob& signature, CadesType type) const override;
    bool VerifyCadesDetached(const Blob& signature, const Blob& source, CadesType type) const override;
};