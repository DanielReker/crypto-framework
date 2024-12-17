#pragma once

#include <string>

#include "cryptofw/Blob.hpp"
#include "cryptofw/ICsp.hpp"
#include "cryptofw/CadesType.hpp"

#include "cryptofw-backend.h"


class MscapiCertificate;

class MscapiCsp : public ICsp {
private:
    std::string mscapi_name_;
    std::vector<std::shared_ptr<MscapiCertificate>> certificates_;

public:
    MscapiCsp(const std::string& mscapi_name);

    std::vector<std::shared_ptr<ICertificate>> GetCertificates() override;

    Blob EncryptWithCertificate(const Blob& data, const MscapiCertificate& cert) const;

    Blob DecryptWithCertificate(const Blob& encrypted_data, const MscapiCertificate& cert) const;

    virtual Blob SignCadesWithCertificate(const Blob& data, CadesType type, const MscapiCertificate& cert, bool detached) const;

    bool VerifyCadesAttached(const Blob& signature, CadesType type) const override;
    bool VerifyCadesDetached(const Blob& signature, const Blob& source, CadesType type) const override;
};