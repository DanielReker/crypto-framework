#pragma once

#include "cryptofw/Blob.hpp"
#include "cryptofw/ICsp.hpp"
#include "cryptofw/CadesType.hpp"
#include "cryptofw/XadesType.hpp"


class VipNetCertificate;

class VipNetCsp : public ICsp {
private:
    std::vector<std::shared_ptr<VipNetCertificate>> certificates_;

public:
    VipNetCsp();

    std::vector<std::shared_ptr<ICertificate>> GetCertificates() override;

    Blob EncryptWithCertificate(const Blob& data, const VipNetCertificate& cert) const;

    Blob DecryptWithCertificate(const Blob& encrypted_data, const VipNetCertificate& cert) const;

    Blob SignCadesWithCertificate(const Blob& data, CadesType type, const VipNetCertificate& cert) const;
    bool VerifyCadesWithCertificate(const Blob& signature, CadesType type, const VipNetCertificate& cert) const;

    Blob SignXadesWithCertificate(const Blob& data, XadesType type, const VipNetCertificate& cert) const;
    bool VerifyXadesWithCertificate(const Blob& signature, XadesType type, const VipNetCertificate& cert) const;
};