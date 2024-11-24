#pragma once

#include "cryptofw/Blob.hpp"
#include "cryptofw/ICsp.hpp"
#include "cryptofw/CadesType.hpp"
#include "cryptofw/XadesType.hpp"
#include "windows.h"
#include "wincrypt.h"



class VipNetCertificate;

class VipNetCsp : public ICsp {
private:
    std::vector<std::shared_ptr<VipNetCertificate>> certificates_;
    Blob SignCadesBes (PCCERT_CONTEXT cert, bool detached, const Blob& data) const;
public:
    VipNetCsp();

    std::vector<std::shared_ptr<ICertificate>> GetCertificates() override;

    Blob EncryptWithCertificate(const Blob& data, const VipNetCertificate& cert) const;

    Blob DecryptWithCertificate(const Blob& encrypted_data, const VipNetCertificate& cert) const;

    Blob SignCadesWithCertificate(const Blob& data, CadesType type, const VipNetCertificate& cert, bool detached) const;
    bool VerifyCadesWithCertificate(const Blob& signature, CadesType type, const VipNetCertificate& cert) const;

    Blob SignXadesWithCertificate(const Blob& data, XadesType type, const VipNetCertificate& cert) const;
    bool VerifyXadesWithCertificate(const Blob& signature, XadesType type, const VipNetCertificate& cert) const;
};