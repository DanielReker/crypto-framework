#pragma once

#include <windows.h>
#include <wincrypt.h>

#include "cryptofw/Blob.hpp"
#include "cryptofw/ICsp.hpp"
#include "cryptofw/CadesType.hpp"
#include "cryptofw/XadesType.hpp"


class VipNetCertificate;

class VipNetCsp : public ICsp {
private:
    std::vector<std::shared_ptr<VipNetCertificate>> certificates_;
    Blob SignCadesBes (PCCERT_CONTEXT cert, bool detached, const Blob& data) const;

    bool VerifyAttachedSignVipnet(const Blob& signature)const;
    bool VerifyDetachedSignVipnet(const Blob& signature, const Blob& message) const;

public:
    VipNetCsp();

    std::vector<std::shared_ptr<ICertificate>> GetCertificates() override;

    Blob EncryptWithCertificate(const Blob& data, const VipNetCertificate& cert) const;

    Blob DecryptWithCertificate(const Blob& encrypted_data, const VipNetCertificate& cert) const;

    Blob SignCadesWithCertificate(const Blob& data, CadesType type, const VipNetCertificate& cert, bool detached) const;

    bool VerifyCadesAttached(const Blob& signature, CadesType type) const override;
    bool VerifyCadesDetached(const Blob& signature, const Blob& source, CadesType type) const override;

    Blob SignXadesWithCertificate(const Blob& data, XadesType type, const VipNetCertificate& cert) const;
    bool VerifyXades(const Blob& signature, XadesType type) const override;
};