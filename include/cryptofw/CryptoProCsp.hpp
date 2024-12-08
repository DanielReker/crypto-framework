#pragma once

#include <windows.h>
#include <wincrypt.h>

#include "cryptofw/Blob.hpp"
#include "cryptofw/ICsp.hpp"
#include "cryptofw/CadesType.hpp"
#include "cryptofw/XadesType.hpp"

class CryptoProCertificate;

class CryptoProCsp : public ICsp {
private:
    std::vector<std::shared_ptr<CryptoProCertificate>> certificates_;
    Blob SignCadesBes(PCCERT_CONTEXT context, const Blob& data, bool detached) const;
    Blob SignCadesXLong1(PCCERT_CONTEXT context, const Blob& data, bool detached) const;

    bool VerifyCadesXLong1Detached(const Blob& signature, const Blob& message) const;
    bool VerifyCadesXLong1Attached(const Blob& signature) const;

    bool VerifyCadesBesDetached(const Blob& signature, const Blob& message) const;
    bool VerifyCadesBesAttached(const Blob& signature) const;

public:
    CryptoProCsp();

	std::vector<std::shared_ptr<ICertificate>> GetCertificates() override;

    Blob EncryptWithCertificate(const Blob& data, const CryptoProCertificate& cert) const;

    Blob DecryptWithCertificate(const Blob& encrypted_data, const CryptoProCertificate& cert) const;

    Blob SignCadesWithCertificate(const Blob& data, CadesType type, const CryptoProCertificate& cert, bool detached) const;

    bool VerifyCadesAttached(const Blob& signature, CadesType type) const override;
    bool VerifyCadesDetached(const Blob& signature, const Blob& source, CadesType type) const override;

    Blob SignXadesWithCertificate(const Blob& data, XadesType type, const CryptoProCertificate& cert) const;
    bool VerifyXades(const Blob& signature, XadesType type) const override;
};