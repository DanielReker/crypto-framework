#pragma once

#include "cryptofw/Blob.hpp"
#include "cryptofw/ICsp.hpp"
#include "cryptofw/CadesType.hpp"
#include "cryptofw/XadesType.hpp"
#include "Blob.hpp"
#include <windows.h>
#include <wincrypt.h>


class CryptoProCertificate;

class CryptoProCsp : public ICsp {
private:
    std::vector<std::shared_ptr<CryptoProCertificate>> certificates_;
    Blob SignCadesBes(PCCERT_CONTEXT context, const Blob& data, bool detached) const;
    Blob SignCadesXLong1(PCCERT_CONTEXT context, const Blob& data, bool detached) const;
public:
    CryptoProCsp();

	std::vector<std::shared_ptr<ICertificate>> GetCertificates() override;

    Blob EncryptWithCertificate(const Blob& data, const CryptoProCertificate& cert) const;

    Blob DecryptWithCertificate(const Blob& encrypted_data, const CryptoProCertificate& cert) const;

    Blob SignCadesWithCertificate(const Blob& data, CadesType type, const CryptoProCertificate& cert, bool detached) const;
    bool VerifyCadesWithCertificate(const Blob& signature, CadesType type, const CryptoProCertificate& cert) const;

    Blob SignXadesWithCertificate(const Blob& data, XadesType type, const CryptoProCertificate& cert) const;
    bool VerifyXadesWithCertificate(const Blob& signature, XadesType type, const CryptoProCertificate& cert) const;
};