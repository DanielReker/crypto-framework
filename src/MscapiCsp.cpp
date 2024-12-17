#include <iostream>

#include "MscapiCsp.hpp"
#include "MscapiCertificate.hpp"

MscapiCsp::MscapiCsp(const std::string& mscapi_name) : mscapi_name_(mscapi_name) {
    _MscapiCertificatesList certs;
    _Error e = _GetMscapiCspCertificates(mscapi_name.c_str(), &certs);
    if (e != E_OK) throw std::runtime_error(_GetErrorMessage(e));

    for (size_t i = 0; i < certs.count; i++) {
        _MscapiCertificate* cert = certs.certificates[i];

        char* subject_name_cstr;
        e = _GetMscapiCertificateSubject(cert, &subject_name_cstr);
        if (e != E_OK) throw std::runtime_error(_GetErrorMessage(e));

        certificates_.push_back(std::make_shared<MscapiCertificate>(*this, subject_name_cstr, cert));

        delete[] subject_name_cstr;
    }

    delete[] certs.certificates;
}

std::vector<std::shared_ptr<ICertificate>> MscapiCsp::GetCertificates() {
	return { certificates_.begin(), certificates_.end() };
}


Blob MscapiCsp::EncryptWithCertificate(const Blob& data, const MscapiCertificate& cert) const {
    _Blob _data;
    _data.size = data.size();
    _data.data = (uint8_t*)data.data();

    _Blob encrypted;
    _MscapiEncryptData(cert.GetCertContext(), _data, &encrypted);

    Blob result(encrypted.data, encrypted.data + encrypted.size);
    delete[] encrypted.data;
    return result;
}

Blob MscapiCsp::DecryptWithCertificate(const Blob& encrypted_data, const MscapiCertificate& cert) const {
    _Blob _encrypted_data;
    _encrypted_data.size = encrypted_data.size();
    _encrypted_data.data = (uint8_t*)encrypted_data.data();

    _Blob decrypted;
    _MscapiDecryptData(cert.GetCertContext(), _encrypted_data, &decrypted);

    Blob result(decrypted.data, decrypted.data + decrypted.size);
    delete[] decrypted.data;
    return result;
}

Blob MscapiCsp::SignCadesWithCertificate(const Blob& data, CadesType type, const MscapiCertificate& cert, bool detached) const {
    if (type != CadesType::kBes)
        throw std::logic_error("MS CryptoApi only supports CAdES BES signatures");

    _Blob _data;
    _data.size = data.size();
    _data.data = (uint8_t*)data.data();

    _Blob signature;
    _MscapiSignCadesBes(cert.GetCertContext(), detached, _data, &signature);

    Blob result(signature.data, signature.data + signature.size);
    delete[] signature.data;
    return result;
}

bool MscapiCsp::VerifyCadesAttached(const Blob& signature, CadesType type) const {
    if (type != CadesType::kBes)
        throw std::logic_error("MS CryptoApi only supports CAdES BES signatures");

    _Blob _signature;
    _signature.size = signature.size();
    _signature.data = (uint8_t*)signature.data();

    bool verification;
    _MscapiVerifyAttachedSign(_signature, &verification);

    return verification;
}

bool MscapiCsp::VerifyCadesDetached(const Blob& signature, const Blob& source, CadesType type) const {
    if (type != CadesType::kBes)
        throw std::logic_error("MS CryptoApi only supports CAdES BES signatures");

    _Blob _signature;
    _signature.size = signature.size();
    _signature.data = (uint8_t*)signature.data();

    _Blob _source;
    _source.size = source.size();
    _source.data = (uint8_t*)source.data();

    bool verification;
    _MscapiVerifyDetachedSign(_signature, _source, &verification);

    return verification;
}
