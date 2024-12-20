#include "CryptoProCsp.hpp"


std::shared_ptr<ICsp> CryptoProCsp::instance_;

const std::string CryptoProCsp::mscapi_name_ = "Crypto-Pro";


std::shared_ptr<ICsp> CryptoProCsp::GetInstance() {
    if (!CryptoProCsp::instance_) {
        if (MscapiCsp::IsMscapiCspAvailable(CryptoProCsp::mscapi_name_))
            CryptoProCsp::instance_ = std::make_shared<CryptoProCsp>();
        else
            CryptoProCsp::instance_ = std::shared_ptr<CryptoProCsp>();
    }

    return CryptoProCsp::instance_;
}

CryptoProCsp::CryptoProCsp() : MscapiCsp(CryptoProCsp::mscapi_name_) { }

Blob CryptoProCsp::SignCadesWithCertificate(const Blob& data, CadesType type, const MscapiCertificate& cert, bool detached, const std::wstring& tsp_server_url) const {
	if (type == CadesType::kBes)
		return MscapiCsp::SignCadesWithCertificate(data, type, cert, detached, tsp_server_url);

    _Blob _data;
    _data.size = data.size();
    _data.data = (uint8_t*)data.data();

    _Blob signature;
    _CryptoProSignCadesXl(cert.GetCertContext(), _data, detached, tsp_server_url.c_str(), &signature);

    Blob result(signature.data, signature.data + signature.size);
    delete[] signature.data;
    return result;
}

bool CryptoProCsp::VerifyCadesAttached(const Blob& signature, CadesType type) const {
    if (type == CadesType::kBes)
        return MscapiCsp::VerifyCadesAttached(signature, type);

    _Blob _signature;
    _signature.size = signature.size();
    _signature.data = (uint8_t*)signature.data();

    bool verification;
    _CryptoProVerifyCadesXlAttached(_signature, &verification);

    return verification;
}

bool CryptoProCsp::VerifyCadesDetached(const Blob& signature, const Blob& source, CadesType type) const {
    if (type == CadesType::kBes)
        return MscapiCsp::VerifyCadesDetached(signature, source, type);

    _Blob _signature;
    _signature.size = signature.size();
    _signature.data = (uint8_t*)signature.data();

    _Blob _source;
    _source.size = source.size();
    _source.data = (uint8_t*)source.data();

    bool verification;
    _CryptoProVerifyCadesXlDetached(_signature, _source, &verification);

	return verification;
}


