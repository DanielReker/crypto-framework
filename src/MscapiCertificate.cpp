#include "MscapiCertificate.hpp"
#include "MscapiCsp.hpp"


MscapiCertificate::MscapiCertificate(const MscapiCsp& mscapi_csp, const std::string& subject_name, _MscapiCertificate* context) :
	mscapi_csp_(mscapi_csp), subject_name_(subject_name), context_(context) {
}

Blob MscapiCertificate::Encrypt(const Blob& data) const {
	return mscapi_csp_.EncryptWithCertificate(data, *this);
}

Blob MscapiCertificate::Decrypt(const Blob& encrypted_data) const {
	return mscapi_csp_.DecryptWithCertificate(encrypted_data, *this);
}

Blob MscapiCertificate::SignCades(const Blob& data, CadesType type, bool detached, const std::wstring& tsp_server_url) const {
	return mscapi_csp_.SignCadesWithCertificate(data, type, *this, detached, tsp_server_url);
}

std::string MscapiCertificate::GetSubjectName() const {
	return subject_name_;
}

_MscapiCertificate* MscapiCertificate::GetCertContext() const {
	return context_;
}