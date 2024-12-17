#include "MscapiCertificate.hpp"
#include "MscapiCsp.hpp"


MscapiCertificate::MscapiCertificate(const MscapiCsp& vip_net_csp, const std::string& subject_name, _MscapiCertificate* context) :
	vip_net_csp_(vip_net_csp), subject_name_(subject_name), context_(context) {
}

Blob MscapiCertificate::Encrypt(const Blob& data) const {
	return vip_net_csp_.EncryptWithCertificate(data, *this);
}

Blob MscapiCertificate::Decrypt(const Blob& encrypted_data) const {
	return vip_net_csp_.DecryptWithCertificate(encrypted_data, *this);
}

Blob MscapiCertificate::SignCades(const Blob& data, CadesType type, bool detached) const {
	return vip_net_csp_.SignCadesWithCertificate(data, type, *this, detached);
}

std::string MscapiCertificate::GetSubjectName() const {
	return subject_name_;
}

_MscapiCertificate* MscapiCertificate::GetCertContext() const {
	return context_;
}