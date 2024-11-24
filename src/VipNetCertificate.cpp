#include "cryptofw/VipNetCertificate.hpp"
#include "cryptofw/VipNetCsp.hpp"


VipNetCertificate::VipNetCertificate(const VipNetCsp& vip_net_csp, const std::string& subject_name, PCCERT_CONTEXT context) :
	vip_net_csp_(vip_net_csp), subject_name_(subject_name), context_(context) {
}

Blob VipNetCertificate::Encrypt(const Blob& data) const {
	return vip_net_csp_.EncryptWithCertificate(data, *this);
}

Blob VipNetCertificate::Decrypt(const Blob& encrypted_data) const {
	return vip_net_csp_.DecryptWithCertificate(encrypted_data, *this);
}

Blob VipNetCertificate::SignCades(const Blob& data, CadesType type) const {
	return vip_net_csp_.SignCadesWithCertificate(data, type, *this);
}

bool VipNetCertificate::VerifyCades(const Blob& signature, CadesType type) const {
	return vip_net_csp_.VerifyCadesWithCertificate(signature, type, *this);
}

Blob VipNetCertificate::SignXades(const Blob& data, XadesType type) const {
	return vip_net_csp_.SignXadesWithCertificate(data, type, *this);
}

bool VipNetCertificate::VerifyXades(const Blob& signature, XadesType type) const {
	return vip_net_csp_.VerifyXadesWithCertificate(signature, type, *this);
}

std::string VipNetCertificate::GetSubjectName() const {
	return subject_name_;
}