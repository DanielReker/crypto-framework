
#include "cryptofw/CryptoProCertificate.hpp"
#include "cryptofw/CryptoProCsp.hpp"


CryptoProCertificate::CryptoProCertificate(const CryptoProCsp& crypto_pro_csp, const std::string& subject_name, PCCERT_CONTEXT context) :
	crypto_pro_csp_(crypto_pro_csp), subject_name_(subject_name), context_(context) { }

Blob CryptoProCertificate::Encrypt(const Blob& data) const {
	return crypto_pro_csp_.EncryptWithCertificate(data, *this);
}

Blob CryptoProCertificate::Decrypt(const Blob& encrypted_data) const {
	return crypto_pro_csp_.DecryptWithCertificate(encrypted_data, *this);
}

Blob CryptoProCertificate::SignCades(const Blob& data, CadesType type) const {
	return crypto_pro_csp_.SignCadesWithCertificate(data, type, *this);
}

bool CryptoProCertificate::VerifyCades(const Blob& signature, CadesType type) const {
	return crypto_pro_csp_.VerifyCadesWithCertificate(signature, type, *this);
}

Blob CryptoProCertificate::SignXades(const Blob& data, XadesType type) const {
	return crypto_pro_csp_.SignXadesWithCertificate(data, type, *this);
}

bool CryptoProCertificate::VerifyXades(const Blob& signature, XadesType type) const {
	return crypto_pro_csp_.VerifyXadesWithCertificate(signature, type, *this);
}

std::string CryptoProCertificate::GetSubjectName() const {
	return subject_name_;
}