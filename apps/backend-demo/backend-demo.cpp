#include <iostream>
#include <iomanip>

#include "cryptofw-backend.h"


std::ostream& operator<<(std::ostream& out, _Blob blob) {
	out << "Size: " << std::dec << blob.size << ", data: ";
	for (size_t i = 0; i < blob.size; i++) {
		out << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(blob.data[i]) << ' ';
	}
	out << '\n';
	return out;
}

int main() {
	uint8_t _data[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	_Blob data;
	data.size = 16;
	data.data = _data;

	std::cout << "Data | " << data;

	std::string csp_name = "Crypto-Pro";

	_MscapiCertificatesList certs;
	_Error e = _GetMscapiCspCertificates(csp_name.c_str(), &certs);
	std::cout << _GetErrorMessage(e) << '\n';
	std::cout << certs.count << '\n';

	for (size_t i = 0; i < certs.count; i++) {
		_MscapiCertificate* cert = certs.certificates[i];

		char* subject_name_cstr;
		e = _GetMscapiCertificateSubject(cert, &subject_name_cstr);
		std::cout << _GetErrorMessage(e) << '\n';
		std::cout << subject_name_cstr << '\n';
		delete[] subject_name_cstr;
	}

	_MscapiCertificate* cert = certs.certificates[0];

	_Blob encrypted;
	_MscapiEncryptData(cert, data, &encrypted);
	std::cout << "Encrypted | " << encrypted;

	_Blob decrypted;
	_MscapiDecryptData(cert, encrypted, &decrypted);
	std::cout << "Decrypted | " << decrypted;


	_Blob detached;
	_MscapiSignCadesBes(cert, true, data, &detached);
	std::cout << "Detached | " << detached;

	_Blob attached;
	_MscapiSignCadesBes(cert, false, data, &attached);
	std::cout << "Attached | " << attached;

	bool detached_verified;
	_MscapiVerifyDetachedSign(detached, data, &detached_verified);
	std::cout << "Detached verified | " << detached_verified << '\n';

	bool attached_verified;
	_MscapiVerifyAttachedSign(attached, &attached_verified);
	std::cout << "Attached verified | " << attached_verified << '\n';


	delete[] encrypted.data;
	delete[] decrypted.data;

	delete[] detached.data;
	delete[] attached.data;

	delete[] certs.certificates;
}
