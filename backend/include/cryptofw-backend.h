#ifdef __cplusplus
extern "C" {
#endif


	#include <stdint.h>
	#include <stdbool.h>


	typedef struct __Blob {
		uint8_t* data;
		size_t size;
	} _Blob;


	enum __Error {
		E_OK = 0,
		E_MSCAPI_CERT_STORE_OPEN_FAIL = 1,
		E_MSCAPI_INVALID_CERT_CONTEXT = 2,
		E_UNKNOWN = 3
	};
	typedef enum __Error _Error;

	const char* _GetErrorMessage(_Error error);


	// MS CryptoApi

	typedef	struct __MscapiCertificate _MscapiCertificate;

	typedef struct __MscapiCertificatesList {
		_MscapiCertificate** certificates;
		size_t count;
	} _MscapiCertificatesList;


	_Error _GetMscapiCspCertificates(const char* csp_name, _MscapiCertificatesList* out);
	_Error _DoesMscapiCertificateBelongToCsp(_MscapiCertificate* certificate, const char* csp_name, bool* result);
	_Error _GetMscapiCertificateSubject(_MscapiCertificate* certificate, char** out);

	const char* _MscapiGetHashOid(_MscapiCertificate* p_cert);

	_Error _MscapiEncryptData(_MscapiCertificate* cert, _Blob source_data, _Blob* out);
	_Error _MscapiDecryptData(_MscapiCertificate* cert, _Blob encrypted_data, _Blob* out);

	_Error _MscapiSignCadesBes(_MscapiCertificate* cert, bool detached, _Blob data, _Blob* out);
	_Error _MscapiVerifyDetachedSignVipnet(_Blob signature, _Blob message, bool* out);
	_Error _MscapiVerifyAttachedSignVipnet(_Blob signature, bool* out);


#ifdef __cplusplus
}
#endif
