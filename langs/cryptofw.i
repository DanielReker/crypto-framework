%module cryptofw
%{
#include "../include/cryptofw/Blob.hpp"
#include "../include/cryptofw/ICsp.hpp"
#include "../include/cryptofw/ICertificate.hpp"
#include "../include/cryptofw/utils.hpp"
#include "../include/cryptofw/CadesType.hpp"
%}
%include <std_string.i>
%include <std_vector.i>
%include <std_shared_ptr.i>
%include <exception.i>
%include <stdint.i>

%template(Blob) std::vector<uint8_t>;

%shared_ptr(ICertificate);
%shared_ptr(MscapiCertificate);
%shared_ptr(ICsp);
%shared_ptr(CryptoProCsp);
%shared_ptr(MscapiCsp);
%template(CertificateVector) std::vector<std::shared_ptr<ICertificate>>;

%include "../include/cryptofw/Blob.hpp"
%include "../include/cryptofw/utils.hpp"
%include "../include/cryptofw/ICsp.hpp"
%include "../include/cryptofw/ICertificate.hpp"
%include "../include/cryptofw/CadesType.hpp"
