%module cryptofw
%{
#include "../include/cryptofw/Blob.hpp"
#include "../include/cryptofw/ICsp.hpp"
#include "../include/cryptofw/ICertificate.hpp"
#include "../include/cryptofw/utils.hpp"
#include "../include/cryptofw/CadesType.hpp"
#include "../include/cryptofw/CryptoProCertificate.hpp"
#include "../include/cryptofw/CryptoProCsp.hpp"
#include "../include/cryptofw/VipNetCertificate.hpp"
#include "../include/cryptofw/VipNetCsp.hpp"
#include "../include/cryptofw/XadesType.hpp"
%}
%include <std_string.i>
%include <std_vector.i>
%include <std_shared_ptr.i>
%include <exception.i>
%include <stdint.i>

%template(Blob) std::vector<uint8_t>;

%shared_ptr(ICertificate);
%shared_ptr(CryptoProCertificate);
%shared_ptr(VipNetCertificate);
%shared_ptr(ICsp);
%shared_ptr(CryptoProCsp);
%shared_ptr(VipNetCsp);
%template(CertificateVector) std::vector<std::shared_ptr<ICertificate>>;


// %typemap(out) std::shared_ptr<ICsp> {
//     if (!$1) {
//         $result = Py_None;
//         Py_INCREF(Py_None);
//     } else {
//         $result = SWIG_NewPointerObj(new std::shared_ptr<ICsp>($1), SWIGTYPE_p_ICsp, SWIG_POINTER_OWN);
//     }
// }

// %extend ICsp {
//     std::shared_ptr<ICertificate> get_certificate(size_t index) {
//         const auto& certificates = self->GetCertificates();
//         if (index >= certificates.size()) {
//             throw std::out_of_range("Invalid certificate index");
//         }
//         return certificates[index];
//     }
    
//     size_t get_certificate_count() {
//         return self->GetCertificates().size();
//     }
// }

%extend ICertificate {
    VipNetCertificate *asVipNetCertificate() {
        return dynamic_cast<VipNetCertificate *>(self);
    }
    CryptoProCertificate *asCryptoProCetificate() {
        return dynamic_cast<CryptoProCertificate *>(self);
    }
}

%include "../include/cryptofw/Blob.hpp"
%include "../include/cryptofw/utils.hpp"
%include "../include/cryptofw/ICsp.hpp"
%include "../include/cryptofw/ICertificate.hpp"
%include "../include/cryptofw/CadesType.hpp"
%include "../include/cryptofw/CryptoProCertificate.hpp"
%include "../include/cryptofw/CryptoProCsp.hpp"
%include "../include/cryptofw/VipNetCertificate.hpp"
%include "../include/cryptofw/VipNetCsp.hpp"
%include "../include/cryptofw/XadesType.hpp"
