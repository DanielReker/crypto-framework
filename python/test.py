from swig_generated import cryptofw

csp = cryptofw.CryptoProCsp()
certs = csp.GetCertificates()
cert = csp.get_certificate(0)
for i, k in enumerate(certs):
    print("Cert " +str(i)+": ", k.GetSubjectName())

b = cryptofw.Blob([1,2,3])
b.push_back(2)

print("Data (hex): ", list(b))
print("Cert obj: ", cert)
signed = cert.SignCades(b, 0, False)
print("Signed message (hex): ", signed)
