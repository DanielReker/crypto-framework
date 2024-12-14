from swig_generated import cryptofw

csp = cryptofw.GetVipNetCsp()
certs = csp.GetCertificates()
cert = certs[0]
for i, k in enumerate(certs):
    print("Cert " +str(i)+": ", k.GetSubjectName())

b = cryptofw.Blob([1,2,3])
b.push_back(2)

print("Data (hex): ", list(b))
print("Cert obj: ", cert)
signed = cert.SignCades(b, cryptofw.CadesType_kBes, False)
# print("Signed message (hex): ", signed)
print("Signed message size: ", len(signed))

verified = csp.VerifyCadesAttached(signed, 0)
print(verified)

encrypted = cert.Encrypt(b)
decrypted = cert.Decrypt(encrypted)
print("Encrypted data size:", len(encrypted))
print("Decrypted data:", decrypted)
encrypted = csp.EncryptWithCertificate(b, cert.asVipNetCertificate())
decrypted = csp.DecryptWithCertificate(encrypted, cert.asVipNetCertificate())
print("Encrypted data size:", len(encrypted))
print("Decrypted data:", decrypted)
cryptofw.SaveDataToFile(decrypted, "ababbbb")