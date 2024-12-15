from swig_generated import cryptofw

csp = cryptofw.Utils.GetVipNetCsp()
certs = csp.GetCertificates()
cert = certs[0]
for i, k in enumerate(certs):
    print(f"Cert {i}: {k.GetSubjectName()}")

data = [1,2,3]
data.append(1)

print("Data (hex): ", data)
print("Cert obj: ", cert)
signed = cert.SignCades(data, cryptofw.CadesType_kBes, False)
# print("Signed message (hex): ", signed)
print("Signed message size: ", len(signed))

verified = csp.VerifyCadesAttached(signed, 0)
print(verified)

encrypted = cert.Encrypt(data)
decrypted = cert.Decrypt(encrypted)
print("Encrypted data size:", len(encrypted))
print("Decrypted data:", decrypted)
cryptofw.Utils.SaveDataToFile(decrypted, "test_file.dat")