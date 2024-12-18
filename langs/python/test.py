from swig_generated import cryptofw
import os
import random

def demonstrate_csp(csp_type, name):
    print(f"\n\nDemonstrating {name}:\n")

    # Get CSP instance
    try:
        csp = cryptofw.CryptoFramework.GetCspInstance(csp_type)
    except Exception as e:
        print(f"Error getting CSP instance: {e}")
        return

    # Get available certificates
    certs = csp.GetCertificates()
    if len(certs) == 0:
        print(f"No {name} certificates found")
        return

    print(f"{len(certs)} certificates of {name} available:")
    for i, cert in enumerate(certs):
        print(f"  - Certificate #{i + 1}, subject: {cert.GetSubjectName()}")

    # Select a random certificate
    cert = random.choice(certs)
    print(f"\nRandomly selected certificate to work with: {cert.GetSubjectName()}")

    # Prepare data
    os.makedirs(name, exist_ok=True)
    file_path = os.path.join(name, "hello.txt")
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
    except Exception as e:
        print(f"Error reading file: {e}, setting default data")
        file_data = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                           0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        with open(file_path, "wb") as f:
            f.write(file_data)

    print(f"File data: {file_data.hex()}")

    # Encryption/decryption
    try:
        print("\nEncrypting data...")
        encrypted = cert.Encrypt(file_data)
        with open(os.path.join(name, "encrypted.p7e"), "wb") as f:
            f.write(bytes(encrypted))
        print(f"Encrypted data size: {len(encrypted)}")

        print("\nDecrypting data...")
        decrypted = cert.Decrypt(bytes(encrypted))
        with open(os.path.join(name, "decrypted.dat"), "wb") as f:
            f.write(bytes(decrypted))
        print(f"Decrypted data: {decrypted}")
    except Exception as e:
        print(f"Exception during encryption/decryption: {e}")

    # CAdES-BES
    try:
        print("\nCreating detached CAdES-BES signature...")
        cades_bes_detached = cert.SignCades(file_data, cryptofw.CadesType_kBes, True)
        with open(os.path.join(name, "cadesBesDetached.p7s"), "wb") as f:
            f.write(bytes(cades_bes_detached))

        print("\nVerifying detached CAdES-BES signature...")
        is_valid = csp.VerifyCadesDetached(cades_bes_detached, file_data, cryptofw.CadesType_kBes)
        print("Detached CAdES-BES signature is VALID" if is_valid else "Detached CAdES-BES signature is INVALID")

        print("\nCreating attached CAdES-BES signature...")
        cades_bes_attached = cert.SignCades(file_data, cryptofw.CadesType_kBes, False)
        with open(os.path.join(name, "cadesBesAttached.p7s"), "wb") as f:
            f.write(bytes(cades_bes_attached))

        print("\nVerifying attached CAdES-BES signature...")
        is_valid = csp.VerifyCadesAttached(cades_bes_attached, cryptofw.CadesType_kBes)
        print("Attached CAdES-BES signature is VALID" if is_valid else "Attached CAdES-BES signature is INVALID")
    except Exception as e:
        print(f"Exception during work with CAdES-BES: {e}")

    # CAdES-X Long Type 1
    tsp_server_url = "http://pki.tax.gov.ru/tsp/tsp.srf"
    try:
        print("\nCreating detached CAdES-X Long Type 1 signature...")
        cades_xl_detached = cert.SignCades(file_data, cryptofw.CadesType_kXLongType1, True, tsp_server_url)
        with open(os.path.join(name, "cadesXlDetached.p7s"), "wb") as f:
            f.write(cades_xl_detached)

        print("\nVerifying detached CAdES-X Long Type 1 signature...")
        is_valid = csp.VerifyCadesDetached(cades_xl_detached, file_data, cryptofw.CadesType_kXLongType1)
        print("Detached CAdES-X Long Type 1 signature is VALID" if is_valid else "Detached CAdES-X Long Type 1 signature is INVALID")

        print("\nCreating attached CAdES-X Long Type 1 signature...")
        cades_xl_attached = cert.SignCades(file_data, cryptofw.CadesType_kXLongType1, False, tsp_server_url)
        with open(os.path.join(name, "cadesXlAttached.p7s"), "wb") as f:
            f.write(cades_xl_attached)

        print("\nVerifying attached CAdES-X Long Type 1 signature...")
        is_valid = csp.VerifyCadesAttached(cades_xl_attached, cryptofw.CadesType_kXLongType1)
        print("Attached CAdES-X Long Type 1 signature is VALID" if is_valid else "Attached CAdES-X Long Type 1 signature is INVALID")
    except Exception as e:
        print(f"Exception during work with CAdES-X Long Type 1: {e}")


if __name__ == "__main__":
    print("Hello from CryptoFramework demo app!")

    demonstrate_csp(cryptofw.CspType_kCryptoProCsp, "CryptoPro_CSP")
    demonstrate_csp(cryptofw.CspType_kVipNetCsp, "ViPNet_CSP")