import java.io.File;
import java.util.List;
import java.util.Random;

public class test {
    public static void demonstrateCsp(CspType cspType, String name) {
        System.out.println("\n\n");

        // Получение экземпляра CSP
        ICsp csp;
        try {
            csp = CryptoFramework.GetCspInstance(cspType);
        } catch (Exception e) {
            System.out.println("Selected CSP is not available: " + e.getMessage());
            return;
        }

        System.out.println("Demonstrating " + name + ":\n");

        // Получение сертификатов
        List<ICertificate> certs = csp.GetCertificates();
        if (certs.isEmpty()) {
            System.out.println("No " + name + " certificates found");
            return;
        }

        System.out.println(certs.size() + " certificates of " + name + " available:");
        for (int i = 0; i < certs.size(); i++) {
            ICertificate cert = certs.get(i);
            System.out.println("  - Certificate #" + (i + 1) + ", subject: " + cert.GetSubjectName());
        }

        // Выбор случайного сертификата
        Random rand = new Random();
        int certNumber = rand.nextInt(certs.size());
        ICertificate cert = certs.get(certNumber);
        System.out.println("\nRandomly selected certificate #" + (certNumber + 1) + " to work with");

        // Подготовка данных
        File dir = new File(name);
        if (!dir.exists()) dir.mkdir();
        Blob fileData;
        File file = new File(name + "/hello.txt");
        if (!file.exists()) {
            System.out.println("File does not exist, creating with default data.");
            try {
                fileData = new Blob(new short[]{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF});
                Utils.SaveDataToFile(fileData, file.getAbsolutePath());
            } catch (Exception saveException) {
                System.out.println("Failed to create default file: " + saveException.getMessage());
                saveException.printStackTrace();
                throw saveException;
            }
        } else {
            System.out.println("File exists, attempting to read.");
            fileData = Utils.ReadDataFromFile(file.getAbsolutePath());
        }
        System.out.println("\nFile data: " + fileData);

        // Шифрование/дешифрование
        try {
            System.out.println("\nEncrypting data...");
            Blob encrypted = cert.Encrypt(fileData);
            Utils.SaveDataToFile(encrypted, name + "/encrypted.p7e");
            System.out.println("Encrypted data size: " + encrypted.size());

            System.out.println("\nDecrypting data...");
            Blob decrypted = cert.Decrypt(encrypted);
            Utils.SaveDataToFile(decrypted, name + "/decrypted.dat");
            System.out.println("Decrypted data: " + decrypted);
        } catch (Exception e) {
            System.out.println("Exception during encryption/decryption: " + e.getMessage());
        }

        // Подпись CAdES-BES
        try {
            System.out.println("\nCreating detached CAdES-BES signature...");
            Blob cadesBesDetached = cert.SignCades(fileData, CadesType.kBes, true);
            Utils.SaveDataToFile(cadesBesDetached, name + "/cadesBesDetached.p7s");

            System.out.println("\nVerifying detached CAdES-BES signature...");
            boolean isValidDetached = csp.VerifyCadesDetached(cadesBesDetached, fileData, CadesType.kBes);
            System.out.println("Detached CAdES-BES signature is " + (isValidDetached ? "VALID" : "INVALID"));

            System.out.println("\nCreating attached CAdES-BES signature...");
            Blob cadesBesAttached = cert.SignCades(fileData, CadesType.kBes, false);
            Utils.SaveDataToFile(cadesBesAttached, name + "/cadesBesAttached.p7s");

            System.out.println("\nVerifying attached CAdES-BES signature...");
            boolean isValidAttached = csp.VerifyCadesAttached(cadesBesAttached, CadesType.kBes);
            System.out.println("Attached CAdES-BES signature is " + (isValidAttached ? "VALID" : "INVALID"));
        } catch (Exception e) {
            System.out.println("Exception during work with CAdES-BES: " + e.getMessage());
        }

        // Подпись CAdES-X Long Type 1
        String tspServerUrl = "http://pki.tax.gov.ru/tsp/tsp.srf";

        try {
            System.out.println("\nCreating detached CAdES-X Long Type 1 signature...");
            Blob cadesXlDetached = cert.SignCades(fileData, CadesType.kXLongType1, true, tspServerUrl);
            Utils.SaveDataToFile(cadesXlDetached, name + "/cadesXlDetached.p7s");

            System.out.println("\nVerifying detached CAdES-X Long Type 1 signature...");
            boolean isValidXlDetached = csp.VerifyCadesDetached(cadesXlDetached, fileData, CadesType.kXLongType1);
            System.out.println("Detached CAdES-X Long Type 1 signature is " + (isValidXlDetached ? "VALID" : "INVALID"));

            System.out.println("\nCreating attached CAdES-X Long Type 1 signature...");
            Blob cadesXlAttached = cert.SignCades(fileData, CadesType.kXLongType1, false, tspServerUrl);
            Utils.SaveDataToFile(cadesXlAttached, name + "/cadesXlAttached.p7s");

            System.out.println("\nVerifying attached CAdES-X Long Type 1 signature...");
            boolean isValidXlAttached = csp.VerifyCadesAttached(cadesXlAttached, CadesType.kXLongType1);
            System.out.println("Attached CAdES-X Long Type 1 signature is " + (isValidXlAttached ? "VALID" : "INVALID"));
        } catch (Exception e) {
            System.out.println("Exception during work with CAdES-X Long Type 1: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        System.loadLibrary("java_cryptofw");
        System.out.println("Hello from CryptoFramework demo app!");

        demonstrateCsp(CspType.kCryptoProCsp, "CryptoPro_CSP");
        demonstrateCsp(CspType.kVipNetCsp, "ViPNet_CSP");
    }
}