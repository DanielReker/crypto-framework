import java.util.List;
public class test {
 public static void main(String[] args) {
        System.loadLibrary("java_cryptofw");
        try {
            // Данные для работы
            Blob data = new Blob(new short[]{1, 2, 3});
            data.add((short)5);
            System.out.println("Data for work: " + data);

            // Получение VipNetCsp через Utils
            ICsp csp = Utils.GetVipNetCsp();

            // Получение сертификатов 
            List<ICertificate> certs = csp.GetCertificates();
            ICertificate cert = certs.get(0);

            // Перебор сертификатов и вывод их SubjectName
            for (int i = 0; i < certs.size(); i++) {
                ICertificate k = certs.get(i);
                System.out.println("Cert " + i + ": " + k.GetSubjectName());
            }

            System.out.println("Cert obj: " + cert);

            // Подпись данных
            Blob signed = cert.SignCades(data, CadesType.kBes, false);
            // System.out.println("Signed message (hex): " + signed);
            System.out.println("Signed message size: " + signed.size());

            // // Верификация подписи
            boolean verified = csp.VerifyCadesAttached(signed, CadesType.kBes);
            System.out.println("Verified: " + verified);

            // // Шифрование и дешифрование данных
            Blob encrypted = cert.Encrypt(data);
            Blob decrypted = cert.Decrypt(encrypted);
            System.out.println("Encrypted data size: " + encrypted.size());
            System.out.println("Decrypted data: " + decrypted);

            // // Сохранение данные в файл
            Utils.SaveDataToFile(decrypted, "test_file.dat");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}