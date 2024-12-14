import java.util.List;
public class test {
 public static void main(String[] args) {
        System.loadLibrary("java_cryptofw");
        try {
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

            // Данные для работы
            short[] shortArray = {1, 2, 3, 4};
            Blob data = new Blob(shortArray);
            data.add((short)5);
            // data = appendToArray(data, 1);

            // System.out.println("Data (hex): " + bytesToHex(data));
            System.out.println("Cert obj: " + cert);

            // Подпись данных
            Blob signed = cert.SignCades(data, CadesType.kBes, false);
            // System.out.println("Signed message (hex): " + bytesToHex(signed));
            System.out.println("Signed message size: " + signed.size());

            // // Верификация подписи
            boolean verified = csp.VerifyCadesAttached(signed, CadesType.kBes);
            System.out.println("Verified: " + verified);

            // // Шифрование и дешифрование данных
            Blob encrypted = cert.Encrypt(data);
            Blob decrypted = cert.Decrypt(encrypted);
            System.out.println("Encrypted data size: " + encrypted.size());
            System.out.println("Decrypted data: " + decrypted);

            // // Сохранение данных в файл
            // Utils.SaveDataToFile(decrypted, "ababbbb");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Вспомогательная функция для добавления элемента в массив
    private static byte[] appendToArray(byte[] array, byte value) {
        byte[] result = new byte[array.length + 1];
        System.arraycopy(array, 0, result, 0, array.length);
        result[array.length] = value;
        return result;
    }

    // Вспомогательная функция для преобразования массива байтов в строку в формате hex
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}