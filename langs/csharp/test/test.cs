using System;
using System.Collections.Generic;

namespace CryptoFwApp
{
    class test
    {
        static public void print_bytes(IList<byte> list) {
            Console.Write("[");
            foreach (var item in list) {
                    Console.Write(item + ", ");
                }
            Console.WriteLine("\b\b]");
        }

        static void Main(string[] args)
        {
            try
            {
                // Данные для работы
                Blob data = new Blob(new byte[] { 1, 2, 3 });
                data.Add((byte)5);

                Console.Write("Data for work: ");
                print_bytes(data);

                // Получение VipNetCsp через Utils
                ICsp csp = Utils.GetVipNetCsp();

                // Получение сертификатов 
                var certs = csp.GetCertificates();
                ICertificate cert = certs[0];

                // Перебор сертификатов и вывод их SubjectName
                for (int i = 0; i < certs.Count; i++)
                {
                    ICertificate k = certs[i];
                    Console.WriteLine($"Cert {i}: {k.GetSubjectName()}");
                }

                Console.WriteLine("Cert obj: " + cert);

                // Подпись данных
                Blob signed = cert.SignCades(data, CadesType.kBes, false);
                Console.WriteLine("Signed message size: " + signed.Count);

                // Верификация подписи
                bool verified = csp.VerifyCadesAttached(signed, CadesType.kBes);
                Console.WriteLine("Verified: " + verified);

                // Шифрование и дешифрование данных
                Blob encrypted = cert.Encrypt(data);
                Blob decrypted = cert.Decrypt(encrypted);
                Console.WriteLine("Encrypted data size: " + encrypted.Count);
                Console.Write("Decrypted data: ");
                print_bytes(decrypted);

                // Сохранение данных в файл
                Utils.SaveDataToFile(decrypted, "test_file.dat");
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: " + e.Message);
                Console.WriteLine(e.StackTrace);
            }
        }
    }
}