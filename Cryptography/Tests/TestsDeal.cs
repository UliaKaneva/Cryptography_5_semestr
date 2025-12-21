using System.Security.Cryptography;
using System.Text;
using Cryptography.Core;
using Cryptography.Core.Algorithms;
using Cryptography.Core.Enums;
using PaddingMode = Cryptography.Core.Enums.PaddingMode;
using Cryptography.Core.Algorithms.DEAL;

namespace Cryptogtaphy.Tests
{
    class TestsDeal
    {
        static int testCount = 0;
        static int passedCount = 0;
        static int failedCount = 0;

        private static void RunTest(string testName, Action testAction)
        {
            testCount++;
            Console.Write($"Тест #{testCount}: {testName}... ");

            try
            {
                testAction();
                Console.WriteLine("УСПЕХ");
                passedCount++;
            }
            catch (Exception ex)
            {
                failedCount++;
                Console.WriteLine($"ОШИБКА");
                Console.WriteLine($"   Сообщение: {ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"   Внутренняя ошибка: {ex.InnerException.Message}");
            }
        }

        private static async Task RunTestAsync(string testName, Func<Task> testAction)
        {
            testCount++;
            Console.Write($"Тест #{testCount}: {testName}... ");

            try
            {
                await testAction();
                Console.WriteLine("УСПЕХ");
                passedCount++;
            }
            catch (Exception ex)
            {
                failedCount++;
                Console.WriteLine($"ОШИБКА");
                Console.WriteLine($"   Сообщение: {ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"   Внутренняя ошибка: {ex.InnerException.Message}");
            }
        }

        public static async Task RunAllTests()
        {
            Console.WriteLine("=== Тестирование алгоритма DEAL ===\n");

            try
            {
                TestDEALAlgorithm();
                await TestCipherContextModes();
                await TestFileOperations();
                await TestFileNotText();
                await TestEdgeCases();
                await TestPerformance();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nОшибка при выполнении тестов: {ex.Message}");
                Console.WriteLine($"StackTrace: {ex.StackTrace}");
            }

            Console.WriteLine("\n=== Результаты тестирования ===");
            Console.WriteLine($"Всего тестов: {testCount}");
            Console.WriteLine($"Пройдено: {passedCount}");
            Console.WriteLine($"Не пройдено: {failedCount}");
            Console.WriteLine(
                $"Успешность: {(testCount > 0 ? (passedCount * 100.0 / testCount).ToString("F2") : "0")}%");

            if (failedCount == 0)
                Console.WriteLine("\nВсе тесты пройдены успешно!");
            else
                Console.WriteLine($"\nНайдены ошибки: {failedCount} тестов не пройдено");
        }

        static void TestDEALAlgorithm()
        {
            Console.WriteLine("\n=== Тестирование базового алгоритма DEAL ===\n");

            RunTest("Инициализация DEAL", () =>
            {
                var deal = new DEAL();
                byte[] key = GenerateKey(16);
                deal.Initialize(key);

                if (!deal.IsInitialized)
                    throw new Exception("DEAL не инициализирован");

                if (deal.BlockSize != 16)
                    throw new Exception($"Неверный размер блока: {deal.BlockSize}, ожидается 16");

                if (deal.RoundsCount != 6)
                    throw new Exception($"Неверное количество раундов: {deal.RoundsCount}, ожидается 6");
            });

            RunTest("Шифрование/дешифрование одного блока DEAL (128 бит)", () =>
            {
                var deal = new DEAL();
                byte[] key = GenerateKey(16);
                deal.Initialize(key);

                byte[] plaintext = Encoding.UTF8.GetBytes("Hi, DEAL World!!");
                byte[] ciphertext = deal.EncryptBlock(plaintext);
                byte[] decrypted = deal.DecryptBlock(ciphertext);
                if (!plaintext.SequenceEqual(decrypted))
                {
                    throw new Exception("Дешифрованный текст не совпадает с оригиналом");
                }
            });

            RunTest("Шифрование/дешифрование нескольких блоков DEAL", () =>
            {
                var deal = new DEAL();
                byte[] key = GenerateKey(16);
                deal.Initialize(key);

                string text = "Hello World!!! This is a test message for DEAL algorithm. It's longer than one block.";
                byte[] plaintext = Encoding.UTF8.GetBytes(text);
                byte[] ciphertext = deal.Encrypt(plaintext);
                byte[] decrypted = deal.Decrypt(ciphertext);

                string decryptedText = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
                if (text != decryptedText)
                {
                    Console.WriteLine($"Ожидалось: {text}");
                    Console.WriteLine($"Получено: {decryptedText}");
                    throw new Exception("Дешифрованный текст не совпадает с оригиналом");
                }
            });

            RunTest("Тест с разными размерами ключей", () =>
            {
                byte[] plaintext = Encoding.UTF8.GetBytes("Test message for");

                int[] keySizes = [16, 24, 32];

                foreach (int keySize in keySizes)
                {
                    var deal = new DEAL();
                    byte[] key = GenerateKey(keySize);
                    deal.Initialize(key);

                    byte[] ciphertext = deal.Encrypt(plaintext);
                    byte[] decrypted = deal.Decrypt(ciphertext);

                    if (!plaintext.SequenceEqual(decrypted))
                        throw new Exception($"Тест с ключом {keySize * 8} бит не прошел!");
                }
            });
        }

        static async Task TestCipherContextModes()
        {
            Console.WriteLine("\n=== Тестирование CipherContext с различными режимами ===\n");

            byte[] key = GenerateKey(32);
            byte[] iv = GenerateKey(16);
            string testData =
                "This is a test message for encryption. It should be long enough to require multiple blocks.";

            var modes = new[]
            {
                (EncryptionMode.ECB, "ECB"),
                (EncryptionMode.CBC, "CBC"),
                (EncryptionMode.PCBC, "PCBC"),
                (EncryptionMode.CFB, "CFB"),
                (EncryptionMode.OFB, "OFB"),
                (EncryptionMode.CTR, "CTR"),
                (EncryptionMode.RandomDelta, "RandomDelta")
            };

            foreach (var (mode, modeName) in modes)
            {
                await RunTestAsync($"Режим {modeName} - шифрование/дешифрование", async () =>
                {
                    using var context = new CipherContext(
                        new DEAL(),
                        key,
                        mode,
                        PaddingMode.PKCS7,
                        mode == EncryptionMode.ECB ? null : iv);

                    byte[] plaintext = Encoding.UTF8.GetBytes(testData);
                    byte[] encrypted = await context.Encrypt(plaintext);
                    byte[] decrypted = await context.Decrypt(encrypted);

                    string result = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
                    if (testData != result)
                        throw new Exception($"Ошибка в режиме {modeName}: дешифрованный текст не совпадает");
                });

                if (mode != EncryptionMode.ECB)
                {
                    await RunTestAsync($"Режим {modeName} - проверка зависимости от IV", async () =>
                    {
                        byte[] iv2 = GenerateKey(16);

                        using var context1 = new CipherContext(new DEAL(), key, mode, PaddingMode.PKCS7, iv);
                        using var context2 = new CipherContext(new DEAL(), key, mode, PaddingMode.PKCS7, iv2);

                        byte[] plaintext = Encoding.UTF8.GetBytes(testData);
                        byte[] encrypted1 = await context1.Encrypt(plaintext);
                        byte[] encrypted2 = await context2.Encrypt(plaintext);

                        if (encrypted1.SequenceEqual(encrypted2))
                            throw new Exception($"IV не влияет на результат в режиме {modeName}");
                    });
                }
            }

            var paddingModes = new[]
            {
                (PaddingMode.Zeros, "Zero"),
                (PaddingMode.PKCS7, "PKCS7"),
                (PaddingMode.ANSIX923, "ANAIX923"),
                (PaddingMode.ISO10126, "ISO10126")
            };

            foreach (var (paddingMode, paddingName) in paddingModes)
            {
                await RunTestAsync($"Паддинг {paddingName}", async () =>
                {
                    using var context = new CipherContext(
                        new DEAL(),
                        key,
                        EncryptionMode.CBC,
                        paddingMode,
                        iv);

                    byte[] plaintext = "Short"u8.ToArray();
                    byte[] encrypted = await context.Encrypt(plaintext);
                    byte[] decrypted = await context.Decrypt(encrypted);

                    string result = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
                    if ("Short" != result)
                        throw new Exception($"Ошибка с режимом дополнения {paddingMode}");
                });
            }
        }

        static async Task TestFileOperations()
        {
            Console.WriteLine("\n=== Тестирование файловых операций ===\n");

            byte[] key = GenerateKey(32);
            byte[] iv = GenerateKey(16);
            string testFilePath = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_input.txt";
            string encryptedFilePath =
                "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_encrypted_deal.txt";
            string decryptedFilePath =
                "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_decrypted_deal.txt";

            await RunTestAsync("Шифрование/дешифрование текстового файла", async () =>
            {
                using var context = new CipherContext(
                    new DEAL(),
                    key,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);

                await context.Encrypt(testFilePath, encryptedFilePath, 1024);
                await context.Decrypt(encryptedFilePath, decryptedFilePath, 1024);

                string original = await File.ReadAllTextAsync(testFilePath, Encoding.UTF8);
                string decrypted = await File.ReadAllTextAsync(decryptedFilePath, Encoding.UTF8);

                if (original != decrypted)
                    throw new Exception("Потоковое шифрование/дешифрование не работает");
            });

            await RunTestAsync("Шифрование в буфер", async () =>
            {
                using var context = new CipherContext(
                    new DEAL(),
                    key,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);

                byte[] plaintext = Encoding.UTF8.GetBytes("Test buffer encryption");
                byte[] outputBuffer = new byte[256];

                int encryptedLength = await context.Encrypt(plaintext, outputBuffer);
                if (encryptedLength <= 0)
                    throw new Exception("Ошибка при шифровании в буфер");

                byte[] encryptedData = outputBuffer.Take(encryptedLength).ToArray();
                byte[] decryptedBuffer = new byte[256];

                int decryptedLength = await context.Decrypt(encryptedData, decryptedBuffer);
                if (decryptedLength <= 0)
                    throw new Exception("Ошибка при дешифровании из буфера");

                string result = Encoding.UTF8.GetString(decryptedBuffer, 0, decryptedLength).TrimEnd('\0');
                if ("Test buffer encryption" != result)
                    throw new Exception("Шифрование в буфер не работает");
            });
        }

        static async Task TestFileNotText()
        {
            Console.WriteLine("\n=== Тестирование шифрования бинарных файлов ===\n");

            byte[] key = GenerateKey(32);
            byte[] iv = GenerateKey(16);

            using var context = new CipherContext(
                new DEAL(),
                key,
                EncryptionMode.CBC,
                PaddingMode.PKCS7,
                iv);

            await RunTestAsync("Шифрование картинки", async () =>
            {
                string filePathInput = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem.jpg";
                string filePathEncrypt =
                    "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem_encrypt_deal.jpg";
                string filePathDecrypt =
                    "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem_decrypt_deal.jpg";

                await context.Encrypt(filePathInput, filePathEncrypt, 1024);
                await context.Decrypt(filePathEncrypt, filePathDecrypt, 1024);

                FileInfo fileInfoInput = new FileInfo(filePathInput);
                FileInfo fileInfoDecrypt = new FileInfo(filePathDecrypt);
                FileInfo fileInfoEncrypt = new FileInfo(filePathEncrypt);
                if (fileInfoInput.Length != fileInfoDecrypt.Length)
                {
                    throw new Exception(
                        $"Длинны оригинального файла {fileInfoInput.Length} и расшифрованного различаются {fileInfoDecrypt.Length} {fileInfoEncrypt.Length}");
                }
            });

            await RunTestAsync("Шифрование видео", async () =>
            {
                string filePathInput = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/kot.mp4";
                string filePathEncrypt =
                    "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/kot_encrypt_deal.mp4";
                string filePathDecrypt =
                    "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/kot_decrypt_deal.mp4";

                await context.Encrypt(filePathInput, filePathEncrypt, 1024);
                await context.Decrypt(filePathEncrypt, filePathDecrypt, 1024);

                FileInfo fileInfoInput = new FileInfo(filePathInput);
                FileInfo fileInfoDecrypt = new FileInfo(filePathDecrypt);
                FileInfo fileInfoEncrypt = new FileInfo(filePathEncrypt);
                if (fileInfoInput.Length != fileInfoDecrypt.Length)
                {
                    throw new Exception(
                        $"Длинны оригинального файла {fileInfoInput.Length} и расшифрованного различаются {fileInfoDecrypt.Length} {fileInfoEncrypt.Length}");
                }
            });
        }

        static async Task TestEdgeCases()
        {
            Console.WriteLine("\n=== Тестирование граничных случаев ===\n");

            byte[] key = GenerateKey(32);
            byte[] iv = GenerateKey(16);

            await RunTestAsync("Пустые данные", async () =>
            {
                using var context = new CipherContext(
                    new DEAL(),
                    key,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);
                try
                {
                    byte[] emptyData = Array.Empty<byte>();
                    byte[] encrypted = await context.Encrypt(emptyData);
                }
                catch
                {
                    return;
                }

                throw new Exception("Должна была возникнуть ошибка");
            });

            await RunTestAsync("Крайне короткие данные", async () =>
            {
                using var context = new CipherContext(
                    new DEAL(),
                    key,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);

                for (int i = 1; i <= 3; i++)
                {
                    byte[] data = new byte[i];
                    RandomNumberGenerator.Fill(data);

                    byte[] encrypted = await context.Encrypt(data);
                    byte[] decrypted = await context.Decrypt(encrypted);

                    if (!data.SequenceEqual(decrypted))
                        throw new Exception($"Данные длиной {i} байт обрабатываются некорректно");
                }
            });

            RunTest("Обработка исключений - неверный ключ", () =>
            {
                var deal = new DEAL();
                byte[] invalidKey = new byte[10];

                try
                {
                    deal.Initialize(invalidKey);
                    throw new Exception("Ожидалось исключение для неверного ключа");
                }
                catch (ArgumentException)
                {
                    // Ожидаемое поведение
                }
            });

            RunTest("Обработка исключений - неверный IV", () =>
            {
                try
                {
                    byte[] invalidIV = new byte[10]; // Неверный размер IV
                    using var context = new CipherContext(
                        new DEAL(),
                        key,
                        EncryptionMode.CBC,
                        PaddingMode.PKCS7,
                        invalidIV);

                    throw new Exception("Ожидалось исключение для неверного IV");
                }
                catch (ArgumentException)
                {
                    // Ожидаемое поведение
                }
            });

            await RunTestAsync("Проверка очистки ресурсов (Dispose)", async () =>
            {
                var context = new CipherContext(
                    new DEAL(),
                    key,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);

                context.Dispose();

                try
                {
                    byte[] data = new byte[16];
                    await context.Encrypt(data);
                }
                catch (ObjectDisposedException)
                {
                    return;
                }

                throw new Exception("Ожидалось исключение после Dispose");
            });

            await RunTestAsync("Параллельное шифрование", async () =>
            {
                using var context = new CipherContext(
                    new DEAL(),
                    key,
                    EncryptionMode.ECB,
                    PaddingMode.PKCS7);

                byte[] data = new byte[1024 * 8];
                RandomNumberGenerator.Fill(data);

                var tasks = new Task[10];
                for (int i = 0; i < 10; i++)
                {
                    tasks[i] = Task.Run(async () =>
                    {
                        byte[] encrypted = await context.Encrypt(data);
                        byte[] decrypted = await context.Decrypt(encrypted);

                        if (!data.SequenceEqual(decrypted))
                            throw new Exception("Параллельная операция дала некорректный результат");
                    });
                }

                await Task.WhenAll(tasks);
            });
        }

        static async Task TestPerformance()
        {
            Console.WriteLine("\n=== Тестирование производительности ===\n");

            await RunTestAsync("Тест производительности (1 МБ данных)", async () =>
            {
                byte[] key = GenerateKey(32);
                byte[] iv = GenerateKey(16);

                int dataSize = 1024 * 1024;
                byte[] largeData = new byte[dataSize];
                RandomNumberGenerator.Fill(largeData);

                Console.WriteLine($"   Размер тестовых данных: {dataSize / 1024} КБ");

                var deal = new DEAL();
                using var context = new CipherContext(
                    deal,
                    key,
                    EncryptionMode.CTR,
                    PaddingMode.PKCS7,
                    iv);

                var startTime = DateTime.Now;
                byte[] encrypted = await context.Encrypt(largeData);
                var encryptTime = DateTime.Now - startTime;

                Console.WriteLine($"   Время шифрования: {encryptTime.TotalMilliseconds:F2} мс");
                Console.WriteLine(
                    $"   Скорость шифрования: {dataSize / encryptTime.TotalSeconds / 1024 / 1024:F2} МБ/с");

                startTime = DateTime.Now;
                byte[] decrypted = await context.Decrypt(encrypted);
                var decryptTime = DateTime.Now - startTime;

                Console.WriteLine($"   Время дешифрования: {decryptTime.TotalMilliseconds:F2} мс");
                Console.WriteLine(
                    $"   Скорость дешифрования: {dataSize / decryptTime.TotalSeconds / 1024 / 1024:F2} МБ/с");

                if (!largeData.SequenceEqual(decrypted))
                    throw new Exception("Большой объем данных обработан некорректно!");
            });
        }

        private static byte[] GenerateKey(int sizeInBytes)
        {
            byte[] key = new byte[sizeInBytes];
            RandomNumberGenerator.Fill(key);
            return key;
        }

        private static void CleanupFile(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                    File.Delete(filePath);
            }
            catch
            {
                //
            }
        }
    }
}