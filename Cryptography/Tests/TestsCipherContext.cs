using System.Security.Cryptography;
using System.Text;
using Cryptography.Core;
using Cryptography.Core.Algorithms;
using Cryptography.Core.Enums;
using PaddingMode = Cryptography.Core.Enums.PaddingMode;
using Cryptography.Core.Interfaces;

namespace Cryptogtaphy.Tests
{
    class TestsCipherContext
    {
        static int testCount = 0;
        static int passedCount = 0;
        static int failedCount = 0;

        public static async Task RunAllTests()
        {
            Console.WriteLine("=== Тестирование криптографической библиотеки ===\n");

            try
            {
                TestDESAlgorithm();
                await TestCipherContextModes();
                await TestFileOperations();
                await TestFileNotText();
                await TestEdgeCases();
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

        public static void TestDESAlgorithm()
        {
            Console.WriteLine("\n=== Тестирование алгоритма DES ===\n");

            RunTest("Инициализация DES", () =>
            {
                var des = new Des();
                byte[] key = GenerateKey(7);
                des.Initialize(key);

                if (!des.IsInitialized)
                    throw new Exception("DES не инициализирован");

                if (des.BlockSize != 8)
                    throw new Exception($"Неверный размер блока: {des.BlockSize}, ожидается 8");

                if (des.RoundsCount != 16)
                    throw new Exception($"Неверное количество раундов: {des.RoundsCount}, ожидается 16");
            });

            RunTest("Шифрование/дешифрование одного блока DES", () =>
            {
                var des = new Des();
                byte[] key = GenerateKey(7);
                des.Initialize(key);

                byte[] plaintext = Encoding.UTF8.GetBytes("ABCDEFGH");
                byte[] ciphertext = des.EncryptBlock(plaintext);
                byte[] decrypted = des.DecryptBlock(ciphertext);
                if (!plaintext.SequenceEqual(decrypted))
                {
                    throw new Exception("Дешифрованный текст не совпадает с оригиналом");
                }
            });

            RunTest("Шифрование/дешифрование нескольких блоков DES", () =>
            {
                var des = new Des();
                byte[] key = GenerateKey(7);
                des.Initialize(key);

                string text = "Hello World!!! This is a test message for DES algorithm.";
                byte[] plaintext = Encoding.UTF8.GetBytes(text);
                byte[] ciphertext = des.Encrypt(plaintext);
                byte[] decrypted = des.Decrypt(ciphertext);

                string decryptedText = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
                if (text != decryptedText)
                {
                    Console.WriteLine($"Ожидалось: {text}");
                    Console.WriteLine($"Получено: {decryptedText}");
                    throw new Exception("Дешифрованный текст не совпадает с оригиналом");
                }
            });

            RunTest("Генерация раундовых ключей DES", () =>
            {
                var des = new Des();
                byte[] key = GenerateKey(7);
                byte[][] roundKeys = des.GenerateRoundKeys(key);

                if (roundKeys == null)
                    throw new Exception("Раундовые ключи не сгенерированы");

                if (roundKeys.Length != 16)
                    throw new Exception($"Неверное количество раундовых ключей: {roundKeys.Length}, ожидается 16");

                foreach (var roundKey in roundKeys)
                {
                    if (roundKey.Length != 6)
                        throw new Exception($"Неверный размер раундового ключа: {roundKey.Length}, ожидается 6");
                }
            });
        }

        public static async Task TestCipherContextModes()
        {
            Console.WriteLine("\n=== Тестирование CipherContext с различными режимами ===\n");

            byte[] key = GenerateKey(7);
            byte[] iv = GenerateKey(8);
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
                        new Des(),
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
                        byte[] iv2 = GenerateKey(8);

                        using var context1 = new CipherContext(new Des(), key, mode, PaddingMode.PKCS7, iv);
                        using var context2 = new CipherContext(new Des(), key, mode, PaddingMode.PKCS7, iv2);

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
                        new Des(),
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

        public static async Task TestFileOperations()
        {
            Console.WriteLine("\n=== Тестирование файловых операций ===\n");

            byte[] key = GenerateKey(7);
            byte[] iv = GenerateKey(8);
            string testFilePath = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_input.txt";
            string encryptedFilePath =
                "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_encrypted.txt";
            string decryptedFilePath =
                "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_decrypted.txt";

            // Очистка предыдущих файлов перед тестом
            CleanupFile(encryptedFilePath);
            CleanupFile(decryptedFilePath);

            await RunTestAsync("Шифрование/дешифрование файла", async () =>
            {
                using var context = new CipherContext(
                    new Des(),
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
                    new Des(),
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

        public static async Task TestFileNotText()
        {
            Console.WriteLine("\n=== Тестирование производительности ===\n");

            byte[] key = GenerateKey(7);
            byte[] iv = GenerateKey(8);

            using var context = new CipherContext(
                new Des(),
                key,
                EncryptionMode.RandomDelta,
                PaddingMode.ISO10126,
                iv);

            await RunTestAsync("Шифрование картинки", async () =>
            {
                string filePathInput = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem.jpg";
                string filePathEncrypt = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem_encrypt.jpg";
                string filePathDecrypt = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem_decrypt.jpg";

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
                string filePathEncrypt = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/kot_encrypt.mp4";
                string filePathDecrypt = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/kot_decrypt.mp4";

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

        public static async Task TestEdgeCases()
        {
            Console.WriteLine("\n=== Тестирование граничных случаев ===\n");

            byte[] key = GenerateKey(7);
            byte[] iv = GenerateKey(8);

            await RunTestAsync("Пустые данные", async () =>
            {
                using var context = new CipherContext(
                    new Des(),
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
                    new Des(),
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
                var des = new Des();
                byte[] invalidKey = new byte[5];

                try
                {
                    des.Initialize(invalidKey);
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
                    byte[] invalidIV = new byte[4]; // Неверный размер IV
                    using var context = new CipherContext(
                        new Des(),
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
                    new Des(),
                    key,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);

                context.Dispose();

                try
                {
                    byte[] data = new byte[8];
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
                    new Des(),
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