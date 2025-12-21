using System.Security.Cryptography;
using System.Text;
using Cryptography.Core;
using Cryptography.Core.Enums;
using PaddingMode = Cryptography.Core.Enums.PaddingMode;
using TripleDES = Cryptography.Core.Algorithms.TripleDES.TripleDES;


namespace Cryptogtaphy.Tests
{
    class TestsTripleDes
    {
        static int testCount = 0;
        static int passedCount = 0;
        static int failedCount = 0;

        public static async Task RunAllTests()
        {
            Console.WriteLine("=== Тестирование TripleDES криптографической библиотеки ===\n");

            try
            {
                TestTripleDESAlgorithm();
                await TestTripleDESCipherContextModes();
                await TestTripleDESFileOperations();
                await TestTripleDESEdgeCases();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nОшибка при выполнении тестов: {ex.Message}");
                Console.WriteLine($"StackTrace: {ex.StackTrace}");
            }

            Console.WriteLine("\n=== Результаты тестирования TripleDES ===");
            Console.WriteLine($"Всего тестов: {testCount}");
            Console.WriteLine($"Пройдено: {passedCount}");
            Console.WriteLine($"Не пройдено: {failedCount}");
            Console.WriteLine(
                $"Успешность: {(testCount > 0 ? (passedCount * 100.0 / testCount).ToString("F2") : "0")}%");

            if (failedCount == 0)
                Console.WriteLine("\nВсе тесты TripleDES пройдены успешно!");
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

        public static void TestTripleDESAlgorithm()
        {
            Console.WriteLine("\n=== Тестирование алгоритма TripleDES ===\n");

            RunTest("Инициализация TripleDES с ключом 21 байт", () =>
            {
                var tripleDes = new TripleDES();
                byte[] key = GenerateKey(21);
                tripleDes.Initialize(key);

                if (!tripleDes.IsInitialized)
                    throw new Exception("TripleDES не инициализирован");

                if (tripleDes.BlockSize != 8)
                    throw new Exception($"Неверный размер блока: {tripleDes.BlockSize}, ожидается 8");

                if (tripleDes.RoundsCount != 1)
                    throw new Exception($"Неверное количество раундов: {tripleDes.RoundsCount}, ожидается 1");

                if (!tripleDes.SupportedKeySizes.Contains(21))
                    throw new Exception("Ключ 21 байт должен поддерживаться");
            });

            RunTest("Инициализация TripleDES с ключом 24 байта", () =>
            {
                var tripleDes = new TripleDES();
                byte[] key = GenerateKey(24);
                tripleDes.Initialize(key);

                if (!tripleDes.IsInitialized)
                    throw new Exception("TripleDES не инициализирован");

                if (!tripleDes.SupportedKeySizes.Contains(24))
                    throw new Exception("Ключ 24 байта должен поддерживаться");
            });

            RunTest("Шифрование/дешифрование одного блока TripleDES (ключ 21 байт)", () =>
            {
                var tripleDes = new TripleDES();
                byte[] key = GenerateKey(21);
                tripleDes.Initialize(key);

                byte[] plaintext = Encoding.UTF8.GetBytes("ABCDEFGH"); // 8 байт
                byte[] ciphertext = tripleDes.EncryptBlock(plaintext);
                byte[] decrypted = tripleDes.DecryptBlock(ciphertext);
                
                if (!plaintext.SequenceEqual(decrypted))
                {
                    throw new Exception("Дешифрованный текст не совпадает с оригиналом");
                }
            });

            RunTest("Шифрование/дешифрование одного блока TripleDES (ключ 24 байта)", () =>
            {
                var tripleDes = new TripleDES();
                byte[] key = GenerateKey(24);
                tripleDes.Initialize(key);

                byte[] plaintext = Encoding.UTF8.GetBytes("ABCDEFGH"); // 8 байт
                byte[] ciphertext = tripleDes.EncryptBlock(plaintext);
                byte[] decrypted = tripleDes.DecryptBlock(ciphertext);
                
                if (!plaintext.SequenceEqual(decrypted))
                {
                    throw new Exception("Дешифрованный текст не совпадает с оригиналом");
                }
            });

            RunTest("Шифрование/дешифрование нескольких блоков TripleDES", () =>
            {
                var tripleDes = new TripleDES();
                byte[] key = GenerateKey(24);
                tripleDes.Initialize(key);

                string text = "Hello World!!! This is a test message for TripleDES algorithm. It should work perfectly!";
                byte[] plaintext = Encoding.UTF8.GetBytes(text);
                byte[] ciphertext = tripleDes.Encrypt(plaintext);
                byte[] decrypted = tripleDes.Decrypt(ciphertext);

                string decryptedText = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
                if (text != decryptedText)
                {
                    Console.WriteLine($"Ожидалось: {text}");
                    Console.WriteLine($"Получено: {decryptedText}");
                    throw new Exception("Дешифрованный текст не совпадает с оригиналом");
                }
            });

            RunTest("Проверка параллельной обработки блоков", () =>
            {
                var tripleDes = new TripleDES();
                byte[] key = GenerateKey(24);
                tripleDes.Initialize(key);

                // Создаем данные размером в несколько блоков
                byte[] plaintext = new byte[64]; // 8 блоков
                RandomNumberGenerator.Fill(plaintext);

                byte[] ciphertext = tripleDes.Encrypt(plaintext);
                byte[] decrypted = tripleDes.Decrypt(ciphertext);

                if (!plaintext.SequenceEqual(decrypted))
                {
                    throw new Exception("Параллельная обработка блоков работает некорректно");
                }
            });

            RunTest("Проверка некорректного размера ключа", () =>
            {
                var tripleDes = new TripleDES();
                byte[] invalidKey = new byte[16]; // Неправильный размер

                try
                {
                    tripleDes.Initialize(invalidKey);
                    throw new Exception("Ожидалось исключение для неверного ключа");
                }
                catch (ArgumentException)
                {
                    // Ожидаемое поведение
                }
            });

            RunTest("Проверка некорректного размера блока", () =>
            {
                var tripleDes = new TripleDES();
                byte[] key = GenerateKey(24);
                tripleDes.Initialize(key);

                byte[] invalidBlock = new byte[7]; // Меньше размера блока

                try
                {
                    tripleDes.EncryptBlock(invalidBlock);
                    throw new Exception("Ожидалось исключение для неверного размера блока");
                }
                catch (ArgumentException)
                {
                    // Ожидаемое поведение
                }
            });
        }

        public static async Task TestTripleDESCipherContextModes()
        {
            Console.WriteLine("\n=== Тестирование CipherContext с TripleDES и различными режимами ===\n");

            byte[] key = GenerateKey(24); // Используем 24-байтовый ключ
            byte[] iv = GenerateKey(8);   // IV остается 8 байт
            string testData =
                "This is a test message for TripleDES encryption. It should be long enough to require multiple blocks.";

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
                await RunTestAsync($"TripleDES Режим {modeName} - шифрование/дешифрование", async () =>
                {
                    using var context = new CipherContext(
                        new TripleDES(),
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
                    await RunTestAsync($"TripleDES Режим {modeName} - проверка зависимости от IV", async () =>
                    {
                        byte[] iv2 = GenerateKey(8);

                        using var context1 = new CipherContext(new TripleDES(), key, mode, PaddingMode.PKCS7, iv);
                        using var context2 = new CipherContext(new TripleDES(), key, mode, PaddingMode.PKCS7, iv2);

                        byte[] plaintext = Encoding.UTF8.GetBytes(testData);
                        byte[] encrypted1 = await context1.Encrypt(plaintext);
                        byte[] encrypted2 = await context2.Encrypt(plaintext);

                        if (encrypted1.SequenceEqual(encrypted2))
                            throw new Exception($"IV не влияет на результат в режиме {modeName}");
                    });
                }
            }

            // Тестирование с ключом 21 байт
            await RunTestAsync("TripleDES с ключом 21 байт в режиме CBC", async () =>
            {
                byte[] key21 = GenerateKey(21);
                
                using var context = new CipherContext(
                    new TripleDES(),
                    key21,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);

                byte[] plaintext = Encoding.UTF8.GetBytes(testData);
                byte[] encrypted = await context.Encrypt(plaintext);
                byte[] decrypted = await context.Decrypt(encrypted);

                string result = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
                if (testData != result)
                    throw new Exception("Ключ 21 байт работает некорректно");
            });

            var paddingModes = new[]
            {
                (PaddingMode.Zeros, "Zero"),
                (PaddingMode.PKCS7, "PKCS7"),
                (PaddingMode.ANSIX923, "ANSI X923"),
                (PaddingMode.ISO10126, "ISO10126")
            };

            foreach (var (paddingMode, paddingName) in paddingModes)
            {
                await RunTestAsync($"TripleDES Паддинг {paddingName}", async () =>
                {
                    using var context = new CipherContext(
                        new TripleDES(),
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

        public static async Task TestTripleDESFileOperations()
        {
            Console.WriteLine("\n=== Тестирование файловых операций с TripleDES ===\n");

            byte[] key = GenerateKey(24);
            byte[] iv = GenerateKey(8);
            string testFilePath = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_input.txt";
            string encryptedFilePath =
                "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_tripledes_encrypted.txt";
            string decryptedFilePath =
                "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_tripledes_decrypted.txt";

            // Очистка предыдущих файлов перед тестом
            CleanupFile(encryptedFilePath);
            CleanupFile(decryptedFilePath);

            await RunTestAsync("TripleDES Шифрование/дешифрование файла", async () =>
            {
                using var context = new CipherContext(
                    new TripleDES(),
                    key,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);

                await context.Encrypt(testFilePath, encryptedFilePath, 1024);
                await context.Decrypt(encryptedFilePath, decryptedFilePath, 1024);

                string original = await File.ReadAllTextAsync(testFilePath, Encoding.UTF8);
                string decrypted = await File.ReadAllTextAsync(decryptedFilePath, Encoding.UTF8);

                if (original != decrypted)
                    throw new Exception("TripleDES потоковое шифрование/дешифрование не работает");
            });

            await RunTestAsync("TripleDES Шифрование в буфер", async () =>
            {
                using var context = new CipherContext(
                    new TripleDES(),
                    key,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);

                byte[] plaintext = Encoding.UTF8.GetBytes("Test TripleDES buffer encryption");
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
                if ("Test TripleDES buffer encryption" != result)
                    throw new Exception("TripleDES шифрование в буфер не работает");
            });

            await RunTestAsync("TripleDES Шифрование бинарного файла", async () =>
            {
                using var context = new CipherContext(
                    new TripleDES(),
                    key,
                    EncryptionMode.RandomDelta,
                    PaddingMode.ISO10126,
                    iv);

                string filePathInput = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem.jpg";
                string filePathEncrypt = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem_tripledes_encrypt.jpg";
                string filePathDecrypt = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem_tripledes_decrypt.jpg";

                await context.Encrypt(filePathInput, filePathEncrypt, 1024);
                await context.Decrypt(filePathEncrypt, filePathDecrypt, 1024);

                FileInfo fileInfoInput = new FileInfo(filePathInput);
                FileInfo fileInfoDecrypt = new FileInfo(filePathDecrypt);
                
                if (fileInfoInput.Length != fileInfoDecrypt.Length)
                {
                    throw new Exception(
                        $"Длины оригинального файла {fileInfoInput.Length} и расшифрованного различаются {fileInfoDecrypt.Length}");
                }
            });
        }

        public static async Task TestTripleDESEdgeCases()
        {
            Console.WriteLine("\n=== Тестирование граничных случаев TripleDES ===\n");

            byte[] key = GenerateKey(24);
            byte[] iv = GenerateKey(8);

            await RunTestAsync("TripleDES Пустые данные", async () =>
            {
                using var context = new CipherContext(
                    new TripleDES(),
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

            await RunTestAsync("TripleDES Крайне короткие данные", async () =>
            {
                using var context = new CipherContext(
                    new TripleDES(),
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

            RunTest("TripleDES Обработка исключений - неверный ключ", () =>
            {
                var tripleDes = new TripleDES();
                byte[] invalidKey = new byte[16]; // Неправильный размер

                try
                {
                    tripleDes.Initialize(invalidKey);
                    throw new Exception("Ожидалось исключение для неверного ключа");
                }
                catch (ArgumentException)
                {
                    // Ожидаемое поведение
                }
            });

            RunTest("TripleDES Обработка исключений - неверный IV", () =>
            {
                try
                {
                    byte[] invalidIV = new byte[4]; // Неверный размер IV
                    using var context = new CipherContext(
                        new TripleDES(),
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

            await RunTestAsync("TripleDES Проверка очистки ресурсов (Dispose)", async () =>
            {
                var context = new CipherContext(
                    new TripleDES(),
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

            await RunTestAsync("TripleDES Параллельное шифрование", async () =>
            {
                using var context = new CipherContext(
                    new TripleDES(),
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

            await RunTestAsync("TripleDES Большие данные", async () =>
            {
                using var context = new CipherContext(
                    new TripleDES(),
                    key,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);

                // Тестируем с данными размером 10 МБ
                byte[] largeData = new byte[10 * 1024 * 1024];
                RandomNumberGenerator.Fill(largeData);

                byte[] encrypted = await context.Encrypt(largeData);
                byte[] decrypted = await context.Decrypt(encrypted);

                if (!largeData.SequenceEqual(decrypted))
                    throw new Exception("Большие данные обрабатываются некорректно");
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
                // Игнорируем ошибки при удалении
            }
        }
    }
}