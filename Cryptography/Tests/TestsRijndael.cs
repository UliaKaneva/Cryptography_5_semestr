using System.Security.Cryptography;
using System.Text;
using Cryptography.Core;
using Cryptography.Core.Enums;
using PaddingMode = Cryptography.Core.Enums.PaddingMode;
using Rijndael = Cryptography.Core.Algorithms.Rijndael.Rijndael;

namespace Cryptography.Tests
{
    class TestsRijndael
    {
        static int testCount = 0;
        static int passedCount = 0;
        static int failedCount = 0;

        public static async Task RunAllTests()
        {
            Console.WriteLine("=== Тестирование алгоритма Rijndael ===\n");

            try
            {
                TestRijndaelAlgorithmBasic();
                await TestRijndaelAlgorithmDifferentSizes();
                await TestRijndaelCipherContextModes();
                await TestRijndaelFileOperations();
                await TestRijndaelEdgeCases();
                await TestRijndaelPerformance();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nОшибка при выполнении тестов: {ex.Message}");
                Console.WriteLine($"StackTrace: {ex.StackTrace}");
            }

            Console.WriteLine("\n=== Результаты тестирования Rijndael ===");
            Console.WriteLine($"Всего тестов: {testCount}");
            Console.WriteLine($"Пройдено: {passedCount}");
            Console.WriteLine($"Не пройдено: {failedCount}");
            Console.WriteLine(
                $"Успешность: {(testCount > 0 ? (passedCount * 100.0 / testCount).ToString("F2") : "0")}%");

            if (failedCount == 0)
                Console.WriteLine("\nВсе тесты Rijndael пройдены успешно!");
            else
                Console.WriteLine($"\nНайдены ошибки в Rijndael: {failedCount} тестов не пройдено");
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
                Console.WriteLine("ОШИБКА");
                Console.WriteLine($"   Сообщение: {ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"   Внутренняя ошибка: {ex.InnerException.Message}");
                Console.WriteLine($"   StackTrace: {ex.StackTrace}");
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
                Console.WriteLine("ОШИБКА");
                Console.WriteLine($"   Сообщение: {ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"   Внутренняя ошибка: {ex.InnerException.Message}");
                Console.WriteLine($"   StackTrace: {ex.StackTrace}");
            }
        }

        public static void TestRijndaelAlgorithmBasic()
        {
            Console.WriteLine("\n=== Тестирование базовой функциональности Rijndael ===\n");

            RunTest("Инициализация Rijndael-128/128", () =>
            {
                var rijndael = new Rijndael();
                byte[] key = GenerateKey(16);
                rijndael.Initialize(key);

                if (!rijndael.IsInitialized)
                    throw new Exception("Rijndael не инициализирован");

                if (rijndael.BlockSize != 16)
                    throw new Exception($"Неверный размер блока: {rijndael.BlockSize} байт, ожидается 16");

                if (rijndael.RoundsCount != 10)
                    throw new Exception($"Неверное количество раундов: {rijndael.RoundsCount}, ожидается 10 для 128-битного ключа");
            });

            RunTest("Инициализация Rijndael-128/256", () =>
            {
                var rijndael = new Rijndael(16, 0x1B);
                byte[] key = GenerateKey(32);
                rijndael.Initialize(key);

                if (rijndael.RoundsCount != 14)
                    throw new Exception($"Неверное количество раундов: {rijndael.RoundsCount}, ожидается 14 для 256-битного ключа");
            });

            RunTest("Шифрование/дешифрование одного блока Rijndael-128/128", () =>
            {
                var rijndael = new Rijndael(16, 0x1B);
                byte[] key = new byte[16];
                RandomNumberGenerator.Fill(key);
                rijndael.Initialize(key);

                byte[] plaintext = [0x2D, 0x8F, 0x1E, 0xC3, 0x76, 0xA9, 0x4B, 0xF5, 0x30, 0x9C, 0xE2, 0x57, 0x0A, 0xBD, 0x64, 0xD8];
                RandomNumberGenerator.Fill(plaintext);
                
                byte[] ciphertext = rijndael.EncryptBlock(plaintext);
                byte[] decrypted = rijndael.DecryptBlock(ciphertext);
                
                if (!plaintext.SequenceEqual(decrypted))
                {
                    Console.WriteLine($"Оригинал: {BitConverter.ToString(plaintext)}");
                    Console.WriteLine($"Расшифровано: {BitConverter.ToString(decrypted)}");
                    throw new Exception("Дешифрованный текст не совпадает с оригиналом");
                }
            });

            RunTest("Шифрование/дешифрование нескольких блоков Rijndael", () =>
            {
                var rijndael = new Rijndael(16, 0x1B);
                byte[] key = GenerateKey(16);
                rijndael.Initialize(key);

                string text = "Hello World!!! This is a test message for Rijndael algorithm. It's longer than one block.";
                byte[] plaintext = Encoding.UTF8.GetBytes(text);
                byte[] ciphertext = rijndael.Encrypt(plaintext);
                byte[] decrypted = rijndael.Decrypt(ciphertext);

                string decryptedText = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
                if (text != decryptedText)
                {
                    Console.WriteLine($"Ожидалось: {text}");
                    Console.WriteLine($"Получено: {decryptedText}");
                    throw new Exception("Дешифрованный текст не совпадает с оригиналом");
                }
            });

            RunTest("Генерация раундовых ключей Rijndael", () =>
            {
                var rijndael = new Rijndael(16, 0x1B);
                byte[] key = GenerateKey(16);
                byte[][] roundKeys = rijndael.GenerateRoundKeys(key);

                if (roundKeys == null)
                    throw new Exception("Раундовые ключи не сгенерированы");

                if (roundKeys.Length != 44)
                    throw new Exception($"Неверное количество раундовых ключей: {roundKeys.Length}, ожидается 44");

                foreach (var roundKey in roundKeys)
                {
                    if (roundKey.Length != 4)
                        throw new Exception($"Неверный размер раундового ключа: {roundKey.Length}, ожидается 4");
                }
            });
        }

        public static async Task TestRijndaelAlgorithmDifferentSizes()
        {
            Console.WriteLine("\n=== Тестирование Rijndael с разными размерами ключей и блоков ===\n");

            var testCases = new[]
            {
                (blockSize: 16, keySize: 16, rounds: 10, description: "Rijndael-128/128 (AES-128)"),
                (blockSize: 16, keySize: 24, rounds: 12, description: "Rijndael-128/192 (AES-192)"),
                (blockSize: 16, keySize: 32, rounds: 14, description: "Rijndael-128/256 (AES-256)"),
                (blockSize: 24, keySize: 16, rounds: 12, description: "Rijndael-192/128"),
                (blockSize: 24, keySize: 24, rounds: 12, description: "Rijndael-192/192"),
                (blockSize: 24, keySize: 32, rounds: 14, description: "Rijndael-192/256"),
                (blockSize: 32, keySize: 16, rounds: 14, description: "Rijndael-256/128"),
                (blockSize: 32, keySize: 24, rounds: 14, description: "Rijndael-256/192"),
                (blockSize: 32, keySize: 32, rounds: 14, description: "Rijndael-256/256")
            };

            foreach (var (blockSize, keySize, expectedRounds, description) in testCases)
            {
                await RunTestAsync($"{description} - проверка раундов", async () =>
                {
                    var rijndael = new Rijndael(blockSize, 0x1B);
                    byte[] key = GenerateKey(keySize);
                    rijndael.Initialize(key);

                    if (rijndael.RoundsCount != expectedRounds)
                        throw new Exception($"Ожидалось {expectedRounds} раундов, получено {rijndael.RoundsCount}");
                });

                await RunTestAsync($"{description} - шифрование/дешифрование", async () =>
                {
                    var rijndael = new Rijndael(blockSize, 0x1B);
                    byte[] key = GenerateKey(keySize);
                    rijndael.Initialize(key);

                    byte[] plaintext = new byte[blockSize];
                    RandomNumberGenerator.Fill(plaintext);

                    byte[] ciphertext = rijndael.EncryptBlock(plaintext);
                    byte[] decrypted = rijndael.DecryptBlock(ciphertext);

                    if (!plaintext.SequenceEqual(decrypted))
                        throw new Exception($"Ошибка в {description}");
                });
            }
        }

        public static async Task TestRijndaelCipherContextModes()
        {
            Console.WriteLine("\n=== Тестирование CipherContext с Rijndael и различными режимами ===\n");

            byte[] key = GenerateKey(16);
            byte[] iv = GenerateKey(16);
            string testData = "This is a test message for Rijndael encryption. " +
                             "It should be long enough to require multiple blocks.";

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
                await RunTestAsync($"Rijndael - режим {modeName} - шифрование/дешифрование", async () =>
                {
                    using var context = new CipherContext(
                        new Rijndael(16, 0x1B),
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
                    await RunTestAsync($"Rijndael - режим {modeName} - проверка зависимости от IV", async () =>
                    {
                        byte[] iv2 = GenerateKey(16);

                        using var context1 = new CipherContext(
                            new Rijndael(16, 0x1B), key, mode, PaddingMode.PKCS7, iv);
                        using var context2 = new CipherContext(
                            new Rijndael(16, 0x1B), key, mode, PaddingMode.PKCS7, iv2);

                        byte[] plaintext = Encoding.UTF8.GetBytes(testData);
                        byte[] encrypted1 = await context1.Encrypt(plaintext);
                        byte[] encrypted2 = await context2.Encrypt(plaintext);

                        if (encrypted1.SequenceEqual(encrypted2))
                            throw new Exception($"IV не влияет на результат в режиме {modeName}");
                    });
                }
            }
            
            var keySizes = new[] { 16, 24, 32 };
            foreach (var keySize in keySizes)
            {
                await RunTestAsync($"Rijndael с ключом {keySize * 8} бит в режиме CBC", async () =>
                {
                    byte[] testKey = GenerateKey(keySize);
                    byte[] testIv = GenerateKey(16);

                    using var context = new CipherContext(
                        new Rijndael(16, 0x1B),
                        testKey,
                        EncryptionMode.CBC,
                        PaddingMode.PKCS7,
                        testIv);

                    byte[] plaintext = Encoding.UTF8.GetBytes(testData);
                    byte[] encrypted = await context.Encrypt(plaintext);
                    byte[] decrypted = await context.Decrypt(encrypted);

                    string result = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
                    if (testData != result)
                        throw new Exception($"Ошибка с ключом {keySize * 8} бит");
                });
            }
            
            var paddingModes = new[]
            {
                (PaddingMode.Zeros, "Zero"),
                (PaddingMode.PKCS7, "PKCS7"),
                (PaddingMode.ANSIX923, "ANSIX923"),
                (PaddingMode.ISO10126, "ISO10126")
            };

            foreach (var (paddingMode, paddingName) in paddingModes)
            {
                await RunTestAsync($"Rijndael - паддинг {paddingName}", async () =>
                {
                    using var context = new CipherContext(
                        new Rijndael(16, 0x1B),
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

        public static async Task TestRijndaelFileOperations()
        {
            Console.WriteLine("\n=== Тестирование файловых операций с Rijndael ===\n");

            byte[] key = GenerateKey(16);
            byte[] iv = GenerateKey(16);
            
            string testFilePath = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_input.txt";
            string encryptedFilePath = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_encrypted_rijndael.txt";
            string decryptedFilePath = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_decrypted_rijndael.txt";
            
            CleanupFile(encryptedFilePath);
            CleanupFile(decryptedFilePath);

            await RunTestAsync("Rijndael - шифрование/дешифрование файла", async () =>
            {
                using var context = new CipherContext(
                    new Rijndael(16, 0x1B),
                    key,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);

                await context.Encrypt(testFilePath, encryptedFilePath, 4096);
                await context.Decrypt(encryptedFilePath, decryptedFilePath, 4096);

                string original = await File.ReadAllTextAsync(testFilePath, Encoding.UTF8);
                string decrypted = await File.ReadAllTextAsync(decryptedFilePath, Encoding.UTF8);

                if (original != decrypted)
                    throw new Exception("Потоковое шифрование/дешифрование не работает");
            });

            await RunTestAsync("Rijndael - шифрование в буфер", async () =>
            {
                using var context = new CipherContext(
                    new Rijndael(16, 0x1B),
                    key,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);

                byte[] plaintext = Encoding.UTF8.GetBytes("Test buffer encryption with Rijndael");
                byte[] outputBuffer = new byte[512];

                int encryptedLength = await context.Encrypt(plaintext, outputBuffer);
                if (encryptedLength <= 0)
                    throw new Exception("Ошибка при шифровании в буфер");

                byte[] encryptedData = outputBuffer.Take(encryptedLength).ToArray();
                byte[] decryptedBuffer = new byte[512];

                int decryptedLength = await context.Decrypt(encryptedData, decryptedBuffer);
                if (decryptedLength <= 0)
                    throw new Exception("Ошибка при дешифровании из буфера");

                string result = Encoding.UTF8.GetString(decryptedBuffer, 0, decryptedLength).TrimEnd('\0');
                if ("Test buffer encryption with Rijndael" != result)
                    throw new Exception("Шифрование в буфер не работает");
            });
        }

        public static async Task TestRijndaelEdgeCases()
        {
            Console.WriteLine("\n=== Тестирование граничных случаев Rijndael ===\n");

            byte[] key = GenerateKey(16);
            byte[] iv = GenerateKey(16);

            await RunTestAsync("Rijndael - пустые данные", async () =>
            {
                using var context = new CipherContext(
                    new Rijndael(16, 0x1B),
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

            await RunTestAsync("Rijndael - крайне короткие данные", async () =>
            {
                using var context = new CipherContext(
                    new Rijndael(16, 0x1B),
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

            await RunTestAsync("Rijndael - данные кратные блоку", async () =>
            {
                using var context = new CipherContext(
                    new Rijndael(16, 0x1B),
                    key,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);
                
                for (int blocks = 1; blocks <= 4; blocks++)
                {
                    byte[] data = new byte[blocks * 16];
                    RandomNumberGenerator.Fill(data);

                    byte[] encrypted = await context.Encrypt(data);
                    byte[] decrypted = await context.Decrypt(encrypted);

                    if (!data.SequenceEqual(decrypted))
                        throw new Exception($"Данные из {blocks} блоков обрабатываются некорректно");
                }
            });

            RunTest("Rijndael - обработка исключений - неверный ключ", () =>
            {
                var rijndael = new Rijndael(16, 0x1B);
                byte[] invalidKey = new byte[10];

                try
                {
                    rijndael.Initialize(invalidKey);
                    throw new Exception("Ожидалось исключение для неверного ключа");
                }
                catch (ArgumentException)
                {
                    // Ожидаемое поведение
                }
            });

            RunTest("Rijndael - обработка исключений - неверный IV", () =>
            {
                try
                {
                    byte[] invalidIV = new byte[8];
                    using var context = new CipherContext(
                        new Rijndael(16, 0x1B),
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

            await RunTestAsync("Rijndael - проверка очистки ресурсов (Dispose)", async () =>
            {
                var context = new CipherContext(
                    new Rijndael(16, 0x1B),
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

            await RunTestAsync("Rijndael - параллельное шифрование", async () =>
            {
                using var context = new CipherContext(
                    new Rijndael(16, 0x1B),
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

        public static async Task TestRijndaelPerformance()
        {
            Console.WriteLine("\n=== Тестирование производительности Rijndael ===\n");

            byte[] key = GenerateKey(16);
            byte[] iv = GenerateKey(16);

            using var context = new CipherContext(
                new Rijndael(16, 0x1B),
                key,
                EncryptionMode.CTR,
                PaddingMode.ISO10126,
                iv);

            await RunTestAsync("Rijndael - шифрование картинки", async () =>
            {
                string filePathInput = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem.jpg";
                string filePathEncrypt = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem_encrypt_rijndael.jpg";
                string filePathDecrypt = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem_decrypt_rijndael.jpg";

                CleanupFile(filePathEncrypt);
                CleanupFile(filePathDecrypt);

                await context.Encrypt(filePathInput, filePathEncrypt, 4096);

                await context.Decrypt(filePathEncrypt, filePathDecrypt, 4096);

                FileInfo fileInfoInput = new FileInfo(filePathInput);
                FileInfo fileInfoDecrypt = new FileInfo(filePathDecrypt);
                FileInfo fileInfoEncrypt = new FileInfo(filePathEncrypt);
                
                if (fileInfoInput.Length != fileInfoDecrypt.Length)
                {
                    throw new Exception(
                        $"Длинны оригинального файла ({fileInfoInput.Length}) и расшифрованного ({fileInfoDecrypt.Length}) различаются");
                }
                
                if (File.ReadAllBytes(filePathInput).SequenceEqual(File.ReadAllBytes(filePathEncrypt)))
                {
                    throw new Exception("Шифрование не изменило файл!");
                }
                
                byte[] originalBytes = File.ReadAllBytes(filePathInput);
                byte[] decryptedBytes = File.ReadAllBytes(filePathDecrypt);
                if (!originalBytes.SequenceEqual(decryptedBytes))
                {
                    throw new Exception("Расшифрованный файл не совпадает с оригиналом!");
                }
            });

            await RunTestAsync("Rijndael - шифрование видео", async () =>
            {
                string filePathInput = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/kot.mp4";
                string filePathEncrypt = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/kot_encrypt_rijndael.mp4";
                string filePathDecrypt = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/kot_decrypt_rijndael.mp4";

                CleanupFile(filePathEncrypt);
                CleanupFile(filePathDecrypt);

                await context.Encrypt(filePathInput, filePathEncrypt, 4096);

                await context.Decrypt(filePathEncrypt, filePathDecrypt, 4096);

                FileInfo fileInfoInput = new FileInfo(filePathInput);
                FileInfo fileInfoDecrypt = new FileInfo(filePathDecrypt);
                
                if (fileInfoInput.Length != fileInfoDecrypt.Length)
                {
                    throw new Exception(
                        $"Длинны оригинального файла ({fileInfoInput.Length}) и расшифрованного ({fileInfoDecrypt.Length}) различаются");
                }
            });
            
            await RunTestAsync("Rijndael - большие данные", async () =>
            {
                using var context = new CipherContext(
                    new Rijndael(16, 0x1B),
                    key,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);
                
                byte[] largeData = new byte[1024 * 1024];
                RandomNumberGenerator.Fill(largeData);

                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                byte[] encrypted = await context.Encrypt(largeData);
                stopwatch.Stop();
                Console.WriteLine($"   Шифрование 1 МБ: {stopwatch.ElapsedMilliseconds} мс");

                stopwatch.Restart();
                byte[] decrypted = await context.Decrypt(encrypted);
                stopwatch.Stop();
                Console.WriteLine($"   Дешифрование 1 МБ: {stopwatch.ElapsedMilliseconds} мс");

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