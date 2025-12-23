using System.Security.Cryptography;
using System.Text;
using Cryptography.Core;
using Cryptography.Core.Enums;
using Cryptography.Cor.Algorithms.FROG;
using PaddingMode = Cryptography.Core.Enums.PaddingMode;

namespace Cryptography.Tests
{
    class TestsFROG
    {
        static int testCount = 0;
        static int passedCount = 0;
        static int failedCount = 0;

        public static async Task RunAllTests()
        {
            Console.WriteLine("=== Тестирование алгоритма FROG ===\n");

            try
            {
                await TestFROGAlgorithmBasic();
                await TestFROGAlgorithmDifferentKeySizes();
                await TestFROGCipherContextModes();
                await TestFROGFileOperations();
                await TestFROGEdgeCases();
                await TestFROGPerformance();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nОшибка при выполнении тестов: {ex.Message}");
                Console.WriteLine($"StackTrace: {ex.StackTrace}");
            }

            Console.WriteLine("\n=== Результаты тестирования FROG ===");
            Console.WriteLine($"Всего тестов: {testCount}");
            Console.WriteLine($"Пройдено: {passedCount}");
            Console.WriteLine($"Не пройдено: {failedCount}");
            Console.WriteLine(
                $"Успешность: {(testCount > 0 ? (passedCount * 100.0 / testCount).ToString("F2") : "0")}%");

            if (failedCount == 0)
                Console.WriteLine("\nВсе тесты FROG пройдены успешно!");
            else
                Console.WriteLine($"\nНайдены ошибки в FROG: {failedCount} тестов не пройдено");
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
            Console.Write($"Тест #{testName}... ");

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

        public static async Task TestFROGAlgorithmBasic()
        {
            Console.WriteLine("\n=== Тестирование базовой функциональности FROG ===\n");

            RunTest("Инициализация FROG с минимальным ключом (5 байт)", () =>
            {
                var frog = new FROG();
                byte[] key = GenerateKey(5);
                frog.Initialize(key);

                if (!frog.IsInitialized)
                    throw new Exception("FROG не инициализирован");

                if (frog.BlockSize != 16)
                    throw new Exception($"Неверный размер блока: {frog.BlockSize} байт, ожидается 16");

                if (frog.RoundsCount != 8)
                    throw new Exception($"Неверное количество раундов: {frog.RoundsCount}, ожидается 8");
            });

            RunTest("Инициализация FROG с максимальным ключом (125 байт)", () =>
            {
                var frog = new FROG();
                byte[] key = GenerateKey(125);
                frog.Initialize(key);

                if (!frog.IsInitialized)
                    throw new Exception("FROG не инициализирован");

                if (frog.RoundsCount != 8)
                    throw new Exception($"Неверное количество раундов: {frog.RoundsCount}, ожидается 8");
            });

            RunTest("Шифрование/дешифрование одного блока FROG", () =>
            {
                var frog = new FROG();
                byte[] key = GenerateKey(16);
                frog.Initialize(key);

                byte[] plaintext = new byte[16];
                RandomNumberGenerator.Fill(plaintext);
                
                byte[] ciphertext = frog.EncryptBlock(plaintext);
                byte[] decrypted = frog.DecryptBlock(ciphertext);
                
                if (!plaintext.SequenceEqual(decrypted))
                {
                    Console.WriteLine($"Оригинал: {BitConverter.ToString(plaintext)}");
                    Console.WriteLine($"Расшифровано: {BitConverter.ToString(decrypted)}");
                    throw new Exception("Дешифрованный текст не совпадает с оригиналом");
                }
            });

            RunTest("Шифрование/дешифрование нескольких блоков FROG", () =>
            {
                var frog = new FROG();
                byte[] key = GenerateKey(16);
                frog.Initialize(key);

                string text = "Hello World!!! This is a test message for FROG algorithm. It's longer than one block.";
                byte[] plaintext = Encoding.UTF8.GetBytes(text);
                
                // Дополняем до размера блока
                int padding = 16 - (plaintext.Length % 16);
                if (padding != 16)
                {
                    byte[] padded = new byte[plaintext.Length + padding];
                    Array.Copy(plaintext, padded, plaintext.Length);
                    plaintext = padded;
                }

                byte[] ciphertext = frog.Encrypt(plaintext);
                byte[] decrypted = frog.Decrypt(ciphertext);

                string decryptedText = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
                string expected = Encoding.UTF8.GetString(plaintext).TrimEnd('\0');
                
                if (expected != decryptedText)
                {
                    Console.WriteLine($"Ожидалось: {expected}");
                    Console.WriteLine($"Получено: {decryptedText}");
                    throw new Exception("Дешифрованный текст не совпадает с оригиналом");
                }
            });

            RunTest("Генерация раундовых ключей FROG", () =>
            {
                var frog = new FROG();
                byte[] key = GenerateKey(16);
                byte[][] roundKeys = frog.GenerateRoundKeys(key);

                if (roundKeys == null)
                    throw new Exception("Раундовые ключи не сгенерированы");

                if (roundKeys.Length != 8)
                    throw new Exception($"Неверное количество раундовых ключей: {roundKeys.Length}, ожидается 8");

                foreach (var roundKey in roundKeys)
                {
                    if (roundKey.Length != 16)
                        throw new Exception($"Неверный размер раундового ключа: {roundKey.Length}, ожидается 16");
                }
            });
        }

        public static async Task TestFROGAlgorithmDifferentKeySizes()
        {
            Console.WriteLine("\n=== Тестирование FROG с разными размерами ключей ===\n");

            // Тестируем различные размеры ключей (минимальный, средние, максимальный)
            var keySizes = new[] { 5, 16, 32, 64, 100, 125 };

            foreach (var keySize in keySizes)
            {
                await RunTestAsync($"FROG - ключ {keySize} байт - инициализация", async () =>
                {
                    var frog = new FROG();
                    byte[] key = GenerateKey(keySize);
                    frog.Initialize(key);

                    if (!frog.IsInitialized)
                        throw new Exception($"FROG не инициализирован с ключом {keySize} байт");
                });

                await RunTestAsync($"FROG - ключ {keySize} байт - шифрование/дешифрование", async () =>
                {
                    var frog = new FROG();
                    byte[] key = GenerateKey(keySize);
                    frog.Initialize(key);

                    byte[] plaintext = new byte[32]; // 2 блока
                    RandomNumberGenerator.Fill(plaintext);

                    byte[] ciphertext = frog.Encrypt(plaintext);
                    byte[] decrypted = frog.Decrypt(ciphertext);

                    if (!plaintext.SequenceEqual(decrypted))
                        throw new Exception($"Ошибка с ключом {keySize} байт");
                });

                await RunTestAsync($"FROG - ключ {keySize} байт - проверка раундовых ключей", async () =>
                {
                    var frog = new FROG();
                    byte[] key = GenerateKey(keySize);
                    byte[][] roundKeys = frog.GenerateRoundKeys(key);

                    if (roundKeys == null || roundKeys.Length != 8)
                        throw new Exception($"Проблема с генерацией ключей для размера {keySize} байт");
                });
            }

            // Тест с недопустимыми размерами ключей
            await RunTestAsync("FROG - обработка слишком короткого ключа (4 байта)", async () =>
            {
                var frog = new FROG();
                byte[] invalidKey = GenerateKey(4);

                try
                {
                    frog.Initialize(invalidKey);
                    throw new Exception("Ожидалось исключение для слишком короткого ключа");
                }
                catch (ArgumentException)
                {
                    // Ожидаемое поведение
                }
            });

            await RunTestAsync("FROG - обработка слишком длинного ключа (126 байт)", async () =>
            {
                var frog = new FROG();
                byte[] invalidKey = GenerateKey(126);

                try
                {
                    frog.Initialize(invalidKey);
                    throw new Exception("Ожидалось исключение для слишком длинного ключа");
                }
                catch (ArgumentException)
                {
                    // Ожидаемое поведение
                }
            });
        }

        public static async Task TestFROGCipherContextModes()
        {
            Console.WriteLine("\n=== Тестирование CipherContext с FROG и различными режимами ===\n");

            byte[] key = GenerateKey(16);
            byte[] iv = GenerateKey(16);
            string testData = "This is a test message for FROG encryption. " +
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
                await RunTestAsync($"FROG - режим {modeName} - шифрование/дешифрование", async () =>
                {
                    using var context = new CipherContext(
                        new FROG(),
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
                    await RunTestAsync($"FROG - режим {modeName} - проверка зависимости от IV", async () =>
                    {
                        byte[] iv2 = GenerateKey(16);

                        using var context1 = new CipherContext(
                            new FROG(), key, mode, PaddingMode.PKCS7, iv);
                        using var context2 = new CipherContext(
                            new FROG(), key, mode, PaddingMode.PKCS7, iv2);

                        byte[] plaintext = Encoding.UTF8.GetBytes(testData);
                        byte[] encrypted1 = await context1.Encrypt(plaintext);
                        byte[] encrypted2 = await context2.Encrypt(plaintext);

                        if (encrypted1.SequenceEqual(encrypted2))
                            throw new Exception($"IV не влияет на результат в режиме {modeName}");
                    });
                }
            }

            // Тестируем различные размеры ключей с CipherContext
            var keySizes = new[] { 5, 32, 64, 125 };
            foreach (var keySize in keySizes)
            {
                await RunTestAsync($"FROG с ключом {keySize} байт в режиме CBC", async () =>
                {
                    byte[] testKey = GenerateKey(keySize);
                    byte[] testIv = GenerateKey(16);

                    using var context = new CipherContext(
                        new FROG(),
                        testKey,
                        EncryptionMode.CBC,
                        PaddingMode.PKCS7,
                        testIv);

                    byte[] plaintext = Encoding.UTF8.GetBytes(testData);
                    byte[] encrypted = await context.Encrypt(plaintext);
                    byte[] decrypted = await context.Decrypt(encrypted);

                    string result = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
                    if (testData != result)
                        throw new Exception($"Ошибка с ключом {keySize} байт");
                });
            }

            // Тестируем различные режимы паддинга
            var paddingModes = new[]
            {
                (PaddingMode.Zeros, "Zero"),
                (PaddingMode.PKCS7, "PKCS7"),
                (PaddingMode.ANSIX923, "ANSIX923"),
                (PaddingMode.ISO10126, "ISO10126")
            };

            foreach (var (paddingMode, paddingName) in paddingModes)
            {
                await RunTestAsync($"FROG - паддинг {paddingName}", async () =>
                {
                    using var context = new CipherContext(
                        new FROG(),
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

        public static async Task TestFROGFileOperations()
        {
            Console.WriteLine("\n=== Тестирование файловых операций с FROG ===\n");

            byte[] key = GenerateKey(16);
            byte[] iv = GenerateKey(16);

            string testFilePath = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_input.txt";
            string encryptedFilePath = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_encrypted_frog.txt";
            string decryptedFilePath = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_decrypted_frog.txt";

            CleanupFile(encryptedFilePath);
            CleanupFile(decryptedFilePath);

            await RunTestAsync("FROG - шифрование/дешифрование файла", async () =>
            {
                using var context = new CipherContext(
                    new FROG(),
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

            await RunTestAsync("FROG - шифрование в буфер", async () =>
            {
                using var context = new CipherContext(
                    new FROG(),
                    key,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);

                byte[] plaintext = Encoding.UTF8.GetBytes("Test buffer encryption with FROG");
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
                if ("Test buffer encryption with FROG" != result)
                    throw new Exception("Шифрование в буфер не работает");
            });
        }

        public static async Task TestFROGEdgeCases()
        {
            Console.WriteLine("\n=== Тестирование граничных случаев FROG ===\n");

            byte[] key = GenerateKey(16);
            byte[] iv = GenerateKey(16);

            await RunTestAsync("FROG - пустые данные", async () =>
            {
                using var context = new CipherContext(
                    new FROG(),
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

            await RunTestAsync("FROG - крайне короткие данные", async () =>
            {
                using var context = new CipherContext(
                    new FROG(),
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

            await RunTestAsync("FROG - данные кратные блоку", async () =>
            {
                using var context = new CipherContext(
                    new FROG(),
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

            RunTest("FROG - обработка исключений - неверный ключ", () =>
            {
                var frog = new FROG();
                byte[] invalidKey = new byte[4]; // Слишком короткий

                try
                {
                    frog.Initialize(invalidKey);
                    throw new Exception("Ожидалось исключение для неверного ключа");
                }
                catch (ArgumentException)
                {
                    // Ожидаемое поведение
                }
            });

            RunTest("FROG - обработка исключений - неверный IV", () =>
            {
                try
                {
                    byte[] invalidIV = new byte[8]; // Неверный размер для FROG
                    using var context = new CipherContext(
                        new FROG(),
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

            await RunTestAsync("FROG - проверка очистки ресурсов (Dispose)", async () =>
            {
                var context = new CipherContext(
                    new FROG(),
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

            await RunTestAsync("FROG - параллельное шифрование", async () =>
            {
                using var context = new CipherContext(
                    new FROG(),
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

            // Тест на устойчивость к нестандартным символам
            await RunTestAsync("FROG - шифрование данных с нулевыми байтами", async () =>
            {
                using var context = new CipherContext(
                    new FROG(),
                    key,
                    EncryptionMode.CBC,
                    PaddingMode.PKCS7,
                    iv);

                byte[] data = new byte[64];
                data[0] = 0xFF;
                data[31] = 0x00;
                data[63] = 0xFF;

                byte[] encrypted = await context.Encrypt(data);
                byte[] decrypted = await context.Decrypt(encrypted);

                if (!data.SequenceEqual(decrypted))
                    throw new Exception("Данные с нулевыми байтами обрабатываются некорректно");
            });
        }

        public static async Task TestFROGPerformance()
        {
            Console.WriteLine("\n=== Тестирование производительности FROG ===\n");

            byte[] key = GenerateKey(16);
            byte[] iv = GenerateKey(16);

            using var context = new CipherContext(
                new FROG(),
                key,
                EncryptionMode.CTR,
                PaddingMode.ISO10126,
                iv);

            await RunTestAsync("FROG - шифрование картинки", async () =>
            {
                string filePathInput = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem.jpg";
                string filePathEncrypt = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem_encrypt_frog.jpg";
                string filePathDecrypt = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem_decrypt_frog.jpg";

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
                        $"Длины оригинального файла ({fileInfoInput.Length}) и расшифрованного ({fileInfoDecrypt.Length}) различаются");
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

            await RunTestAsync("FROG - шифрование видео", async () =>
            {
                string filePathInput = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/kot.mp4";
                string filePathEncrypt = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/kot_encrypt_frog.mp4";
                string filePathDecrypt = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/kot_decrypt_frog.mp4";

                CleanupFile(filePathEncrypt);
                CleanupFile(filePathDecrypt);

                await context.Encrypt(filePathInput, filePathEncrypt, 4096);

                await context.Decrypt(filePathEncrypt, filePathDecrypt, 4096);

                FileInfo fileInfoInput = new FileInfo(filePathInput);
                FileInfo fileInfoDecrypt = new FileInfo(filePathDecrypt);

                if (fileInfoInput.Length != fileInfoDecrypt.Length)
                {
                    throw new Exception(
                        $"Длины оригинального файла ({fileInfoInput.Length}) и расшифрованного ({fileInfoDecrypt.Length}) различаются");
                }
            });

            await RunTestAsync("FROG - большие данные", async () =>
            {
                using var context = new CipherContext(
                    new FROG(),
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

            // Тест производительности с разными размерами ключей
            var perfKeySizes = new[] { 5, 16, 64, 125 };
            foreach (var keySize in perfKeySizes)
            {
                await RunTestAsync($"FROG - производительность с ключом {keySize} байт", async () =>
                {
                    byte[] perfKey = GenerateKey(keySize);
                    using var perfContext = new CipherContext(
                        new FROG(),
                        perfKey,
                        EncryptionMode.CBC,
                        PaddingMode.PKCS7,
                        iv);

                    byte[] testData = new byte[1024 * 128]; // 128 KB
                    RandomNumberGenerator.Fill(testData);

                    var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                    byte[] encrypted = await perfContext.Encrypt(testData);
                    stopwatch.Stop();
                    
                    Console.WriteLine($"   Ключ {keySize} байт: {stopwatch.ElapsedMilliseconds} мс на 128 KB");
                });
            }
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