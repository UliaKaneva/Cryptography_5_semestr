using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Cryptography.Core.Algorithms.RSA;
using Cryptography.Core.Algorithms.RSA.PrimeTests;
using RSA = Cryptography.Core.Algorithms.RSA.RSA;

namespace Cryptography.Tests
{
    class TestsRSA
    {
        static int testCount = 0;
        static int passedCount = 0;
        static int failedCount = 0;

        public static async Task RunAllTests()
        {
            Console.WriteLine("=== Тестирование алгоритма RSA ===\n");

            try
            {
                TestRSABasicFunctionality();
                await TestRSAKeyGeneration();
                await TestRSAEncryptionDecryption();
                await TestRSAFileOperations();
                await TestRSAEdgeCases();
                await TestRSAPerformance();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nОшибка при выполнении тестов: {ex.Message}");
                Console.WriteLine($"StackTrace: {ex.StackTrace}");
            }

            Console.WriteLine("\n=== Результаты тестирования RSA ===");
            Console.WriteLine($"Всего тестов: {testCount}");
            Console.WriteLine($"Пройдено: {passedCount}");
            Console.WriteLine($"Не пройдено: {failedCount}");
            Console.WriteLine(
                $"Успешность: {(testCount > 0 ? (passedCount * 100.0 / testCount).ToString("F2") : "0")}%");

            if (failedCount == 0)
                Console.WriteLine("\nВсе тесты RSA пройдены успешно!");
            else
                Console.WriteLine($"\nНайдены ошибки в RSA: {failedCount} тестов не пройдено");
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

        public static void TestRSABasicFunctionality()
        {
            Console.WriteLine("\n=== Тестирование базовой функциональности RSA ===\n");

            RunTest("Инициализация RSA с MillerRabin", () =>
            {
                var rsa = new RSA(RSA.PrimeTestType.MillerRabin, 0.9999, 1024);

                if (rsa == null)
                    throw new Exception("RSA не инициализирован");
            });

            RunTest("Инициализация RSA с SolovayStrassen", () =>
            {
                var rsa = new RSA(RSA.PrimeTestType.SolovayStrassen, 0.9999, 1024);

                if (rsa == null)
                    throw new Exception("RSA не инициализирован");
            });

            RunTest("Инициализация RSA с Fermat", () =>
            {
                var rsa = new RSA(RSA.PrimeTestType.Fermat, 0.9999, 1024);

                if (rsa == null)
                    throw new Exception("RSA не инициализирован");
            });

            RunTest("Генерация пары ключей RSA-1024", () =>
            {
                var rsa = new RSA(RSA.PrimeTestType.MillerRabin, 0.95, 1024);
                var keyPair = rsa.GenerateNewKeyPair();

                if (keyPair == null)
                    throw new Exception("Пара ключей не сгенерирована");

                if (keyPair.PublicKey.Modulus <= 0)
                    throw new Exception("Некорректный модуль публичного ключа");

                if (keyPair.PrivateKey.Modulus <= 0)
                    throw new Exception("Некорректный модуль приватного ключа");

                if (keyPair.PublicKey.Modulus != keyPair.PrivateKey.Modulus)
                    throw new Exception("Модули публичного и приватного ключей не совпадают");

                Console.WriteLine($"   Модуль: {keyPair.PublicKey.Modulus.GetBitLength()} бит");
            });

            RunTest("Проверка корректности пары ключей", () =>
            {
                var rsa = new RSA(RSA.PrimeTestType.MillerRabin, 0.9999, 1024);
                var keyPair = rsa.GenerateNewKeyPair();

                // Проверяем, что e*d ≡ 1 mod φ(n)
                BigInteger phi = (keyPair.PrivateKey.P - 1) * (keyPair.PrivateKey.Q - 1);
                BigInteger product = keyPair.PublicKey.Exponent * keyPair.PrivateKey.Exponent;
                BigInteger remainder = product % phi;

                if (remainder != 1)
                    throw new Exception($"Не выполняется условие e*d ≡ 1 mod φ(n): {remainder}");

                // Проверяем, что n = p*q
                BigInteger n = keyPair.PrivateKey.P * keyPair.PrivateKey.Q;
                if (n != keyPair.PublicKey.Modulus)
                    throw new Exception("Модуль не равен произведению p и q");
            });
        }

        public static async Task TestRSAKeyGeneration()
        {
            Console.WriteLine("\n=== Тестирование генерации ключей RSA с разными параметрами ===\n");

            var bitLengths = new[] { 128, 256, 512, 1024 };
            var primeTests = new[]
            {
                RSA.PrimeTestType.MillerRabin,
                RSA.PrimeTestType.SolovayStrassen,
                RSA.PrimeTestType.Fermat
            };
            var probabilities = new[] { 0.99, 0.999, 0.9999 };

            foreach (var bitLength in bitLengths)
            {
                await RunTestAsync($"Генерация RSA-{bitLength}", async () =>
                {
                    var rsa = new RSA(RSA.PrimeTestType.MillerRabin, 0.9999, bitLength);
                    var keyPair = rsa.GenerateNewKeyPair();

                    if (keyPair.PublicKey.Modulus.GetBitLength() < bitLength)
                        throw new Exception(
                            $"Сгенерированный ключ имеет длину {keyPair.PublicKey.Modulus.GetBitLength()} бит, ожидалось {bitLength}");
                });
            }

            foreach (var primeTest in primeTests)
            {
                await RunTestAsync($"Генерация с тестом простоты {primeTest}", async () =>
                {
                    var rsa = new RSA(primeTest, 0.9999, 512);
                    var keyPair = rsa.GenerateNewKeyPair();

                    if (keyPair == null)
                        throw new Exception("Пара ключей не сгенерирована");
                });
            }

            foreach (var probability in probabilities)
            {
                await RunTestAsync($"Генерация с вероятностью {probability}", async () =>
                {
                    var rsa = new RSA(RSA.PrimeTestType.MillerRabin, probability, 512);
                    var keyPair = rsa.GenerateNewKeyPair();

                    if (keyPair == null)
                        throw new Exception("Пара ключей не сгенерирована");
                });
            }

            await RunTestAsync("Генерация нескольких пар ключей", async () =>
            {
                var rsa = new RSA(RSA.PrimeTestType.MillerRabin, 0.9999, 512);
                var previousModulus = BigInteger.Zero;

                for (int i = 0; i < 5; i++)
                {
                    var keyPair = rsa.GenerateNewKeyPair();

                    if (keyPair == null)
                        throw new Exception($"Пара ключей #{i + 1} не сгенерирована");

                    // Убедимся, что каждая пара ключей уникальна
                    if (i > 0)
                    {
                        if (keyPair.PublicKey.Modulus == previousModulus)
                            throw new Exception($"Пара ключей #{i + 1} совпадает с предыдущей");
                    }

                    previousModulus = keyPair.PublicKey.Modulus;
                    Console.WriteLine($"   Пара #{i + 1}: модуль {keyPair.PublicKey.Modulus.GetBitLength()} бит");
                }
            });
        }

        public static async Task TestRSAEncryptionDecryption()
        {
            Console.WriteLine("\n=== Тестирование шифрования и дешифрования RSA ===\n");

            var rsa = new RSA(RSA.PrimeTestType.MillerRabin, 0.9999, 1024);
            var keyPair = rsa.GenerateNewKeyPair();

            var testMessages = new[]
            {
                "Hello, RSA!",
                "Тестирование русского текста",
                "1234567890",
                "!@#$%^&*()_+-=[]{}|;:,.<>?",
                "This is a longer message that might be split into multiple blocks for RSA encryption."
            };

            foreach (var message in testMessages)
            {
                await RunTestAsync($"Шифрование/дешифрование: '{message}'", async () =>
                {
                    byte[] plaintext = Encoding.UTF8.GetBytes(message);

                    // Шифруем публичным ключом
                    byte[] encrypted = rsa.Encrypt(plaintext, keyPair.PublicKey);

                    if (encrypted == null || encrypted.Length == 0)
                        throw new Exception("Шифрование вернуло пустой результат");

                    // Расшифровываем приватным ключом
                    byte[] decrypted = rsa.Decrypt(encrypted, keyPair.PrivateKey);

                    if (decrypted == null || decrypted.Length == 0)
                        throw new Exception("Дешифрование вернуло пустой результат");

                    string decryptedText = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');

                    if (message != decryptedText)
                    {
                        Console.WriteLine($"   Оригинал: '{message}'");
                        Console.WriteLine($"   Результат: '{decryptedText}'");
                        throw new Exception("Дешифрованный текст не совпадает с оригиналом");
                    }
                });
            }

            await RunTestAsync("Шифрование/дешифрование блока", async () =>
            {
                byte[] testBlock = new byte[32];
                RandomNumberGenerator.Fill(testBlock);

                byte[] encryptedBlock = rsa.EncryptBlock(testBlock, keyPair.PublicKey);
                byte[] decryptedBlock = rsa.DecryptBlock(encryptedBlock, keyPair.PrivateKey);

                if (!testBlock.SequenceEqual(decryptedBlock))
                    throw new Exception("Дешифрованный блок не совпадает с оригиналом");
            });

            await RunTestAsync("Шифрование/дешифрование больших данных", async () =>
            {
                // Генерируем данные размером 100 байт
                byte[] largeData = new byte[100];
                RandomNumberGenerator.Fill(largeData);

                byte[] encrypted = rsa.Encrypt(largeData, keyPair.PublicKey);
                byte[] decrypted = rsa.Decrypt(encrypted, keyPair.PrivateKey);

                if (!largeData.SequenceEqual(decrypted))
                    throw new Exception("Большие данные обрабатываются некорректно");
            });

            await RunTestAsync("Шифрование чужим ключом, дешифрование своим", async () =>
            {
                // Генерируем вторую пару ключей
                var rsa2 = new RSA(RSA.PrimeTestType.MillerRabin, 0.9999, 1024);
                var keyPair2 = rsa2.GenerateNewKeyPair();

                byte[] testData = Encoding.UTF8.GetBytes("Secret message");

                // Шифруем публичным ключом из первой пары
                byte[] encrypted = rsa.Encrypt(testData, keyPair.PublicKey);

                // Пытаемся расшифровать приватным ключом из второй пары (не должно получиться)
                try
                {
                    byte[] decrypted = rsa2.Decrypt(encrypted, keyPair2.PrivateKey);
                    // Если мы здесь, то расшифрование "успешно", но результат должен быть мусором
                    string decryptedText = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
                    if (decryptedText == "Secret message")
                        throw new Exception("Удалось расшифровать чужим ключом - ошибка безопасности!");
                }
                catch
                {
                    // Ожидаемое поведение - должно выбрасываться исключение
                }
            });
        }

        public static async Task TestRSAFileOperations()
        {
            Console.WriteLine("\n=== Тестирование файловых операций RSA ===\n");

            var rsa = new RSA(RSA.PrimeTestType.MillerRabin, 0.9999, 1024);
            var keyPair = rsa.GenerateNewKeyPair();

            string testFilePath = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_input.txt";
            string encryptedFilePath =
                "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_encrypted_rsa.txt";
            string decryptedFilePath =
                "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/test_decrypted_rsa.txt";

            CleanupFile(encryptedFilePath);
            CleanupFile(decryptedFilePath);

            await RunTestAsync("RSA - шифрование/дешифрование файла (буферизованное)", async () =>
            {
                rsa.EncryptFileBuffered(testFilePath, encryptedFilePath, keyPair.PublicKey);
                rsa.DecryptFileBuffered(encryptedFilePath, decryptedFilePath, keyPair.PrivateKey);

                string original = await File.ReadAllTextAsync(testFilePath, Encoding.UTF8);
                string decrypted = await File.ReadAllTextAsync(decryptedFilePath, Encoding.UTF8);

                if (original != decrypted)
                {
                    Console.WriteLine($"   Оригинал: {original.Length} символов");
                    Console.WriteLine($"   Расшифровано: {decrypted.Length} символов");
                    throw new Exception("Потоковое шифрование/дешифрование не работает");
                }
            });

            await RunTestAsync("RSA - шифрование/дешифрование бинарного файла", async () =>
            {
                string binaryFilePath = "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem.jpg";
                string encryptedBinaryPath =
                    "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem_encrypted_rsa.bin";
                string decryptedBinaryPath =
                    "C:/Users/julie/RiderProjects/Cryptography/Cryptography/Tests/Mem_decrypted_rsa.jpg";

                CleanupFile(encryptedBinaryPath);
                CleanupFile(decryptedBinaryPath);

                rsa.EncryptFileBuffered(binaryFilePath, encryptedBinaryPath, keyPair.PublicKey);
                rsa.DecryptFileBuffered(encryptedBinaryPath, decryptedBinaryPath, keyPair.PrivateKey);

                FileInfo originalInfo = new FileInfo(binaryFilePath);
                FileInfo decryptedInfo = new FileInfo(decryptedBinaryPath);

                if (originalInfo.Length != decryptedInfo.Length)
                    throw new Exception(
                        $"Размеры файлов не совпадают: {originalInfo.Length} vs {decryptedInfo.Length}");

                byte[] originalBytes = File.ReadAllBytes(binaryFilePath);
                byte[] decryptedBytes = File.ReadAllBytes(decryptedBinaryPath);

                if (!originalBytes.SequenceEqual(decryptedBytes))
                    throw new Exception("Бинарные файлы не совпадают после шифрования/дешифрования");
            });
        }

        public static async Task TestRSAEdgeCases()
        {
            Console.WriteLine("\n=== Тестирование граничных случаев RSA ===\n");

            var rsa = new RSA(RSA.PrimeTestType.MillerRabin, 0.9999, 1024);
            var keyPair = rsa.GenerateNewKeyPair();

            await RunTestAsync("RSA - пустые данные", async () =>
            {
                byte[] emptyData = Array.Empty<byte>();

                try
                {
                    byte[] encrypted = rsa.Encrypt(emptyData, keyPair.PublicKey);
                    byte[] decrypted = rsa.Decrypt(encrypted, keyPair.PrivateKey);

                    if (decrypted.Length != 0)
                        throw new Exception("Пустые данные обрабатываются некорректно");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"   Исключение: {ex.Message}");
                    // Пустые данные могут вызывать исключение из-за паддинга
                }
            });

            await RunTestAsync("RSA - очень короткие данные", async () =>
            {
                for (int i = 1; i <= 10; i++)
                {
                    byte[] data = new byte[i];
                    RandomNumberGenerator.Fill(data);

                    byte[] encrypted = rsa.Encrypt(data, keyPair.PublicKey);
                    byte[] decrypted = rsa.Decrypt(encrypted, keyPair.PrivateKey);

                    if (!data.SequenceEqual(decrypted))
                        throw new Exception($"Данные длиной {i} байт обрабатываются некорректно");
                }
            });

            await RunTestAsync("RSA - данные максимального размера", async () =>
            {
                int modulusSize = (int)(keyPair.PublicKey.Modulus.GetBitLength() + 7) / 8;
                int maxDataSize = modulusSize - 11; // Минус размер PKCS#1 паддинга

                byte[] maxData = new byte[maxDataSize];
                RandomNumberGenerator.Fill(maxData);

                byte[] encrypted = rsa.Encrypt(maxData, keyPair.PublicKey);
                byte[] decrypted = rsa.Decrypt(encrypted, keyPair.PrivateKey);

                if (!maxData.SequenceEqual(decrypted))
                    throw new Exception(
                        $"Данные максимального размера ({maxDataSize} байт) обрабатываются некорректно");

                // Пытаемся зашифровать данные больше максимального размера для одного блока
                byte[] tooLargeData = new byte[maxDataSize + 1];
                RandomNumberGenerator.Fill(tooLargeData);

                // Это должно пройти успешно, так как данные будут разбиты на блоки
                byte[] encryptedTooLarge = rsa.Encrypt(tooLargeData, keyPair.PublicKey);
                byte[] decryptedTooLarge = rsa.Decrypt(encryptedTooLarge, keyPair.PrivateKey);

                if (!tooLargeData.SequenceEqual(decryptedTooLarge))
                    throw new Exception("Данные больше максимального размера блока обрабатываются некорректно");
            });

            RunTest("RSA - проверка паддинга PKCS#1", () =>
            {
                byte[] testData = Encoding.UTF8.GetBytes("Test");
                int modulusSize = (int)(keyPair.PublicKey.Modulus.GetBitLength() + 7) / 8;

                // Шифруем блок
                byte[] encryptedBlock = rsa.EncryptBlock(testData, keyPair.PublicKey);

                if (encryptedBlock.Length != modulusSize)
                    throw new Exception(
                        $"Размер зашифрованного блока {encryptedBlock.Length}, ожидалось {modulusSize}");

                // Расшифровываем и проверяем удаление паддинга
                byte[] decryptedBlock = rsa.DecryptBlock(encryptedBlock, keyPair.PrivateKey);

                if (!testData.SequenceEqual(decryptedBlock))
                    throw new Exception("Паддинг PKCS#1 работает некорректно");
            });

            await RunTestAsync("RSA - параллельное шифрование/дешифрование", async () =>
            {
                var tasks = new List<Task>();

                for (int i = 0; i < 5; i++)
                {
                    tasks.Add(Task.Run(async () =>
                    {
                        var localRsa = new RSA(RSA.PrimeTestType.MillerRabin, 0.9999, 1024);
                        var localKeyPair = localRsa.GenerateNewKeyPair();

                        byte[] data = new byte[50];
                        RandomNumberGenerator.Fill(data);

                        byte[] encrypted = localRsa.Encrypt(data, localKeyPair.PublicKey);
                        byte[] decrypted = localRsa.Decrypt(encrypted, localKeyPair.PrivateKey);

                        if (!data.SequenceEqual(decrypted))
                            throw new Exception("Параллельная операция дала некорректный результат");
                    }));
                }

                await Task.WhenAll(tasks);
            });

            RunTest("RSA - обработка исключений - неверный закрытый ключ", () =>
            {
                byte[] testData = Encoding.UTF8.GetBytes("Test message");
                byte[] encrypted = rsa.Encrypt(testData, keyPair.PublicKey);

                // Создаем некорректный закрытый ключ
                var invalidPrivateKey = new RSA.RSAPrivateKey(
                    keyPair.PrivateKey.Exponent + 1, // Изменяем экспоненту
                    keyPair.PrivateKey.Modulus,
                    keyPair.PrivateKey.P,
                    keyPair.PrivateKey.Q);

                try
                {
                    byte[] decrypted = rsa.Decrypt(encrypted, invalidPrivateKey);
                    // Если мы здесь, результат должен быть мусором
                    string decryptedText = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
                    if (decryptedText == "Test message")
                        throw new Exception("Удалось расшифровать с некорректным ключом!");
                }
                catch
                {
                    // Ожидаемое поведение
                }
            });
        }

        public static async Task TestRSAPerformance()
        {
            Console.WriteLine("\n=== Тестирование производительности RSA ===\n");

            var bitLengths = new[] { 512, 1024, 2048 };

            foreach (var bitLength in bitLengths)
            {
                await RunTestAsync($"Производительность RSA-{bitLength} - генерация ключей", async () =>
                {
                    var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                    var rsa = new RSA(RSA.PrimeTestType.MillerRabin, 0.9999, bitLength);
                    var keyPair = rsa.GenerateNewKeyPair();
                    stopwatch.Stop();

                    Console.WriteLine($"   Генерация RSA-{bitLength}: {stopwatch.ElapsedMilliseconds} мс");

                    if (keyPair == null)
                        throw new Exception("Ключи не сгенерированы");
                });
            }

            await RunTestAsync("RSA - шифрование/дешифрование больших данных", async () =>
            {
                var rsa = new RSA(RSA.PrimeTestType.MillerRabin, 0.9999, 2048);
                var keyPair = rsa.GenerateNewKeyPair();

                // Для RSA 2048 бит, максимальный размер данных для шифрования: 256 - 11 = 245 байт
                int modulusSize = (int)(keyPair.PublicKey.Modulus.GetBitLength() + 7) / 8;
                int maxDataSize = modulusSize - 11;

                byte[] data = new byte[maxDataSize];
                RandomNumberGenerator.Fill(data);

                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                byte[] encrypted = rsa.Encrypt(data, keyPair.PublicKey);
                stopwatch.Stop();
                Console.WriteLine($"   Шифрование {maxDataSize} байт: {stopwatch.ElapsedMilliseconds} мс");

                stopwatch.Restart();
                byte[] decrypted = rsa.Decrypt(encrypted, keyPair.PrivateKey);
                stopwatch.Stop();
                Console.WriteLine($"   Дешифрование {maxDataSize} байт: {stopwatch.ElapsedMilliseconds} мс");

                if (!data.SequenceEqual(decrypted))
                    throw new Exception("Большие данные обрабатываются некорректно");
            });
            

            await RunTestAsync("RSA - сравнение разных тестов простоты", async () =>
            {
                var bitLength = 512;
                var testCases = new[]
                {
                    (RSA.PrimeTestType.MillerRabin, "MillerRabin"),
                    (RSA.PrimeTestType.SolovayStrassen, "SolovayStrassen"),
                    (RSA.PrimeTestType.Fermat, "Fermat")
                };

                foreach (var (testType, testName) in testCases)
                {
                    var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                    var rsa = new RSA(testType, 0.9999, bitLength);
                    var keyPair = rsa.GenerateNewKeyPair();
                    stopwatch.Stop();

                    Console.WriteLine($"   {testName}: {stopwatch.ElapsedMilliseconds} мс");

                    if (keyPair == null)
                        throw new Exception($"Ключи не сгенерированы для {testName}");
                }
            });
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