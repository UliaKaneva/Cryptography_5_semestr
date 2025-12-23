using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cryptography.Core.Algorithms.RC4;

namespace RC4ConsoleTests
{
    class TestsRC4
    {
        static int passedTests = 0;
        static int failedTests = 0;

        public static void RunAllTests()
        {
            Console.WriteLine("=== ТЕСТИРОВАНИЕ RC4 ===");
            Console.WriteLine();

            try
            {
                TestBasicFunctionality();
                TestKeySizes();
                TestEdgeCases();
                TestPerformance();
                TestKnownVectors();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ОШИБКА: {ex.Message}");
                Console.WriteLine($"StackTrace: {ex.StackTrace}");
            }

            Console.WriteLine();
            Console.WriteLine("=== РЕЗУЛЬТАТЫ ===");
            Console.WriteLine($"Всего тестов: {passedTests + failedTests}");
            Console.WriteLine($"Пройдено: {passedTests}");
            Console.WriteLine($"Не пройдено: {failedTests}");
            Console.WriteLine($"Успешность: {Math.Round(passedTests * 100.0 / (passedTests + failedTests), 2)}%");

            if (failedTests == 0)
            {
                Console.WriteLine("ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!");
            }
        }
        

        static void TestBasicFunctionality()
        {
            Console.WriteLine("=== ТЕСТ БАЗОВОЙ ФУНКЦИОНАЛЬНОСТИ ===");

            // Тест 1: Инициализация с валидным ключом
            RunTest("Инициализация RC4 с ключом 16 байт", () =>
            {
                var rc4 = new RC4();
                var key = new byte[16];
                Array.Fill(key, (byte)1);
                rc4.Initialize(key);
                return rc4.IsInitialized;
            });

            // Тест 2: Шифрование и дешифрование
            RunTest("Шифрование/дешифрование данных", () =>
            {
                var rc4 = new RC4();
                var key = Encoding.UTF8.GetBytes("1234567890123456");
                var plaintext = Encoding.UTF8.GetBytes("Hello World!!! This is a test message for RC4 algorithm.");

                rc4.Initialize(key);
                var ciphertext = rc4.Encrypt(plaintext);
                rc4.Reset();
                var decrypted = rc4.Decrypt(ciphertext);
                var result = Encoding.UTF8.GetString(decrypted);

                return result == "Hello World!!! This is a test message for RC4 algorithm.";
            });

            // Тест 3: Симметричность (с Reset)
            RunTest("Симметричность шифрования/дешифрования (с Reset)", () =>
            {
                var rc4 = new RC4();
                var key = new byte[16];
                Array.Fill(key, (byte)42);
                var data = Encoding.UTF8.GetBytes("Test data");

                rc4.Initialize(key);
                var encrypted1 = rc4.Encrypt(data);
                rc4.Reset();
                var encrypted2 = rc4.Encrypt(data);

                return encrypted1.SequenceEqual(encrypted2);
            });

            // Тест 4: Без Reset получаем разные результаты
            RunTest("Без Reset получаем разные результаты", () =>
            {
                var rc4 = new RC4();
                var key = new byte[16];
                Array.Fill(key, (byte)42);
                var data = Encoding.UTF8.GetBytes("Test data");

                rc4.Initialize(key);
                var encrypted1 = rc4.Encrypt(data);
                // Не вызываем Reset
                var encrypted2 = rc4.Encrypt(data);

                return !encrypted1.SequenceEqual(encrypted2);
            });

            // Тест 5: Генерация раундовых ключей (должна возвращать пустой массив)
            RunTest("Генерация раундовых ключей", () =>
            {
                var rc4 = new RC4();
                var key = new byte[16];
                var roundKeys = rc4.GenerateRoundKeys(key);
                return roundKeys != null && roundKeys.Length == 0;
            });

            // Тест 6: Переинициализация
            RunTest("Переинициализация с новым ключом", () =>
            {
                var rc4 = new RC4();
                var key1 = Encoding.UTF8.GetBytes("FirstKey12345678");
                var key2 = Encoding.UTF8.GetBytes("SecondKey1234567");
                var data = Encoding.UTF8.GetBytes("Test data");

                rc4.Initialize(key1);
                var encryptedWithKey1 = rc4.Encrypt(data);
                rc4.Initialize(key2);
                var encryptedWithKey2 = rc4.Encrypt(data);

                return !encryptedWithKey1.SequenceEqual(encryptedWithKey2);
            });
        }

        static void TestKeySizes()
        {
            Console.WriteLine();
            Console.WriteLine("=== ТЕСТИРОВАНИЕ РАЗНЫХ РАЗМЕРОВ КЛЮЧЕЙ ===");

            var keySizes = new[] { 5, 7, 8, 10, 12, 16, 24, 32 };
            var testMessage = "Test message for key size ";

            foreach (var keySize in keySizes)
            {
                RunTest($"Ключ {keySize} байт ({keySize * 8} бит)", () =>
                {
                    var rc4 = new RC4();
                    var key = new byte[keySize];
                    Array.Fill(key, (byte)keySize);
                    var plaintext = Encoding.UTF8.GetBytes(testMessage + keySize);

                    rc4.Initialize(key);
                    var ciphertext = rc4.Encrypt(plaintext);
                    rc4.Reset();
                    var decrypted = rc4.Decrypt(ciphertext);

                    return plaintext.SequenceEqual(decrypted);
                });
            }

            // Тест на слишком короткий ключ
            RunTest("Слишком короткий ключ (4 байта)", () =>
            {
                try
                {
                    var rc4 = new RC4();
                    var key = new byte[4];
                    rc4.Initialize(key);
                    return false; // Не должно дойти сюда
                }
                catch (ArgumentException ex)
                {
                    return ex.Message.Contains("between 5 and 256 bytes");
                }
            });

            // Тест на слишком длинный ключ
            RunTest("Слишком длинный ключ (257 байт)", () =>
            {
                try
                {
                    var rc4 = new RC4();
                    var key = new byte[257];
                    rc4.Initialize(key);
                    return false; // Не должно дойти сюда
                }
                catch (ArgumentException ex)
                {
                    return ex.Message.Contains("between 5 and 256 bytes");
                }
            });
        }

        static void TestEdgeCases()
        {
            Console.WriteLine();
            Console.WriteLine("=== ТЕСТИРОВАНИЕ ГРАНИЧНЫХ СЛУЧАЕВ ===");

            // Тест с пустыми данными
            RunTest("Пустые данные", () =>
            {
                var rc4 = new RC4();
                var key = new byte[16];
                rc4.Initialize(key);
                var encrypted = rc4.Encrypt(Array.Empty<byte>());
                rc4.Reset();
                var decrypted = rc4.Decrypt(Array.Empty<byte>());
                return encrypted.Length == 0 && decrypted.Length == 0;
            });

            // Тест с одним байтом
            RunTest("Однобайтовые данные", () =>
            {
                var rc4 = new RC4();
                var key = new byte[16];
                var data = new byte[] { 0x42 };

                rc4.Initialize(key);
                var encrypted = rc4.Encrypt(data);
                rc4.Reset();
                var decrypted = rc4.Decrypt(encrypted);

                return data[0] == decrypted[0];
            });

            // Тест с большими данными
            RunTest("Большие объемы данных (1 МБ)", () =>
            {
                var rc4 = new RC4();
                var key = new byte[24];
                var random = new Random(42);
                
                var largeData = new byte[1024 * 1024]; // 1 МБ
                random.NextBytes(largeData);

                rc4.Initialize(key);
                var encrypted = rc4.Encrypt(largeData);
                rc4.Reset();
                var decrypted = rc4.Decrypt(encrypted);

                return largeData.SequenceEqual(decrypted);
            });

            // Тест с бинарными данными (все байты 0-255)
            RunTest("Бинарные данные (все байты 0-255)", () =>
            {
                var rc4 = new RC4();
                var key = new byte[24];
                var random = new Random(12345);
                random.NextBytes(key);
                
                var binaryData = new byte[256];
                for (int i = 0; i < binaryData.Length; i++)
                {
                    binaryData[i] = (byte)i;
                }

                rc4.Initialize(key);
                var encrypted = rc4.Encrypt(binaryData);
                rc4.Reset();
                var decrypted = rc4.Decrypt(encrypted);

                return binaryData.SequenceEqual(decrypted);
            });

            // Тест исключений
            RunTest("Исключение при неверном ключе", () =>
            {
                try
                {
                    var rc4 = new RC4();
                    rc4.Initialize(new byte[3]); // Слишком короткий ключ
                    return false;
                }
                catch (ArgumentException)
                {
                    return true;
                }
            });

            RunTest("Исключение при null ключе", () =>
            {
                try
                {
                    var rc4 = new RC4();
                    rc4.Initialize(null);
                    return false;
                }
                catch (ArgumentException)
                {
                    return true;
                }
            });

            // Тест параллельности
            RunTest("Параллельное шифрование (разные экземпляры)", () =>
            {
                var key = new byte[16];
                var data = Encoding.UTF8.GetBytes("Test data");
                var results = new List<bool>();
                var tasks = new List<Task>();
                var random = new Random();

                for (int i = 0; i < 10; i++)
                {
                    tasks.Add(Task.Run(() =>
                    {
                        var rc4 = new RC4();
                        var threadKey = new byte[16];
                        random.NextBytes(threadKey);
                        
                        rc4.Initialize(threadKey);
                        var encrypted = rc4.Encrypt(data);
                        rc4.Reset();
                        var decrypted = rc4.Decrypt(encrypted);
                        
                        lock (results)
                        {
                            results.Add(data.SequenceEqual(decrypted));
                        }
                    }));
                }

                Task.WaitAll(tasks.ToArray());
                return results.All(r => r) && results.Count == 10;
            });

            // Тест Reset без инициализации
            RunTest("Reset без инициализации вызывает исключение", () =>
            {
                try
                {
                    var rc4 = new RC4();
                    rc4.Reset();
                    return false;
                }
                catch (InvalidOperationException)
                {
                    return true;
                }
            });

            // Тест шифрования без инициализации
            RunTest("Шифрование без инициализации вызывает исключение", () =>
            {
                try
                {
                    var rc4 = new RC4();
                    rc4.Encrypt(new byte[10]);
                    return false;
                }
                catch (InvalidOperationException)
                {
                    return true;
                }
            });
        }

        static void TestPerformance()
        {
            Console.WriteLine();
            Console.WriteLine("=== ТЕСТИРОВАНИЕ ПРОИЗВОДИТЕЛЬНОСТИ ===");

            var rc4 = new RC4();
            var key = new byte[16];
            var dataSizes = new[] { 1024, 1024 * 1024, 10 * 1024 * 1024 }; // 1KB, 1MB, 10MB

            foreach (var size in dataSizes)
            {
                var data = new byte[size];
                new Random(42).NextBytes(data);

                // Разогрев
                rc4.Initialize(key);
                rc4.Encrypt(new byte[1024]);

                // Тест
                rc4.Reset();
                var stopwatch = Stopwatch.StartNew();
                var encrypted = rc4.Encrypt(data);
                stopwatch.Stop();

                var speed = size / stopwatch.Elapsed.TotalSeconds / 1024 / 1024; // MB/s
                Console.WriteLine($"Размер: {size / 1024} KB - Время: {stopwatch.Elapsed.TotalMilliseconds:F2} мс - Скорость: {speed:F2} MB/s");

                // Проверяем, что дешифрование работает
                rc4.Reset();
                var decrypted = rc4.Decrypt(encrypted);
                if (!data.SequenceEqual(decrypted))
                {
                    Console.WriteLine($"  ОШИБКА: данные не совпадают после дешифрования!");
                    failedTests++;
                }
                else
                {
                    Console.WriteLine($"  OK: данные корректно дешифрованы");
                }
            }

            passedTests++; // Считаем весь блок тестов производительности за один пройденный
        }

        static void TestKnownVectors()
        {
            Console.WriteLine();
            Console.WriteLine("=== ТЕСТИРОВАНИЕ С ИЗВЕСТНЫМИ ВЕКТОРАМИ ===");

            // Тест 2: RFC 6229 Test Vector 1 (40-bit key)
            RunTest("RFC 6229 Test Vector 1 (40-bit key)", () =>
            {
                var rc4 = new RC4();
                var key = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
                var plaintext = new byte[256]; // Все нули
                
                rc4.Initialize(key);
                var keystream = rc4.Encrypt(plaintext);
                
                var expectedFirst16Bytes = new byte[] 
                {
                    0xB2, 0x39, 0x63, 0x05, 0xF0, 0x3D, 0xC0, 0x27,
                    0xCC, 0xC3, 0x52, 0x4A, 0x0A, 0x11, 0x18, 0xA8
                };
                
                return keystream.Take(16).SequenceEqual(expectedFirst16Bytes);
            });

            // Тест 3: RFC 6229 Test Vector 2 (56-bit key)
            RunTest("RFC 6229 Test Vector 2 (56-bit key)", () =>
            {
                var rc4 = new RC4();
                var key = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
                var plaintext = new byte[256];
                
                rc4.Initialize(key);
                var keystream = rc4.Encrypt(plaintext);
                
                var expectedFirst16Bytes = new byte[] 
                {
                    0x29, 0x3F, 0x02, 0xD4, 0x7F, 0x37, 0xC9, 0xB6,
                    0x33, 0xF2, 0xAF, 0x52, 0x85, 0xFE, 0xB4, 0x6B
                };
                
                return keystream.Take(16).SequenceEqual(expectedFirst16Bytes);
            });

            // Тест 4: Проверка свойства симметричности на рандомных данных
            RunTest("Симметричность на случайных данных", () =>
            {
                var rc4 = new RC4();
                var random = new Random(42);
                
                for (int i = 0; i < 100; i++)
                {
                    var key = new byte[random.Next(5, 33)];
                    random.NextBytes(key);
                    
                    var data = new byte[random.Next(1, 1000)];
                    random.NextBytes(data);
                    
                    rc4.Initialize(key);
                    var encrypted = rc4.Encrypt(data);
                    rc4.Reset();
                    var decrypted = rc4.Decrypt(encrypted);
                    
                    if (!data.SequenceEqual(decrypted))
                    {
                        Console.WriteLine($"  Ошибка на итерации {i}: key={key.Length}b, data={data.Length}b");
                        return false;
                    }
                }
                return true;
            });

            // Тест 5: Разные ключи дают разный шифртекст для одинаковых данных
            RunTest("Разные ключи → разный шифртекст", () =>
            {
                var plaintext = Encoding.UTF8.GetBytes("Same plaintext");
                var ciphertexts = new HashSet<string>();
                
                for (int i = 0; i < 100; i++)
                {
                    var rc4 = new RC4();
                    var key = new byte[16];
                    new Random(i).NextBytes(key);
                    
                    rc4.Initialize(key);
                    var ciphertext = rc4.Encrypt(plaintext);
                    var hex = BitConverter.ToString(ciphertext);
                    
                    if (ciphertexts.Contains(hex))
                    {
                        Console.WriteLine($"  Коллизия на итерации {i}");
                        return false;
                    }
                    ciphertexts.Add(hex);
                }
                return true;
            });
        }

        static void RunTest(string testName, Func<bool> testAction)
        {
            try
            {
                Console.Write($"Тест: {testName}... ");
                
                var success = testAction();
                
                if (success)
                {
                    Console.WriteLine("УСПЕХ");
                    passedTests++;
                }
                else
                {
                    Console.WriteLine("ОШИБКА");
                    failedTests++;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ОШИБКА: {ex.Message}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"  Внутреннее исключение: {ex.InnerException.Message}");
                }
                failedTests++;
            }
        }
    }
    
}