using System;
using System.Numerics;
using Cryptography.Core.Algorithms.RSA;

namespace Cryptography.Tests;
    /// <summary>
    /// Демонстрационный класс для тестирования атаки Винера на RSA
    /// </summary>
    public class TestsWienerAttack
    {
        private readonly WienerAttackService _wienerAttackService = new();
        private readonly Random _random = new();
        public void RunDemo()
        {
            Console.WriteLine("=== Демонстрация атаки Винера на RSA ===\n");
            Console.WriteLine("Тест 1: Атака на сгенерированный уязвимый ключ");
            TestWithGeneratedKey(256);
            Console.WriteLine();

            // Тест 2: Атака на известный уязвимый ключ
            Console.WriteLine("Тест 2: Атака на известный уязвимый ключ");
            TestWithKnownVulnerableKey();
            Console.WriteLine();

            // Тест 3: Атака на безопасный ключ
            Console.WriteLine("Тест 3: Атака на безопасный ключ (должна завершиться неудачей)");
            TestWithSafeKey();
            Console.WriteLine();

            // Тест 4: Массовое тестирование
            Console.WriteLine("Тест 4: Массовое тестирование (5 ключей)");
            RunMassTest(5, 256);
        }
        
        private void TestWithGeneratedKey(int bitLength)
        {
            try
            {
                Console.WriteLine($"Генерация уязвимого RSA ключа ({bitLength} бит)...");
                var keyPair = _wienerAttackService.CreateVulnerableKey(bitLength);
                BigInteger e = keyPair.PublicKey.Exponent;
                BigInteger n = keyPair.PublicKey.Modulus;
                BigInteger d = keyPair.PrivateKey.Exponent;

                Console.WriteLine($"n = {n}");
                Console.WriteLine($"e = {e}");
                Console.WriteLine($"d = {d} (должно быть маленьким для атаки Винера)");
                
                bool isVulnerable = _wienerAttackService.IsKeyVulnerable(d, n);
                Console.WriteLine($"Ключ уязвим для атаки Винера: {isVulnerable}");

                if (isVulnerable)
                {
                    Console.WriteLine("\nЗапуск атаки Винера...");
                    var result = _wienerAttackService.Attack(e, n);
                    
                    Console.WriteLine($"Проверено подходящих дробей: {result.Iterations}");
                    
                    if (result.Success)
                    {
                        Console.WriteLine("Атака успешно проведена");
                        Console.WriteLine($"Найденный d: {result.FoundD}");
                        Console.WriteLine($"Оригинальный d: {d}");
                        Console.WriteLine($"Совпадают: {result.FoundD == d}");
                        Console.WriteLine($"Найденный φ(n): {result.FoundPhi}");
                        Console.WriteLine($"Найденный p: {result.FoundP}");
                        Console.WriteLine($"Найденный q: {result.FoundQ}");
                        Console.WriteLine($"n = p * q: {result.FoundP * result.FoundQ == n}");

                        // Вывод первых 5 подходящих дробей
                        Console.WriteLine("\nПервые 5 подходящих дробей:");
                        for (int i = 0; i < Math.Min(5, result.Convergents.Count); i++)
                        {
                            var conv = result.Convergents[i];
                            Console.WriteLine($"  {i + 1}. k/d = {conv.K}/{conv.D}");
                        }
                    }
                    else
                    {
                        Console.WriteLine("Атака провалена");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
            }
        }
        
        private void TestWithKnownVulnerableKey()
        {
            try
            {
                BigInteger n = BigInteger.Parse("90581");
                BigInteger e = BigInteger.Parse("17993");
                
                Console.WriteLine($"Известный уязвимый ключ:");
                Console.WriteLine($"n = {n}");
                Console.WriteLine($"e = {e}");

                // Выполнение атаки
                Console.WriteLine("\nЗапуск атаки Винера...");
                var result = _wienerAttackService.Attack(e, n);

                
                Console.WriteLine($"Проверено подходящих дробей: {result.Iterations}");
                
                if (result.Success)
                {
                    Console.WriteLine("Атака успешна проведена");
                    Console.WriteLine($"Найденный d: {result.FoundD}");
                    Console.WriteLine($"Найденный φ(n): {result.FoundPhi}");
                    Console.WriteLine($"Найденный p: {result.FoundP}");
                    Console.WriteLine($"Найденный q: {result.FoundQ}");

                    BigInteger originalP = 379;
                    BigInteger originalQ = 239;
                    Console.WriteLine($"Ожидаемый p: {originalP}");
                    Console.WriteLine($"Ожидаемый q: {originalQ}");
                    Console.WriteLine($"Корректность разложения: {result.FoundP == originalP && result.FoundQ == originalQ}");
                }
                else
                {
                    Console.WriteLine($"Атака провалена");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
            }
        }
        private void TestWithSafeKey()
        {
            try
            {
                // Генерация безопасного ключа (большой d)
                Console.WriteLine("Генерация безопасного RSA ключа...");
                RSA rsa = new RSA(bitLength: 128);
                RSA.RSAKeyPair keyPair = rsa.GetCurrentKeyPair();

                BigInteger n = keyPair.PrivateKey.Modulus;
                BigInteger d = keyPair.PrivateKey.Exponent;
                BigInteger e = keyPair.PublicKey.Modulus;
                
                Console.WriteLine($"n = {n}");
                Console.WriteLine($"e = {e}");
                Console.WriteLine($"d = {d} (большое, безопасное)");
                
                // Проверка уязвимости
                bool isVulnerable = _wienerAttackService.IsKeyVulnerable(d, n);
                Console.WriteLine($"Ключ уязвим для атаки Винера: {isVulnerable}");
                
                Console.WriteLine("\nЗапуск атаки Винера...");
                var result = _wienerAttackService.Attack(e, n);
                

                Console.WriteLine($"Атака успешна: {result.Success}");
                Console.WriteLine($"Проверено подходящих дробей: {result.Iterations}");
                
                if (!result.Success)
                {
                    Console.WriteLine("Атака не удалась, как и ожидалось для безопасного ключа");
                }
                else
                {
                    Console.WriteLine("Атака получилась, но так не должно быть");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
            }
        }
        private void RunMassTest(int count, int bitLength)
        {
            int successfulAttacks = 0;
            int vulnerableKeys = 0;
            
            Console.WriteLine($"Запуск массового тестирования на {count} ключах...\n");

            for (int i = 0; i < count; i++)
            {
                Console.WriteLine($"\nКлюч #{i + 1}:");
                
                try
                {
                    var keyPair = _wienerAttackService.CreateVulnerableKey(bitLength);
                    BigInteger e = keyPair.PublicKey.Exponent;
                    BigInteger n = keyPair.PublicKey.Modulus;
                    BigInteger d = keyPair.PrivateKey.Exponent;
                    
                    bool isVulnerable = _wienerAttackService.IsKeyVulnerable(d, n);
                    if (isVulnerable) vulnerableKeys++;

                    // Выполнение атаки
                    var result = _wienerAttackService.Attack(e, n);
                    
                    Console.WriteLine($"  Уязвим: {isVulnerable}");
                    Console.WriteLine($"  Атака успешна: {result.Success}");
                    Console.WriteLine($"  Проверено дробей: {result.Iterations}");
                    
                    if (result.Success)
                    {
                        successfulAttacks++;
                        Console.WriteLine($"  Найденный d совпадает с оригинальным: {result.FoundD == d}");
                    }
                    System.Threading.Thread.Sleep(10);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  Ошибка: {ex.Message}");
                }
            }

            Console.WriteLine($"\nИтоги массового тестирования:");
            Console.WriteLine($"  Всего ключей: {count}");
            Console.WriteLine($"  Уязвимых ключей: {vulnerableKeys}");
            Console.WriteLine($"  Успешных атак: {successfulAttacks}");
            Console.WriteLine($"  Эффективность: {(double)successfulAttacks / count * 100:F2}%");
        }
        
    }