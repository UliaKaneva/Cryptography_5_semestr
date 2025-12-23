using System.Numerics;
using Cryptography.Core.Interfaces;
using Cryptography.Core.Algorithms.RSA.PrimeTests;
using System.Diagnostics;
namespace Cryptography.Tests;

static class TestsPrimeTest
    {
        public static void RunAllTests()
        {
            Console.WriteLine("=== ТЕСТИРОВАНИЕ ВЕРОЯТНОСТНЫХ ТЕСТОВ ПРОСТОТЫ ===\n");
            
            // Создаем экземпляры тестов
            var tests = new Dictionary<string, IProbabilisticPrimeTest>
            {
                { "Ферма", new FermatTest() },
                { "Соловей-Штрассен", new SolovayStrassenTest() },
                { "Миллер-Рабин", new MillerRabinTest() }
            };

            // Тестовые числа
            var testNumbers = new[]
            {
                new { Name = "Малое простое", Value = new BigInteger(17) },
                new { Name = "Среднее простое", Value = new BigInteger(101) },
                new { Name = "Большое простое", Value = BigInteger.Parse("32416190071") },
                new { Name = "Число Кармайкла", Value = new BigInteger(561) },
                new { Name = "Малая составная", Value = new BigInteger(15) },
                new { Name = "Средняя составная", Value = new BigInteger(1001) },
                new { Name = "Четное составное", Value = new BigInteger(100) },
                new { Name = "1 (не простое)", Value = new BigInteger(1) },
                new { Name = "2 (простое)", Value = new BigInteger(2) },
                new { Name = "Очень большое (возможно простое)", Value = BigInteger.Parse("170141183460469231731687303715884105727") }
            };

            // Тест 1: Проверка правильности определения
            Console.WriteLine("ТЕСТ 1: Проверка правильности определения простоты");
            Console.WriteLine(new string('-', 80));
            
            foreach (var testCase in testNumbers)
            {
                Console.WriteLine($"\n{testCase.Name}: {testCase.Value}");
                
                foreach (var test in tests)
                {
                    try
                    {
                        bool result = test.Value.IsProbablePrime(testCase.Value, 0.99);
                        Console.WriteLine($"  {test.Key}: {(result ? "Простое" : "Не является простым")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"  {test.Key}: ОШИБКА - {ex.Message}");
                    }
                }
            }

            // Тест 2: Производительность и статистика
            Console.WriteLine("\n\nТЕСТ 2: Производительность и статистическая оценка");
            Console.WriteLine(new string('-', 80));
            
            var performanceNumbers = new[]
            {
                new BigInteger(1000003),
                new BigInteger(1000001),
                new BigInteger(32416190071)
            };

            foreach (var number in performanceNumbers)
            {
                Console.WriteLine($"\nЧисло: {number}");
                
                foreach (var test in tests)
                {
                    var stopwatch = Stopwatch.StartNew();
                    int iterations = 0;
                    int positiveResults = 0;
                    
                    // Многократный запуск для статистики
                    for (int i = 0; i < 100; i++)
                    {
                        try
                        {
                            bool result = test.Value.IsProbablePrime(number, 0.99);
                            if (result) positiveResults++;
                            iterations++;
                        }
                        catch
                        {
                            // Игнорируем ошибки для статистики
                        }
                    }
                    
                    stopwatch.Stop();
                    
                    if (iterations > 0)
                    {
                        double successRate = (double)positiveResults / iterations * 100;
                        Console.WriteLine($"  {test.Key}:");
                        Console.WriteLine($"    Время 100 итераций: {stopwatch.ElapsedMilliseconds} мс");
                        Console.WriteLine($"    Успешных результатов: {successRate:F2}%");
                        Console.WriteLine($"    Вероятность ошибки за итерацию: {test.Value.SingleIterationErrorProbability:P0}");
                    }
                }
            }

            // Тест 3: Граничные случаи
            Console.WriteLine("\n\nТЕСТ 3: Граничные случаи и обработка ошибок");
            Console.WriteLine(new string('-', 80));
            
            var edgeCases = new[]
            {
                new { Number = new BigInteger(0), Name = "Ноль" },
                new { Number = new BigInteger(-5), Name = "Отрицательное" },
                new { Number = new BigInteger(1), Name = "Единица" },
                new { Number = new BigInteger(2), Name = "Двойка" },
                new { Number = new BigInteger(3), Name = "Тройка" }
            };

            foreach (var edgeCase in edgeCases)
            {
                Console.WriteLine($"\n{edgeCase.Name}: {edgeCase.Number}");
                
                foreach (var test in tests)
                {
                    try
                    {
                        bool result = test.Value.IsProbablePrime(edgeCase.Number, 0.99);
                        Console.WriteLine($"  {test.Key}: {(result ? "Простое" : "Не является простым")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"  {test.Key}: ОШИБКА - {ex.Message}");
                    }
                }
            }

            // Тест 4: Числа Кармайкла (ложные срабатывания теста Ферма)
            Console.WriteLine("\n\nТЕСТ 4: Числа Кармайкла (известные ложные простые для теста Ферма)");
            Console.WriteLine(new string('-', 80));
            
            var carmichaelNumbers = new[]
            {
                new BigInteger(561),
                new BigInteger(1105),
                new BigInteger(1729),
                new BigInteger(2465),
                new BigInteger(2821)
            };

            Console.WriteLine("\nЧисло Кармайкла | Ферма | Соловей-Штрассен | Миллер-Рабин");
            Console.WriteLine(new string('-', 80));
            
            foreach (var number in carmichaelNumbers)
            {
                Console.Write($"{number,16} |");
                
                foreach (var test in tests)
                {
                    try
                    {
                        bool result = test.Value.IsProbablePrime(number, 0.99);
                        Console.Write($" {result,6} |");
                    }
                    catch
                    {
                        Console.Write(" ОШИБКА |");
                    }
                }
                Console.WriteLine();
            }

            // Тест 5: Влияние minProbability на количество итераций
            Console.WriteLine("\n\nТЕСТ 5: Влияние требуемой вероятности на количество итераций");
            Console.WriteLine(new string('-', 80));
            
            var testNumber = new BigInteger(1000003);
            var probabilities = new[] { 0.5, 0.75, 0.9, 0.99, 0.999, 0.9999 };
            
            Console.WriteLine($"\nТестируемое число: {testNumber}\n");
            Console.WriteLine("Вероятность | Теорет. итераций Ферма | Теорет. итерации Миллер-Рабин");
            Console.WriteLine(new string('-', 80));
            
            foreach (var prob in probabilities)
            {
                // Расчет для теста Ферма (вероятность ошибки 0.5)
                double iterationsFermat = Math.Ceiling(Math.Log(1.0 - prob) / Math.Log(0.5));
                
                // Расчет для теста Миллера-Рабина (вероятность ошибки 0.25)
                double iterationsMillerRabin = Math.Ceiling(Math.Log(1.0 - prob) / Math.Log(0.25));
                
                Console.WriteLine($"{prob,10:P0} | {iterationsFermat,21:F0} | {iterationsMillerRabin,25:F0}");
            }

            // Тест 6: Интеграционный тест - генерация "простых" чисел
            Console.WriteLine("\n\nТЕСТ 6: Поиск простых чисел в диапазоне");
            Console.WriteLine(new string('-', 80));
            
            int start = 1000;
            int end = 1050;
            int foundCount = 0;
            
            Console.WriteLine($"\nПоиск простых чисел в диапазоне [{start}, {end}]:\n");
            
            for (int i = start; i <= end; i++)
            {
                var number = new BigInteger(i);
                bool allTestsAgree = true;
                bool? firstResult = null;
                
                foreach (var test in tests)
                {
                    try
                    {
                        bool result = test.Value.IsProbablePrime(number, 0.99);
                        
                        if (firstResult == null)
                        {
                            firstResult = result;
                        }
                        else if (firstResult != result)
                        {
                            allTestsAgree = false;
                        }
                    }
                    catch
                    {
                        allTestsAgree = false;
                    }
                }
                
                if (allTestsAgree && firstResult == true)
                {
                    Console.WriteLine($"  Найдено простое число: {i}");
                    foundCount++;
                }
            }
            
            Console.WriteLine($"\nВсего найдено: {foundCount} чисел");

            Console.WriteLine("\n\n=== ТЕСТИРОВАНИЕ ЗАВЕРШЕНО ===");
        }
    }