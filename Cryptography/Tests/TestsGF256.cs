using System.Numerics;
using Cryptography.Core.Algorithms.Rijndael;

namespace Cryptogtaphy.Tests
{

    class GF256Tests
    {
        private static readonly GaloisField256 Gf256 = new GaloisField256();

        public static void RunAllTests()
        {
            Console.WriteLine("=== Тестирование GF256 ===");

            TestAddition();
            TestMultiplication();
            TestInverse();
            TestIrreduciblePolynomials();
            TestFactorization();
            TestExceptions();

            Console.WriteLine("\nВсе тесты завершены!");
        }

        static void TestAddition()
        {
            Console.WriteLine("\n--- Тест сложения ---");

            byte[][] testCases =
            [
                [0, 0, 0],
                [255, 0, 255],
                [170, 85, 255],
                [1, 1, 0],
                [0x57, 0x83, 0xD4]
            ];

            foreach (var test in testCases)
            {
                byte result = Gf256.FieldAddition(test[0], test[1]);
                bool passed = result == test[2];
                Console.WriteLine(
                    $"{test[0]:X2} + {test[1]:X2} = {result:X2} | Ожидалось: {test[2]:X2} | {(passed ? "Yes" : "No")}");
            }
        }

        static void TestMultiplication()
        {
            Console.WriteLine("\n--- Тест умножения ---");

            byte irreducible = 0x1B;

            byte[][] testCases =
            [
                [0, 0, 0],
                [1, 0, 0],
                [0, 1, 0],
                [1, 1, 1],
                [2, 3, 6],
                [0x57, 0x83, 0xC1]
            ];

            foreach (var test in testCases)
            {
                byte result = Gf256.FieldMultiplication(test[0], test[1], irreducible);
                bool passed = result == test[2];
                Console.WriteLine(
                    $"{test[0]:X2} * {test[1]:X2} = {result:X2} | Ожидалось: {test[2]:X2} | {(passed ? "Yes" : "No")}");
            }

            Console.WriteLine("\nПроверка ассоциативности:");
            byte a = 0x57, b = 0x83, c = 0x13;
            byte res1 = Gf256.FieldMultiplication(Gf256.FieldMultiplication(a, b, irreducible), c, irreducible);
            byte res2 = Gf256.FieldMultiplication(a, Gf256.FieldMultiplication(b, c, irreducible), irreducible);
            Console.WriteLine($"({a:X2}*{b:X2})*{c:X2} = {res1:X2}");
            Console.WriteLine($"{a:X2}*({b:X2}*{c:X2}) = {res2:X2}");
            Console.WriteLine($"Ассоциативность {(res1 == res2 ? "Yes" : "No")}");
        }

        static void TestInverse()
        {
            Console.WriteLine("\n--- Тест обратного элемента ---");

            byte irreducible = 0x1B;

            for (int i = 1; i <= 10; i++)
            {
                byte element = (byte)(i * 17 % 256);
                try
                {
                    byte inverse = Gf256.MultiplicativeInverse(element, irreducible);
                    byte product = Gf256.FieldMultiplication(element, inverse, irreducible);
                    bool passed = product == 1;
                    Console.WriteLine(
                        $"Обратный к {element:X2}: {inverse:X2}, проверка: {element:X2}*{inverse:X2}={product:X2} | {(passed ? "Yes" : "No")}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Ошибка для {element:X2}: {ex.Message}");
                }
            }

            try
            {
                Gf256.MultiplicativeInverse(0, irreducible);
                Console.WriteLine("Ошибка: Для 0 не должно быть обратного!");
            }
            catch (DivideByZeroException)
            {
                Console.WriteLine("Для 0 корректно вызывается исключение.");
            }
        }

        static void TestIrreduciblePolynomials()
        {
            Console.WriteLine("\n--- Тест неприводимых многочленов ---");
            
            byte[] testPolynomials = [0x1B, 0x1D, 0x2B, 0x63];

            foreach (byte poly in testPolynomials)
            {
                bool irreducible = Gf256.ValidatePolynomialIrreducibility(poly);
                Console.WriteLine($"Многочлен 0x1{poly:X2} неприводим: {irreducible}");
            }

            Console.WriteLine("\nНеприводимых многочлены:");
            List<byte> allIrreducible = Gf256.FindAllIrreduciblePolynomials();
            for (int i = 0; i < allIrreducible.Count; i++)
            {
                Console.WriteLine(
                    $"0x1{allIrreducible[i]:X2} - 1{Convert.ToString(allIrreducible[i], 2).PadLeft(8, '0')}");
            }

            Console.WriteLine($"Всего найдено: {allIrreducible.Count}");
        }

        static void TestFactorization()
        {
            Console.WriteLine("\n--- Тест факторизации ---");

            BigInteger[] testPolynomials =
            {
                0x11B, 
                0x171,
                0x1F5,
                0x100
            };

            foreach (BigInteger poly in testPolynomials)
            {
                Console.WriteLine($"\nФакторизация многочлена 0x{poly:X}:");
                List<BigInteger> factors = Gf256.PerformPolynomialFactorization(poly);

                if (factors.Count == 0)
                {
                    Console.WriteLine("  Многочлен не имеет факторов (возможно, неприводим)");
                }
                else
                {
                    Console.WriteLine($"  Найдено {factors.Count} факторов:");
                    foreach (var factor in factors)
                    {
                        Console.WriteLine($"    0x{factor:X}");
                    }
                }
            }
        }
        static void TestExceptions()
{
    Console.WriteLine("\n--- Тест исключений ---");
    
    try
    {
        Console.Write("Тест 1: Умножение с приводимым многочленом 0x1C... ");
        byte result = Gf256.FieldMultiplication(0x57, 0x83, 0x1C);
        Console.WriteLine($"Неожиданно успех: {result:X2}");
    }
    catch (ArgumentException ex)
    {
        Console.WriteLine($"Ожидаемое исключение: {ex.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Неожиданное исключение: {ex.GetType().Name}: {ex.Message}");
    }

    try
    {
        Console.Write("Тест 2: Поиск обратного для 0... ");
        byte inverse = Gf256.MultiplicativeInverse(0, 0x1B);
        Console.WriteLine($"Неожиданно успех: {inverse:X2}");
    }
    catch (DivideByZeroException ex)
    {
        Console.WriteLine($"Ожидаемое исключение: {ex.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Неожиданное исключение: {ex.GetType().Name}: {ex.Message}");
    }

    try
    {
        Console.Write("Тест 3: Поиск обратного с приводимым многочленом 0x1C... ");
        byte inverse = Gf256.MultiplicativeInverse(0x57, 0x1C);
        Console.WriteLine($"Неожиданно успех: {inverse:X2}");
    }
    catch (ArgumentException ex)
    {
        Console.WriteLine($"Ожидаемое исключение: {ex.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Неожиданное исключение: {ex.GetType().Name}: {ex.Message}");
    }

    try
    {
        Console.Write("Тест 4: Попытка найти обратный для элемента в поле с многочленом 0x168... ");
        byte inverse = Gf256.MultiplicativeInverse(0x03, 0x68);
        Console.WriteLine($"Неожиданно успех: {inverse:X2}");
    }
    catch (ArithmeticException ex)
    {
        Console.WriteLine($"Ожидаемое исключение: {ex.Message}");
    }
    catch (ArgumentException ex)
    {
        Console.WriteLine($"Ожидаемое исключение: {ex.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Неожиданное исключение: {ex.GetType().Name}: {ex.Message}");
    }

    try
    {
        Console.Write("Тест 5: Деление на ноль в внутреннем методе... ");
        GaloisField256 tempField = new GaloisField256();
        var method = typeof(GaloisField256).GetMethod("PolynomialDivision", 
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        
        if (method != null)
        {
            object[] parameters = { 0x11B, 0, null };
            int quotient = (int)method.Invoke(null, parameters);
            Console.WriteLine($"Неожиданно успех: {quotient:X}");
        }
        else
        {
            Console.WriteLine("Не удалось найти метод для тестирования");
        }
    }
    catch (System.Reflection.TargetInvocationException ex) when (ex.InnerException is DivideByZeroException)
    {
        Console.WriteLine($"Ожидаемое исключение: {ex.InnerException.Message}");
    }
    catch (DivideByZeroException ex)
    {
        Console.WriteLine($"Ожидаемое исключение: {ex.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Неожиданное исключение: {ex.GetType().Name}: {ex.Message}");
    }
    
    Console.WriteLine("\nТест 6: Проверка крайних значений для многочленов:");
    try
    {
        bool isIrreducible = Gf256.ValidatePolynomialIrreducibility(0x00);
        Console.WriteLine($"Многочлен 0x100 (0x00) неприводим: {isIrreducible}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Исключение при проверке 0x00: {ex.GetType().Name}: {ex.Message}");
    }
    
    try
    {

        bool isIrreducible = Gf256.ValidatePolynomialIrreducibility(0xFF);
        Console.WriteLine($"Многочлен 0x1FF (0xFF) неприводим: {isIrreducible}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Исключение при проверке 0xFF: {ex.GetType().Name}: {ex.Message}");
    }
}
    }
}