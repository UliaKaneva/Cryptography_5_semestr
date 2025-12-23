namespace Cryptography.Tests;

using System.Numerics;
using Cryptography.Core.Algorithms.Protocols;

public class TestsDiffieHellman
{
    public static void RunAllTests()
    {
        Console.WriteLine("=== Начало тестирования Diffie-Hellman ===");

        Test1_KeyExchange();
        Test2_SamePrivateKey();
        Test3_InvalidParameters();
        Test4_InvalidPublicKey();
        Test5_InvalidPrivateKeyRange();
        Test6_LargeNumbers();

        Console.WriteLine("=== Тестирование завершено ===");
    }

    static void Test1_KeyExchange()
    {
        Console.WriteLine("\nТест 1: Обмен ключами между двумя сторонами");

        BigInteger p = 23; // простое число
        BigInteger g = 5; // первообразный корень

        DiffieHellman alice = new DiffieHellman(p, g);
        DiffieHellman bob = new DiffieHellman(p, g);

        BigInteger alicePublic = alice.GetPublicKey();
        BigInteger bobPublic = bob.GetPublicKey();

        BigInteger aliceSharedSecret = alice.ComputeSharedSecret(bobPublic);
        BigInteger bobSharedSecret = bob.ComputeSharedSecret(alicePublic);

        Console.WriteLine($"p = {p}, g = {g}");
        Console.WriteLine($"Публичный ключ Алисы: {alicePublic}");
        Console.WriteLine($"Публичный ключ Боба: {bobPublic}");
        Console.WriteLine($"Общий секрет Алисы: {aliceSharedSecret}");
        Console.WriteLine($"Общий секрет Боба: {bobSharedSecret}");

        if (aliceSharedSecret == bobSharedSecret)
        {
            Console.WriteLine("✓ Общие секреты совпадают!");
        }
        else
        {
            Console.WriteLine("✗ Ошибка: Общие секреты не совпадают!");
        }
    }

    static void Test2_SamePrivateKey()
    {
        Console.WriteLine("\nТест 2: Проверка с одинаковыми приватными ключами");

        // Используем маленькие числа для теста
        BigInteger p = 23;
        BigInteger g = 5;

        DiffieHellman alice = new DiffieHellman(p, g);
        DiffieHellman bob = new DiffieHellman(p, g);

        // Устанавливаем одинаковые приватные ключи в допустимом диапазоне
        BigInteger samePrivateKey = new BigInteger(10); // 1 < 10 < p-1 (22)
        alice.SetPrivateKey(samePrivateKey);
        bob.SetPrivateKey(samePrivateKey);

        BigInteger alicePublic = alice.GetPublicKey();
        BigInteger bobPublic = bob.GetPublicKey();

        Console.WriteLine($"p = {p}, g = {g}");
        Console.WriteLine($"Приватный ключ: {samePrivateKey}");
        Console.WriteLine($"Публичный ключ Алисы: {alicePublic}");
        Console.WriteLine($"Публичный ключ Боба: {bobPublic}");

        if (alicePublic == bobPublic)
        {
            Console.WriteLine("✓ Публичные ключи совпадают при одинаковых приватных ключах!");
        }
        else
        {
            Console.WriteLine("✗ Ошибка: Публичные ключи должны совпадать!");
        }
    }

    static void Test3_InvalidParameters()
    {
        Console.WriteLine("\nТест 3: Проверка обработки неверных параметров");

        try
        {
            DiffieHellman dh = new DiffieHellman(0, 5);
            Console.WriteLine("✗ Ошибка: Ожидалось исключение для p <= 0");
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"✓ Исключение перехвачено: {ex.Message}");
        }

        try
        {
            DiffieHellman dh = new DiffieHellman(23, 0);
            Console.WriteLine("✗ Ошибка: Ожидалось исключение для g <= 0");
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"✓ Исключение перехвачено: {ex.Message}");
        }
    }

    static void Test4_InvalidPublicKey()
    {
        Console.WriteLine("\nТест 4: Проверка неверного публичного ключа");

        DiffieHellman dh = new DiffieHellman(23, 5);

        try
        {
            BigInteger invalidKey = 100; // > p
            BigInteger secret = dh.ComputeSharedSecret(invalidKey);
            Console.WriteLine("✗ Ошибка: Ожидалось исключение для публичного ключа >= p");
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"✓ Исключение перехвачено: {ex.Message}");
        }

        try
        {
            BigInteger invalidKey = 0; // <= 0
            BigInteger secret = dh.ComputeSharedSecret(invalidKey);
            Console.WriteLine("✗ Ошибка: Ожидалось исключение для публичного ключа <= 0");
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"✓ Исключение перехвачено: {ex.Message}");
        }
    }

    static void Test5_InvalidPrivateKeyRange()
    {
        Console.WriteLine("\nТест 5: Проверка диапазона приватного ключа");

        DiffieHellman dh = new DiffieHellman(23, 5);

        try
        {
            dh.SetPrivateKey(0); // <= 1
            Console.WriteLine("✗ Ошибка: Ожидалось исключение для приватного ключа <= 1");
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"✓ Исключение перехвачено: {ex.Message}");
        }

        try
        {
            dh.SetPrivateKey(1); // <= 1
            Console.WriteLine("✗ Ошибка: Ожидалось исключение для приватного ключа <= 1");
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"✓ Исключение перехвачено: {ex.Message}");
        }

        try
        {
            dh.SetPrivateKey(22); // >= p-1
            Console.WriteLine("✗ Ошибка: Ожидалось исключение для приватного ключа >= p-1");
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"✓ Исключение перехвачено: {ex.Message}");
        }

        try
        {
            dh.SetPrivateKey(10); // корректное значение
            Console.WriteLine("✓ Корректный приватный ключ установлен успешно");
        }
        catch (ArgumentException)
        {
            Console.WriteLine("✗ Ошибка: Не должно быть исключения для корректного ключа");
        }
    }

    static void Test6_LargeNumbers()
    {
        Console.WriteLine("\nТест 6: Работа с большими числами (стандартные параметры DH)");

        // Используем безопасное простое число для теста (меньше, чем стандартное 1024-битное)
        // 128-битное простое число для теста
        string hexString = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFF61"; // 128-битное простое число
        BigInteger p = BigInteger.Parse(hexString, System.Globalization.NumberStyles.HexNumber);
        BigInteger g = 2;

        Console.WriteLine($"Используется 128-битное простое число");
        Console.WriteLine($"p (десятичное): {p}");

        DiffieHellman alice = new DiffieHellman(p, g);
        DiffieHellman bob = new DiffieHellman(p, g);

        BigInteger alicePublic = alice.GetPublicKey();
        BigInteger bobPublic = bob.GetPublicKey();

        Console.WriteLine($"Публичный ключ Алисы: {alicePublic}");
        Console.WriteLine($"Публичный ключ Боба: {bobPublic}");

        BigInteger aliceSharedSecret = alice.ComputeSharedSecret(bobPublic);
        BigInteger bobSharedSecret = bob.ComputeSharedSecret(alicePublic);

        if (aliceSharedSecret == bobSharedSecret)
        {
            Console.WriteLine("✓ Общие секреты совпадают для больших чисел!");
            Console.WriteLine($"Общий секрет: {aliceSharedSecret}");
        }
        else
        {
            Console.WriteLine("✗ Ошибка: Общие секреты не совпадают для больших чисел!");
        }
    }
}