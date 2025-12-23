using System.Numerics;

namespace Cryptography.Core.Algorithms.RSA;

public static class NumberTheoryService
    {
        public static int LegendreSymbol(BigInteger a, BigInteger p)
        {
            if (p <= 2 || p % 2 == 0)
                throw new ArgumentException("p должно быть нечетным простым числом > 2", nameof(p));

            BigInteger a1 = a % p;
            if (a1 < 0) a1 += p;
            
            if (a1 == 0) return 0;
            if (a1 == 1) return 1;
            
            BigInteger exponent = (p - 1) / 2;
            BigInteger result = ModularPow(a1, exponent, p);
            
            if (result == 1) 
                return 1;
            if (result == p - 1) 
                return -1;
            throw new Exception($"Некорректный результат по критерию Эйлера: {result}");
        }

        public static int JacobiSymbol(BigInteger a1, BigInteger n)
        {
            if (n <= 0 || n % 2 == 0)
                throw new ArgumentException("n должно быть нечетным положительным числом", nameof(n));
            BigInteger a = a1 % n;
            
            int result = 1;
            
            while (a != 0)
            {
                int t = 0;
                while (a % 2 == 0)
                {
                    a /= 2;
                    t++;
                }
                if (t % 2 == 1)
                {
                    BigInteger mod8 = n % 8;
                    if (mod8 == 3 || mod8 == 5)
                        result = -result;
                }
                
                if (a % 4 == 3 && n % 4 == 3)
                {
                    result = -result;
                }
                
                BigInteger temp = a;
                a = n % temp;
                n = temp;
            }
            
            return (n == 1) ? result : 0;
        }
        
        public static BigInteger EuclideanGCD(BigInteger a, BigInteger b)
        {
            a = BigInteger.Abs(a);
            b = BigInteger.Abs(b);
            
            while (b != 0)
            {
                BigInteger temp = b;
                b = a % b;
                a = temp;
            }
            
            return a;
        }
        public static BigInteger ExtendedEuclidean(BigInteger a, BigInteger b, 
            out BigInteger x, out BigInteger y)
        {
            BigInteger x0 = 1, y0 = 0;
            BigInteger x1 = 0, y1 = 1;
            BigInteger r0 = a, r1 = b;
            
            while (r1 != 0)
            {
                BigInteger quotient = r0 / r1;

                BigInteger r2 = r0 - quotient * r1;
                r0 = r1;
                r1 = r2;
                
                BigInteger x2 = x0 - quotient * x1;
                BigInteger y2 = y0 - quotient * y1;
                
                x0 = x1;
                y0 = y1;
                x1 = x2;
                y1 = y2;
            }

            x = x0;
            y = y0;
            return r0;
        }
        
        public static BigInteger ModularInverse(BigInteger a, BigInteger m)
        {
            BigInteger x, y;
            BigInteger gcd = ExtendedEuclidean(a, m, out x, out y);

            if (gcd != 1)
                return -1;

            x = x % m;
            if (x < 0) x += m;
            
            return x;
        }
        
        public static BigInteger ModularPow(BigInteger basis, BigInteger exponent, BigInteger modulus)
        {
            if (modulus == 1) return 0;
            if (exponent < 0)
            {
                BigInteger inverse = ModularInverse(basis, modulus);
                if (inverse == -1)
                    throw new InvalidOperationException(
                        $"Не существует модульного обратного для {basis} по модулю {modulus}");
                
                basis = inverse;
                exponent = -exponent;
            }
            BigInteger result = 1;
            BigInteger b = basis % modulus;
            BigInteger e = exponent;
            while (e > 0)
            {
                if ((e & 1) == 1)
                {
                    result = (result * b) % modulus;
                }
                b = (b * b) % modulus;
                e >>= 1;
            }
            
            return result;
        }
    }