namespace Cryptography.Core.Algorithms.RSA.PrimeTests;

using System.Numerics;
using Cryptography.Core.Algorithms.RSA;

    /// <summary>
    /// Тест простоты Соловея-Штрассена
    /// Основан на сравнении символа Якоби и модульного возведения в степень
    /// Вероятность ошибки: ≤ 1/2 за итерацию
    /// </summary>
    public class SolovayStrassenTest : ProbabilisticPrimeTestBase
    {
        
        public override string TestName => "Соловей-Штрассен";
        
        protected override double BaseErrorProbability => 0.5;
        
        protected override bool RunTestIteration(BigInteger n, BigInteger a)
        {
            if (NumberTheoryService.EuclideanGCD(a, n) > 1)
                return false;
            
            int jS = NumberTheoryService.JacobiSymbol(a, n);
            BigInteger jacobiSymbol = new BigInteger(jS);
            
            if (jacobiSymbol < 0)
                jacobiSymbol = (n + jacobiSymbol);
            
            BigInteger exponent = (n - 1) / 2;
            BigInteger modularPower = ModularPow(a, exponent, n);
            
            return modularPower == jacobiSymbol;
        }
    }
