using System.Numerics;
using Cryptography.Core.Interfaces;

namespace Cryptography.Core.Algorithms.RSA.PrimeTests;

public abstract class ProbabilisticPrimeTestBase : IProbabilisticPrimeTest
{

    protected static readonly Random Random = new Random();

    public abstract string TestName { get; }
    
    protected abstract double BaseErrorProbability { get; }
    
    public double SingleIterationErrorProbability => BaseErrorProbability;

    public bool IsProbablePrime(BigInteger number, double minProbability)
    {
        if (number <= 1)
            return false;

        if (number == 2 || number == 3)
            return true;

        if (number % 2 == 0)
            return false;

        if (minProbability < 0.5 || minProbability > 1.0)
            throw new ArgumentException("Вероятность должна быть в диапазоне [0.5, 1]", nameof(minProbability));
        
        int iterations = CalculateRequiredIterations(minProbability);
        
        for (int i = 1; i <= iterations; i++)
        {

            BigInteger a = GenerateRandomBase(number);
            
            bool isPrimeInIteration = RunTestIteration(number, a);
            
            if (!isPrimeInIteration)
            {
                return false;
            }
        }
        
        
        return true;
    }
    
    protected virtual int CalculateRequiredIterations(double minProbability)
    {
        double requiredIterations = Math.Log(1.0 - minProbability) / Math.Log(BaseErrorProbability);
        return (int)Math.Ceiling(requiredIterations);
    }
    
    
    protected virtual BigInteger GenerateRandomBase(BigInteger n)
    {
        BigInteger a;
        do
        {
            byte[] bytes = new byte[n.ToByteArray().Length];
            Random.NextBytes(bytes);
            a = new BigInteger(bytes);

            if (a < 0) a = -a;

            a = a % (n - 3) + 2;
        } while (a >= n - 1 || a <= 1);

        return a;
    }
    
    protected abstract bool RunTestIteration(BigInteger n, BigInteger a);
    
    protected BigInteger ModularPow(BigInteger @base, BigInteger exponent, BigInteger modulus)
    {
        return NumberTheoryService.ModularPow(@base, exponent, modulus);
    }
}