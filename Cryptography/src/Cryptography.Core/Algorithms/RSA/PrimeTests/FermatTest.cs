namespace Cryptography.Core.Algorithms.RSA.PrimeTests;

using System.Numerics;

public class FermatTest : ProbabilisticPrimeTestBase
{
    public override string TestName => "Ферма";

    protected override double BaseErrorProbability => 0.5;

    protected override bool RunTestIteration(BigInteger n, BigInteger a)
    {
        BigInteger result = ModularPow(a, n - 1, n);
        return result == 1;
    }

    protected override BigInteger GenerateRandomBase(BigInteger n)
    {
        BigInteger a;
        do
        {
            byte[] bytes = new byte[n.ToByteArray().Length];
            Random.NextBytes(bytes);
            a = new BigInteger(bytes);
            if (a < 0) a = -a;
            a = a % (n - 2) + 2;
        } while (a >= n || a <= 1);

        return a;
    }
}