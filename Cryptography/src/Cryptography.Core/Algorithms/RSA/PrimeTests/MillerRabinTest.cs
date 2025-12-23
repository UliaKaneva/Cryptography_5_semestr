namespace Cryptography.Core.Algorithms.RSA.PrimeTests;

using System.Numerics;
using System.Text;

public class MillerRabinTest : ProbabilisticPrimeTestBase
{
    public override string TestName => "Миллер-Рабин";

    protected override double BaseErrorProbability => 0.25;

    protected override bool RunTestIteration(BigInteger n, BigInteger a)
    {
        BigInteger s = n - 1;
        int d = 0;

        while (s % 2 == 0)
        {
            s /= 2;
            d++;
        }
        BigInteger x = ModularPow(a, s, n);
        
        if (x == 1 || x == n - 1)
            return true;
        
        for (int r = 1; r < d; r++)
        {
            x = ModularPow(x, 2, n);
            if (x == n - 1)
                return true;
            
            if (x == 1)
                return false;
        }
        return false;
    }
}