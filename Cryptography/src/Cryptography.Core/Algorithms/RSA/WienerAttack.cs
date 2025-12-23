using Cryptography.Core.Algorithms.RSA.PrimeTests;

namespace Cryptography.Core.Algorithms.RSA;

using System;
using System.Numerics;
using System.Collections.Generic;


public class WienerAttackResult
{
    public bool Success { get; set; }
    public BigInteger FoundD { get; set; }
    public BigInteger FoundPhi { get; set; }
    public BigInteger FoundP { get; set; }
    public BigInteger FoundQ { get; set; }
    public List<ConvergentInfo> Convergents { get; set; } = new();
    public int Iterations { get; set; }
}

public class ConvergentInfo
{
    public int Index { get; set; }
    public BigInteger K { get; set; }
    public BigInteger D { get; set; }
    
}

public class WienerAttackService
{
    public WienerAttackResult Attack(BigInteger e, BigInteger n)
    {
        var result = new WienerAttackResult();

        List<BigInteger> continuedFraction = ComputeContinuedFraction(e, n);

        List<(BigInteger K, BigInteger D)> convergents = ComputeConvergents(continuedFraction);
        
        for (int i = 0; i < convergents.Count && i <= 1000; i++)
        {
            result.Iterations++;
            var (k, d) = convergents[i];

            var convergentInfo = new ConvergentInfo
            {
                Index = i + 1,
                K = k,
                D = d
            };
            
            var checkResult = CheckCandidate(e, n, k, d);

            result.Convergents.Add(convergentInfo);
            
            
            if (checkResult.Found)
            {
                result.Success = true;
                result.FoundD = d;
                result.FoundPhi = checkResult.Phi;
                result.FoundP = checkResult.P;
                result.FoundQ = checkResult.Q;
                break;
            }
        }
        return result;
    }
    
    private List<BigInteger> ComputeContinuedFraction(BigInteger a, BigInteger b)
    {
        List<BigInteger> result = new List<BigInteger>();

        while (b != 0)
        {
            BigInteger quotient = a / b;
            BigInteger remainder = a % b;

            result.Add(quotient);

            a = b;
            b = remainder;
        }
        return result;
    }
    
    private List<(BigInteger K, BigInteger D)> ComputeConvergents(List<BigInteger> continuedFraction)
    {
        List<(BigInteger, BigInteger)> convergents = new List<(BigInteger, BigInteger)>();

        if (continuedFraction.Count == 0)
            return convergents;

        BigInteger hPrev2 = 0, kPrev2 = 1;
        BigInteger hPrev1 = 1, kPrev1 = 0;

        for (int i = 0; i < continuedFraction.Count && i <= 1000; i++)
        {
            BigInteger a_i = continuedFraction[i];
            
            BigInteger h_i = a_i * hPrev1 + hPrev2;
            BigInteger k_i = a_i * kPrev1 + kPrev2;

            convergents.Add((h_i, k_i));
            hPrev2 = hPrev1;
            kPrev2 = kPrev1;
            hPrev1 = h_i;
            kPrev1 = k_i;
        }
        return convergents;
    }

    

    private class CandidateCheckResult
    {
        public bool Found { get; set; }
        public BigInteger Phi { get; set; }
        public BigInteger P { get; set; }
        public BigInteger Q { get; set; }
    }
    
    private CandidateCheckResult CheckCandidate(BigInteger e, BigInteger n, BigInteger k, BigInteger d)
    {
        var result = new CandidateCheckResult();
        
        if (k == 0 || d == 0)
        {
            return result;
        }
        
        BigInteger ed = e * d;
        if (ed <= 1)
        {
            return result;
        }

        if ((ed - 1) % k != 0)
        {
            return result;
        }
        
        BigInteger phi = (ed - 1) / k;

        if (phi <= 0 || phi >= n)
        {
            return result;
        }
        
        BigInteger b = n - phi + 1;
        BigInteger discriminant = b * b - 4 * n;
        if (discriminant < 0)
        {
            return result;
        }
        
        BigInteger sqrtD = Sqrt(discriminant);
        if (sqrtD * sqrtD != discriminant)
        {
            return result;
        }
        BigInteger p = (b + sqrtD) / 2;
        BigInteger q = (b - sqrtD) / 2;

        if (p * q != n || p <= 1 || q <= 1) return result;
        result.Found = true;
        result.Phi = phi;
        result.P = p;
        result.Q = q;
        return result;
    }
    
    
    private BigInteger Sqrt(BigInteger n)
    {
        if (n < 0) throw new ArgumentException("Отрицательное число");
        if (n == 0) return 0;

        BigInteger x = n;
        BigInteger y = (x + 1) / 2;

        while (y < x)
        {
            x = y;
            y = (x + n / x) / 2;
        }

        return x;
    }
    
    private BigInteger ApproximateFourthRoot(BigInteger n)
    {
        BigInteger sqrtN = Sqrt(n);
        return Sqrt(sqrtN);
    }

    public RSA.RSAKeyPair CreateVulnerableKey(int bitLength = 256)
    {

        Random rng = new Random();

        BigInteger p = GenerateProbablePrime(bitLength / 2, rng);
        BigInteger q = GenerateProbablePrime(bitLength / 2, rng);
        
        while (BigInteger.Abs(p - q) < (BigInteger.One << (bitLength / 2 - 10)))
        {
            q = GenerateProbablePrime(bitLength / 2, rng);
        }

        BigInteger n = p * q;
        BigInteger phi = (p - 1) * (q - 1);
        

        BigInteger d;
        BigInteger e;
        int attempts = 0;

        do
        {
            attempts++;
            byte[] bytes = new byte[(n.GetBitLength() / 8) / 4];
            rng.NextBytes(bytes);
            d = new BigInteger(bytes);
            if (d < 0) d = -d;
            e = NumberTheoryService.ModularInverse(d, phi);
            
        } while ((e == 0 || e == -1) && attempts < 1000);

        if (e == 0)
            throw new Exception("Не удалось создать уязвимый ключ");

        RSA.RSAKeyPair res = new RSA.RSAKeyPair(new RSA.RSAPublicKey(e, n),
            new RSA.RSAPrivateKey(d, n, p, q));

        return res;
    }
    
    private BigInteger GenerateProbablePrime(int bitLength, Random rng)
    {
        MillerRabinTest primeTest = new MillerRabinTest();
        while (true)
        {
            byte[] bytes = new byte[bitLength / 8 + 1];
            rng.NextBytes(bytes);
            BigInteger n = new BigInteger(bytes);
            if (n < 0) n = -n;

            if (n % 2 == 0) n += 1;

            if (primeTest.IsProbablePrime(n, 0.99))
                return n;
        }
    }
    
    private bool IsProbablePrimeSimple(BigInteger n)
    {
        if (n < 2) return false;
        if (n == 2 || n == 3) return true;
        if (n % 2 == 0) return false;
        
        int[] smallPrimes = { 3, 5, 7, 11, 13, 17, 19, 23, 29, 31 };

        foreach (int prime in smallPrimes)
        {
            if (n % prime == 0 && n != prime)
                return false;
        }
        
        return BigInteger.ModPow(2, n - 1, n) == 1;
    }
    
    
    public bool IsKeyVulnerable(BigInteger d, BigInteger n)
    {
        BigInteger nFourthRoot = ApproximateFourthRoot(n);
        BigInteger wienerBound = nFourthRoot / 3;

        return d < wienerBound;
    }
}