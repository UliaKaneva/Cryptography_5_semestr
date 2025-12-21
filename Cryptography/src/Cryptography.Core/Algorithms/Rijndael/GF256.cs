using System.Numerics;

namespace Cryptography.Core.Algorithms.Rijndael;


public class GaloisField256
{
    public byte FieldAddition(byte operand1, byte operand2)
    {
        return (byte)(operand1 ^ operand2);
    }

    public byte FieldMultiplication(byte factor1, byte factor2, byte irreduciblePolynomial)
    {
        if (!ValidatePolynomialIrreducibility(irreduciblePolynomial))
        {
            throw new ArgumentException($"Polynomial 0x{irreduciblePolynomial:X} is not irreducible over GF(2).");
        }

        int extendedPolynomial = 0x100 | irreduciblePolynomial;
        int accumulator = 0;
        int tempFactor1 = factor1;
        int tempFactor2 = factor2;

        for (int iteration = 0; iteration < 8; iteration++)
        {
            if ((tempFactor2 & 1) == 1)
            {
                accumulator ^= tempFactor1;
            }

            bool highBitSet = (tempFactor1 & 0x80) != 0;
            tempFactor1 <<= 1;

            if (highBitSet)
            {
                tempFactor1 ^= extendedPolynomial;
            }

            tempFactor2 >>= 1;
        }

        return (byte)accumulator;
    }

    public byte MultiplicativeInverse(byte element, byte irreduciblePolynomial)
    {
        if (!ValidatePolynomialIrreducibility(irreduciblePolynomial))
        {
            throw new ArgumentException($"Polynomial 0x{irreduciblePolynomial:X} is reducible.");
        }

        if (element == 0) throw new DivideByZeroException("Zero element has no multiplicative inverse.");

        int polynomial = 0x100 | irreduciblePolynomial;
        int currentElement = element;

        int coefficient1 = 0;
        int coefficient2 = 1;

        while (currentElement > 0)
        {
            int quotient = PolynomialDivision(polynomial, currentElement, out int nextElement);

            polynomial = currentElement;
            currentElement = nextElement;

            int product = MultiplyPolynomials(quotient, coefficient2);
            int nextCoefficient = coefficient1 ^ product;

            coefficient1 = coefficient2;
            coefficient2 = nextCoefficient;
        }

        if (polynomial != 1)
            throw new ArithmeticException("Multiplicative inverse does not exist (GCD is not 1).");

        return (byte)(coefficient1 & 0xFF);
    }

    public bool ValidatePolynomialIrreducibility(byte polynomial)
    {
        int fullPolynomial = 0x100 | polynomial;
        if ((fullPolynomial & 0x1) == 0)
        {
            return false;
        }
        
        

        for (int testDivisor = 3; testDivisor < 32; testDivisor += 2)
        {
            PolynomialDivision(fullPolynomial, testDivisor, out int remainder);
            if (remainder == 0) return false;
        }

        return true;
    }

    public List<byte> FindAllIrreduciblePolynomials()
    {
        var irreduciblePolynomials = new List<byte>();
        
        for (int polynomialValue = 1; polynomialValue < 256; polynomialValue += 2)
        {
            if (ValidatePolynomialIrreducibility((byte)polynomialValue))
            {
                irreduciblePolynomials.Add((byte)polynomialValue);
            }
        }

        return irreduciblePolynomials;
    }

    public List<BigInteger> PerformPolynomialFactorization(BigInteger polynomial)
    {
        var factorList = new List<BigInteger>();

        if (polynomial.IsZero) return factorList;
        if (polynomial == 1) return factorList;

        BigInteger currentPolynomial = polynomial;

        while ((currentPolynomial & 1) == 0)
        {
            factorList.Add(new BigInteger(2));
            currentPolynomial >>= 1;
        }

        BigInteger currentDivisor = 3;

        while (true)
        {
            long divisorDegree = ComputePolynomialDegree(currentDivisor);
            long polynomialDegree = ComputePolynomialDegree(currentPolynomial);

            if (divisorDegree * 2 > polynomialDegree)
            {
                if (currentPolynomial > 1)
                {
                    factorList.Add(currentPolynomial);
                }
                break;
            }

            BigIntegerDivision(currentPolynomial, currentDivisor, out BigInteger remainder);

            if (remainder == 0)
            {
                factorList.Add(currentDivisor);
                currentPolynomial = BigIntegerDivision(currentPolynomial, currentDivisor, out _);
            }
            else
            {
                currentDivisor += 2;
            }
        }

        return factorList;
    }

    private static int ComputePolynomialDegree(int polynomial)
    {
        if (polynomial == 0) return -1;
        int degree = 0;
        int temp = polynomial;
        
        while (temp >= 2)
        {
            temp >>= 1;
            degree++;
        }

        return degree;
    }

    private static int MultiplyPolynomials(int poly1, int poly2)
    {
        int result = 0;
        int multiplier = poly2;
        
        while (poly1 > 0)
        {
            if ((poly1 & 1) != 0) result ^= multiplier;
            multiplier <<= 1;
            poly1 >>= 1;
        }

        return result;
    }

    private static int PolynomialDivision(int dividend, int divisor, out int remainder)
    {
        int dividendDegree = ComputePolynomialDegree(dividend);
        int divisorDegree = ComputePolynomialDegree(divisor);
        int quotient = 0;
        remainder = dividend;

        if (divisor == 0) throw new DivideByZeroException();

        while (dividendDegree >= divisorDegree && remainder != 0)
        {
            int shiftAmount = dividendDegree - divisorDegree;
            quotient |= (1 << shiftAmount);
            remainder ^= (divisor << shiftAmount);
            dividendDegree = ComputePolynomialDegree(remainder);
        }

        return quotient;
    }

    private static long ComputePolynomialDegree(BigInteger polynomial)
    {
        if (polynomial.IsZero) return -1;
        return polynomial.GetBitLength() - 1;
    }

    private static BigInteger BigIntegerDivision(BigInteger dividend, BigInteger divisor, out BigInteger remainder)
    {
        if (divisor.IsZero) throw new DivideByZeroException();

        BigInteger quotient = 0;
        remainder = dividend;

        long divisorDegree = ComputePolynomialDegree(divisor);
        long remainderDegree = ComputePolynomialDegree(remainder);

        while (remainderDegree >= divisorDegree && !remainder.IsZero)
        {
            int shift = (int)(remainderDegree - divisorDegree);
            BigInteger shiftMask = BigInteger.One << shift;
            
            quotient ^= shiftMask;
            remainder ^= (divisor << shift);
            
            remainderDegree = ComputePolynomialDegree(remainder);
        }

        return quotient;
    }
}