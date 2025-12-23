using System.Numerics;

namespace Cryptography.Core.Interfaces;

public interface IProbabilisticPrimeTest
{
    bool IsProbablePrime(BigInteger number, double minProbability);

    string TestName { get; }

    double SingleIterationErrorProbability { get; }
}