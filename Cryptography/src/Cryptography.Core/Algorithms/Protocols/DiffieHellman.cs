using System.Numerics;
using System.Security.Cryptography;
using Cryptography.Core.Algorithms.RSA;

namespace Cryptography.Core.Algorithms.Protocols
{
    public class DiffieHellman
    {
        private readonly BigInteger _p;
        private readonly BigInteger _g;
        private BigInteger _privateKey;

        public DiffieHellman(BigInteger p, BigInteger g)
        {
            if (p <= 0 || g <= 0)
                throw new ArgumentException("Arguments must be positive");

            _p = p;
            _g = g;
            _privateKey = GenerateRandomPrivateKey(_p);
        }

        public BigInteger GetPublicKey()
        {
            return NumberTheoryService.ModularPow(_g, _privateKey, _p);
        }

        public BigInteger ComputeSharedSecret(BigInteger otherPublicKey)
        {
            if (otherPublicKey <= 0 || otherPublicKey >= _p)
                throw new ArgumentException("Invalid public key");

            return NumberTheoryService.ModularPow(otherPublicKey, _privateKey, _p);
        }

        public void SetPrivateKey(BigInteger privateKey)
        {
            if (privateKey <= 1 || privateKey >= _p - 1)
                throw new ArgumentException("Invalid private key range");
            
            _privateKey = privateKey;
        }

        private BigInteger GenerateRandomPrivateKey(BigInteger p)
        {
            BigInteger limit = p - 2;
            byte[] bytes = limit.ToByteArray();
            BigInteger result;

            do
            {
                RandomNumberGenerator.Fill(bytes);
                bytes[^1] &= 0x7F; 
                result = new BigInteger(bytes);
            } 
            while (result >= limit || result <= 1);

            return result;
        }
    }
}