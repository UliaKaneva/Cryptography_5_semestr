namespace Cryptography.Core.Algorithms.RSA;

using System;
using System.Numerics;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Cryptography.Core.Algorithms.RSA.PrimeTests;
using Cryptography.Core.Interfaces;

public class RSA
{
    public enum PrimeTestType
    {
        Fermat,
        SolovayStrassen,
        MillerRabin
    }

    public struct RSAPublicKey(BigInteger exponent, BigInteger modulus)
    {
        public BigInteger Exponent { get; } = exponent;
        public BigInteger Modulus { get; } = modulus;
    }

    public struct RSAPrivateKey(BigInteger exponent, BigInteger modulus, BigInteger p, BigInteger q)
    {
        public BigInteger Exponent { get; } = exponent;
        public BigInteger Modulus { get; } = modulus;
        public BigInteger P { get; } = p;
        public BigInteger Q { get; } = q;
    }

    public class RSAKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey)
    {
        public RSAPublicKey PublicKey { get; } = publicKey;
        public RSAPrivateKey PrivateKey { get; } = privateKey;
    }


    private class RSAKeyGenerator
    {
        private readonly IProbabilisticPrimeTest _primeTest;
        private readonly double _minPrimeProbability;
        private readonly int _bitLength;

        private readonly RandomNumberGenerator _rng;

        public RSAKeyGenerator(PrimeTestType primeTestType, double minPrimeProbability, int bitLength = 128)
        {
            if (bitLength < 128 || (bitLength & 7) != 0)
                throw new ArgumentException("Битовая длина должна быть не менее 128 и кратна 8", nameof(bitLength));

            if (minPrimeProbability < 0.5 || minPrimeProbability >= 1.0)
                throw new ArgumentException("Вероятность должна быть в диапазоне [0.5, 1]",
                    nameof(minPrimeProbability));

            _primeTest = CreatePrimeTest(primeTestType);
            _minPrimeProbability = minPrimeProbability;
            _bitLength = bitLength;
            _rng = RandomNumberGenerator.Create();
        }

        private BigInteger GenerateRandomPrime(int bitLength)
        {
            while (true)
            {
                byte[] bytes = new byte[(bitLength + 7) / 8];
                _rng.GetBytes(bytes);
                
                int excessBits = (bytes.Length * 8) - bitLength;
                if (excessBits > 0)
                {
                    bytes[^1] &= (byte)((1 << (8 - excessBits)) - 1);
                }
                
                bytes[^1] |= (byte)(1 << ((bitLength - 1) % 8));

                bytes[0] |= 0x01;

                BigInteger candidate = new BigInteger(bytes, isUnsigned: true);

                if (candidate < 2) continue;
                if (candidate % 2 == 0) continue;

                if (_primeTest.IsProbablePrime(candidate, _minPrimeProbability))
                {
                    return candidate;
                }
            }
        }

        public RSAKeyPair GenerateKeyPair()
        {
            BigInteger p, q;
            int attempts = 0;
            do
            {
                if (attempts > 50)
                {
                    throw new InvalidOperationException(
                        "Не удалось сгенерировать безопасные простые числа после 50 попыток");
                }

                attempts++;
                
                p = GenerateRandomPrime(_bitLength);

                do
                {
                    q = GenerateRandomPrime(_bitLength);
                } while (q == p || BigInteger.Abs(p - q) < (BigInteger.One << (_bitLength / 2)));
            } while (!_primeTest.IsProbablePrime(p, _minPrimeProbability) ||
                     !_primeTest.IsProbablePrime(q, _minPrimeProbability));

            BigInteger n = p * q;

            BigInteger phi = (p - 1) * (q - 1);

            BigInteger e = ChooseExponents(phi, n, out var d);

            var publicKey = new RSAPublicKey(e, n);
            var privateKey = new RSAPrivateKey(d, n, p, q);
            var keyPair = new RSAKeyPair(publicKey, privateKey);

            return keyPair;
        }

        private static IProbabilisticPrimeTest CreatePrimeTest(PrimeTestType primeTestType)
        {
            return primeTestType switch
            {
                PrimeTestType.Fermat => new FermatTest(),
                PrimeTestType.SolovayStrassen => new SolovayStrassenTest(),
                PrimeTestType.MillerRabin => new MillerRabinTest(),
                _ => throw new ArgumentOutOfRangeException(nameof(primeTestType), primeTestType, null)
            };
        }

        private BigInteger ChooseExponents(BigInteger phi, BigInteger n, out BigInteger d)
        {
            BigInteger[] commonExponents = [65537, 131101, 131113];

            foreach (BigInteger e in commonExponents)
            {
                if (e < phi && NumberTheoryService.EuclideanGCD(e, phi) == 1)
                {
                    d = NumberTheoryService.ModularInverse(e, phi);
                    if (IsSecureAgainstWiener(d, n))
                    {
                        return e;
                    }
                }
            }

            BigInteger exponent;
            int attempts = 0;
            BigInteger dTemp = new BigInteger();
            do
            {
                attempts++;
                if (attempts > 1000)
                    throw new InvalidOperationException("Не удалось найти подходящую экспоненту e");

                byte[] bytes = new byte[phi.GetBitLength() / 8];
                _rng.GetBytes(bytes);
                bytes[0] |= 0x01;
                bytes[^1] &= 0x7F;
                exponent = new BigInteger(bytes);
                if (NumberTheoryService.EuclideanGCD(exponent, phi) != 1)
                {
                    continue;
                }

                dTemp = NumberTheoryService.ModularInverse(exponent, phi);
            } while (!IsSecureAgainstWiener(dTemp, n));

            d = dTemp;
            return exponent;
        }

        private bool IsSecureAgainstWiener(BigInteger d, BigInteger n)
        {
            return 81 * BigInteger.Pow(d, 4) >= n;
        }
    }

    private readonly RSAKeyGenerator _keyGenerator;
    private RSAKeyPair _currentKeyPair;
    private readonly RandomNumberGenerator _rng;

    public RSA(PrimeTestType primeTestType = PrimeTestType.MillerRabin,
        double minPrimeProbability = 0.9999,
        int bitLength = 1024)
    {
        _keyGenerator = new RSAKeyGenerator(primeTestType, minPrimeProbability, bitLength);
        _rng = RandomNumberGenerator.Create();
    }

    public RSAKeyPair GenerateNewKeyPair()
    {
        _currentKeyPair = _keyGenerator.GenerateKeyPair();
        return _currentKeyPair;
    }

    public RSAKeyPair GetCurrentKeyPair()
    {
        if (_currentKeyPair == null)
        {
            GenerateNewKeyPair();
        }

        return _currentKeyPair;
    }

    public byte[] EncryptBlock(byte[] data, RSAPublicKey publicKey)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));

        byte[] paddedData = AddPKCS1Padding(data, publicKey.Modulus);


        BigInteger dataNum = new BigInteger(paddedData, isUnsigned: true, isBigEndian: true);
        if (dataNum >= publicKey.Modulus)
            throw new ArgumentException($"Сообщение слишком большое после паддинга");

        BigInteger encryptedBlock = NumberTheoryService.ModularPow(
            dataNum, publicKey.Exponent, publicKey.Modulus);
    
        int modulusSize = (int)(publicKey.Modulus.GetBitLength() + 7) / 8;
        byte[] result = encryptedBlock.ToByteArray(isUnsigned: true, isBigEndian: true);
        
        if (result.Length < modulusSize)
        {
            byte[] padded = new byte[modulusSize];
            Array.Copy(result, 0, padded, modulusSize - result.Length, result.Length);
            return padded;
        }

        return result;
    }

    public byte[] DecryptBlock(byte[] data, RSAPrivateKey privateKey)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));

        BigInteger dataNum = new BigInteger(data, isUnsigned: true, isBigEndian: true);
        
        int modulusByteSize = (int) (privateKey.Modulus.GetBitLength() + 7) / 8;
    

        if (dataNum >= privateKey.Modulus)
        {
            if (data.Length > modulusByteSize)
            {
                throw new ArgumentException(
                    $"Сообщение слишком большое: {data.Length} байт, ожидалось максимум {modulusByteSize}");
            }
            else
            {
                throw new ArgumentException(
                    $"Числовое значение сообщения больше модуля: {dataNum} >= {privateKey.Modulus}");
            }
        }

        BigInteger decryptedBlock = NumberTheoryService.ModularPow(
            dataNum, privateKey.Exponent, privateKey.Modulus);

        byte[] paddedResult = decryptedBlock.ToByteArray(isUnsigned: true, isBigEndian: true);

        if (paddedResult.Length < modulusByteSize)
        {
            byte[] fullResult = new byte[modulusByteSize];
            Array.Copy(paddedResult, 0, fullResult, modulusByteSize - paddedResult.Length, paddedResult.Length);
            paddedResult = fullResult;
        }

        return RemovePKCS1Padding(paddedResult);
    }

    public byte[] Encrypt(byte[] data, RSAPublicKey publicKey)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));

        int modulusSize = (int)(publicKey.Modulus.GetBitLength() + 7) / 8;
        int blockSize = modulusSize - 11;

        if (blockSize <= 0)
            throw new InvalidOperationException("Размер блока слишком мал для выбранного паддинга");

        int numBlocks = (data.Length + blockSize - 1) / blockSize;
        List<byte[]> encryptedBlocks = new List<byte[]>();

        for (int i = 0; i < numBlocks; i++)
        {
            int currentBlockSize = Math.Min(blockSize, data.Length - i * blockSize);
            byte[] block = new byte[currentBlockSize];
            Array.Copy(data, i * blockSize, block, 0, currentBlockSize);

            byte[] encryptedBlock = EncryptBlock(block, publicKey);
            encryptedBlocks.Add(encryptedBlock);
        }

        return CombineBlocks(encryptedBlocks, modulusSize);
    }

    public byte[] Decrypt(byte[] encryptedData, RSAPrivateKey privateKey)
    {
        if (encryptedData == null) throw new ArgumentNullException(nameof(encryptedData));

        int modulusSize = (int)(privateKey.Modulus.GetBitLength() + 7) / 8;

        List<byte[]> blocks = SplitIntoBlocks(encryptedData, modulusSize);

        List<byte[]> decryptedBlocks = new List<byte[]>();

        for (int i = 0; i < blocks.Count; i++)
        {
            byte[] block = blocks[i];
            byte[] decryptedBlock = DecryptBlock(block, privateKey);
            decryptedBlocks.Add(decryptedBlock);
        }

        return CombineDecryptedBlocks(decryptedBlocks);
    }

    private byte[] CombineBlocks(List<byte[]> blocks, int blockSize)
    {
        int totalSize = blocks.Count * blockSize;
        byte[] result = new byte[totalSize];

        for (int i = 0; i < blocks.Count; i++)
        {
            byte[] block = blocks[i];
            if (block.Length > blockSize)
            {
                throw new InvalidOperationException(
                    $"Блок {i} превышает максимальный размер: {block.Length} > {blockSize}");
            }

            int offset = i * blockSize;

            Array.Copy(block, 0, result, offset, block.Length);
        }

        return result;
    }

    private byte[] CombineDecryptedBlocks(List<byte[]> blocks)
    {
        List<byte> result = new List<byte>();
        foreach (var block in blocks)
        {
            result.AddRange(block);
        }

        return result.ToArray();
    }

    private List<byte[]> SplitIntoBlocks(byte[] encryptedData, int blockSize)
    {
        List<byte[]> blocks = new List<byte[]>();

        int blockCount = encryptedData.Length / blockSize;
        int expectedSize = blockCount * blockSize;
        if (encryptedData.Length != expectedSize)
        {
            throw new ArgumentException(
                $"Некорректный размер данных. Ожидалось {expectedSize}, получено {encryptedData.Length}");
        }

        for (int i = 0; i < blockCount; i++)
        {
            byte[] block = new byte[blockSize];
            int offset = i * blockSize;
            Array.Copy(encryptedData, offset, block, 0, blockSize);
            blocks.Add(block);
        }

        return blocks;
    }

    private byte[] AddPKCS1Padding(byte[] data, BigInteger modulus)
    {
        int modulusSize = (int)(modulus.GetBitLength() + 7) / 8;
        int dataLength = data.Length;

        if (dataLength > modulusSize - 11)
            throw new ArgumentException($"Данные слишком большие для выбранного размера ключа");

        byte[] padded = new byte[modulusSize];

        padded[0] = 0x02;

        byte[] ps = new byte[modulusSize - dataLength - 2];
        _rng.GetBytes(ps);
        for (int i = 0; i < ps.Length; i++)
        {
            while (ps[i] == 0x00)
            {
                _rng.GetBytes(new Span<byte>(ref ps[i]));
            }
        }

        Array.Copy(ps, 0, padded, 1, ps.Length);
        padded[1 + ps.Length] = 0x00;
        Array.Copy(data, 0, padded, 2 + ps.Length, dataLength);

        return padded;
    }

    private byte[] RemovePKCS1Padding(byte[] paddedData)
    {
        if (paddedData[0] != 0x02)
            throw new CryptographicException("Некорректный паддинг PKCS#1");

        int paddingEndIndex = -1;

        for (int i = 1; i < paddedData.Length; i++)
        {
            if (paddedData[i] == 0x00)
            {
                paddingEndIndex = i;
                break;
            }
        }

        if (paddingEndIndex == -1 || paddingEndIndex == paddedData.Length - 1)
            throw new CryptographicException("Не найден разделитель паддинга");

        int dataLength = paddedData.Length - paddingEndIndex - 1;
        byte[] data = new byte[dataLength];
        Array.Copy(paddedData, paddingEndIndex + 1, data, 0, dataLength);

        return data;
    }

    public void EncryptFileBuffered(string inputFile, string outputFile, RSAPublicKey publicKey)
    {
        int modulusSize = (int)(publicKey.Modulus.GetBitLength() + 7) / 8;
        int inputBlockSize = modulusSize - 11;

        const int BUFFER_SIZE = 81920;

        using (FileStream inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
        using (FileStream outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
        {
            byte[] readBuffer = new byte[BUFFER_SIZE];
            int bytesRead;
            int offset = 0;

            while ((bytesRead = inputStream.Read(readBuffer, offset, BUFFER_SIZE - offset)) > 0)
            {
                bytesRead += offset;
                offset = 0;
                
                while (offset + inputBlockSize <= bytesRead)
                {
                    byte[] block = new byte[inputBlockSize];
                    Array.Copy(readBuffer, offset, block, 0, inputBlockSize);
                    offset += inputBlockSize;

                    byte[] encryptedBlock = EncryptBlock(block, publicKey);
                    outputStream.Write(encryptedBlock, 0, encryptedBlock.Length);
                }

                if (offset < bytesRead)
                {
                    int remaining = bytesRead - offset;
                    Array.Copy(readBuffer, offset, readBuffer, 0, remaining);
                    offset = remaining;
                }
                else
                {
                    offset = 0;
                }
            }

            if (offset > 0)
            {
                byte[] lastBlock = new byte[offset];
                Array.Copy(readBuffer, 0, lastBlock, 0, offset);

                byte[] encryptedBlock = EncryptBlock(lastBlock, publicKey);
                outputStream.Write(encryptedBlock, 0, encryptedBlock.Length);
            }
        }
    }

    public void DecryptFileBuffered(string inputFile, string outputFile, RSAPrivateKey privateKey)
    {
        int modulusSize = (int)(privateKey.Modulus.GetBitLength() + 7) / 8;

        const int BUFFER_SIZE = 81920;

        using (FileStream inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
        using (FileStream outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
        {
            byte[] readBuffer = new byte[BUFFER_SIZE];
            int bytesRead;
            int offset = 0;

            while ((bytesRead = inputStream.Read(readBuffer, offset, BUFFER_SIZE - offset)) > 0)
            {
                bytesRead += offset;
                offset = 0;

                while (offset + modulusSize <= bytesRead)
                {
                    byte[] encryptedBlock = new byte[modulusSize];
                    Array.Copy(readBuffer, offset, encryptedBlock, 0, modulusSize);
                    offset += modulusSize;

                    try
                    {
                        byte[] decryptedBlock = DecryptBlock(encryptedBlock, privateKey);
                        outputStream.Write(decryptedBlock, 0, decryptedBlock.Length);
                    }
                    catch (ArgumentException ex) when (ex.Message.Contains("слишком большое"))
                    {
                        throw new CryptographicException("Некорректный зашифрованный блок", ex);
                    }
                }

                if (offset < bytesRead)
                {
                    int remaining = bytesRead - offset;
                    Array.Copy(readBuffer, offset, readBuffer, 0, remaining);
                    offset = remaining;
                }
                else
                {
                    offset = 0;
                }
            }
            if (offset > 0)
            {
                if (offset == modulusSize)
                {
                    byte[] lastBlock = new byte[modulusSize];
                    Array.Copy(readBuffer, 0, lastBlock, 0, modulusSize);
                    byte[] decryptedBlock = DecryptBlock(lastBlock, privateKey);
                    outputStream.Write(decryptedBlock, 0, decryptedBlock.Length);
                }
                else
                {
                    throw new CryptographicException(
                        $"Некорректный размер последнего блока: {offset} байт, ожидалось {modulusSize}");
                }
            }
        }
    }
}