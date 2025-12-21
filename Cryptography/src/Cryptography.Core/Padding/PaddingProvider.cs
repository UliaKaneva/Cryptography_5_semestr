using System;
using System.Security.Cryptography;

namespace Cryptography.Core.Padding
{
    public class PaddingProvider : IPaddingProvider
    {
        public Enums.PaddingMode Mode => Enums.PaddingMode.Zeros;
        
        public byte[] AddPadding(byte[] data, int blockSize)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (blockSize <= 0) throw new ArgumentException("Размер блока должен быть больше 0", nameof(blockSize));
            
            int paddingLength = blockSize - (data.Length % blockSize);
            if (paddingLength == blockSize) paddingLength = 0;
            
            byte[] result = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, result, 0, data.Length);

            for (int i = data.Length; i < result.Length; i++)
            {
                result[i] = 0;
            }
            
            return result;
        }
        
        public byte[] RemovePadding(byte[] data, int blockSize)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (data.Length == 0 || data.Length % blockSize != 0)
                throw new ArgumentException("Данные должны быть кратны размеру блока", nameof(data));
            
            int i = data.Length - 1;
            while (i >= 0 && data[i] == 0)
            {
                i--;
            }
            
            int dataLength = i + 1;
            byte[] result = new byte[dataLength];
            Array.Copy(data, 0, result, 0, dataLength);
            
            return result;
        }
    }

    public class AnsiX923PaddingProvider : IPaddingProvider
    {
        public Enums.PaddingMode Mode => Enums.PaddingMode.ANSIX923;

        public byte[] AddPadding(byte[] data, int blockSize)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (blockSize <= 0) throw new ArgumentException("Размер блока должен быть больше 0", nameof(blockSize));
            
            int paddingLength = blockSize - (data.Length % blockSize);
            if (paddingLength == blockSize) paddingLength = 0;
            
            byte[] result = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, result, 0, data.Length);
            
            for (int i = data.Length; i < result.Length - 1; i++)
            {
                result[i] = 0;
            }

            if (result.Length - data.Length > 0)
            {
                result[^1] = (byte) paddingLength;
            }
            return result;
        }

        public byte[] RemovePadding(byte[] data, int blockSize)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (data.Length == 0 || data.Length % blockSize != 0)
                throw new ArgumentException("Данные должны быть кратны размеру блока", nameof(data));
            
            int lastByte = data[^1];
            int dataLength;
            if (lastByte > 0 && lastByte < blockSize)
            {
                dataLength = data.Length - lastByte;
            }
            else
            {
                dataLength = data.Length;
            }
            byte[] result = new byte[dataLength];
            Array.Copy(data, 0, result, 0, dataLength);
            
            return result;
        }
    }

    public class Pkcs7PaddingProvider : IPaddingProvider
    {
        public Enums.PaddingMode Mode => Enums.PaddingMode.PKCS7;

        public byte[] AddPadding(byte[] data, int blockSize)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (blockSize <= 0) throw new ArgumentException("Размер блока должен быть больше 0", nameof(blockSize));
            
            int paddingLength = blockSize - (data.Length % blockSize);
            if (paddingLength == blockSize) paddingLength = 0;
            
            byte[] result = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, result, 0, data.Length);
            
            for (int i = data.Length; i < result.Length; i++)
            {
                result[i] = (byte) paddingLength;
            }
            return result;
        }

        public byte[] RemovePadding(byte[] data, int blockSize)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (data.Length == 0)
            {
                return data;
            }
            if (data.Length % blockSize != 0)
                throw new ArgumentException("Данные должны быть кратны размеру блока", nameof(data));
            
            int lastByte = data[^1];
            int i = data.Length - 1;
            int count = 0;
            while (i >= 0 && data[i] == lastByte && count++ < lastByte)
            {
                i--;
            }

            if (count == lastByte)
            {
                int dataLength = data.Length - lastByte;
                byte[] result = new byte[dataLength];
                Array.Copy(data, 0, result, 0, dataLength);
            
                return result;
            }
            
            byte[] res = new byte[data.Length];
            Array.Copy(data, res, data.Length);
            
            return res;
        }
    }

    public class Iso10126PaddingProvider : IPaddingProvider
{
    private readonly RandomNumberGenerator _rng;
    
    public Iso10126PaddingProvider()
    {
        _rng = RandomNumberGenerator.Create();
    }
    
    public Enums.PaddingMode Mode => Enums.PaddingMode.ISO10126;

    public byte[] AddPadding(byte[] data, int blockSize)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (blockSize <= 0) throw new ArgumentException("Размер блока должен быть больше 0", nameof(blockSize));
        
        int paddingLength = blockSize - (data.Length % blockSize);
        if (paddingLength == blockSize) paddingLength = 0;
        
        byte[] result = new byte[data.Length + paddingLength];
        Array.Copy(data, 0, result, 0, data.Length);
        
        if (paddingLength > 0)
        {
            // Генерируем случайные байты для всех позиций паддинга, кроме последней
            byte[] randomBytes = new byte[paddingLength - 1];
            _rng.GetBytes(randomBytes);
            Array.Copy(randomBytes, 0, result, data.Length, paddingLength - 1);
            
            // Последний байт - количество паддинга
            result[^1] = (byte)paddingLength;
        }
        
        return result;
    }

    public byte[] RemovePadding(byte[] data, int blockSize)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (data.Length == 0 || data.Length % blockSize != 0)
            throw new ArgumentException("Данные должны быть кратны размеру блока", nameof(data));
        
        int lastByte = data[^1];
        if (lastByte == 0 || lastByte > blockSize)
        {
            throw new ArgumentException("Данные не удовлетворяют паддингу", nameof(data));
        }
        
        int dataLength = data.Length - lastByte;
        byte[] result = new byte[dataLength];
        Array.Copy(data, 0, result, 0, dataLength);
        
        return result;
    }
    
    ~Iso10126PaddingProvider()
    {
        _rng.Dispose();
    }
}
}