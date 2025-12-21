using System;

namespace Cryptography.Core.Interfaces
{
    public interface IEncryptionRound
    {
        byte[] Encrypt(byte[] inputBlock, byte[] roundKey);
        byte[] Decrypt(byte[] inputBlock, byte[] roundKey);
        int BlockSize { get; }
        bool IsValidBlockSize(int blockSize);
        bool IsValidKeySize(int keySize);
    }
}