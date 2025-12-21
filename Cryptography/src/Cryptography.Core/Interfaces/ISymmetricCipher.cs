using System;

namespace Cryptography.Core.Interfaces
{
    public interface ISymmetricCipher
    {
        void Initialize(byte[] key);
        byte[] EncryptBlock(byte[] plaintextBlock);
        byte[] DecryptBlock(byte[] ciphertextBlock);
        byte[] Encrypt(byte[] plaintext);
        byte[] Decrypt(byte[] ciphertext);
        
        byte[][] GenerateRoundKeys(byte[] key);
        
        int BlockSize { get; }
        
        int[] SupportedKeySizes { get; }
        
        int RoundsCount { get; }

        bool IsInitialized { get; }

        byte[][] RoundKeys { get; }
    }
}