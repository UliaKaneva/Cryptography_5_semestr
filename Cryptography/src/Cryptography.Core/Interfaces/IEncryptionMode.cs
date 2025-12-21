using System;

namespace Cryptography.Core.Interfaces
{
    public interface IEncryptionMode
    {
        byte[] Encrypt(byte[] plaintext, ISymmetricCipher blockCipher, byte[] iv = null);
        byte[] Decrypt(byte[] ciphertext, ISymmetricCipher blockCipher, byte[] iv = null);
        string Name { get; }
        bool RequiresIV { get; }
        int IVSize { get; }
    }
}