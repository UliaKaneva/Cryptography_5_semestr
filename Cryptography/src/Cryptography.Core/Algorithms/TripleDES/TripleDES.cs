using System.Security.Cryptography;
using Cryptography.Core.Interfaces;
using Cryptography.Core.Algorithms;
namespace Cryptography.Core.Algorithms.TripleDES;


public class TripleDES : ISymmetricCipher
{
    private bool _initialized;
    private Des _des1;
    private Des _des2;
    private Des _des3;

    public TripleDES()
    {
        _des1 = new Des();
        _des2 = new Des();
        _des3 = new Des();
        _initialized = false;
    }
    
    public void Initialize(byte[] key)
    {
        if (key ==  null) throw new ArgumentNullException(nameof(key));
        if (key.Length != 21 &&  key.Length != 24) throw new ArgumentException("Key must be 21 and 24 bytes long");
        byte[] key1 = new byte[key.Length / 3];
        byte[] key2 = new byte[key.Length / 3];
        byte[] key3 = new byte[key.Length / 3];
        Array.Copy(key, 0, key1, 0, key1.Length);
        Array.Copy(key, key1.Length, key2, 0, key2.Length);
        Array.Copy(key, key2.Length + key1.Length, key3, 0, key3.Length);
        _des1.Initialize(key1);
        _des2.Initialize(key2);
        _des3.Initialize(key3);
        _initialized = true;
    }

    public byte[] EncryptBlock(byte[] plaintextBlock)
    {
        if (!_initialized) throw new InvalidOperationException("The algorithm has not been initialized");
        if (plaintextBlock == null) throw new ArgumentNullException(nameof(plaintextBlock));
        if  (plaintextBlock.Length != BlockSize) throw new ArgumentException("plaintextBlock length mast be 8");
        byte[] ciphertextBlock = _des3.EncryptBlock(_des2.DecryptBlock(_des1.EncryptBlock(plaintextBlock)));
        return ciphertextBlock;
    }

    public byte[] DecryptBlock(byte[] ciphertextBlock)
    {
        if (!_initialized) throw new InvalidOperationException("The algorithm has not been initialized");
        if (ciphertextBlock == null) throw new ArgumentNullException(nameof(ciphertextBlock));
        if  (ciphertextBlock.Length != BlockSize) throw new ArgumentException("plaintextBlock length mast be 8");
        byte[] plaintextBlock = _des1.DecryptBlock(_des2.EncryptBlock(_des3.DecryptBlock(ciphertextBlock)));
        return plaintextBlock;
    }

    public byte[] Encrypt(byte[] plaintext)
    {
        if (!_initialized)
        {
            throw new Exception("The algorithm is not initialized.");
        }
        if (plaintext == null)
            throw new ArgumentNullException(nameof(plaintext));

        int blockCount = (plaintext.Length + BlockSize - 1) / BlockSize;
        byte[] result = new byte[BlockSize * blockCount];

        Parallel.For(0, blockCount, i =>
        {
            int lenCopy = Math.Min(BlockSize, plaintext.Length - i * BlockSize);
            byte[] block = new byte[BlockSize];
            Array.Copy(plaintext, i * BlockSize, block, 0, lenCopy);
            byte[] encryptedBlock = EncryptBlock(block);
            Array.Copy(encryptedBlock, 0, result, i * BlockSize, BlockSize);
        });
        return result;
    }

    public byte[] Decrypt(byte[] ciphertext)
    {
        if (!_initialized)
        {
            throw new Exception("The algorithm is not initialized.");
        }
        if (ciphertext == null)
            throw new ArgumentNullException(nameof(ciphertext));

        if (ciphertext.Length % BlockSize != 0)
            throw new ArgumentException($"Ciphertext length must be multiple of {BlockSize} bytes", nameof(ciphertext));

        int blockCount = (ciphertext.Length + BlockSize - 1) / BlockSize;
        byte[] result = new byte[blockCount * BlockSize];

        Parallel.For(0, blockCount, i =>
        {
            int lenCopy = Math.Min(BlockSize, ciphertext.Length - i * BlockSize);
            byte[] block = new byte[BlockSize];
            Array.Copy(ciphertext, i * BlockSize, block, 0, lenCopy);
            byte[] decryptBlock = DecryptBlock(block);
            Array.Copy(decryptBlock, 0, result, i * BlockSize, BlockSize);
        });
        return result;
    }

    public byte[][] GenerateRoundKeys(byte[] key)
    {
        if (!_initialized) throw new InvalidOperationException("The algorithm is not initialized.");
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (key.Length != 24 && key.Length != 21) throw new ArgumentException("Key must be 24 or 21 bytes long");
        return null;
    }

    public int BlockSize => 8;
    public int[] SupportedKeySizes => [21, 24];
    public int RoundsCount => 1;
    public bool IsInitialized => _initialized;
    public byte[][] RoundKeys => null;
}