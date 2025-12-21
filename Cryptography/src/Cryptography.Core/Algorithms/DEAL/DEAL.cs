using Cryptography.Core.Interfaces;
namespace Cryptography.Core.Algorithms.DEAL;

public class DEAL : ISymmetricCipher
{
    private bool _initialized = false;
    private FeistelNetwork _feistelNetwork;
    private int _roundCount;

    public DEAL()
    {
        _feistelNetwork = new FeistelNetwork(new DealKeyExpander(), new DealFeistelRound());
    }
    public void Initialize(byte[] key)
    {
        _feistelNetwork.Initialize(key);
        _roundCount = key.Length switch
        {
            16 or 24 => 6,
            32 => 8,
            _ => throw new ArgumentOutOfRangeException()
        };
        _initialized = true;
    }

    public byte[] EncryptBlock(byte[] plaintextBlock)
    {
        if (!_initialized) throw new InvalidOperationException("The algorithm has not been initialized.");
        if  (plaintextBlock == null) throw new ArgumentNullException(nameof(plaintextBlock));
        if (plaintextBlock.Length != BlockSize) throw new InvalidOperationException("The plaintextBlock length must be equal to BlockSize.");
        byte[] ciphertextBlock = _feistelNetwork.EncryptBlock(plaintextBlock);
        return ciphertextBlock;
    }

    public byte[] DecryptBlock(byte[] ciphertextBlock)
    {
        if (!_initialized) throw new InvalidOperationException("The algorithm has not been initialized.");
        if  (ciphertextBlock == null) throw new ArgumentNullException(nameof(ciphertextBlock));
        if (ciphertextBlock.Length != BlockSize) throw new InvalidOperationException("The plaintextBlock length must be equal to BlockSize.");
        byte[] decryptBlock = _feistelNetwork.DecryptBlock(ciphertextBlock);
        return decryptBlock;
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
        return _feistelNetwork.GenerateRoundKeys(key);
    }

    public int BlockSize => 16;
    public int[] SupportedKeySizes => [16, 24, 32];
    public int RoundsCount => _roundCount;
    public bool IsInitialized =>  _initialized;
    public byte[][] RoundKeys => _feistelNetwork.RoundKeys;
}