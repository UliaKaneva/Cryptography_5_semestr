using Cryptography.Core.Interfaces;

namespace Cryptography.Core.Algorithms
{
    public class Des : ISymmetricCipher
    {
        private bool _initialized = false;
        private FeistelNetwork _feistelNetwork;

        private readonly int[] IPTable =
        [
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        ];

        private readonly int[] IPInverseTable =
        [
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        ];


        public Des()
        {
            _feistelNetwork = new FeistelNetwork(new DesKeyExpander(), new DesFeistelRound());
        }

        public void Initialize(byte[] key)
        {
            _feistelNetwork.Initialize(key);
            _initialized = true;
        }

        public byte[] EncryptBlock(byte[] plaintextBlock)
        {
            if (!_initialized)
            {
                throw new Exception("The algorithm is not initialized.");
            }
            
            if (plaintextBlock == null)
                throw new ArgumentNullException(nameof(plaintextBlock));

            if (plaintextBlock.Length != BlockSize)
                throw new ArgumentException($"Plaintext block must be {BlockSize} bytes", nameof(plaintextBlock));

            byte[] textBlock =
                BitPermutation.PermuteBits(plaintextBlock, IPTable, startBit: BitPermutation.StartBit.One);
            byte[] cipherBlock = _feistelNetwork.EncryptBlock(textBlock);

            byte[] cipherTextBlock =
                BitPermutation.PermuteBits(cipherBlock, IPInverseTable, startBit: BitPermutation.StartBit.One);
            return cipherTextBlock;
        }

        public byte[] DecryptBlock(byte[] ciphertextBlock)
        {
            if (!_initialized)
            {
                throw new Exception("The algorithm is not initialized.");
            }
            
            if (ciphertextBlock == null)
                throw new ArgumentNullException(nameof(ciphertextBlock));

            if (ciphertextBlock.Length != BlockSize)
                throw new ArgumentException($"Ciphertext block must be {BlockSize} bytes", nameof(ciphertextBlock));

            byte[] textBlock =
                BitPermutation.PermuteBits(ciphertextBlock, IPTable, startBit: BitPermutation.StartBit.One);
            byte[] decryptBlock = _feistelNetwork.DecryptBlock(textBlock);

            byte[] decryptTextBlock =
                BitPermutation.PermuteBits(decryptBlock, IPInverseTable, startBit: BitPermutation.StartBit.One);
            return decryptTextBlock;
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

        public int BlockSize => 8;

        public int[] SupportedKeySizes => [7];

        public int RoundsCount => 16;

        public bool IsInitialized => _initialized;

        public byte[][] RoundKeys => _feistelNetwork.RoundKeys;
    }
}