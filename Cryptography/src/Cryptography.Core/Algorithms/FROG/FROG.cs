using Cryptography.Core.Interfaces;

namespace Cryptography.Cor.Algorithms.FROG
{
    public class FROG : ISymmetricCipher
    {
        public int BlockSize => 16;
        public int[] SupportedKeySizes { get; }
        public int RoundsCount => 8;
        public bool IsInitialized => _roundKeys != null;
        public byte[][] RoundKeys => GetRoundKeysArray();

        private const int Rounds = 8;
        private const int BlockSizeBytes = 16;
        private const int KeyStructSize = 2304;
        private bool _initialized = false;

        public FROG()
        {
            SupportedKeySizes = Enumerable.Range(5, 125).ToArray();
        }

        private struct RoundKey
        {
            public byte[] XorKey;
            public byte[] Substitution;
            public byte[] InvSubstitution;
        }

        private RoundKey[] _roundKeys;

        public byte[] Decrypt(byte[] ciphertext)
        {
            if (!_initialized)
                throw new InvalidOperationException("Cipher not initialized. Call Initialize() first.");

            if (ciphertext.Length % BlockSizeBytes != 0)
                throw new ArgumentException($"Ciphertext length must be multiple of {BlockSizeBytes} bytes");

            byte[] result = new byte[ciphertext.Length];
            
            for (int i = 0; i < ciphertext.Length; i += BlockSizeBytes)
            {
                byte[] block = new byte[BlockSizeBytes];
                Array.Copy(ciphertext, i, block, 0, BlockSizeBytes);
                byte[] decryptedBlock = DecryptBlock(block);
                Array.Copy(decryptedBlock, 0, result, i, BlockSizeBytes);
            }

            return result;
        }

        public byte[][] GenerateRoundKeys(byte[] key)
        {
            Initialize(key);
            return RoundKeys;
        }

        public void Initialize(byte[] key)
        {
            if (key == null || key.Length < 5 || key.Length > 125)
                throw new ArgumentException("FROG key length must be between 5 and 125 bytes");

            byte[] internalBuffer = MakeInternalKey(key);

            _roundKeys = new RoundKey[Rounds];
            
            for (int i = 0; i < Rounds; i++)
            {
                _roundKeys[i] = new RoundKey
                {
                    XorKey = new byte[BlockSizeBytes],
                    Substitution = new byte[256],
                    InvSubstitution = new byte[256]
                };

                int offset = i * (BlockSizeBytes + 256);

                Array.Copy(internalBuffer, offset, _roundKeys[i].XorKey, 0, BlockSizeBytes);
                Array.Copy(internalBuffer, offset + BlockSizeBytes, _roundKeys[i].Substitution, 0, 256);

                for (int j = 0; j < 256; j++)
                {
                    byte val = _roundKeys[i].Substitution[j];
                    _roundKeys[i].InvSubstitution[val] = (byte)j;
                }
            }

            _initialized = true;
        }

        public byte[] EncryptBlock(byte[] block)
        {
            if (!_initialized)
                throw new InvalidOperationException("Cipher not initialized. Call Initialize() first.");
                
            if (block.Length != BlockSizeBytes)
                throw new ArgumentException($"Block size must be {BlockSizeBytes} bytes");

            byte[] currentBlock = (byte[])block.Clone();

            for (int r = 0; r < Rounds; r++)
            {
                for (int i = 0; i < BlockSizeBytes; i++)
                {
                    currentBlock[i] ^= _roundKeys[r].XorKey[i];
                }

                for (int i = 0; i < BlockSizeBytes; i++)
                {
                    currentBlock[i] = _roundKeys[r].Substitution[currentBlock[i]];
                }

                for (int i = 0; i < BlockSizeBytes - 1; i++)
                {
                    currentBlock[i + 1] ^= currentBlock[i];
                }
                currentBlock[0] ^= currentBlock[BlockSizeBytes - 1];
            }

            return currentBlock;
        }

        public byte[] DecryptBlock(byte[] block)
        {
            if (!_initialized)
                throw new InvalidOperationException("Cipher not initialized. Call Initialize() first.");
                
            if (block.Length != BlockSizeBytes)
                throw new ArgumentException($"Block size must be {BlockSizeBytes} bytes");

            byte[] currentBlock = (byte[])block.Clone();

            for (int r = Rounds - 1; r >= 0; r--)
            {
                currentBlock[0] ^= currentBlock[BlockSizeBytes - 1];
                for (int i = BlockSizeBytes - 1; i > 0; i--)
                {
                    currentBlock[i] ^= currentBlock[i - 1];
                }

                for (int i = 0; i < BlockSizeBytes; i++)
                {
                    currentBlock[i] = _roundKeys[r].InvSubstitution[currentBlock[i]];
                }

                for (int i = 0; i < BlockSizeBytes; i++)
                {
                    currentBlock[i] ^= _roundKeys[r].XorKey[i];
                }
            }

            return currentBlock;
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            if (!_initialized)
                throw new InvalidOperationException("Cipher not initialized. Call Initialize() first.");

            if (plaintext.Length % BlockSizeBytes != 0)
                throw new ArgumentException($"Plaintext length must be multiple of {BlockSizeBytes} bytes");

            byte[] result = new byte[plaintext.Length];
            
            for (int i = 0; i < plaintext.Length; i += BlockSizeBytes)
            {
                byte[] block = new byte[BlockSizeBytes];
                Array.Copy(plaintext, i, block, 0, BlockSizeBytes);
                byte[] encryptedBlock = EncryptBlock(block);
                Array.Copy(encryptedBlock, 0, result, i, BlockSizeBytes);
            }

            return result;
        }

        private byte[][] GetRoundKeysArray()
        {
            if (_roundKeys == null) return null;
            
            byte[][] result = new byte[Rounds][];
            for (int i = 0; i < Rounds; i++)
            {
                result[i] = _roundKeys[i].XorKey;
            }
            return result;
        }

        private byte[] MakeInternalKey(byte[] key)
        {
            byte[] buf = new byte[KeyStructSize];
            int keyLen = key.Length;
            
            for (int i = 0; i < KeyStructSize; i++)
            {
                buf[i] = key[i % keyLen];
            }

            byte last = 0;
            for (int i = 0; i < KeyStructSize; i++)
            {
                buf[i] ^= last;
                last = buf[i];
            }

            byte[] finalBuffer = new byte[KeyStructSize];
            int currentOffset = 0;
            int randIdx = 0;

            for (int r = 0; r < Rounds; r++)
            {
                for (int k = 0; k < 16; k++)
                {
                    finalBuffer[currentOffset + k] = buf[randIdx % KeyStructSize];
                    randIdx = (randIdx + 1) % KeyStructSize;
                }
                currentOffset += 16;

                byte[] sBox = new byte[256];
                for (int k = 0; k < 256; k++) 
                    sBox[k] = (byte)k;

                for (int k = 0; k < 255; k++)
                {
                    int swapIndex = k + (buf[randIdx % KeyStructSize] % (256 - k));
                    randIdx = (randIdx + 1) % KeyStructSize;
                    
                    (sBox[k], sBox[swapIndex]) = (sBox[swapIndex], sBox[k]);
                }

                Array.Copy(sBox, 0, finalBuffer, currentOffset, 256);
                currentOffset += 256;
            }

            return finalBuffer;
        }
    }
}