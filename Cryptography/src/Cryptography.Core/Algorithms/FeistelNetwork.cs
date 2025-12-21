using System;
using Cryptography.Core.Interfaces;

namespace Cryptography.Core.Algorithms
{
    public class FeistelNetwork : ISymmetricCipher
    {
        private readonly IKeyExpander _keyExpander;
        private readonly IEncryptionRound _roundFunction;
        private byte[][] _roundKeys;
        private bool _isInitialized = false;
        
        public FeistelNetwork(IKeyExpander keyExpander, IEncryptionRound roundFunction)
        {
            _keyExpander = keyExpander ?? throw new ArgumentNullException(nameof(keyExpander));
            _roundFunction = roundFunction ?? throw new ArgumentNullException(nameof(roundFunction));
        }
        
        public void Initialize(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            
            if (!_keyExpander.IsValidKeySize(key.Length))
            {
                string supportedSizes = string.Join(", ", _keyExpander.GetSupportedKeySizes());
                throw new ArgumentException(
                    $"Некорректный размер ключа. Поддерживаемые размеры: {supportedSizes} байт. " +
                    $"Фактический размер: {key.Length} байт",
                    nameof(key));
            }

            _roundKeys = _keyExpander.ExpandKey(key);
            _isInitialized = true;
        }
 
        public byte[] EncryptBlock(byte[] plaintextBlock)
        {
            CheckInitialization();
            if (plaintextBlock.Length != BlockSize)
            {
                throw new ArgumentException($"Длина блока должна быть равна {BlockSize}, она равна {plaintextBlock.Length}");
            }
            
            return EncryptBlockInternal(plaintextBlock);
        }
        
        public byte[] DecryptBlock(byte[] ciphertextBlock)
        {
            CheckInitialization();
            if (ciphertextBlock.Length != BlockSize)
            {
                throw new ArgumentException($"Длина блока должна быть равна {BlockSize}, она равна {ciphertextBlock.Length}");
            }
            
            return DecryptBlockInternal(ciphertextBlock);
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            CheckInitialization();
            
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));
                
            if (plaintext.Length % BlockSize != 0)
                throw new ArgumentException(
                    $"Длина данных должна быть кратна размеру блока ({BlockSize} байт). " +
                    $"Фактическая длина: {plaintext.Length} байт",
                    nameof(plaintext));
            
            return EncryptInternal(plaintext);
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            CheckInitialization();
            
            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));
                
            if (ciphertext.Length % BlockSize != 0)
                throw new ArgumentException(
                    $"Длина данных должна быть кратна размеру блока ({BlockSize} байт). " +
                    $"Фактическая длина: {ciphertext.Length} байт",
                    nameof(ciphertext));
            
            return DecryptInternal(ciphertext);
        }
        
        public byte[][] GenerateRoundKeys(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            
            if (!_keyExpander.IsValidKeySize(key.Length))
            {
                string supportedSizes = string.Join(", ", _keyExpander.GetSupportedKeySizes());
                throw new ArgumentException(
                    $"Некорректный размер ключа. Поддерживаемые размеры: {supportedSizes} байт",
                    nameof(key));
            }
            
            return _keyExpander.ExpandKey(key);
        }
        
        public int BlockSize => 2 * _roundFunction.BlockSize;
        
        public int[] SupportedKeySizes => _keyExpander.GetSupportedKeySizes();
        
        public int RoundsCount => _roundKeys.Length;

        public bool IsInitialized => _isInitialized;

        public byte[][] RoundKeys
        {
            get
            {
                if (!_isInitialized)
                    throw new InvalidOperationException("Алгоритм не инициализирован. Вызовите Initialize() сначала.");
                return _roundKeys;
            }
        }


        private byte[] EncryptBlockInternal(byte[] plaintextBlock)
        {
            int halfSize = BlockSize / 2;
            byte[] left = new byte[halfSize];
            byte[] right = new byte[halfSize];
            
            Array.Copy(plaintextBlock, 0, left, 0, halfSize);
            Array.Copy(plaintextBlock, halfSize, right, 0, halfSize);
            
            for (int round = 0; round < RoundsCount; round++)
            {
                byte[] temp = _roundFunction.Encrypt(right, _roundKeys[round]);
                byte[] newLeft = new byte[halfSize];
                byte[] newRight = new byte[halfSize];
                
                Array.Copy(right, newLeft, halfSize);
                
                for (int i = 0; i < halfSize; i++)
                {
                    newRight[i] = (byte)(left[i] ^ temp[i]);
                }
            
                Array.Copy(newRight, right, halfSize);
                Array.Copy(newLeft, left, halfSize);
            }
            
            byte[] result = new byte[BlockSize];
            Array.Copy(left, 0, result, halfSize, halfSize);
            Array.Copy(right, 0, result, 0, halfSize);
            
            return result;
        }

        private byte[] DecryptBlockInternal(byte[] ciphertextBlock)
        {
            int halfSize = BlockSize / 2;
            byte[] left = new byte[halfSize];
            byte[] right = new byte[halfSize];
            
            Array.Copy(ciphertextBlock, 0, left, 0, halfSize);
            Array.Copy(ciphertextBlock, halfSize, right, 0, halfSize);
            
            for (int round = RoundsCount - 1; round >=0 ; round--)
            {
                byte[] temp = _roundFunction.Encrypt(right, _roundKeys[round]);
                byte[] newLeft = new byte[halfSize];
                byte[] newRight = new byte[halfSize];
                
                Array.Copy(right, newLeft, halfSize);
                
                for (int i = 0; i < halfSize; i++)
                {
                    newRight[i] = (byte)(left[i] ^ temp[i]);
                }
            
                Array.Copy(newRight, right, halfSize);
                Array.Copy(newLeft, left, halfSize);
            }
            
            byte[] result = new byte[BlockSize];
            Array.Copy(left, 0, result, halfSize, halfSize);
            Array.Copy(right, 0, result, 0, halfSize);
            
            return result;
        }
        
        private byte[] EncryptInternal(byte[] plaintext)
        {
            int blockCount = plaintext.Length / BlockSize;
            byte[] result = new byte[plaintext.Length];
            
            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[BlockSize];
                Array.Copy(plaintext, i * BlockSize, block, 0, BlockSize);
                byte[] encryptedBlock = EncryptBlock(block);
                Array.Copy(encryptedBlock, 0, result, i * BlockSize, BlockSize);
            }
            
            return result;
        }

        private byte[] DecryptInternal(byte[] ciphertext)
        {
            int blockCount = ciphertext.Length / BlockSize;
            byte[] result = new byte[ciphertext.Length];
            
            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[BlockSize];
                Array.Copy(ciphertext, i * BlockSize, block, 0, BlockSize);
                byte[] decryptedBlock = DecryptBlock(block);
                Array.Copy(decryptedBlock, 0, result, i * BlockSize, BlockSize);
            }
            
            return result;
        }
        
        private void CheckInitialization()
        {
            if (!_isInitialized)
                throw new InvalidOperationException(
                    "Алгоритм не инициализирован. Вызовите Initialize() с ключом шифрования.");
            
            if (_roundKeys == null || _roundKeys.Length == 0)
                throw new InvalidOperationException(
                    "Раундовые ключи не сгенерированы. Вызовите Initialize() с ключом шифрования.");
        }

        
        private bool _disposed = false;
        
        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _roundKeys = null;
                }
                
                _disposed = true;
            }
        }
        
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        
        ~FeistelNetwork()
        {
            Dispose(false);
        }

    }
}