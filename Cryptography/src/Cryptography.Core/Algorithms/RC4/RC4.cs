using Cryptography.Core.Interfaces;

namespace Cryptography.Core.Algorithms.RC4
{
    public class RC4 : ISymmetricCipher
    {
        private byte[] _s;            
        private byte[] _initialS;
        private int _i;
        private int _j;
        private bool _isInitialized;
        
        public int BlockSize => 0;
        public int[] SupportedKeySizes => new int[] { 5, 16, 24, 32 };
        public int RoundsCount => 0;
        public bool IsInitialized => _isInitialized;
        public byte[][] RoundKeys => Array.Empty<byte[]>();

        public void Initialize(byte[] key)
        {
            if (key == null || key.Length == 0)
                throw new ArgumentException("Key cannot be null or empty", nameof(key));
            
            if (key.Length < 5 || key.Length > 256)
                throw new ArgumentException("RC4 key length must be between 5 and 256 bytes (40-2048 bits)", nameof(key));

            _s = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                _s[i] = (byte)i;
            }

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + _s[i] + key[i % key.Length]) & 0xFF;
                Swap(i, j);
            }

            _initialS = (byte[])_s.Clone();
            
            _i = 0;
            _j = 0;
            _isInitialized = true;
        }

        public void Reset()
        {
            if (!_isInitialized)
                throw new InvalidOperationException("RC4 must be initialized before reset");
            
            if (_initialS != null)
            {
                Buffer.BlockCopy(_initialS, 0, _s, 0, 256);
            }
            _i = 0;
            _j = 0;
        }

        public byte[] Process(byte[] data)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("RC4 must be initialized before processing");
            
            if (data == null)
                return Array.Empty<byte>();

            byte[] result = new byte[data.Length];

            for (int k = 0; k < data.Length; k++)
            {
                _i = (_i + 1) & 0xFF;
                _j = (_j + _s[_i]) & 0xFF;
                Swap(_i, _j);
                
                byte t = (byte)((_s[_i] + _s[_j]) & 0xFF);
                byte keyStreamByte = _s[t];
                
                result[k] = (byte)(data[k] ^ keyStreamByte);
            }

            return result;
        }

        public byte[] Encrypt(byte[] data) => Process(data);
        public byte[] Decrypt(byte[] data) => Process(data);
        
        public byte[] EncryptBlock(byte[] plaintextBlock) => Process(plaintextBlock);
        public byte[] DecryptBlock(byte[] ciphertextBlock) => Process(ciphertextBlock);
        
        public byte[][] GenerateRoundKeys(byte[] key)
        {
            Initialize(key);
            return Array.Empty<byte[]>();
        }

        private void Swap(int index1, int index2)
        {
            (_s[index1], _s[index2]) = (_s[index2], _s[index1]);
        }
    }
}