
using Cryptography.Core.Interfaces;

namespace Cryptography.Core.Algorithms.Rijndael;

public class Rijndael : ISymmetricCipher
{
    
    private int _blockSize;
    private bool _initialized;
    private static readonly GaloisField256 Gf256 = new GaloisField256();
    private readonly byte _polynomial;
    
    private RijndaelKeyExpander _keyExpander;
    private int _keySize;
    private byte[][] _roundKeys;

    public Rijndael(int blockSize = 16, byte polynomial = 0x1B)
    {
        _blockSize = blockSize;
        _initialized = false;
        _polynomial = polynomial;
        _keyExpander = new RijndaelKeyExpander(polynomial, blockSize);

    }

    public void Initialize(byte[] key)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (!IsValidKeySize(key.Length)) 
            throw new ArgumentException($"Invalid key size: {key.Length * 8} bits");
        
        _keySize = key.Length;
        _roundKeys = _keyExpander.ExpandKey(key, RoundsCount);
        _initialized = true;
    }

    public byte[] EncryptBlock(byte[] plaintextBlock)
    {
        if (!_initialized) throw new InvalidOperationException("Cipher not initialized");
        if (plaintextBlock == null) throw new ArgumentNullException(nameof(plaintextBlock));
        if (plaintextBlock.Length != _blockSize)
            throw new ArgumentException($"Block size must be {_blockSize} bits");
        
        int nb = _blockSize / 4;
        byte[][] state = BytesToState(plaintextBlock, nb);
        

        Utility.AddRoundKey(state, _roundKeys, 0, nb);
        
        for (int round = 1; round < RoundsCount; round++)
        {
            Utility.SubBytes(state, _keyExpander.SBlock);
            Utility.ShiftRows(state, nb);
            Utility.MixColumns(state, nb, 0x1B);
            Utility.AddRoundKey(state, _roundKeys, round, nb);
        }
        

        Utility.SubBytes(state, _keyExpander.SBlock);
        Utility.ShiftRows(state, nb);
        Utility.AddRoundKey(state, _roundKeys, RoundsCount, nb);
        
        return StateToBytes(state, nb);
    }

    public byte[] DecryptBlock(byte[] ciphertextBlock)
    {
        if (!_initialized) throw new InvalidOperationException("Cipher not initialized");
        if (ciphertextBlock == null) throw new ArgumentNullException(nameof(ciphertextBlock));
        if (ciphertextBlock.Length != _blockSize)
            throw new ArgumentException($"Block size must be {_blockSize} bytes");
    
        int nb = _blockSize / 4;
        byte[][] state = BytesToState(ciphertextBlock, nb);
        
        Utility.AddRoundKey(state, _roundKeys, RoundsCount, nb);
    
        for (int round = RoundsCount - 1; round > 0; round--)
        {
            Utility.InvShiftRows(state, nb);
            Utility.SubBytes(state, _keyExpander.SBlockInvers);
            Utility.AddRoundKey(state, _roundKeys, round, nb);
            Utility.InvMixColumns(state, nb, _polynomial);
        }
        
        Utility.InvShiftRows(state, nb);
        Utility.SubBytes(state, _keyExpander.SBlockInvers);
        Utility.AddRoundKey(state, _roundKeys, 0, nb);
    
        return StateToBytes(state, nb);
    }
    

    private byte[][] BytesToState(byte[] bytes, int nb)
    {
        byte[][] state = new byte[nb][];
        for (int col = 0; col < nb; col++)
        {
            state[col] = new byte[4];
            for (int row = 0; row < 4; row++)
            {
                state[col][row] = bytes[col * 4 + row];
            }
        }
        return state;
    }

    private byte[] StateToBytes(byte[][] state, int nb)
    {
        byte[] bytes = new byte[nb * 4];
        for (int col = 0; col < nb; col++)
        {
            for (int row = 0; row < 4; row++)
            {
                bytes[col * 4 + row] = state[col][row];
            }
        }
        return bytes;
    }

    public byte[] Encrypt(byte[] plaintext)
    {
        if (!_initialized) throw new InvalidOperationException("Cipher not initialized");
        if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
        int blockSizeBytes = _blockSize;
        int blocks = (plaintext.Length + blockSizeBytes - 1) / blockSizeBytes;
        byte[] result = new byte[blocks * blockSizeBytes];
        
        for (int i = 0; i < blocks; i++)
        {
            byte[] block = new byte[blockSizeBytes];
            Array.Copy(plaintext, i * blockSizeBytes, block, 0, 
                Math.Min(blockSizeBytes, plaintext.Length - i * blockSizeBytes));
            
            byte[] encryptedBlock = EncryptBlock(block);
            Array.Copy(encryptedBlock, 0, result, i * blockSizeBytes, blockSizeBytes);
        }
        
        return result;
    }

    public byte[] Decrypt(byte[] ciphertext)
    {
        if (!_initialized) throw new InvalidOperationException("Cipher not initialized");
        if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
        int blockSizeBytes = _blockSize;
        if (ciphertext.Length % blockSizeBytes != 0)
            throw new ArgumentException("Ciphertext length must be multiple of block size");
        
        int blocks = ciphertext.Length / blockSizeBytes;
        byte[] result = new byte[blocks * blockSizeBytes];
        
        for (int i = 0; i < blocks; i++)
        {
            byte[] block = new byte[blockSizeBytes];
            Array.Copy(ciphertext, i * blockSizeBytes, block, 0, blockSizeBytes);
            
            byte[] decryptedBlock = DecryptBlock(block);
            Array.Copy(decryptedBlock, 0, result, i * blockSizeBytes, blockSizeBytes);
        }

        return result;
    }

    public byte[][] GenerateRoundKeys(byte[] key)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (!IsValidKeySize(key.Length))  throw new ArgumentException($"Invalid key size: {key.Length * 8} bits");
        return _keyExpander.ExpandKey(key, RoundsCount) ;
    }

    public int BlockSize => _blockSize;
    public int[] SupportedKeySizes => [16, 24, 32];

    public int RoundsCount
    {
        get
        {
            int maxSize = Math.Max(_blockSize, _keySize);
            return maxSize switch
            {
                16 => 10,
                24 => 12,
                32 => 14,
                _ => throw new ArgumentOutOfRangeException($"Unsupported size: {maxSize}")
            };
        }
    }

    public bool IsInitialized => _initialized;
    public byte[][] RoundKeys => _roundKeys;

    private bool IsValidKeySize(int keySizeBits) => 
        keySizeBits == 16 || keySizeBits == 24 || keySizeBits == 32;

    private class RijndaelKeyExpander : IKeyExpander
    {
        private readonly byte _basicPolynomial;
        private readonly int _blockSize;
        private readonly byte[] _rcon;
        private readonly byte[] _sBlockInvers;
        private readonly byte[] _sBlock;
        
        public RijndaelKeyExpander(byte basicPolynomial, int blockSize)
        {
            _basicPolynomial = basicPolynomial;
            _blockSize = blockSize;
            
            if (!Gf256.ValidatePolynomialIrreducibility(basicPolynomial))
            {
                throw new ArgumentException(
                    $"0x{Convert.ToString(basicPolynomial, 16).PadLeft(2, '0')} is a reducible polynomial");
            }

            _rcon = new byte[30];
            _rcon[0] = 1;
            for (int i = 1; i < _rcon.Length; i++)
            {
                _rcon[i] = Gf256.FieldMultiplication(_rcon[i - 1], 2, _basicPolynomial);
            }
            
            _sBlock = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                byte inverse = i != 0 ? Gf256.MultiplicativeInverse((byte)i, _basicPolynomial) : (byte)0;
                byte b = inverse;
                byte result = (byte)(b ^ RotateLeft(b, 1) ^ RotateLeft(b, 2) ^ 
                                   RotateLeft(b, 3) ^ RotateLeft(b, 4) ^ 0x63);
                _sBlock[i] = result;
            }
            
            _sBlockInvers = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                byte b = (byte)(RotateLeft((byte) i, 1) ^ RotateLeft((byte) i, 3) ^ RotateLeft((byte) i, 6) ^ 0x5);
                _sBlockInvers[i] = b != 0 ? Gf256.MultiplicativeInverse(b, _basicPolynomial) : (byte)0;
            }
        }

        private byte RotateLeft(byte value, int n)
        {
            return (byte)((value << n) | (value >> (8 - n)));
        }

        public byte[][] ExpandKey(byte[] inputKey)
        {
            return ExpandKey(inputKey, 10);
        }

        public byte[][] ExpandKey(byte[] inputKey, int roundsCount)
        {
            if (inputKey == null) throw new ArgumentNullException(nameof(inputKey));
            if (!IsValidKeySize(inputKey.Length)) 
                throw new ArgumentException($"Invalid key size: {inputKey.Length} bytes");
            
            int nk = inputKey.Length / 4;
            int nb = _blockSize / 4;
            int expandedWordCount = nb * (roundsCount + 1);
            
            byte[][] expandedKey = new byte[expandedWordCount][];
            
            for (int i = 0; i < nk; i++)
            {
                expandedKey[i] = new byte[4];
                Array.Copy(inputKey, i * 4, expandedKey[i], 0, 4);
            }

            for (int i = nk; i < expandedWordCount; i++)
            {
                byte[] temp = new byte[4];
                Array.Copy(expandedKey[i - 1], temp, 4);
                
                if (i % nk == 0)
                {
                    int rconIndex = i / nk - 1;
                    Utility.RotWord(temp);
                    Utility.SubBytes(temp, _sBlock);
                    temp[0] ^= _rcon[rconIndex];
                }
                else if (nk > 6 && i % nk == 4)
                {
                    Utility.SubBytes(temp, _sBlock);
                }
                
                expandedKey[i] = new byte[4];
                for (int j = 0; j < 4; j++)
                {
                    expandedKey[i][j] = (byte)(expandedKey[i - nk][j] ^ temp[j]);
                }
            }
            
            return expandedKey;
        }

        public bool IsValidKeySize(int keyLength) => keyLength == 16 || keyLength == 24 || keyLength == 32;
        public int[] GetSupportedKeySizes() => [16, 24, 32];

        public byte[] SBlock => _sBlock;
        public byte[] SBlockInvers => _sBlockInvers;
        public byte[] Rcon => _rcon;
        public int RoundKeySize => 4;
    }

    private static class Utility
    {
        public static void RotWord(byte[] word)
        {
            if (word.Length != 4)
                throw new ArgumentException("Word must be 4 bytes");
            
            byte temp = word[0];
            word[0] = word[1];
            word[1] = word[2];
            word[2] = word[3];
            word[3] = temp;
        }

        public static void SubBytes(byte[] word, byte[] sBlock)
        {
            for (int i = 0; i < word.Length; i++)
            {
                word[i] = sBlock[word[i]];
            }
        }

        public static void SubBytes(byte[][] words, byte[] sBlock)
        {
            foreach (var word in words)
            {
                SubBytes(word, sBlock);
            }
        }

        public static void ShiftRows(byte[][] state, int nb)
        {
            ShiftRow(state, 1, 1);
            ShiftRow(state,2, nb == 8 ? 3 : 2);
            ShiftRow(state, 3, nb == 8 ? 4 : 3);
        }

        public static void InvShiftRows(byte[][] state, int nb)
        {
            ShiftRow(state, 1, nb - 1);
            ShiftRow(state, 2, nb == 8 ? nb - 3 : nb - 2);
            ShiftRow(state, 3, nb == 8 ? nb - 4 : nb - 3);
        }

        private static void ShiftRow(byte[][] words, int index, int shift)
        {
            byte[] temp = new byte[words.Length];
            for (int i = 0; i < words.Length; i++)
            {
                temp[i] = words[i][index];
            }
    
            for (int i = 0; i < words.Length; i++)
            {
                int newPos = (i + shift) % words.Length;
                words[i][index] = temp[newPos];
            }
        }

        private static void MultiplicationPolynomialsCoefficientsGf(byte[] pol1, byte[] pol2, byte polynomial)
        {
            byte[] result = new byte[4];
    
            for (int i = 0; i < 4; i++)
            {
                result[i] = 0;
                for (int j = 0; j < 4; j++)
                {
                    byte temp = Gf256.FieldMultiplication(pol1[(i + j) % 4], pol2[j], polynomial);
                    result[i] = Gf256.FieldAddition(result[i], temp);
                }
            }
    
            Array.Copy(result, pol1, 4);
        }

        public static void MixColumns(byte[][] state, int nb, byte basicPolynomial)
        {
            for (int col = 0; col < nb; col++)
            {
                MultiplicationPolynomialsCoefficientsGf(state[col], [0x2, 0x1, 0x1, 0x3], basicPolynomial);
            }
        }

        public static void InvMixColumns(byte[][] state, int nb, byte basicPolynomial)
        {
            for (int col = 0; col < nb; col++)
            {
                MultiplicationPolynomialsCoefficientsGf(state[col], [0x0E, 0x09, 0x0D, 0x0B], basicPolynomial);
            }
        }
        public static void AddRoundKey(byte[][] state, byte[][] roundKeys, int round, int nb)
        {
            int startIndex = round * nb;
            for (int col = 0; col < nb; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    state[col][row] ^= roundKeys[startIndex + col][row];
                }
            }
        }
    }
}