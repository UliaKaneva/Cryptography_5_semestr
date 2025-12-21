using Cryptography.Core.Interfaces;
namespace Cryptography.Core.Algorithms.DEAL;

public class DealKeyExpander : IKeyExpander
{
    private int _keyLength;
    private readonly byte[] _baseKey = [18, 52, 86, 120, 144, 171, 205, 239];
    public byte[][] ExpandKey(byte[] inputKey)
    {
        return inputKey.Length switch
        {
            16 or 24 => ExpandKey(inputKey, 6),
            32 => ExpandKey(inputKey, 8),
            _ => throw new ArgumentOutOfRangeException(nameof(inputKey))
        };
    }

    public byte[][] ExpandKey(byte[] inputKey, int roundsCount)
    {
        if (!IsValidKeySize(inputKey.Length))
        {
            throw new ArgumentOutOfRangeException(nameof(inputKey));
        }
        Des expanderDes =  new Des();
        expanderDes.Initialize(_baseKey);
        _keyLength = inputKey.Length;
        int countKeys = inputKey.Length / 8;
        byte[][] keys = new byte[countKeys][];
        for (int i = 0; i < countKeys; i++)
        {
            keys[i] = new byte[8];
            Array.Copy(inputKey, i * 8, keys[i], 0, 8);
        }

        byte constant = 128;
        byte[][] roundKeys = new byte[roundsCount][];
        roundKeys[0] = expanderDes.EncryptBlock(keys[0]);
        for (int i = 1; i < roundsCount; i++)
        {
            roundKeys[i] = new byte[8];
            Array.Copy(keys[i % countKeys], roundKeys[i], 8);
            for (int j = 0; j < roundKeys[i].Length; j++)
            {
                roundKeys[i][j] ^= roundKeys[i - 1][j];
            }

            if (i / countKeys > 0)
            {
                roundKeys[i][0] ^= constant;
                constant >>= 1;
            }
            roundKeys[i] = expanderDes.EncryptBlock(roundKeys[i]);
        }
        return roundKeys;
    }

    public bool IsValidKeySize(int keyLength)
    {
        return keyLength == 16 || keyLength == 24 || keyLength == 32;
    }

    public int[] GetSupportedKeySizes() => [16, 24, 32];

    public int RoundKeySize => 8;
}
