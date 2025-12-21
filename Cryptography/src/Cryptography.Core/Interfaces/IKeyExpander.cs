using System;

namespace Cryptography.Core.Interfaces
{
    public interface IKeyExpander
    {
        byte[][] ExpandKey(byte[] inputKey);
        byte[][] ExpandKey(byte[] inputKey, int roundsCount);
        bool IsValidKeySize(int keyLength);
        int[] GetSupportedKeySizes();
        int RoundKeySize { get; }
    }
}