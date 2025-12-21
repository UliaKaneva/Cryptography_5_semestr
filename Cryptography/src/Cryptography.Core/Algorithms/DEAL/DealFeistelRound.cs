using Cryptography.Core.Interfaces;

namespace Cryptography.Core.Algorithms.DEAL;


public class DealFeistelRound : IEncryptionRound
{
    public byte[] Encrypt(byte[] inputBlock, byte[] roundKey)
    {
        if (inputBlock == null)  throw new ArgumentNullException(nameof(inputBlock));
        if (roundKey == null) throw new ArgumentNullException(nameof(roundKey));
        if (!IsValidBlockSize(inputBlock.Length)) throw new ArgumentOutOfRangeException(nameof(inputBlock));
        if (!IsValidKeySize(roundKey.Length)) throw new ArgumentOutOfRangeException(nameof(inputBlock));

        var des = new Des();
        des.Initialize(roundKey);
        byte[] result = des.EncryptBlock(inputBlock);
        return result;
    }

    public byte[] Decrypt(byte[] inputBlock, byte[] roundKey)
    {
        return Encrypt(inputBlock, roundKey);
    }

    public int BlockSize => 8;
    public bool IsValidBlockSize(int blockSize)
    {
        return blockSize == BlockSize;
    }
    public bool IsValidKeySize(int keySize) => 8 == keySize;
}