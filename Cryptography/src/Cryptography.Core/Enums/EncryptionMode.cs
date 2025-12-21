namespace Cryptography.Core.Enums
{
    /// <summary>
    /// Режимы шифрования для симметричных блочных шифров
    /// </summary>
    public enum EncryptionMode
    {
        ECB,
        CBC,
        PCBC,
        CFB,
        OFB,
        CTR,
        RandomDelta
    }
}