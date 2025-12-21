using System;

namespace Cryptography.Core.Padding
{
    public interface IPaddingProvider
    {
        byte[] AddPadding(byte[] data, int blockSize);
        byte[] RemovePadding(byte[] data, int blockSize);
        Enums.PaddingMode Mode { get; }
    }
}