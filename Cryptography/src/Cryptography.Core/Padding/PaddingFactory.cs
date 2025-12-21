using System;
using Cryptography.Core.Enums;

namespace Cryptography.Core.Padding
{
    public static class PaddingFactory
    {
        public static IPaddingProvider Create(PaddingMode mode)
        {
            return mode switch
            {
                PaddingMode.Zeros => new PaddingProvider(),
                PaddingMode.ANSIX923 => new AnsiX923PaddingProvider(),
                PaddingMode.PKCS7 => new Pkcs7PaddingProvider(),
                PaddingMode.ISO10126 => new Iso10126PaddingProvider(),
                _ => throw new ArgumentException($"Неподдерживаемый режим паддинга: {mode}")
            };
        }
    }
}