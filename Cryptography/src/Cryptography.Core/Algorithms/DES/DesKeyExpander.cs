using System;
using Cryptography.Core.Interfaces;

namespace Cryptography.Core.Algorithms
{
    public class DesKeyExpander : IKeyExpander
    {
        public byte[][] ExpandKey(byte[] inputKey)
        {
            return ExpandKey(inputKey, 16);
        }

        public byte[][] ExpandKey(byte[] inputKey, int roundsCount)
        {
            if (inputKey == null)
                throw new ArgumentNullException(nameof(inputKey));

            if (!IsValidKeySize(inputKey.Length))
            {
                throw new ArgumentException(
                    $"Некорректный размер ключа. Поддерживаемые размеры: 7 байт. " +
                    $"Фактический размер: {inputKey.Length} байт",
                    nameof(inputKey));
            }

            if (roundsCount <= 0)
                throw new ArgumentException("Количество раундов должно быть больше 0", nameof(roundsCount));
            byte[] keyE;
            if (inputKey.Length == 7)
            {
                int[] keyExTable =
                [
                    1, 2, 3, 4, 5, 6, 7, 1,
                    8, 9, 10, 11, 12, 13, 14, 1,
                    15, 16, 17, 18, 19, 20, 21, 1,
                    22, 23, 24, 25, 26, 27, 28, 1,
                    29, 30, 31, 32, 33, 34, 35, 1,
                    36, 37, 38, 39, 40, 41, 42, 1,
                    43, 44, 45, 46, 47, 48, 49, 1,
                    50, 51, 52, 53, 54, 55, 56, 1
                ];
                keyE = BitPermutation.PermuteBits(inputKey, keyExTable, startBit: BitPermutation.StartBit.One);
                for (int i = 0; i < keyE.Length; i++)
                {
                    keyE[i] &= 0b_1111_1110;
                    byte temp = (byte)((keyE[i] >> 4) ^ (keyE[i] & 0b_0000_1111));
                    temp = (byte)((temp >> 2) ^ (temp & 3));
                    keyE[i] |= (byte)((temp >> 1) ^ (temp & 1) ^ 1);
                }
            }
            else
            {
                keyE = new byte[inputKey.Length];
                Array.Copy(inputKey, keyE, inputKey.Length);
            }


            int[] c0Table =
            [
                57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36
            ];

            int[] d0Table =
            [
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4
            ];

            byte[] c0 = BitPermutation.PermuteBits(keyE, c0Table, startBit: BitPermutation.StartBit.One);
            byte[] d0 = BitPermutation.PermuteBits(keyE, d0Table, startBit: BitPermutation.StartBit.One);

            byte[][] roundKeys = new byte[roundsCount][];

            int[] numberLeftShift = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

            for (int i = 0; i < roundsCount; i++)
            {
                int[] kTable =
                [
                    14, 17, 11, 24, 1, 5,
                    3, 28, 15, 6, 21, 10,
                    23, 19, 12, 4, 26, 8,
                    16, 7, 27, 20, 13, 2,
                    41, 52, 31, 37, 47, 55,
                    30, 40, 51, 45, 33, 48,
                    44, 49, 39, 56, 34, 53,
                    46, 42, 50, 36, 29, 32
                ];

                CyclicShiftLeft(c0, numberLeftShift[i]);
                CyclicShiftLeft(d0, numberLeftShift[i]);
                byte[] tempKey = SplitCD(c0, d0);
                roundKeys[i] = BitPermutation.PermuteBits(tempKey, kTable, startBit: BitPermutation.StartBit.One);
            }

            return roundKeys;
        }

        private void CyclicShiftLeft(byte[] inputKey, int n)
        {
            byte toEnd = (byte)(inputKey[0] >> (8 - n));
            for (int i = 0; i < inputKey.Length - 1; i++)
            {
                inputKey[i] = (byte)(inputKey[i] << n);
                inputKey[i] |= (byte)(inputKey[i + 1] >> (8 - n));
            }

            inputKey[^1] <<= n;
            inputKey[^1] |= (byte)(toEnd << 4);
        }

        private byte[] SplitCD(byte[] c, byte[] d)
        {
            byte[] res = new byte[7];
            Array.Copy(c, 0, res, 0, c.Length);
            for (int i = 0; i < d.Length - 1; i++)
            {
                res[3 + i] |= (byte)(d[i] >> 4);
                res[4 + i] |= (byte)(d[i] << 4);
            }

            res[^1] |= (byte)(d[^1] >> 4);
            return res;
        }


        public bool IsValidKeySize(int keyLength) => keyLength == 7 || keyLength == 8;

        public int[] GetSupportedKeySizes() => [7, 8];

        public int RoundKeySize => 6;

        public int GetDefaultRoundsCount(int keySize) => 16;
    }
}