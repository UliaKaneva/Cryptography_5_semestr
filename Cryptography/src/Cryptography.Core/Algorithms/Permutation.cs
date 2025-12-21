namespace Cryptography.Core.Algorithms
{
    public static class BitPermutation
    {
        public enum BitIndexing
        {
            SmallerIndexFirst,
            LargeIndexFirst
        }

        public enum StartBit
        {
            Zero,
            One
        }

        public static byte[] PermuteBits(byte[] input, int[] permutationRule,
            BitIndexing indexing = BitIndexing.SmallerIndexFirst, StartBit startBit = StartBit.Zero)
        {
            if (input == null || input.Length == 0)
                throw new ArgumentNullException(nameof(input));
            if (permutationRule == null || permutationRule.Length == 0)
                throw new ArgumentNullException(nameof(permutationRule));

            int totalInputBits = input.Length * 8;

            foreach (int position in permutationRule)
            {
                int maxAllowedPosition = totalInputBits - (startBit == StartBit.Zero ? 1 : 0);
                if (position < (startBit == StartBit.Zero ? 0 : 1) || position > maxAllowedPosition)
                {
                    throw new ArgumentException(
                        "The position in the permutation rule is outside the acceptable range!");
                }
            }

            int outputByteCount = (permutationRule.Length + 7) / 8;
            byte[] output = new byte[outputByteCount];

            for (int i = 0; i < permutationRule.Length; i++)
            {
                int num = permutationRule[i] - (int)startBit;
                num = indexing == BitIndexing.LargeIndexFirst ? totalInputBits - num - 1 : num;
                int numByte = num / 8;
                int numPos = num % 8;

                output[i / 8] |= (byte)(((input[numByte] >> (7 - numPos)) & 1) << (7 - (i % 8)));
            }

            return output;
        }
    }
}