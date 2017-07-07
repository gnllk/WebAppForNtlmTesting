using System;
using System.Linq;

namespace NtlmAuth
{
    public static class HexHelper
    {
        public static string BytesToHex(this byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            return BitConverter.ToString(bytes).Replace("-", string.Empty);
        }

        public static byte[] HexToBytes(this string hex)
        {
            if (hex == null) throw new ArgumentNullException(nameof(hex));
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }
    }
}