using System;

namespace NtlmAuth
{
    public static class ArrayExtention
    {
        public static byte[] NewCopy(this byte[] data, int startIndex, int length = -1)
        {
            if (data == null)
                throw new ArgumentNullException($"{nameof(data)} was null");
            if (data.Length == 0)
                throw new ArgumentException($"{nameof(data)} was empty");

            if (startIndex < 0 || startIndex >= data.Length)
                throw new ArgumentOutOfRangeException($"{nameof(startIndex)} was out of range [0,{data.Length})");

            if (length > data.Length - startIndex || length < 0)
                length = data.Length - startIndex;

            var temp = new byte[length];
            Array.Copy(data, startIndex, temp, 0, length);

            return temp;
        }

        public static byte[] PadRight(this byte[] data, int totalWidth, byte paddingByte = 0)
        {
            if (data != null && data.Length >= totalWidth) return data;

            var result = new byte[totalWidth];
            data?.CopyTo(result, 0);
            for (var i = data?.Length ?? 0; i < totalWidth; i++)
            {
                result[i] = paddingByte;
            }
            return result;
        }

        public static byte[] PadLeftt(this byte[] data, int totalWidth, byte paddingByte = 0)
        {
            if (data != null && data.Length >= totalWidth) return data;

            var result = new byte[totalWidth];
            var startIndex = totalWidth - data?.Length ?? 0;
            data?.CopyTo(result, startIndex);
            for (var i = 0; i < startIndex; i++)
            {
                result[i] = paddingByte;
            }
            return result;
        }
    }
}
