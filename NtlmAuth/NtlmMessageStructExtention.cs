using System;
using System.Runtime.InteropServices;

namespace NtlmAuth
{
    public static class NtlmMessageStructExtention
    {
        public static byte[] ToBytes<T>(this T structure) where T : struct
        {
            var structPtr = IntPtr.Zero;
            try
            {
                var structSize = Marshal.SizeOf(typeof(T));
                structPtr = Marshal.AllocHGlobal(structSize);
                Marshal.StructureToPtr(structure, structPtr, true);
                var buffer = new byte[structSize];
                Marshal.Copy(structPtr, buffer, 0, structSize);
                return buffer;
            }
            finally
            {
                if (structPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(structPtr);
            }
        }

        public static T ToStruct<T>(this byte[] data) where T : struct
        {
            if (data == null)
                throw new ArgumentNullException($"{nameof(data)} was null");
            if (data.Length == 0)
                throw new ArgumentException($"{nameof(data)} was empty");

            var structPtr = IntPtr.Zero;
            try
            {
                var structSize = Marshal.SizeOf(typeof(T));
                structPtr = Marshal.AllocHGlobal(structSize);
                Marshal.Copy(data, 0, structPtr, structSize);
                return Marshal.PtrToStructure<T>(structPtr);
            }
            finally
            {
                if (structPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(structPtr);
            }
        }

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
            if (data.Length >= totalWidth) return data;
            var result = new byte[totalWidth];
            data.CopyTo(result, 0);
            for (var i = data.Length; i < totalWidth; i++)
            {
                result[i] = paddingByte;
            }
            return result;
        }

        public static byte[] PadLeftt(this byte[] data, int totalWidth, byte paddingByte = 0)
        {
            if (data.Length >= totalWidth) return data;
            var result = new byte[totalWidth];
            var startIndex = totalWidth - data.Length;
            data.CopyTo(result, startIndex);
            for (var i = 0; i < startIndex; i++)
            {
                result[i] = paddingByte;
            }
            return result;
        }
    }
}