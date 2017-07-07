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
    }
}