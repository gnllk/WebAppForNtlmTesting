namespace NtlmAuth
{
    public class Constants
    {
        public const string Ntlmssp = "NTLMSSP\0";

        public static readonly byte[] NtlmsspBytes = { 0x4E, 0x54, 0x4c, 0x4D, 0x53, 0x53, 0x50, 0x00 };
    }
}
