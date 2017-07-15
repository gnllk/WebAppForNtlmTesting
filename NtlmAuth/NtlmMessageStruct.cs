using System.Runtime.InteropServices;

namespace NtlmAuth
{
    [StructLayout(LayoutKind.Sequential)]
    public struct NegotiationMessageStruct
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Signature;
        public MessageType Type;
        public MessageFlag Flags;

        public short DomainNameLength;
        public short DomainNameSpace;
        public int DomainNameOffset;

        public short HostNameLength;
        public short HostNameSpace;
        public int HostNameOffset;

        public byte OsMajorVersion;
        public byte OsMinorVersion;
        public short OsBuildNumber;
        public int OsReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ChallengeMessageStruct
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Signature;
        public MessageType Type;

        public short TargetNameLength;
        public short TargetNameSpace;
        public int TargetNameOffset;

        public MessageFlag Flags;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Challenge;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Context;

        public short TargetInfosLength;
        public short TargetInfosSpace;
        public int TargetInfosOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TargetInfoStruct
    {
        public TargetInfoType Type;

        public short Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AuthenticationMessageStruct
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Protocol;
        public MessageType Type;

        public short LmResponseLength;
        public short LmResponseSpace;
        public int LmResponseOffset;

        public short NtlmResponseLength;
        public short NtlmResponseSpace;
        public int NtlmResponseOffset;

        public short TargetNameLength;
        public short TargetNameSpace;
        public int TargetNametOffset;

        public short UserNameLength;
        public short UserNameSpace;
        public int UserNameOffset;

        public short HostNameLength;
        public short HostNameSpace;
        public int HostNameOffset;

        public short SessionKeyLength;
        public short SessionKeySpace;
        public int SessionKeyOffset;

        public MessageFlag Flags;

        public byte OsMajorVersion;
        public byte OsMinorVersion;
        public short OsBuildNumber;
        public int OsReserved;
    }
}