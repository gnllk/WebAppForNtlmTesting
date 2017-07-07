using System.Runtime.InteropServices;

namespace NtlmAuth
{
    [StructLayout(LayoutKind.Sequential)]
    public struct NegotiationMessage
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Protocol;
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
    public struct ChallengeMessage
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Protocol;
        public MessageType Type;

        public short TargetNameLength;
        public short TargetNameSpace;
        public int TargetNametOffset;

        public MessageFlag Flags;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Challenge;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Context;

        public short TargetInfoLength;
        public short TargetInfoSpace;
        public int TargetInfoOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TargetInfo
    {
        public TargetInfoType Type;

        public short Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AuthenticationMessage
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Protocol;
        public MessageType Type;

        public short LanManagerResponseLength;
        public short LanManagerResponseSpace;
        public int LanManagerResponseOffset;

        public short NtlmManagerResponseLength;
        public short NtlmManagerResponseSpace;
        public int NtlmManagerResponseOffset;

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