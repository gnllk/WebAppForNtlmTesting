using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace NtlmAuth
{
    [Flags]
    public enum MessageFlag : uint
    {
        NegotiateUnicode = 0x00000001,
        NegotiateOem = 0x00000002,
        RequestTarget = 0x00000004,
        NegotiateSign = 0x00000010,
        NegotiateSeal = 0x00000020,
        NegotiateDatagramStyle = 0x00000040,
        NegotiateLanManagerKey = 0x00000080,
        NegotiateNetware = 0x00000100,
        NegotiateNtlm = 0x00000200,
        NegotiateAnonymous = 0x00000800,
        NegotiateDomainSupplied = 0x00001000,
        NegotiateWorkstationSupplied = 0x00002000,
        NegotiateLocalCall = 0x00004000,
        NegotiateAlwaysSign = 0x00008000,
        TargetTypeDomain = 0x00010000,
        TargetTypeServer = 0x00020000,
        TargetTypeShare = 0x00040000,
        NegotiateNtlm2Key = 0x00080000,
        RequestInitResponse = 0x00100000,
        RequestAcceptResponse = 0x00200000,
        RequestNonNtSessionKey = 0x00400000,
        NegotiateTargetInfo = 0x00800000,
        Negotiate128 = 0x20000000,
        NegotiateKeyExchange = 0x40000000,
        Negotiate56 = 0x80000000
    }

    public enum MessageType
    {
        Negotiation = 1, Challenge = 2, Authentication = 3
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct NegotiationMessage
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Protocol;
        public int Type;
        public int Flags;

        public short DomainLength;
        public short DomainSpace;
        public int DomainOffset;

        public short HostLength;
        public short HostSpace;
        public int HostOffset;

        public byte OsMajorVersion;
        public byte OsMinorVersion;
        public short OsBuildNumber;
        public int OsReserved;
    }

    public class NegotiationMessageShell
    {
        private readonly NegotiationMessage _message;

        private readonly byte[] _messageBuffer;

        public NegotiationMessageShell(NegotiationMessage message, byte[] messageBuffer)
        {
            _message = message;
            _messageBuffer = messageBuffer;
        }

        public string Protocol => Encoding.ASCII.GetString(_message.Protocol);

        public MessageType Type => (MessageType)_message.Type;

        public string Domain
        {
            get
            {
                var temp = new byte[_message.DomainLength];
                Array.Copy(_messageBuffer, _message.DomainOffset, temp, 0, _message.DomainLength);
                return Encoding.ASCII.GetString(temp);
            }
        }

        public string Host
        {
            get
            {
                var temp = new byte[_message.HostLength];
                Array.Copy(_messageBuffer, _message.HostOffset, temp, 0, _message.HostLength);
                return Encoding.ASCII.GetString(temp);
            }
        }

        public MessageFlag[] SupportedFlags
        {
            get
            {
                var result = new List<MessageFlag>();
                foreach (var item in Enum.GetValues(typeof(MessageFlag)))
                {
                    if (((uint)item & (uint)_message.Flags) > 0)
                        result.Add((MessageFlag)item);
                }
                return result.ToArray();
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ChallengeMessage
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Protocol;
        public int Type;
        public int Zero;
        public int MessageLength;
        public int Flags;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Nonce;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] FillZero;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AuthenticationMessage
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Protocol;
        public int Type;

        public int LanManagerResponseLength;
        public int LanManagerResponseOffset;

        public int NtlmManagerResponseLength;
        public int NtlmManagerResponseOffset;

        public int DomainLength;
        public int DomainOffset;

        public int UserLength;
        public int UserOffset;

        public int HostLength;
        public int HostOffset;

        public int Zero;
        public int MessageLength;
        public int Flags;
    }
}