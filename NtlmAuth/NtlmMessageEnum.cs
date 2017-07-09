using System;

namespace NtlmAuth
{
    [Flags]
    public enum MessageFlag : uint
    {
        NegotiateUnicode = 0x00000001,
        NegotiateOem = 0x00000002,
        RequestTarget = 0x00000004,
        Unknown1 = 0x00000008,
        NegotiateSign = 0x00000010,
        NegotiateSeal = 0x00000020,
        NegotiateDatagramStyle = 0x00000040,
        NegotiateLanManagerKey = 0x00000080,
        NegotiateNetware = 0x00000100,
        NegotiateNtlm = 0x00000200,
        Unknown2 = 0x00000400,
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
        Unknown3 = 0x01000000,
        Unknown4 = 0x02000000,
        Unknown5 = 0x04000000,
        Unknown6 = 0x08000000,
        Unknown7 = 0x10000000,
        Negotiate128 = 0x20000000,
        NegotiateKeyExchange = 0x40000000,
        Negotiate56 = 0x80000000
    }

    public enum MessageType : uint
    {
        Negotiation = 1, Challenge = 2, Authentication = 3
    }

    public enum MessageVersion
    {
        /// <summary>
        /// The Supplied Domain and Workstation security buffers and OS Version structure 
        /// are omitted completely. In this case the message ends after the flags field, 
        /// and is a fixed-length 16-byte structure. This form is typically seen in older 
        /// Win9x-based systems, and is roughly documented in the Open Group's ActiveX 
        /// reference documentation.
        /// </summary>
        VersionOne,
        /// <summary>
        /// The Supplied Domain and Workstation buffers are present, but the OS Version 
        /// structure is not. The data block begins immediately after the security buffer 
        /// headers, at offset 32. This form is seen in most out-of-box shipping versions 
        /// of Windows.
        /// </summary>
        VersionTwo,
        /// <summary>
        /// Both the Supplied Domain/Workstation buffers are present, as well as the OS 
        /// Version structure. The data block begins after the OS Version structure, at 
        /// offset 40. This form was introduced in a relatively recent Service Pack, and 
        /// is seen on currently-patched versions of Windows 2000, Windows XP, and Windows 
        /// 2003.
        /// </summary>
        VersionThree
    }

    public enum TargetInfoType : ushort
    {
        /// <summary>
        /// Server name
        /// </summary>
        ServerName = 0x0100,
        /// <summary>
        /// Domain name(i.e., domain)
        /// </summary>
        DomainName = 0x0200,
        /// <summary>
        /// Fully-qualified DNS host name (i.e., svr1.domain.com)
        /// </summary>
        FullyQualifiedDomainName = 0x0300,
        /// <summary>
        /// DNS domain name (i.e., domain.com)
        /// </summary>
        DnsDomainName = 0x0400
    }
}