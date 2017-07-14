using System;

namespace NtlmAuth
{
    [Flags]
    public enum MessageFlag : uint
    {
        /// <summary>
        /// Indicates that Unicode strings are supported for use in security buffer data.
        /// </summary>
        NegotiateUnicode = 0x00000001,
        /// <summary>
        /// Indicates that OEM strings are supported for use in security buffer data.
        /// </summary>
        NegotiateOem = 0x00000002,
        /// <summary>
        /// Requests that the server's authentication realm be included in the Type 2 message.
        /// </summary>
        RequestTarget = 0x00000004,
        /// <summary>
        /// This flag's usage has not been identified.
        /// </summary>
        Unknown1 = 0x00000008,
        /// <summary>
        /// Specifies that authenticated communication between the client and server should carry a digital signature (message integrity).
        /// </summary>
        NegotiateSign = 0x00000010,
        /// <summary>
        /// Specifies that authenticated communication between the client and server should be encrypted (message confidentiality).
        /// </summary>
        NegotiateSeal = 0x00000020,
        /// <summary>
        /// Indicates that datagram authentication is being used.
        /// </summary>
        NegotiateDatagramStyle = 0x00000040,
        /// <summary>
        /// Indicates that the Lan Manager Session Key should be used for signing and sealing authenticated communications.
        /// </summary>
        NegotiateLanManagerKey = 0x00000080,
        /// <summary>
        /// This flag's usage has not been identified.
        /// </summary>
        NegotiateNetware = 0x00000100,
        /// <summary>
        /// Indicates that NTLM authentication is being used.
        /// </summary>
        NegotiateNtlm = 0x00000200,
        /// <summary>
        /// This flag's usage has not been identified.
        /// </summary>
        Unknown2 = 0x00000400,
        /// <summary>
        /// Sent by the client in the Type 3 message to indicate that an anonymous context has been established. This also affects the response fields.
        /// </summary>
        NegotiateAnonymous = 0x00000800,
        /// <summary>
        /// Sent by the client in the Type 1 message to indicate that the name of the domain in which the client workstation has membership is included in the message. This is used by the server to determine whether the client is eligible for local authentication.
        /// </summary>
        NegotiateDomainSupplied = 0x00001000,
        /// <summary>
        /// Sent by the client in the Type 1 message to indicate that the client workstation's name is included in the message. This is used by the server to determine whether the client is eligible for local authentication.
        /// </summary>
        NegotiateWorkstationSupplied = 0x00002000,
        /// <summary>
        /// Sent by the server to indicate that the server and client are on the same machine. Implies that the client may use the established local credentials for authentication instead of calculating a response to the challenge.
        /// </summary>
        NegotiateLocalCall = 0x00004000,
        /// <summary>
        /// Indicates that authenticated communication between the client and server should be signed with a "dummy" signature.
        /// </summary>
        NegotiateAlwaysSign = 0x00008000,
        /// <summary>
        /// Sent by the server in the Type 2 message to indicate that the target authentication realm is a domain.
        /// </summary>
        TargetTypeDomain = 0x00010000,
        /// <summary>
        /// Sent by the server in the Type 2 message to indicate that the target authentication realm is a server.
        /// </summary>
        TargetTypeServer = 0x00020000,
        /// <summary>
        /// Sent by the server in the Type 2 message to indicate that the target authentication realm is a share. Presumably, this is for share-level authentication. Usage is unclear.
        /// </summary>
        TargetTypeShare = 0x00040000,
        /// <summary>
        /// Indicates that the NTLM2 signing and sealing scheme should be used for protecting authenticated communications. Note that this refers to a particular session security scheme, and is not related to the use of NTLMv2 authentication. This flag can, however, have an effect on the response calculations.
        /// </summary>
        NegotiateNtlm2Key = 0x00080000,
        /// <summary>
        /// This flag's usage has not been identified.
        /// </summary>
        RequestInitResponse = 0x00100000,
        /// <summary>
        /// This flag's usage has not been identified.
        /// </summary>
        RequestAcceptResponse = 0x00200000,
        /// <summary>
        /// This flag's usage has not been identified.
        /// </summary>
        RequestNonNtSessionKey = 0x00400000,
        /// <summary>
        /// Sent by the server in the Type 2 message to indicate that it is including a Target Information block in the message. The Target Information block is used in the calculation of the NTLMv2 response.
        /// </summary>
        NegotiateTargetInfo = 0x00800000,
        /// <summary>
        /// This flag's usage has not been identified.
        /// </summary>
        Unknown3 = 0x01000000,
        /// <summary>
        /// This flag's usage has not been identified.
        /// </summary>
        Unknown4 = 0x02000000,
        /// <summary>
        /// This flag's usage has not been identified.
        /// </summary>
        Unknown5 = 0x04000000,
        /// <summary>
        /// This flag's usage has not been identified.
        /// </summary>
        Unknown6 = 0x08000000,
        /// <summary>
        /// This flag's usage has not been identified.
        /// </summary>
        Unknown7 = 0x10000000,
        /// <summary>
        /// Indicates that 128-bit encryption is supported.
        /// </summary>
        Negotiate128 = 0x20000000,
        /// <summary>
        /// Indicates that the client will provide an encrypted master key in the "Session Key" field of the Type 3 message.
        /// </summary>
        NegotiateKeyExchange = 0x40000000,
        /// <summary>
        /// Indicates that 56-bit encryption is supported.
        /// </summary>
        Negotiate56 = 0x80000000
    }

    public enum MessageType : uint
    {
        /// <summary>
        /// Message type 1, send by client.
        /// </summary>
        Negotiation = 1,
        /// <summary>
        /// Message type 2, send by server.
        /// </summary>
        Challenge = 2,
        /// <summary>
        /// Message type 3, send by client.
        /// </summary>
        Authentication = 3
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
        /// Terminator subblock(Type: 0; Length: 0)
        /// </summary>
        Terminator = 0,
        /// <summary>
        /// Server name
        /// </summary>
        ServerName = 1,
        /// <summary>
        /// Domain name(i.e., domain)
        /// </summary>
        DomainName = 2,
        /// <summary>
        /// Fully-qualified DNS host name (i.e., svr1.domain.com)
        /// </summary>
        FullyQualifiedDomainName = 3,
        /// <summary>
        /// DNS domain name (i.e., domain.com)
        /// </summary>
        DnsDomainName = 4
    }
}