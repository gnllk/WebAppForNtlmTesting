using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace NtlmAuth
{
    public class NtlmNegotiateMessage : INtlmMessage
    {
        public static readonly int NegotiationMessageStructSize = Marshal.SizeOf(typeof(NegotiationMessageStruct));

        public NegotiationMessageStruct Message;

        public NtlmNegotiateMessage(NegotiationMessageStruct message, string domainName, string hostName)
        {
            Message = message;
            Domain = domainName;
            Host = hostName;

            Rectify();
        }

        public NtlmNegotiateMessage(byte[] messageBuffer)
        {
            Fill(messageBuffer);
        }

        public string Signature => Encoding.ASCII.GetString(Message.Signature);

        public MessageType Type => Message.Type;

        public MessageFlag Flags => Message.Flags;

        public int StructSize => NegotiationMessageStructSize;

        public string Domain { get; private set; }

        public string Host { get; private set; }

        public byte[] ToBytes()
        {
            var data = Message.ToBytes();
            var result = new List<byte>(data);

            if (Message.HostNameLength > 0)
                result.AddRange(Encoding.ASCII.GetBytes(Host));

            if (Message.DomainNameLength > 0)
                result.AddRange(Encoding.ASCII.GetBytes(Domain));

            return result.ToArray();
        }

        public void Fill(byte[] data)
        {
            OnFill(data);
        }

        protected virtual void OnFill(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (data.Length == 0)
                throw new ArgumentException($"{nameof(data)} array is empty.");

            Message = data.ToStruct<NegotiationMessageStruct>();

            if (Message.HostNameLength > 0)
            {
                var tmp = data.NewCopy(Message.HostNameOffset, Message.HostNameLength);
                Host = Encoding.ASCII.GetString(tmp);
            }
            if (Message.DomainNameLength > 0)
            {
                var tmp = data.NewCopy(Message.DomainNameOffset, Message.DomainNameLength);
                Domain = Encoding.ASCII.GetString(tmp);
            }
        }

        protected void Rectify()
        {
            var hostLength = Host?.Length ?? 0;
            Message.HostNameLength = (short)hostLength;
            Message.HostNameSpace = (short)hostLength;

            var domainLength = Domain?.Length ?? 0;
            Message.DomainNameLength = (short)domainLength;
            Message.DomainNameSpace = (short)domainLength;

            Message.HostNameOffset = StructSize;
            Message.DomainNameOffset = Message.HostNameOffset + Message.HostNameLength;
        }

        public static NtlmNegotiateMessage Parse(byte[] data)
        {
            return new NtlmNegotiateMessage(data);
        }
    }
}
