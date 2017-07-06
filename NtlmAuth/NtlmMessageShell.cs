using System;
using System.Collections.Generic;
using System.Text;

namespace NtlmAuth
{
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

        public MessageType Type => _message.Type;

        public MessageFlag Flags => _message.Flags;

        public string Domain
        {
            get
            {
                var temp = new byte[_message.DomainNameLength];
                Array.Copy(_messageBuffer, _message.DomainNameOffset, temp, 0, _message.DomainNameLength);
                return Encoding.ASCII.GetString(temp);
            }
        }

        public string Host
        {
            get
            {
                var temp = new byte[_message.HostNameLength];
                Array.Copy(_messageBuffer, _message.HostNameOffset, temp, 0, _message.HostNameLength);
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
}