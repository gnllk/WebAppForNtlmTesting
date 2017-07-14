using System;
using System.Text;

namespace NtlmAuth
{
    public class AuthenticationMessageShell : INtlmMessage
    {
        private readonly AuthenticationMessageStruct _message;

        private readonly byte[] _messageBuffer;

        public AuthenticationMessageStruct Message => _message;

        public AuthenticationMessageShell(byte[] messageBuffer)
            : this(messageBuffer, messageBuffer.ToStruct<AuthenticationMessageStruct>())
        {
        }

        public AuthenticationMessageShell(byte[] messageBuffer, AuthenticationMessageStruct message)
        {
            _message = message;
            _messageBuffer = messageBuffer;
        }

        public Encoding GetEncoding()
        {
            return (_message.Flags & MessageFlag.NegotiateUnicode) > 0 ? Encoding.Unicode : Encoding.ASCII;
        }

        public byte[] ToBytes()
        {
            return _messageBuffer;
        }

        public void Fill(byte[] data)
        {
            throw new NotImplementedException();
        }

        public string Signature => Encoding.ASCII.GetString(_message.Protocol);

        public MessageType Type => _message.Type;

        public MessageFlag Flags => _message.Flags;

        public string TargetName
        {
            get
            {
                var temp = new byte[_message.TargetNameLength];
                Array.Copy(_messageBuffer, _message.TargetNametOffset,
                    temp, 0, _message.TargetNameLength);
                return GetEncoding().GetString(temp);
            }
        }

        public string UserName
        {
            get
            {
                var temp = new byte[_message.UserNameLength];
                Array.Copy(_messageBuffer, _message.UserNameOffset,
                    temp, 0, _message.UserNameLength);
                return GetEncoding().GetString(temp);
            }
        }

        public string HostName
        {
            get
            {
                var temp = new byte[_message.HostNameLength];
                Array.Copy(_messageBuffer, _message.HostNameOffset,
                    temp, 0, _message.HostNameLength);
                return GetEncoding().GetString(temp);
            }
        }

        public string SessionKey
        {
            get
            {
                var temp = new byte[_message.SessionKeyLength];
                Array.Copy(_messageBuffer, _message.SessionKeyOffset,
                    temp, 0, _message.SessionKeyLength);
                return GetEncoding().GetString(temp);
            }
        }

        public byte[] LmResponseData
        {
            get
            {
                var temp = new byte[_message.LmResponseLength];
                Array.Copy(_messageBuffer, _message.LmResponseOffset,
                    temp, 0, _message.LmResponseLength);
                return temp;
            }
        }

        public byte[] NtlmResponseData
        {
            get
            {
                var temp = new byte[_message.NtlmResponseLength];
                Array.Copy(_messageBuffer, _message.NtlmResponseOffset,
                    temp, 0, _message.NtlmResponseLength);
                return temp;
            }
        }

        public int StructSize
        {
            get
            {
                throw new NotImplementedException();
            }
        }
    }
}
