using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace NtlmAuth
{
    public class NegotiationMessageShell
    {
        private readonly NegotiationMessage _message;

        private readonly byte[] _messageBuffer;

        public NegotiationMessage Message => _message;

        public NegotiationMessageShell(byte[] messageBuffer)
            : this(messageBuffer, messageBuffer.ToStruct<NegotiationMessage>())
        {
        }

        public NegotiationMessageShell(byte[] messageBuffer, NegotiationMessage message)
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

    public class ChallengeMessageShell
    {
        private byte[] _targetNameData;

        private byte[] _targetInfoData;

        public ChallengeMessage Message;

        public byte[] TargetNameData
        {
            get { return _targetNameData ?? (_targetNameData = new byte[0]); }
            set
            {
                _targetNameData = value;
                Rectify();
            }
        }

        public TargetInfo TargetInfo;

        public byte[] TargetInfoData
        {
            get { return _targetInfoData ?? (_targetInfoData = new byte[0]); }
            set
            {
                _targetInfoData = value;
                Rectify();
            }
        }

        public ChallengeMessageShell(ChallengeMessage message, TargetInfo targetInfo)
        {
            Message = message;
            TargetInfo = targetInfo;

            Rectify();
        }

        public ChallengeMessageShell(ChallengeMessage message)
            : this(message, new TargetInfo())
        {
        }

        public ChallengeMessageShell(TargetInfo targetInfo)
            : this(new ChallengeMessage(), targetInfo)
        {
        }

        public ChallengeMessageShell()
            : this(new ChallengeMessage(), new TargetInfo())
        {
        }

        public void SetTargetName(string name, Encoding encoding = null)
        {
            if (encoding == null)
            {
                encoding = GetEncoding();
            }

            TargetNameData = encoding.GetBytes(name);
        }

        public void SetInfoDataContent(string content, Encoding encoding = null)
        {
            if (encoding == null)
            {
                encoding = GetEncoding();
            }
            TargetInfoData = encoding.GetBytes(content);
        }

        public Encoding GetEncoding()
        {
            const MessageFlag supportedFlag = MessageFlag.NegotiateUnicode | MessageFlag.NegotiateOem;
            return (Message.Flags & supportedFlag) > 0 ? Encoding.Unicode : Encoding.ASCII;
        }

        public byte[] ToBytes()
        {
            Rectify();

            var result = new List<byte>();
            result.AddRange(Message.ToBytes());

            if (Message.TargetNameLength > 0)
                result.AddRange(TargetNameData);

            if (Message.TargetInfoLength > 0)
                result.AddRange(TargetInfo.ToBytes());

            if (Message.TargetInfoLength > 0)
                result.AddRange(TargetInfoData);

            return result.ToArray();
        }

        public void Rectify()
        {
            // target name
            var nameLength = _targetNameData?.Length ?? 0;
            Message.TargetNameLength = (short)nameLength;
            Message.TargetNameSpace = (short)nameLength;

            // target info
            var dataLength = _targetInfoData?.Length ?? 0;
            var targetInfoLength = Marshal.SizeOf(typeof(TargetInfo));
            TargetInfo.Length = (short)dataLength;
            Message.TargetInfoLength = (short)(dataLength + targetInfoLength);
            Message.TargetInfoSpace = (short)(dataLength + targetInfoLength);

            // targart offset
            Message.TargetNametOffset = Marshal.SizeOf(typeof(ChallengeMessage));
            Message.TargetInfoOffset = Message.TargetNametOffset + Message.TargetNameLength;
        }
    }

    public class AuthenticationMessageShell
    {
        private readonly AuthenticationMessage _message;

        private readonly byte[] _messageBuffer;

        public AuthenticationMessage Message => _message;

        public AuthenticationMessageShell(byte[] messageBuffer)
            : this(messageBuffer, messageBuffer.ToStruct<AuthenticationMessage>())
        {
        }

        public AuthenticationMessageShell(byte[] messageBuffer, AuthenticationMessage message)
        {
            _message = message;
            _messageBuffer = messageBuffer;
        }

        public Encoding GetEncoding()
        {
            const MessageFlag supportedFlag = MessageFlag.NegotiateUnicode | MessageFlag.NegotiateOem;
            return (_message.Flags & supportedFlag) > 0 ? Encoding.Unicode : Encoding.ASCII;
        }

        public string Protocol => Encoding.ASCII.GetString(_message.Protocol);

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

        public byte[] LanManagerResponseData
        {
            get
            {
                var temp = new byte[_message.LanManagerResponseLength];
                Array.Copy(_messageBuffer, _message.LanManagerResponseOffset,
                    temp, 0, _message.LanManagerResponseLength);
                return temp;
            }
        }

        public byte[] NtlmManagerResponseData
        {
            get
            {
                var temp = new byte[_message.NtlmManagerResponseLength];
                Array.Copy(_messageBuffer, _message.NtlmManagerResponseOffset,
                    temp, 0, _message.NtlmManagerResponseLength);
                return temp;
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