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
                var temp = _messageBuffer.NewCopy(_message.DomainNameOffset, _message.DomainNameLength);
                return Encoding.ASCII.GetString(temp);
            }
        }

        public string Host
        {
            get
            {
                var temp = _messageBuffer.NewCopy(_message.HostNameOffset, _message.HostNameLength);
                return Encoding.ASCII.GetString(temp);
            }
        }
    }

    public class ChallengeMessageShell
    {
        private byte[] _targetNameBytes;

        private byte[] _targetInfoContentBytes;

        public ChallengeMessage Message;

        public TargetInfo TargetInfo;

        public byte[] TargetNameBytes
        {
            get { return _targetNameBytes ?? (_targetNameBytes = new byte[0]); }
            set
            {
                _targetNameBytes = value;
                Rectify();
            }
        }

        public byte[] TargetInfoContentBytes
        {
            get { return _targetInfoContentBytes ?? (_targetInfoContentBytes = new byte[0]); }
            set
            {
                _targetInfoContentBytes = value;
                Rectify();
            }
        }

        public byte[] TargetInfoBytes
        {
            get
            {
                Rectify();

                var result = new List<byte>();
                if (Message.TargetInfoLength > 0)
                {
                    result.AddRange(TargetInfo.ToBytes());
                    result.AddRange(TargetInfoContentBytes);
                }
                return result.ToArray();
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

        public ChallengeMessageShell(byte[] buffer)
        {
            var message = buffer.ToStruct<ChallengeMessage>();
            var targetNameData = buffer.NewCopy(message.TargetNameOffset, message.TargetNameLength);
            var targetInfoData = buffer.NewCopy(message.TargetInfoOffset, message.TargetInfoLength);
            var targetInfo = targetInfoData.ToStruct<TargetInfo>();
            var targetInfoDataContent = targetInfoData.NewCopy(Marshal.SizeOf(typeof(TargetInfo)));

            Message = message;
            TargetInfo = targetInfo;
            TargetNameBytes = targetNameData;
            TargetInfoContentBytes = targetInfoDataContent;

            Rectify();
        }

        public string TargetName
        {
            get { return GetEncoding().GetString(TargetNameBytes); }
            set { TargetNameBytes = GetEncoding().GetBytes(value); }
        }

        public string TargetInfoDataContent
        {
            get { return GetEncoding().GetString(TargetInfoContentBytes); }
            set { TargetInfoContentBytes = GetEncoding().GetBytes(value); }
        }

        public TargetInfoType TargetInfoType
        {
            get { return TargetInfo.Type; }
            set { TargetInfo.Type = value; }
        }

        public Encoding GetEncoding()
        {
            return (Message.Flags & MessageFlag.NegotiateUnicode) > 0 ? Encoding.Unicode : Encoding.ASCII;
        }

        public byte[] ToBytes()
        {
            Rectify();

            var result = new List<byte>();
            result.AddRange(Message.ToBytes());

            if (Message.TargetNameLength > 0)
                result.AddRange(TargetNameBytes);

            if (Message.TargetInfoLength > 0)
                result.AddRange(TargetInfoBytes);

            return result.ToArray();
        }

        public void Rectify()
        {
            // target name
            var nameLength = _targetNameBytes?.Length ?? 0;
            Message.TargetNameLength = (short)nameLength;
            Message.TargetNameSpace = (short)nameLength;

            // target info
            var contentLength = _targetInfoContentBytes?.Length ?? 0;
            var targetInfoStructLength = Marshal.SizeOf(typeof(TargetInfo));
            TargetInfo.Length = (short)contentLength;
            Message.TargetInfoLength = (short)(contentLength + targetInfoStructLength);
            Message.TargetInfoSpace = (short)(contentLength + targetInfoStructLength);

            // offset
            Message.TargetNameOffset = Marshal.SizeOf(typeof(ChallengeMessage));
            Message.TargetInfoOffset = Message.TargetNameOffset + Message.TargetNameLength;
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
            return (_message.Flags & MessageFlag.NegotiateUnicode) > 0 ? Encoding.Unicode : Encoding.ASCII;
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
    }
}