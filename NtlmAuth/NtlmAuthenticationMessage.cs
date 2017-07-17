using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace NtlmAuth
{
    public class NtlmAuthenticationMessage : INtlmMessage
    {
        public static readonly int AuthenticationMessageStructSize = Marshal.SizeOf(typeof(AuthenticationMessageStruct));

        private AuthenticationMessageStruct _message;

        public AuthenticationMessageStruct Message => _message;

        private void BuildMessage(byte[] data)
        {
            Fill(data);
        }

        public NtlmAuthenticationMessage(byte[] messageBuffer)
        {
            BuildMessage(messageBuffer);
        }

        public NtlmAuthenticationMessage(AuthenticationMessageStruct message)
        {
            _message = message;
        }

        public Encoding GetEncoding()
        {
            return (_message.Flags & MessageFlag.NegotiateUnicode) > 0 ? Encoding.Unicode : Encoding.ASCII;
        }

        public int StructSize => AuthenticationMessageStructSize;

        public string Signature => Encoding.ASCII.GetString(_message.Signature);

        public MessageType Type => _message.Type;

        public MessageFlag Flags => _message.Flags;

        private string _targetName;

        private byte[] _targetNameBytes;

        public string TargetName
        {
            get { return _targetName; }
            set
            {
                _targetName = value;
                _targetNameBytes = value == null ? null : GetEncoding().GetBytes(value);
                Rectify();
            }
        }

        private string _userName;

        private byte[] _userNameBytes;

        public string UserName
        {
            get { return _userName; }
            set
            {
                _userName = value;
                _userNameBytes = value == null ? null : GetEncoding().GetBytes(value);
                Rectify();
            }
        }

        private string _hostName;

        private byte[] _hostNameBytes;

        public string HostName
        {
            get { return _hostName; }
            set
            {
                _hostName = value;
                _hostNameBytes = value == null ? null : GetEncoding().GetBytes(value);
                Rectify();
            }
        }

        private string _sessionKey;

        private byte[] _sessionKeyBytes;

        public string SessionKey
        {
            get { return _sessionKey; }
            set
            {
                _sessionKey = value;
                _sessionKeyBytes = value == null ? null : GetEncoding().GetBytes(value);
                Rectify();
            }
        }

        private byte[] _lmResponseData;

        public byte[] LmResponseData
        {
            get
            {
                return _lmResponseData;
            }
            set
            {
                _lmResponseData = value;
                Rectify();
            }
        }

        private byte[] _ntlmResponseData;

        public byte[] NtlmResponseData
        {
            get { return _ntlmResponseData; }
            set
            {
                _ntlmResponseData = value;
                Rectify();
            }
        }

        public virtual byte[] ToBytes()
        {
            Rectify();

            var result = new List<byte>();
            result.AddRange(_message.ToBytes());

            if (_targetNameBytes != null)
                result.AddRange(_targetNameBytes);

            if (_userNameBytes != null)
                result.AddRange(_userNameBytes);

            if (_hostNameBytes != null)
                result.AddRange(_hostNameBytes);

            if (_lmResponseData != null)
                result.AddRange(_lmResponseData);

            if (_ntlmResponseData != null)
                result.AddRange(_ntlmResponseData);

            if (_sessionKeyBytes != null)
                result.AddRange(_sessionKeyBytes);

            return result.ToArray();
        }

        public virtual void Fill(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (data.Length == 0)
                throw new ArgumentException($"{nameof(data)} array is empty.");

            _message = data.ToStruct<AuthenticationMessageStruct>();
            var encoding = GetEncoding();
            _targetNameBytes = data.NewCopy(_message.TargetNameOffset, _message.TargetNameLength);
            _userNameBytes = data.NewCopy(_message.UserNameOffset, _message.UserNameLength);
            _hostNameBytes = data.NewCopy(_message.HostNameOffset, _message.HostNameLength);
            _lmResponseData = data.NewCopy(_message.LmResponseOffset, _message.LmResponseLength);
            _ntlmResponseData = data.NewCopy(_message.NtlmResponseOffset, _message.NtlmResponseLength);
            _sessionKeyBytes = data.NewCopy(_message.SessionKeyOffset, _message.SessionKeyLength);

            _targetName = encoding.GetString(_targetNameBytes);
            _userName = encoding.GetString(_userNameBytes);
            _hostName = encoding.GetString(_hostNameBytes);
            _sessionKey = encoding.GetString(_sessionKeyBytes);
        }

        public void Rectify()
        {
            _message.TargetNameLength = _message.TargetNameSpace = (short)(_targetNameBytes?.Length ?? 0);
            _message.UserNameLength = _message.UserNameSpace = (short)(_userNameBytes?.Length ?? 0);
            _message.HostNameLength = _message.HostNameSpace = (short)(_hostNameBytes?.Length ?? 0);
            _message.LmResponseLength = _message.LmResponseSpace = (short)(_lmResponseData?.Length ?? 0);
            _message.NtlmResponseLength = _message.NtlmResponseSpace = (short)(_ntlmResponseData?.Length ?? 0);
            _message.SessionKeyLength = _message.SessionKeySpace = (short)(_sessionKeyBytes?.Length ?? 0);

            _message.TargetNameOffset = StructSize;
            _message.UserNameOffset = _message.TargetNameOffset + _message.TargetNameLength;
            _message.HostNameOffset = _message.UserNameOffset + _message.UserNameLength;
            _message.LmResponseOffset = _message.HostNameOffset + _message.HostNameLength;
            _message.NtlmResponseOffset = _message.LmResponseOffset + _message.LmResponseLength;
            _message.SessionKeyOffset = _message.NtlmResponseOffset + _message.NtlmResponseLength;
        }

        public static NtlmAuthenticationMessage Parse(byte[] data)
        {
            return new NtlmAuthenticationMessage(data);
        }
    }
}
