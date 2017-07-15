using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtlmAuth
{
    public class NtlmChallengeMessage : INtlmMessage
    {
        public static readonly int ChallengeMessageStructSize = Marshal.SizeOf(typeof(ChallengeMessageStruct));

        public ChallengeMessageStruct Message;

        public string TargetName { get; private set; }

        public byte[] TargetNameBytes => GetEncoding().GetBytes(TargetName);

        public NtlmTargetInfoList TargetInfoList { get; private set; } = new NtlmTargetInfoList();

        public byte[] TargetInfosBytes => TargetInfoList.ToBytes();

        public NtlmChallengeMessage(byte[] messageBuffer)
        {
            Fill(messageBuffer);
        }

        public NtlmChallengeMessage(ChallengeMessageStruct message, string targetName,
            params NtlmTargetInfo[] targetInfos)
        {
            Message = message;
            TargetName = targetName;

            if (targetInfos != null)
                TargetInfoList = new NtlmTargetInfoList(targetInfos);

            Rectify();
        }

        public string Signature => Encoding.ASCII.GetString(Message.Signature);

        public MessageType Type => MessageType.Challenge;

        public MessageFlag Flags => Message.Flags;

        public int StructSize => ChallengeMessageStructSize;

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

            if (Message.TargetInfosLength > 0)
                result.AddRange(TargetInfosBytes);

            return result.ToArray();
        }

        public void Rectify()
        {
            // target name
            var nameLength = TargetNameBytes?.Length ?? 0;
            Message.TargetNameLength = (short)nameLength;
            Message.TargetNameSpace = (short)nameLength;

            // target info
            var targetInfosLength = TargetInfoList.Sum(item => item.TargetInfoTotalLength);
            Message.TargetInfosLength = (short)targetInfosLength;
            Message.TargetInfosSpace = (short)targetInfosLength;

            // offset
            Message.TargetNameOffset = StructSize;
            Message.TargetInfosOffset = Message.TargetNameOffset + Message.TargetNameLength;
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

            Message = data.ToStruct<ChallengeMessageStruct>();

            if (Message.TargetNameLength > 0)
            {
                var targetNameBytes = data.NewCopy(Message.TargetNameOffset, Message.TargetNameLength);
                TargetName = GetEncoding().GetString(targetNameBytes);
            }
            if (Message.TargetNameLength > 0)
            {
                var targetInfosBytes = data.NewCopy(Message.TargetInfosOffset, Message.TargetInfosLength);
                TargetInfoList = NtlmTargetInfoList.Parse(targetInfosBytes, GetEncoding());
            }
        }

        public static NtlmChallengeMessage Parse(byte[] data)
        {
            return new NtlmChallengeMessage(data);
        }
    }

    public class NtlmTargetInfo
    {
        private byte[] _targetContentBytes;

        public static readonly int TargetInfoStructSize = Marshal.SizeOf(typeof(TargetInfoStruct));

        public TargetInfoStruct Info;

        public int TargetInfoTotalLength => TargetInfoStructSize + Info.Length;

        public byte[] TargetContentBytes
        {
            get { return _targetContentBytes; }
            set
            {
                _targetContentBytes = value;
                Info.Length = (short)(value?.Length ?? 0);
            }
        }

        public TargetInfoType TargetInfoType => Info.Type;

        public short TargetInfoLength => Info.Length;

        public Encoding ContentEncoding { get; set; } = Encoding.Unicode;

        public string TargetContent
        {
            get
            {
                if (TargetContentBytes == null) return null;
                return (ContentEncoding ?? Encoding.Unicode).GetString(TargetContentBytes);
            }
        }

        public NtlmTargetInfo()
        {
        }

        public NtlmTargetInfo(TargetInfoStruct targetInfo)
        {
            Info = targetInfo;
        }

        public NtlmTargetInfo(TargetInfoStruct targetInfo, byte[] targetContent, Encoding contentEncoding)
        {
            if (targetContent == null)
                throw new ArgumentNullException(nameof(targetContent));
            if (contentEncoding == null)
                throw new ArgumentNullException(nameof(contentEncoding));

            Info = targetInfo;
            TargetContentBytes = targetContent;
            ContentEncoding = contentEncoding;
        }

        public NtlmTargetInfo(TargetInfoStruct targetInfo, byte[] targetContent)
          : this(targetInfo, targetContent, Encoding.Unicode)
        {
        }

        public NtlmTargetInfo(TargetInfoType targetType, byte[] targetContent, Encoding contentEncoding)
            : this(new TargetInfoStruct { Type = targetType }, targetContent, contentEncoding)
        {
        }

        public NtlmTargetInfo(TargetInfoType targetType, byte[] targetContent)
            : this(targetType, targetContent, Encoding.Unicode)
        {
        }

        public NtlmTargetInfo(TargetInfoType targetType, string targetContent, Encoding contentEncoding)
            : this(targetType, contentEncoding.GetBytes(targetContent), contentEncoding)
        {
        }

        public NtlmTargetInfo(TargetInfoType targetType)
        {
            Info.Type = targetType;
        }

        public NtlmTargetInfo(TargetInfoStruct targetInfo, string targetContent, Encoding contentEncoding)
                : this(targetInfo, contentEncoding.GetBytes(targetContent), contentEncoding)
        {
        }

        public NtlmTargetInfo(byte[] targetInfo, Encoding contentEncoding)
        {
            if (targetInfo == null)
                throw new ArgumentNullException(nameof(targetInfo));
            if (contentEncoding == null)
                throw new ArgumentNullException(nameof(contentEncoding));

            Info = targetInfo.ToStruct<TargetInfoStruct>();

            if (targetInfo.Length > TargetInfoStructSize)
            {
                TargetContentBytes = targetInfo.NewCopy(TargetInfoStructSize, Info.Length);
            }
        }

        public NtlmTargetInfo(byte[] targetInfo)
                : this(targetInfo, Encoding.Unicode)
        {
        }

        public byte[] ToBytes()
        {
            var contentLength = TargetContentBytes?.Length ?? 0;
            var result = new List<byte>(TargetInfoStructSize + contentLength);

            result.AddRange(Info.ToBytes());

            if (TargetContentBytes != null && contentLength > 0)
            {
                result.AddRange(TargetContentBytes);
            }
            return result.ToArray();
        }

        public override string ToString()
        {
            return $"{TargetInfoType}: {TargetContent}";
        }
    }

    public class NtlmTargetInfoList : List<NtlmTargetInfo>
    {
        public NtlmTargetInfoList()
        {
        }

        public NtlmTargetInfoList(int capacity)
            : base(capacity)
        {
        }

        public NtlmTargetInfoList(params NtlmTargetInfo[] targetInfoShells)
            : base(targetInfoShells)
        {
        }

        public NtlmTargetInfoList(IEnumerable<NtlmTargetInfo> targetInfoShells)
            : base(targetInfoShells)
        {
        }

        public NtlmTargetInfoList(byte[] tagetInfo, Encoding encoding)
        {
            Fill(tagetInfo, encoding);
        }

        public byte[] ToBytes()
        {
            var result = new List<byte>();
            foreach (var item in this)
            {
                result.AddRange(item.ToBytes());
            }
            return result.ToArray();
        }

        public void Fill(byte[] tagetInfo, Encoding encoding)
        {
            if (tagetInfo == null)
                throw new ArgumentNullException(nameof(tagetInfo));
            if (tagetInfo.Length == 0)
                throw new ArgumentException($"{nameof(tagetInfo)} is empty.");

            Clear();
            var startIndex = 0;
            while (startIndex < tagetInfo.Length)
            {
                var targetInfo = new NtlmTargetInfo(tagetInfo.NewCopy(startIndex), encoding);
                Add(targetInfo);
                startIndex += targetInfo.TargetInfoTotalLength;
                if (targetInfo.Info.Type == TargetInfoType.Terminator) break;
            }
        }

        public static NtlmTargetInfoList Parse(byte[] tagetInfo, Encoding encoding)
        {
            var result = new NtlmTargetInfoList();
            result.Fill(tagetInfo, encoding);
            return result;
        }
    }
}
