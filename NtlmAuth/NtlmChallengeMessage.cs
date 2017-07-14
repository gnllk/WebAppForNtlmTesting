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

        public TargetInfoShellList TargetInfoList { get; private set; } = new TargetInfoShellList();

        public byte[] TargetInfosBytes => TargetInfoList.ToBytes();

        public NtlmChallengeMessage()
        {
        }

        public NtlmChallengeMessage(byte[] messageBuffer)
        {
            Fill(messageBuffer);
        }

        public NtlmChallengeMessage(ChallengeMessageStruct message, string targetName,
            params TargetInfoShell[] targetInfos)
        {
            Message = message;
            TargetName = targetName;

            if (targetInfos != null)
                TargetInfoList = new TargetInfoShellList(targetInfos);

            Rectify();
        }

        public NtlmChallengeMessage(ChallengeMessageStruct message, string targetName)
            : this(message, targetName, null)
        {

        }

        public string Signature => Encoding.ASCII.GetString(Message.Protocol);

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
            var nameLength = TargetName?.Length ?? 0;
            Message.TargetNameLength = (short)nameLength;
            Message.TargetNameSpace = (short)nameLength;

            // target info
            var targetInfosLength = TargetInfoList.Sum(item => item.TargetInfoTotalLength);
            Message.TargetInfosLength = (short)(ChallengeMessageStructSize + targetInfosLength);
            Message.TargetInfosSpace = (short)(ChallengeMessageStructSize + targetInfosLength);

            // offset
            Message.TargetNameOffset = ChallengeMessageStructSize;
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
                TargetInfoList = TargetInfoShellList.Parse(targetInfosBytes, GetEncoding());
            }
        }
    }

    public class TargetInfoShell
    {
        public static readonly int StructSize = Marshal.SizeOf(typeof(TargetInfoStruct));

        public TargetInfoStruct TargetInfo;

        public int TargetInfoTotalLength => StructSize + TargetContentBytes?.Length ?? 0;

        public byte[] TargetContentBytes { get; set; }

        public TargetInfoType TargetInfoType => TargetInfo.Type;

        public short TargetInfoLength => TargetInfo.Length;

        public Encoding ContentEncoding { get; set; } = Encoding.Unicode;

        public string TargetContent
        {
            get
            {
                if (TargetContentBytes == null) return null;
                return (ContentEncoding ?? Encoding.Unicode).GetString(TargetContentBytes);
            }
        }

        public TargetInfoShell()
        {
        }

        public TargetInfoShell(TargetInfoStruct targetInfo)
        {
            TargetInfo = targetInfo;
        }

        public TargetInfoShell(TargetInfoStruct targetInfo, byte[] targetContent, Encoding contentEncoding)
        {
            if (targetContent == null)
                throw new ArgumentNullException(nameof(targetContent));
            if (contentEncoding == null)
                throw new ArgumentNullException(nameof(contentEncoding));

            TargetInfo = targetInfo;
            TargetContentBytes = targetContent;
            ContentEncoding = contentEncoding;
        }

        public TargetInfoShell(TargetInfoStruct targetInfo, byte[] targetContent)
          : this(targetInfo, targetContent, Encoding.Unicode)
        {
        }

        public TargetInfoShell(TargetInfoType targetType, byte[] targetContent, Encoding contentEncoding)
            : this(new TargetInfoStruct { Type = targetType }, targetContent, contentEncoding)
        {
        }

        public TargetInfoShell(TargetInfoType targetType, byte[] targetContent)
            : this(targetType, targetContent, Encoding.Unicode)
        {
        }

        public TargetInfoShell(TargetInfoType targetType, string targetContent, Encoding contentEncoding)
            : this(targetType, contentEncoding.GetBytes(targetContent), contentEncoding)
        {
        }

        public TargetInfoShell(TargetInfoType targetType)
        {
            TargetInfo.Type = targetType;
        }

        public TargetInfoShell(TargetInfoStruct targetInfo, string targetContent, Encoding contentEncoding)
                : this(targetInfo, contentEncoding.GetBytes(targetContent), contentEncoding)
        {
        }

        public TargetInfoShell(byte[] targetInfo, Encoding contentEncoding)
        {
            if (targetInfo == null)
                throw new ArgumentNullException(nameof(targetInfo));
            if (contentEncoding == null)
                throw new ArgumentNullException(nameof(contentEncoding));

            TargetInfo = targetInfo.ToStruct<TargetInfoStruct>();

            if (targetInfo.Length > StructSize)
            {
                TargetContentBytes = targetInfo.NewCopy(StructSize, TargetInfo.Length);
            }
        }

        public TargetInfoShell(byte[] targetInfo)
                : this(targetInfo, Encoding.Unicode)
        {
        }

        public byte[] ToBytes()
        {
            var contentLength = TargetContentBytes?.Length ?? 0;
            var result = new List<byte>(StructSize + contentLength);

            result.AddRange(TargetInfo.ToBytes());

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

    public class TargetInfoShellList : List<TargetInfoShell>
    {
        public TargetInfoShellList()
        {
        }

        public TargetInfoShellList(int capacity)
            : base(capacity)
        {
        }

        public TargetInfoShellList(params TargetInfoShell[] targetInfoShells)
            : base(targetInfoShells)
        {
        }

        public TargetInfoShellList(IEnumerable<TargetInfoShell> targetInfoShells)
            : base(targetInfoShells)
        {
        }

        public TargetInfoShellList(byte[] tagetInfo, Encoding encoding)
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
                var targetInfo = new TargetInfoShell(tagetInfo.NewCopy(startIndex), encoding);
                Add(targetInfo);
                startIndex += targetInfo.TargetInfoTotalLength;
                if (targetInfo.TargetInfo.Type == TargetInfoType.Terminator) break;
            }
        }

        public static TargetInfoShellList Parse(byte[] tagetInfo, Encoding encoding)
        {
            var result = new TargetInfoShellList();
            result.Fill(tagetInfo, encoding);
            return result;
        }
    }
}
