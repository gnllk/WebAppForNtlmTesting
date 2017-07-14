namespace NtlmAuth
{
    public interface INtlmMessage
    {
        string Signature { get; }

        MessageType Type { get; }

        MessageFlag Flags { get; }

        int StructSize { get; }

        byte[] ToBytes();

        void Fill(byte[] data);
    }
}
