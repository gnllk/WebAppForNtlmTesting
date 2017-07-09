using System.IO;
using System.Security.Cryptography;

namespace NtlmAuth
{
    public static class DesHelper
    {
        public static byte[] Encrypt(byte[] content, byte[] key)
        {
            using (var des = new DESCryptoServiceProvider())
            {
                des.Key = key;
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(content, 0, content.Length);
                        cs.FlushFinalBlock();
                        cs.Close();
                    }
                    return ms.ToArray();
                }
            }
        }

        public static byte[] Decrypt(byte[] content, byte[] key)
        {
            using (var des = new DESCryptoServiceProvider())
            {
                des.Key = key;
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(content, 0, content.Length);
                        cs.FlushFinalBlock();
                        cs.Close();
                    }
                    return ms.ToArray();
                }
            }
        }
    }
}