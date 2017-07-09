using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace NtlmAuth
{
    public interface INtlmResponse
    {
        bool Validate();
    }

    public abstract class NtlmResponseBase
    {
    }

    public class LmResponse : INtlmResponse
    {
        protected static readonly byte[] Kgs = Encoding.ASCII.GetBytes("KGS!@#$%");

        protected static readonly byte[] IgnoreHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        protected readonly byte[] ResponseData;

        protected readonly byte[] Challenge;

        protected readonly byte[] Password;

        public LmResponse(byte[] responseData, byte[] challenge, byte[] password)
        {
            if (responseData == null)
                throw new ArgumentNullException(nameof(responseData));
            if (challenge == null)
                throw new ArgumentNullException(nameof(challenge));
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            if (challenge.Length != 8)
                throw new ArgumentException("The challenge is not 8 bytes");

            ResponseData = responseData;
            Challenge = challenge;
            Password = password;
        }

        public LmResponse(byte[] responseData, string challenge, string password)
            : this(responseData, Encoding.ASCII.GetBytes(challenge),
                  Encoding.ASCII.GetBytes(password.ToUpperInvariant()))
        {
        }

        public virtual bool Validate()
        {
            if (!ResponseData.Any()) return false;
            if (IsIgnore()) return false;
            var bytes = CreateLmResponse(Challenge, Password);
            return bytes.SequenceEqual(ResponseData);
        }

        private bool IsIgnore()
        {
            return ResponseData.SequenceEqual(IgnoreHash);
        }

        public virtual byte[] CreateLmResponse(byte[] challenge, byte[] password)
        {
            // KGS encript
            var maxPasswordLength = 14;
            var paddedPassword = password.PadRight(maxPasswordLength);

            var key1 = paddedPassword.NewCopy(0, 7);
            var key2 = paddedPassword.NewCopy(7);

            var desParityKey1 = ParityAdjust(key1);
            var desParityKey2 = ParityAdjust(key2);

            var kgsCiphered1 = DesHelper.Encrypt(Kgs, desParityKey1);
            var kgsCiphered2 = DesHelper.Encrypt(Kgs, desParityKey2);

            var lmHash = kgsCiphered1.Concat(kgsCiphered2).ToArray();

            // Challege encript
            var maxLmHashLength = 21;
            var paddedLmHash = lmHash.PadRight(maxLmHashLength);

            var kgskey1 = paddedLmHash.NewCopy(0, 7);
            var kgskey2 = paddedLmHash.NewCopy(7, 7);
            var kgskey3 = paddedLmHash.NewCopy(14);

            var kgsParitykey1 = ParityAdjust(kgskey1);
            var kgsParitykey2 = ParityAdjust(kgskey2);
            var kgsParitykey3 = ParityAdjust(kgskey3);

            var challengeCiphered1 = DesHelper.Encrypt(challenge, kgsParitykey1);
            var challengeCiphered2 = DesHelper.Encrypt(challenge, kgsParitykey2);
            var challengeCiphered3 = DesHelper.Encrypt(challenge, kgsParitykey3);

            return challengeCiphered1.Concat(challengeCiphered2).Concat(challengeCiphered3).ToArray();
        }

        protected byte[] ParityAdjust(byte[] data)
        {
            var bitList = new List<int>(56);
            foreach (var item in data)
            {
                byte mask = 0x80;// binary: 1000 0000
                for (var i = 0; i < 8; i++)
                {
                    bitList.Add((mask & item) > 0 ? 1 : 0);
                    mask >>= 1;
                }
            }
            var result = new List<byte>(8);
            var eightBits = new int[8];
            var parityCounter = 0;
            var bitCounter = 0;
            for (var i = 0; i < bitList.Count; i++)
            {
                bitCounter++;
                eightBits[i % 7] = bitList[i];
                if (bitList[i] == 1)
                {
                    parityCounter++;
                }
                if (bitCounter == 7)
                {
                    eightBits[7] = parityCounter % 2 == 0 ? 1 : 0;
                    parityCounter = 0;
                    bitCounter = 0;
                    result.Add(BitsToByte(eightBits));
                }
            }
            return result.ToArray();
        }

        protected byte BitsToByte(int[] eightBits)
        {
            if (eightBits == null)
                throw new ArgumentNullException(nameof(eightBits));

            byte mask = 0x80;// binary: 1000 0000
            byte result = 0;
            foreach (var bit in eightBits)
            {
                if (bit == 1)
                {
                    result |= mask;
                }
                mask >>= 1;
            }
            return result;
        }
    }

    public class NtlmResponse : INtlmResponse
    {
        public bool Validate()
        {
            throw new NotImplementedException();
        }
    }

    public class NtlmV2Response : INtlmResponse
    {
        public bool Validate()
        {
            throw new NotImplementedException();
        }
    }

    public class LmV2Response : INtlmResponse
    {
        public bool Validate()
        {
            throw new NotImplementedException();
        }
    }

    public class NtlmV2SessionResponse : INtlmResponse
    {
        public bool Validate()
        {
            throw new NotImplementedException();
        }
    }

    public class AnonymousResponse : INtlmResponse
    {
        public bool Validate()
        {
            throw new NotImplementedException();
        }
    }
}