using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NtlmAuth
{
    public interface INtlmResponse
    {
        bool Validate();
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

            return CreateLmResponse(Challenge, Password).SequenceEqual(ResponseData);
        }

        private bool IsIgnore()
        {
            return ResponseData.SequenceEqual(IgnoreHash);
        }

        public virtual byte[] CreateLmResponse(byte[] challenge, byte[] password)
        {
            //
            var maxPasswordLength = 14;
            var paddedPassword = password.PadRight(maxPasswordLength);

            var key1 = paddedPassword.NewCopy(0, 7);
            var key2 = paddedPassword.NewCopy(7);

            var desParityKey1 = ParityAdjust(key1);
            var desParityKey2 = ParityAdjust(key2);

            var kgsCiphered1 = DesHelper.Decrypt(Kgs, desParityKey1);
            var kgsCiphered2 = DesHelper.Decrypt(Kgs, desParityKey2);
             
            var lmHash = kgsCiphered1.Concat(kgsCiphered2).ToArray();

            // 
            var maxLmHashLength = 21;
            var paddedLmHash = lmHash.PadRight(maxLmHashLength);

            var kgskey1 = paddedLmHash.NewCopy(0, 7);
            var kgskey2 = paddedLmHash.NewCopy(7, 7);
            var kgskey3 = paddedLmHash.NewCopy(14);

            var kgsParitykey1 = ParityAdjust(kgskey1);
            var kgsParitykey2 = ParityAdjust(kgskey2);
            var kgsParitykey3 = ParityAdjust(kgskey3);


            return null;
        }

        private byte[] ParityAdjust(byte[] data)
        {
            var bitList = new List<bool>(56);
            foreach (var item in data)
            {
                byte mask = 1;
                for (byte i = 0; i < 8; i++)
                {
                    mask <<= i;
                    bitList.Add((mask & item) > 0);
                }
            }
            var result = new List<byte>(8);
            var eightBits = new bool[8];
            var parityCounter = 0;
            for (var i = 0; i < bitList.Count; i++)
            {
                eightBits[i % 7] = bitList[i];
                if (bitList[i])
                {
                    parityCounter++;
                }
                if (i > 0 && i % 7 == 0)
                {
                    eightBits[7] = parityCounter % 2 == 0;
                    result.Add(CompositeAsByte(eightBits));
                }
            }
            return result.ToArray();
        }

        private byte CompositeAsByte(bool[] eightBits)
        {
            if (eightBits == null)
                throw new ArgumentNullException(nameof(eightBits));

            byte mask = 0x80;// binary: 1000 0000
            byte index = 0;
            byte result = 0;
            foreach (var bit in eightBits)
            {
                mask >>= index++;
                if (!bit) continue;
                result |= mask;
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