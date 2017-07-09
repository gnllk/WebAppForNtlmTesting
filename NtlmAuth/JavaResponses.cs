using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace NtlmAuth
{
    /// <summary>
    /// Calculates the various Type 3 responses.
    /// </summary>
    public class JavaResponses
    {
        /**
         * Calculates the LM Response for the given challenge, using the specified
         * password.
         *
         * @param password The user's password.
         * @param challenge The Type 2 challenge from the server.
         *
         * @return The LM Response.
         */
        public static byte[] GetLmResponse(string password, byte[] challenge)
        {
            byte[] lmHash = LmHash(password);
            return LmResponse(lmHash, challenge);
        }

        /**
         * Calculates the NTLM Response for the given challenge, using the
         * specified password.
         *
         * @param password The user's password.
         * @param challenge The Type 2 challenge from the server.
         *
         * @return The NTLM Response.
         */
        public static byte[] GetNTLMResponse(string password, byte[] challenge)
        {
            byte[] ntlmHash = NtlmHash(password);
            return LmResponse(ntlmHash, challenge);
        }

        /**
         * Calculates the NTLMv2 Response for the given challenge, using the
         * specified authentication target, username, password, target information
         * block, and client nonce.
         *
         * @param target The authentication target (i.e., domain).
         * @param user The username. 
         * @param password The user's password.
         * @param targetInformation The target information block from the Type 2
         * message.
         * @param challenge The Type 2 challenge from the server.
         * @param clientNonce The random 8-byte client nonce. 
         *
         * @return The NTLMv2 Response.
         */
        public static byte[] GetNTLMv2Response(string target, string user,
                string password, byte[] targetInformation, byte[] challenge, byte[] clientNonce)
        {
            byte[] ntlmv2Hash = Ntlmv2Hash(target, user, password);
            byte[] blob = CreateBlob(targetInformation, clientNonce);
            return Lmv2Response(ntlmv2Hash, blob, challenge);
        }

        /**
         * Calculates the LMv2 Response for the given challenge, using the
         * specified authentication target, username, password, and client
         * challenge.
         *
         * @param target The authentication target (i.e., domain).
         * @param user The username.
         * @param password The user's password.
         * @param challenge The Type 2 challenge from the server.
         * @param clientNonce The random 8-byte client nonce.
         *
         * @return The LMv2 Response. 
         */
        public static byte[] GetLMv2Response(string target, string user,
                string password, byte[] challenge, byte[] clientNonce)
        {
            byte[] ntlmv2Hash = Ntlmv2Hash(target, user, password);
            return Lmv2Response(ntlmv2Hash, clientNonce, challenge);
        }

        /**
         * Calculates the NTLM2 Session Response for the given challenge, using the
         * specified password and client nonce.
         *
         * @param password The user's password.
         * @param challenge The Type 2 challenge from the server.
         * @param clientNonce The random 8-byte client nonce.
         *
         * @return The NTLM2 Session Response.  This is placed in the NTLM
         * response field of the Type 3 message; the LM response field contains
         * the client nonce, null-padded to 24 bytes.
         */
        public static byte[] GetNTLM2SessionResponse(string password, byte[] challenge, byte[] clientNonce)
        {
            byte[] ntlmHash = NtlmHash(password);
            var md5 = MD5.Create();
            var hash1 = md5.ComputeHash(challenge);
            var hash2 = md5.ComputeHash(clientNonce);
            byte[] sessionHash = new byte[8];
            Array.Copy(hash1.Concat(hash2).ToArray(), 0, sessionHash, 0, 8);
            return LmResponse(ntlmHash, sessionHash);
        }

        /**
         * Creates the LM Hash of the user's password.
         *
         * @param password The password.
         *
         * @return The LM Hash of the given password, used in the calculation
         * of the LM Response.
         */
        private static byte[] LmHash(string password)
        {
            byte[] oemPassword = Encoding.ASCII.GetBytes(password.ToUpperInvariant());
            int Length = Math.Min(oemPassword.Length, 14);
            byte[] keyBytes = new byte[14];
            Array.Copy(oemPassword, 0, keyBytes, 0, Length);
            byte[] lowKey = CreateDESKey(keyBytes, 0);
            byte[] highKey = CreateDESKey(keyBytes, 7);
            byte[] magicConstant = Encoding.ASCII.GetBytes("KGS!@#$%");
            byte[] lowHash = DesHelper.Encrypt(magicConstant, lowKey);
            byte[] highHash = DesHelper.Encrypt(magicConstant, highKey);
            byte[] lmHash = new byte[16];
            Array.Copy(lowHash, 0, lmHash, 0, 8);
            Array.Copy(highHash, 0, lmHash, 8, 8);
            return lmHash;
        }

        /**
         * Creates the NTLM Hash of the user's password.
         *
         * @param password The password.
         *
         * @return The NTLM Hash of the given password, used in the calculation
         * of the NTLM Response and the NTLMv2 and LMv2 Hashes.
         */
        private static byte[] NtlmHash(string password)
        {
            byte[] unicodePassword = Encoding.Unicode.GetBytes(password);
            return new MD4().GetByteHashFromBytes(unicodePassword);
        }

        /**
         * Creates the NTLMv2 Hash of the user's password.
         *
         * @param target The authentication target (i.e., domain).
         * @param user The username.
         * @param password The password.
         *
         * @return The NTLMv2 Hash, used in the calculation of the NTLMv2
         * and LMv2 Responses. 
         */
        private static byte[] Ntlmv2Hash(string target, string user, string password)
        {
            byte[] ntlmHash = NtlmHash(password);
            string identity = user.ToUpperInvariant() + target;
            return HmacMD5(Encoding.Unicode.GetBytes(identity), ntlmHash);
        }

        /**
         * Creates the LM Response from the given hash and Type 2 challenge.
         *
         * @param hash The LM or NTLM Hash.
         * @param challenge The server challenge from the Type 2 message.
         *
         * @return The response (either LM or NTLM, depending on the provided
         * hash).
         */
        private static byte[] LmResponse(byte[] hash, byte[] challenge)
        {
            byte[] keyBytes = new byte[21];
            Array.Copy(hash, 0, keyBytes, 0, 16);

            byte[] lowKey = CreateDESKey(keyBytes, 0);
            byte[] middleKey = CreateDESKey(keyBytes, 7);
            byte[] highKey = CreateDESKey(keyBytes, 14);

            byte[] lowResponse = DesHelper.Encrypt(challenge, lowKey);
            byte[] middleResponse = DesHelper.Encrypt(challenge, middleKey);
            byte[] highResponse = DesHelper.Encrypt(challenge, highKey);

            byte[] lmResponse = new byte[24];
            Array.Copy(lowResponse, 0, lmResponse, 0, 8);
            Array.Copy(middleResponse, 0, lmResponse, 8, 8);
            Array.Copy(highResponse, 0, lmResponse, 16, 8);
            return lmResponse;
        }

        /**
         * Creates the LMv2 Response from the given hash, client data, and
         * Type 2 challenge.
         *
         * @param hash The NTLMv2 Hash.
         * @param clientData The client data (blob or client nonce).
         * @param challenge The server challenge from the Type 2 message.
         *
         * @return The response (either NTLMv2 or LMv2, depending on the
         * client data).
         */
        private static byte[] Lmv2Response(byte[] hash, byte[] clientData, byte[] challenge)
        {
            byte[] data = new byte[challenge.Length + clientData.Length];
            Array.Copy(challenge, 0, data, 0, challenge.Length);
            Array.Copy(clientData, 0, data, challenge.Length, clientData.Length);
            byte[] mac = HmacMD5(data, hash);
            byte[] lmv2Response = new byte[mac.Length + clientData.Length];
            Array.Copy(mac, 0, lmv2Response, 0, mac.Length);
            Array.Copy(clientData, 0, lmv2Response, mac.Length, clientData.Length);
            return lmv2Response;
        }

        /**
         * Creates the NTLMv2 blob from the given target information block and
         * client nonce.
         *
         * @param targetInformation The target information block from the Type 2
         * message.
         * @param clientNonce The random 8-byte client nonce.
         *
         * @return The blob, used in the calculation of the NTLMv2 Response.
         */
        private static byte[] CreateBlob(byte[] targetInformation, byte[] clientNonce)
        {
            byte[] blobSignature = new byte[] { 0x01, 0x01, 0x00, 0x00 };
            byte[] reserved = new byte[] { 0x00, 0x00, 0x00, 0x00 };
            byte[] unknown1 = new byte[] { 0x00, 0x00, 0x00, 0x00 };
            byte[] unknown2 = new byte[] { 0x00, 0x00, 0x00, 0x00 };

            long time = (long)(DateTime.UtcNow - DateTime.Parse("1970-01-01T00:00:00Z")).TotalMilliseconds;
            time += 11644473600000L; // milliseconds from January 1, 1601 -> epoch.
            time *= 10000; // tenths of a microsecond.
                           // convert to little-endian byte array.
            byte[] timestamp = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                timestamp[i] = (byte)time;
                time = time / (int)Math.Pow(2, 8);
            }
            // TODO: Remove this
            //timestamp = HexHelper.HexToBytes("0090d336b734c301");

            byte[] blob = new byte[blobSignature.Length + reserved.Length +
                                   timestamp.Length + clientNonce.Length +
                                   unknown1.Length + targetInformation.Length +
                                   unknown2.Length];

            int offset = 0;
            Array.Copy(blobSignature, 0, blob, offset, blobSignature.Length);
            offset += blobSignature.Length;
            Array.Copy(reserved, 0, blob, offset, reserved.Length);
            offset += reserved.Length;
            Array.Copy(timestamp, 0, blob, offset, timestamp.Length);
            offset += timestamp.Length;
            Array.Copy(clientNonce, 0, blob, offset, clientNonce.Length);
            offset += clientNonce.Length;
            Array.Copy(unknown1, 0, blob, offset, unknown1.Length);
            offset += unknown1.Length;
            Array.Copy(targetInformation, 0, blob, offset, targetInformation.Length);
            offset += targetInformation.Length;
            Array.Copy(unknown2, 0, blob, offset, unknown2.Length);
            return blob;
        }

        /**
         * Calculates the HMAC-MD5 hash of the given data using the specified
         * hashing key.
         *
         * @param data The data for which the hash will be calculated. 
         * @param key The hashing key.
         *
         * @return The HMAC-MD5 hash of the given data.
         */
        private static byte[] HmacMD5(byte[] data, byte[] key)
        {
            byte[] ipad = new byte[64];
            byte[] opad = new byte[64];
            for (int i = 0; i < 64; i++)
            {
                ipad[i] = (byte)0x36;
                opad[i] = (byte)0x5c;
            }
            for (int i = key.Length - 1; i >= 0; i--)
            {
                ipad[i] ^= key[i];
                opad[i] ^= key[i];
            }
            byte[] content = new byte[data.Length + 64];
            Array.Copy(ipad, 0, content, 0, 64);
            Array.Copy(data, 0, content, 64, data.Length);
            var md5 = MD5.Create();
            data = md5.ComputeHash(content);
            content = new byte[data.Length + 64];
            Array.Copy(opad, 0, content, 0, 64);
            Array.Copy(data, 0, content, 64, data.Length);
            return md5.ComputeHash(content);
        }

        /**
         * Creates a DES encryption key from the given key material.
         *
         * @param bytes A byte array containing the DES key material.
         * @param offset The offset in the given byte array at which
         * the 7-byte key material starts.
         *
         * @return A DES encryption key created from the key material
         * starting at the specified offset in the given byte array.
         */
        private static byte[] CreateDESKey(byte[] bytes, int offset)
        {
            byte[] keyBytes = new byte[7];
            Array.Copy(bytes, offset, keyBytes, 0, 7);
            byte[] material = new byte[8];
            material[0] = keyBytes[0];
            material[1] = (byte)(keyBytes[0] << 7 | (keyBytes[1] & 0xff) / (int)Math.Pow(2, 1));
            material[2] = (byte)(keyBytes[1] << 6 | (keyBytes[2] & 0xff) / (int)Math.Pow(2, 2));
            material[3] = (byte)(keyBytes[2] << 5 | (keyBytes[3] & 0xff) / (int)Math.Pow(2, 3));
            material[4] = (byte)(keyBytes[3] << 4 | (keyBytes[4] & 0xff) / (int)Math.Pow(2, 4));
            material[5] = (byte)(keyBytes[4] << 3 | (keyBytes[5] & 0xff) / (int)Math.Pow(2, 5));
            material[6] = (byte)(keyBytes[5] << 2 | (keyBytes[6] & 0xff) / (int)Math.Pow(2, 6));
            material[7] = (byte)(keyBytes[6] << 1);
            OddParity(material);
            return material;
        }

        /**
         * Applies odd parity to the given byte array.
         *
         * @param bytes The data whose parity bits are to be adjusted for
         * odd parity.
         */
        private static void OddParity(byte[] bytes)
        {
            for (int i = 0; i < bytes.Length; i++)
            {
                byte b = bytes[i];
                bool needsParity = (((b / (int)Math.Pow(2, 7)) ^ (b / (int)Math.Pow(2, 6)) ^ (b / (int)Math.Pow(2, 5)) ^
                                        (b / (int)Math.Pow(2, 4)) ^ (b / (int)Math.Pow(2, 3)) ^ (b / (int)Math.Pow(2, 2)) ^
                                        (b / (int)Math.Pow(2, 1))) & 0x01) == 0;
                if (needsParity)
                {
                    bytes[i] |= (byte)0x01;
                }
                else
                {
                    bytes[i] &= (byte)0xfe;
                }
            }
        }
    }
}