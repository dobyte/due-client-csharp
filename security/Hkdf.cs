namespace Due.Security;

using System;
using System.Security.Cryptography;

// HKDF-SHA256 密钥派生（RFC 5869）
internal static class Hkdf
{
    // 派生指定长度的密钥材料
    public static byte[] Sha256(byte[]? ikm, byte[]? salt, byte[]? info, int length)
    {
        if (ikm == null)
        {
            ikm = Array.Empty<byte>();
        }

        if (salt == null || salt.Length == 0)
        {
            salt = new byte[32];
        }

        if (info == null)
        {
            info = Array.Empty<byte>();
        }

        using (HMACSHA256 extract = new HMACSHA256(salt))
        {
            byte[] pseudoRandomKey = extract.ComputeHash(ikm);
            byte[] output = new byte[length];
            byte[] block = Array.Empty<byte>();
            int offset = 0;
            byte counter = 1;

            using (HMACSHA256 expand = new HMACSHA256(pseudoRandomKey))
            {
                while (offset < length)
                {
                    byte[] input = new byte[block.Length + info.Length + 1];
                    Buffer.BlockCopy(block, 0, input, 0, block.Length);
                    Buffer.BlockCopy(info, 0, input, block.Length, info.Length);
                    input[input.Length - 1] = counter;

                    block = expand.ComputeHash(input);

                    int count = Math.Min(block.Length, length - offset);
                    Buffer.BlockCopy(block, 0, output, offset, count);
                    offset += count;
                    counter++;
                }
            }

            return output;
        }
    }
}
