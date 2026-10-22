namespace Due.Security;

using System;
using System.Security.Cryptography;

// 安全模块内部使用的密码学工具
internal static class CryptoUtil
{
    // 生成指定长度的随机字节
    public static byte[] RandomBytes(int length)
    {
        byte[] buffer = new byte[length];

        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(buffer);
        }

        return buffer;
    }

    // 计算多段数据的 SHA256
    public static byte[] Sha256(params byte[][] parts)
    {
        using (SHA256 sha = SHA256.Create())
        {
            return sha.ComputeHash(Concat(parts));
        }
    }

    // 计算 HMAC-SHA256
    public static byte[] HmacSha256(byte[] key, byte[] data)
    {
        using (HMACSHA256 hmac = new HMACSHA256(key))
        {
            return hmac.ComputeHash(data);
        }
    }

    // 拼接多段数据
    public static byte[] Concat(params byte[][] parts)
    {
        int length = 0;

        foreach (byte[] part in parts)
        {
            if (part != null)
            {
                length += part.Length;
            }
        }

        byte[] buffer = new byte[length];
        int offset = 0;

        foreach (byte[] part in parts)
        {
            if (part != null)
            {
                Buffer.BlockCopy(part, 0, buffer, offset, part.Length);
                offset += part.Length;
            }
        }

        return buffer;
    }

    // 定长时间比较，避免时序侧信道
    public static bool FixedTimeEquals(byte[] left, byte[] right)
    {
        if (left == null || right == null || left.Length != right.Length)
        {
            return false;
        }

        int diff = 0;

        for (int i = 0; i < left.Length; i++)
        {
            diff |= left[i] ^ right[i];
        }

        return diff == 0;
    }

    // 从缓冲区切出指定长度的一段
    public static byte[] Slice(byte[] source, ref int offset, int count)
    {
        if (source == null || count < 0 || offset < 0 || offset + count > source.Length)
        {
            throw new CryptographicException("invalid buffer");
        }

        byte[] buffer = new byte[count];
        Buffer.BlockCopy(source, offset, buffer, 0, count);
        offset += count;

        return buffer;
    }
}
