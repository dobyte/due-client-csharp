namespace Due.Security;

using System;
using System.Numerics;

// X25519（RFC 7748）密钥交换；用于握手阶段的临时密钥协商
internal static class X25519
{
    // 密钥字节长度
    private const int KEY_SIZE = 32;

    // 椭圆曲线参数 p = 2^255 - 19
    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;

    // 曲线常数 a24
    private static readonly BigInteger A24 = 121665;

    // 基点 u = 9
    private static readonly byte[] BASE_POINT = CreateBasePoint();

    // 生成随机私钥
    public static byte[] GeneratePrivateKey()
    {
        return CryptoUtil.RandomBytes(KEY_SIZE);
    }

    // 由私钥计算公钥
    public static byte[] GetPublicKey(byte[] privateKey)
    {
        return ScalarMultiply(privateKey, BASE_POINT);
    }

    // 计算共享密钥
    public static byte[] ComputeSharedKey(byte[] privateKey, byte[] publicKey)
    {
        if (publicKey == null || publicKey.Length != KEY_SIZE)
        {
            throw new ArgumentException("x25519: invalid public key", nameof(publicKey));
        }

        return ScalarMultiply(privateKey, publicKey);
    }

    // Montgomery 阶梯计算标量乘法
    private static byte[] ScalarMultiply(byte[] privateKey, byte[] point)
    {
        if (privateKey == null || privateKey.Length != KEY_SIZE)
        {
            throw new ArgumentException("x25519: invalid private key", nameof(privateKey));
        }

        byte[] scalar = (byte[])privateKey.Clone();
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;

        byte[] u = (byte[])point.Clone();
        u[31] &= 127;

        BigInteger x1 = FromLittleEndian(u);
        BigInteger x2 = BigInteger.One;
        BigInteger z2 = BigInteger.Zero;
        BigInteger x3 = x1;
        BigInteger z3 = BigInteger.One;
        int swap = 0;

        for (int t = 254; t >= 0; t--)
        {
            int bit = (scalar[t >> 3] >> (t & 7)) & 1;

            if ((swap ^ bit) != 0)
            {
                Swap(ref x2, ref x3);
                Swap(ref z2, ref z3);
            }

            swap = bit;

            BigInteger a = Mod(x2 + z2);
            BigInteger aa = a * a % P;
            BigInteger b = Mod(x2 - z2);
            BigInteger bb = b * b % P;
            BigInteger e = Mod(aa - bb);
            BigInteger c = Mod(x3 + z3);
            BigInteger d = Mod(x3 - z3);
            BigInteger da = d * a % P;
            BigInteger cb = c * b % P;

            x3 = (da + cb) * (da + cb) % P;
            z3 = x1 * ((da - cb) * (da - cb) % P) % P;
            x2 = aa * bb % P;
            z2 = e * Mod(aa + A24 * e) % P;
        }

        if (swap != 0)
        {
            Swap(ref x2, ref x3);
            Swap(ref z2, ref z3);
        }

        BigInteger result = x2 * BigInteger.ModPow(z2, P - 2, P) % P;

        return ToLittleEndian(result);
    }

    // 取模并归一化为非负数
    private static BigInteger Mod(BigInteger value)
    {
        BigInteger result = value % P;

        return result.Sign < 0 ? result + P : result;
    }

    // 交换两个数
    private static void Swap(ref BigInteger left, ref BigInteger right)
    {
        BigInteger temp = left;
        left = right;
        right = temp;
    }

    // 小端字节数组转整数
    private static BigInteger FromLittleEndian(byte[] buffer)
    {
        BigInteger value = BigInteger.Zero;

        for (int i = buffer.Length - 1; i >= 0; i--)
        {
            value = (value << 8) | buffer[i];
        }

        return value;
    }

    // 整数转 32 字节小端数组
    private static byte[] ToLittleEndian(BigInteger value)
    {
        byte[] buffer = new byte[KEY_SIZE];

        for (int i = 0; i < KEY_SIZE && value.Sign > 0; i++)
        {
            buffer[i] = (byte)(value & 0xff);
            value >>= 8;
        }

        return buffer;
    }

    // 构造基点
    private static byte[] CreateBasePoint()
    {
        byte[] point = new byte[KEY_SIZE];
        point[0] = 9;

        return point;
    }
}
