namespace Due.Security;

using System;
using System.Security.Cryptography;

// AEAD 算法套件；与服务端的 aead.Suite 对应
public interface IAeadSuite
{
    // 线协议中的套件编号
    byte Id { get; }

    // 套件名称
    string Name { get; }

    // 使用会话密钥创建加解密器
    IAeadCipher Create(byte[] key);
}

// AEAD 加解密器；Seal 的输出为 ciphertext || tag
public interface IAeadCipher : IDisposable
{
    // 加密并附加认证标签
    byte[] Seal(byte[] nonce, byte[]? plaintext, byte[]? aad);

    // 校验并解密；认证失败时抛出 CryptographicException
    byte[] Open(byte[] nonce, byte[]? sealedData, byte[]? aad);
}

// AES-256-GCM 套件；套件编号 1，与服务端的 aesgcm.Suite 一致
public sealed class AesGcmSuite : IAeadSuite
{
    // 线协议套件编号
    public const byte SUITE_ID = 1;

    // 密钥字节长度
    public const int KEY_SIZE = 32;

    // 单例
    public static readonly AesGcmSuite Instance = new AesGcmSuite();

    public byte Id => SUITE_ID;

    public string Name => "aes-gcm";

    public IAeadCipher Create(byte[] key)
    {
        if (key == null || key.Length != KEY_SIZE)
        {
            throw new ArgumentException("aes-gcm: invalid key size", nameof(key));
        }

        return new AesGcmCipher(key);
    }
}

// 纯托管的 AES-256-GCM 实现。
// 不依赖 System.Security.Cryptography.AesGcm，保证在 .NET Framework 等运行时下均可使用。
internal sealed class AesGcmCipher : IAeadCipher
{
    // 分组字节长度
    private const int BLOCK_SIZE = 16;

    // 认证标签字节长度
    private const int TAG_SIZE = 16;

    // 分组加密器
    private readonly ICryptoTransform encryptor;

    // GHASH 的哈希子密钥
    private readonly byte[] hashKey;

    // 分组加密器非线程安全，需串行访问
    private readonly object syncRoot = new object();

    // 资源持有者，用于释放底层 AES
    private readonly Aes aes;

    public AesGcmCipher(byte[] key)
    {
        this.aes = Aes.Create() ?? throw new CryptographicException("aes-gcm: aes implementation unavailable");
        this.aes.Mode = CipherMode.ECB;
        this.aes.Padding = PaddingMode.None;
        this.aes.Key = key;
        this.encryptor = this.aes.CreateEncryptor();
        this.hashKey = this.EncryptBlocks(new byte[BLOCK_SIZE]);
    }

    // 释放底层 AES 资源
    public void Dispose()
    {
        this.encryptor.Dispose();
        this.aes.Dispose();
    }

    // 加密：返回 ciphertext || tag
    public byte[] Seal(byte[] nonce, byte[]? plaintext, byte[]? aad)
    {
        this.ValidateNonce(nonce);

        plaintext ??= Array.Empty<byte>();
        aad ??= Array.Empty<byte>();

        byte[] tagMask = this.EncryptBlocks(BuildCounterBlock(nonce, 1));
        byte[] ciphertext = this.Crypt(nonce, plaintext);
        byte[] hash = this.GHash(aad, ciphertext);
        byte[] output = new byte[ciphertext.Length + TAG_SIZE];

        Buffer.BlockCopy(ciphertext, 0, output, 0, ciphertext.Length);

        for (int i = 0; i < TAG_SIZE; i++)
        {
            output[ciphertext.Length + i] = (byte)(hash[i] ^ tagMask[i]);
        }

        return output;
    }

    // 解密：校验标签后返回明文
    public byte[] Open(byte[] nonce, byte[]? sealedData, byte[]? aad)
    {
        this.ValidateNonce(nonce);

        if (sealedData == null || sealedData.Length < TAG_SIZE)
        {
            throw new CryptographicException("aes-gcm: invalid ciphertext");
        }

        aad ??= Array.Empty<byte>();

        int length = sealedData.Length - TAG_SIZE;
        byte[] ciphertext = new byte[length];
        Buffer.BlockCopy(sealedData, 0, ciphertext, 0, length);

        byte[] tagMask = this.EncryptBlocks(BuildCounterBlock(nonce, 1));
        byte[] hash = this.GHash(aad, ciphertext);
        byte[] tag = new byte[TAG_SIZE];

        for (int i = 0; i < TAG_SIZE; i++)
        {
            tag[i] = (byte)(hash[i] ^ tagMask[i]);
        }

        byte[] expected = new byte[TAG_SIZE];
        Buffer.BlockCopy(sealedData, length, expected, 0, TAG_SIZE);

        if (!CryptoUtil.FixedTimeEquals(tag, expected))
        {
            throw new CryptographicException("aes-gcm: authentication failed");
        }

        return this.Crypt(nonce, ciphertext);
    }

    // 校验 nonce 长度；GCM 要求 12 字节
    private void ValidateNonce(byte[] nonce)
    {
        if (nonce == null || nonce.Length != 12)
        {
            throw new ArgumentException("aes-gcm: invalid nonce", nameof(nonce));
        }
    }

    // CTR 加解密；起始计数为 2（计数器 1 用于标签掩码）
    private byte[] Crypt(byte[] nonce, byte[] input)
    {
        if (input.Length == 0)
        {
            return Array.Empty<byte>();
        }

        int blocks = (input.Length + BLOCK_SIZE - 1) / BLOCK_SIZE;
        byte[] counters = new byte[blocks * BLOCK_SIZE];

        for (int i = 0; i < blocks; i++)
        {
            byte[] counter = BuildCounterBlock(nonce, (uint)(i + 2));
            Buffer.BlockCopy(counter, 0, counters, i * BLOCK_SIZE, BLOCK_SIZE);
        }

        byte[] stream = this.EncryptBlocks(counters);
        byte[] output = new byte[input.Length];

        for (int i = 0; i < input.Length; i++)
        {
            output[i] = (byte)(input[i] ^ stream[i]);
        }

        return output;
    }

    // 批量执行 AES 分组加密
    private byte[] EncryptBlocks(byte[] input)
    {
        byte[] output = new byte[input.Length];

        lock (this.syncRoot)
        {
            this.encryptor.TransformBlock(input, 0, input.Length, output, 0);
        }

        return output;
    }

    // 计算 GHASH：AAD 与密文分块后与长度块一起参与运算
    private byte[] GHash(byte[] aad, byte[] ciphertext)
    {
        byte[] y = new byte[BLOCK_SIZE];

        this.Accumulate(ref y, aad);
        this.Accumulate(ref y, ciphertext);

        byte[] lengths = new byte[BLOCK_SIZE];

        WriteUInt64BE(lengths, 0, (ulong)aad.Length * 8);
        WriteUInt64BE(lengths, 8, (ulong)ciphertext.Length * 8);

        return Multiply(XorBlock(y, lengths, 0, BLOCK_SIZE), this.hashKey);
    }

    // 将数据按 16 字节分块累加到 GHASH 状态
    private void Accumulate(ref byte[] y, byte[] data)
    {
        for (int offset = 0; offset < data.Length; offset += BLOCK_SIZE)
        {
            int count = Math.Min(BLOCK_SIZE, data.Length - offset);
            y = Multiply(XorBlock(y, data, offset, count), this.hashKey);
        }
    }

    // GF(2^128) 乘法
    private static byte[] Multiply(byte[] x, byte[] y)
    {
        byte[] z = new byte[BLOCK_SIZE];
        byte[] v = (byte[])y.Clone();

        for (int i = 0; i < BLOCK_SIZE * 8; i++)
        {
            if (((x[i >> 3] >> (7 - (i & 7))) & 1) != 0)
            {
                for (int j = 0; j < BLOCK_SIZE; j++)
                {
                    z[j] ^= v[j];
                }
            }

            bool lsb = (v[BLOCK_SIZE - 1] & 1) != 0;
            int carry = 0;

            for (int j = 0; j < BLOCK_SIZE; j++)
            {
                int current = v[j] & 1;
                v[j] = (byte)((v[j] >> 1) | (carry << 7));
                carry = current;
            }

            if (lsb)
            {
                v[0] ^= 0xE1;
            }
        }

        return z;
    }

    // 将 y 的前 count 个字节与数据异或后返回新块
    private static byte[] XorBlock(byte[] y, byte[] data, int offset, int count)
    {
        byte[] block = (byte[])y.Clone();

        for (int i = 0; i < count; i++)
        {
            block[i] ^= data[offset + i];
        }

        return block;
    }

    // 构造计数器块：nonce(12) || counter(4, big endian)
    private static byte[] BuildCounterBlock(byte[] nonce, uint counter)
    {
        byte[] block = new byte[BLOCK_SIZE];

        Buffer.BlockCopy(nonce, 0, block, 0, 12);
        block[12] = (byte)(counter >> 24);
        block[13] = (byte)(counter >> 16);
        block[14] = (byte)(counter >> 8);
        block[15] = (byte)counter;

        return block;
    }

    // 写入 64 位大端整数
    private static void WriteUInt64BE(byte[] buffer, int offset, ulong value)
    {
        for (int i = 7; i >= 0; i--)
        {
            buffer[offset + i] = (byte)value;
            value >>= 8;
        }
    }
}
