namespace Due.Security;

using System;
using System.Security.Cryptography;

// 消息传输方向；与服务端的 handshake.Direction 对应
public enum Direction : byte
{
    // 客户端到服务端
    ClientToServer = 0,
    // 服务端到客户端
    ServerToClient = 1
}

// 握手协商出的 AEAD 会话。
// 密文载荷布局：epoch(1) | counter(8) | ciphertext | tag；
// nonce 为 4 字节会话盐值拼接 8 字节计数器。
public sealed class Session : IDisposable
{
    // 握手协议版本，同时用于构造 AAD
    private const byte VERSION = 1;
    // 密文信封头长度
    private const int ENVELOPE_HEADER_SIZE = 9;
    // 会话盐值长度
    private const int SALT_SIZE = 4;
    // nonce 长度
    private const int NONCE_SIZE = 12;
    // 认证标签长度
    private const int TAG_SIZE = 16;
    // AAD 长度
    private const int AAD_SIZE = 11;

    // 发送方向加解密器
    private readonly IAeadCipher send;
    // 接收方向加解密器
    private readonly IAeadCipher recv;
    // 会话盐值
    private readonly byte[] salt;
    // 接收重放窗口
    private readonly ReplayWindow replayWindow = new ReplayWindow();
    // 发送计数器与加解密器由该锁保护
    private readonly object sendLock = new object();

    // 发送计数器
    private ulong sendCounter;

    internal Session(IAeadSuite suite, byte[] sendKey, byte[] recvKey, byte[] salt)
    {
        if (suite == null)
        {
            throw new ArgumentNullException(nameof(suite));
        }

        if (salt == null || salt.Length != SALT_SIZE)
        {
            throw new ArgumentException("invalid session salt", nameof(salt));
        }

        this.send = suite.Create(sendKey);
        this.recv = suite.Create(recvKey);
        this.salt = (byte[])salt.Clone();
    }

    // 释放收发方向的加解密器并清零会话盐值
    public void Dispose()
    {
        this.send.Dispose();
        this.recv.Dispose();
        Array.Clear(this.salt, 0, this.salt.Length);
    }

    // 当前密钥世代的编号
    public byte Epoch => VERSION;

    // 加密后附加的字节数（信封头 + 认证标签）
    public int Overhead => ENVELOPE_HEADER_SIZE + TAG_SIZE;

    // 构造附加认证数据：version(1) | direction(1) | epoch(1) | route(4) | seq(4)
    public static byte[] MakeAAD(Direction direction, byte epoch, int route, int seq)
    {
        byte[] aad = new byte[AAD_SIZE];

        aad[0] = VERSION;
        aad[1] = (byte)direction;
        aad[2] = epoch;
        WriteUInt32BE(aad, 3, (uint)route);
        WriteUInt32BE(aad, 7, (uint)seq);

        return aad;
    }

    // 加密消息载荷，返回可直接写入消息体的密文信封
    public byte[] SealMessage(byte[]? plaintext, Direction direction, int route, int seq)
    {
        plaintext ??= Array.Empty<byte>();

        lock (this.sendLock)
        {
            if (this.sendCounter == ulong.MaxValue)
            {
                throw new CryptographicException("session key exhausted");
            }

            ulong counter = this.sendCounter++;
            byte[] nonce = this.BuildNonce(counter);
            byte[] aad = MakeAAD(direction, VERSION, route, seq);
            byte[] body = this.send.Seal(nonce, plaintext, aad);
            byte[] output = new byte[ENVELOPE_HEADER_SIZE + body.Length];

            output[0] = VERSION;
            WriteUInt64BE(output, 1, counter);
            Buffer.BlockCopy(body, 0, output, ENVELOPE_HEADER_SIZE, body.Length);

            return output;
        }
    }

    // 校验并解密消息载荷
    public byte[] OpenMessage(byte[]? sealedData, Direction direction, int route, int seq)
    {
        if (sealedData == null || sealedData.Length < ENVELOPE_HEADER_SIZE + TAG_SIZE)
        {
            throw new CryptographicException("invalid secure message");
        }

        if (sealedData[0] != VERSION)
        {
            throw new CryptographicException("invalid secure message");
        }

        ulong counter = ReadUInt64BE(sealedData, 1);
        byte[] nonce = this.BuildNonce(counter);
        byte[] aad = MakeAAD(direction, VERSION, route, seq);
        byte[] body = new byte[sealedData.Length - ENVELOPE_HEADER_SIZE];

        Buffer.BlockCopy(sealedData, ENVELOPE_HEADER_SIZE, body, 0, body.Length);

        byte[] plaintext = this.recv.Open(nonce, body, aad);

        // 仅在认证通过后推进重放窗口
        if (!this.replayWindow.Advance(counter))
        {
            throw new CryptographicException("replayed message");
        }

        return plaintext;
    }

    // 构造 nonce：salt(4) | counter(8)
    private byte[] BuildNonce(ulong counter)
    {
        byte[] nonce = new byte[NONCE_SIZE];

        Buffer.BlockCopy(this.salt, 0, nonce, 0, SALT_SIZE);
        WriteUInt64BE(nonce, SALT_SIZE, counter);

        return nonce;
    }

    // 写入 32 位大端整数
    private static void WriteUInt32BE(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)(value >> 24);
        buffer[offset + 1] = (byte)(value >> 16);
        buffer[offset + 2] = (byte)(value >> 8);
        buffer[offset + 3] = (byte)value;
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

    // 读取 64 位大端整数
    private static ulong ReadUInt64BE(byte[] buffer, int offset)
    {
        ulong value = 0;

        for (int i = 0; i < 8; i++)
        {
            value = (value << 8) | buffer[offset + i];
        }

        return value;
    }

    // 64 位滑动重放窗口
    private sealed class ReplayWindow
    {
        private readonly object syncRoot = new object();

        private ulong highest;
        private ulong bits;
        private bool inited;

        // 记录计数器并返回是否为新鲜消息
        public bool Advance(ulong counter)
        {
            lock (this.syncRoot)
            {
                if (!this.inited)
                {
                    this.inited = true;
                    this.highest = counter;
                    this.bits = 1;

                    return true;
                }

                if (counter > this.highest)
                {
                    ulong shift = counter - this.highest;

                    if (shift >= 64)
                    {
                        this.bits = 0;
                    }
                    else
                    {
                        this.bits <<= (int)shift;
                    }

                    this.bits |= 1;
                    this.highest = counter;

                    return true;
                }

                ulong diff = this.highest - counter;

                if (diff >= 64 || (this.bits & (1UL << (int)diff)) != 0)
                {
                    return false;
                }

                this.bits |= 1UL << (int)diff;

                return true;
            }
        }
    }
}
