namespace Due.Security;

using System;
using System.Security.Cryptography;
using System.Text;

// 客户端侧的会话安全握手。
// 每条连接都需要重新创建实例，握手状态与连接一一对应。
public sealed class HandshakeClient
{
    // 握手协议版本
    private const byte VERSION = 1;
    // ClientHello 帧类型
    private const byte FRAME_CLIENT_HELLO = 1;
    // ServerHello 帧类型
    private const byte FRAME_SERVER_HELLO = 2;
    // Finished 帧类型
    private const byte FRAME_FINISHED = 3;
    // 随机数字节长度
    private const int RANDOM_SIZE = 32;
    // 公钥字节长度
    private const int PUBLIC_KEY_SIZE = 32;
    // 认证标签字节长度
    private const int MAC_SIZE = 32;
    // 握手帧头字节长度
    private const int FRAME_HEADER_SIZE = 4;
    // 派生密钥材料的总长度：四个 32 字节密钥 + 4 字节盐值
    private const int KEY_MATERIAL_SIZE = 32 * 4 + 4;
    // 握手转录的域分隔标签
    private const string TRANSCRIPT_LABEL = "due-handshake-v1";

    // 服务端签名验证器
    private readonly HandshakeVerifier verifier;
    // 客户端支持的套件
    private readonly IAeadSuite[] suites;

    // 临时私钥
    private byte[] privateKey = Array.Empty<byte>();
    // 客户端随机数
    private byte[] random = Array.Empty<byte>();
    // ClientHello 的 body
    private byte[] hello = Array.Empty<byte>();
    // 握手状态：0 初始，1 已发送 ClientHello，2 已完成
    private int state;

    public HandshakeClient(HandshakeVerifier verifier, params IAeadSuite[]? suites)
    {
        if (verifier == null)
        {
            throw new ArgumentNullException(nameof(verifier));
        }

        if (suites == null || suites.Length == 0)
        {
            suites = new IAeadSuite[] { AesGcmSuite.Instance };
        }

        if (suites.Length > byte.MaxValue)
        {
            throw new ArgumentException("handshake: too many aead suites", nameof(suites));
        }

        foreach (IAeadSuite suite in suites)
        {
            if (suite == null)
            {
                throw new ArgumentException("handshake: aead suite must not be null", nameof(suites));
            }
        }

        this.verifier = verifier;
        this.suites = (IAeadSuite[])suites.Clone();
    }

    // 生成 ClientHello 帧
    public byte[] Hello()
    {
        if (this.state != 0)
        {
            throw new InvalidOperationException("handshake: unexpected state");
        }

        this.privateKey = X25519.GeneratePrivateKey();
        this.random = CryptoUtil.RandomBytes(RANDOM_SIZE);

        byte[] publicKey = X25519.GetPublicKey(this.privateKey);
        byte[] body = new byte[RANDOM_SIZE + PUBLIC_KEY_SIZE + 1 + this.suites.Length];

        Buffer.BlockCopy(this.random, 0, body, 0, RANDOM_SIZE);
        Buffer.BlockCopy(publicKey, 0, body, RANDOM_SIZE, PUBLIC_KEY_SIZE);
        body[RANDOM_SIZE + PUBLIC_KEY_SIZE] = (byte)this.suites.Length;

        for (int i = 0; i < this.suites.Length; i++)
        {
            body[RANDOM_SIZE + PUBLIC_KEY_SIZE + 1 + i] = this.suites[i].Id;
        }

        this.hello = body;
        this.state = 1;

        return EncodeFrame(FRAME_CLIENT_HELLO, body);
    }

    // 处理 ServerHello 帧，返回建立的会话与需要回发的 Finished 帧
    public Session Handle(byte[] frame, out byte[] finished)
    {
        if (this.state != 1)
        {
            throw new InvalidOperationException("handshake: unexpected state");
        }

        DecodeFrame(frame, out byte type, out byte[] body);

        if (type != FRAME_SERVER_HELLO)
        {
            throw new CryptographicException("handshake: invalid message");
        }

        if (body.Length < 1 + RANDOM_SIZE + PUBLIC_KEY_SIZE + 2 + MAC_SIZE)
        {
            throw new CryptographicException("handshake: invalid message");
        }

        int offset = 0;
        byte suiteId = body[offset++];
        byte[] serverRandom = CryptoUtil.Slice(body, ref offset, RANDOM_SIZE);
        byte[] serverPublicKey = CryptoUtil.Slice(body, ref offset, PUBLIC_KEY_SIZE);
        byte[] signatureSizeBytes = CryptoUtil.Slice(body, ref offset, 2);
        int signatureSize = (signatureSizeBytes[0] << 8) | signatureSizeBytes[1];
        byte[] signature = CryptoUtil.Slice(body, ref offset, signatureSize);
        byte[] serverMac = CryptoUtil.Slice(body, ref offset, MAC_SIZE);

        if (offset != body.Length)
        {
            throw new CryptographicException("handshake: invalid message");
        }

        IAeadSuite? suite = this.FindSuite(suiteId);

        if (suite == null)
        {
            throw new CryptographicException("handshake: unsupported aead suite");
        }

        // ServerHello 中被签名的部分：suite | random | public key
        byte[] prefix = new byte[1 + RANDOM_SIZE + PUBLIC_KEY_SIZE];

        Buffer.BlockCopy(body, 0, prefix, 0, prefix.Length);

        byte[] label = Encoding.ASCII.GetBytes(TRANSCRIPT_LABEL);
        byte[] signed = CryptoUtil.Sha256(label, this.hello, prefix);

        if (!this.verifier(signed, signature))
        {
            throw new CryptographicException("handshake: invalid server signature");
        }

        // 握手转录：ClientHello body | ServerHello prefix | 服务端签名
        byte[] transcript = CryptoUtil.Sha256(this.hello, prefix, signature);

        // 临时密钥协商
        byte[] shared = X25519.ComputeSharedKey(this.privateKey, serverPublicKey);

        // HKDF 盐值：客户端随机数 | 服务端随机数
        byte[] salt = new byte[RANDOM_SIZE * 2];

        Buffer.BlockCopy(this.random, 0, salt, 0, RANDOM_SIZE);
        Buffer.BlockCopy(serverRandom, 0, salt, RANDOM_SIZE, RANDOM_SIZE);

        // 派生双向密钥、收尾密钥与会话盐值
        byte[] material = Hkdf.Sha256(shared, salt, CryptoUtil.Concat(label, transcript), KEY_MATERIAL_SIZE);
        byte[] c2sKey = new byte[32];
        byte[] s2cKey = new byte[32];
        byte[] c2sFinish = new byte[32];
        byte[] s2cFinish = new byte[32];
        byte[] sessionSalt = new byte[4];

        Buffer.BlockCopy(material, 0, c2sKey, 0, 32);
        Buffer.BlockCopy(material, 32, s2cKey, 0, 32);
        Buffer.BlockCopy(material, 64, c2sFinish, 0, 32);
        Buffer.BlockCopy(material, 96, s2cFinish, 0, 32);
        Buffer.BlockCopy(material, 128, sessionSalt, 0, 4);

        // 校验服务端的收尾 MAC
        byte[] expected = CryptoUtil.HmacSha256(s2cFinish, transcript);

        if (!CryptoUtil.FixedTimeEquals(expected, serverMac))
        {
            throw new CryptographicException("handshake: invalid server finished mac");
        }

        Session session = new Session(suite, c2sKey, s2cKey, sessionSalt);

        finished = EncodeFrame(FRAME_FINISHED, CryptoUtil.HmacSha256(c2sFinish, transcript));
        this.state = 2;

        return session;
    }

    // 按编号查找本地提供的套件
    private IAeadSuite? FindSuite(byte id)
    {
        foreach (IAeadSuite suite in this.suites)
        {
            if (suite.Id == id)
            {
                return suite;
            }
        }

        return null;
    }

    // 编码握手帧：version(1) | type(1) | length(2) | body
    private static byte[] EncodeFrame(byte type, byte[] body)
    {
        byte[] frame = new byte[FRAME_HEADER_SIZE + body.Length];

        frame[0] = VERSION;
        frame[1] = type;
        frame[2] = (byte)(body.Length >> 8);
        frame[3] = (byte)body.Length;
        Buffer.BlockCopy(body, 0, frame, FRAME_HEADER_SIZE, body.Length);

        return frame;
    }

    // 解码并校验握手帧
    private static void DecodeFrame(byte[] frame, out byte type, out byte[] body)
    {
        if (frame == null || frame.Length < FRAME_HEADER_SIZE)
        {
            throw new CryptographicException("handshake: invalid message");
        }

        if (frame[0] != VERSION)
        {
            throw new CryptographicException("handshake: invalid message");
        }

        int length = (frame[2] << 8) | frame[3];

        if (length != frame.Length - FRAME_HEADER_SIZE)
        {
            throw new CryptographicException("handshake: invalid message");
        }

        type = frame[1];
        body = new byte[length];
        Buffer.BlockCopy(frame, FRAME_HEADER_SIZE, body, 0, length);
    }
}
