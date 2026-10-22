namespace Due.Security;

using System;

// 会话安全配置
public sealed class SecurityOptions
{
    // 服务端签名验证器；通常由服务端公钥创建
    public HandshakeVerifier? Verifier { get; set; }

    // 客户端支持的 AEAD 套件；为空时使用 AES-256-GCM
    public IAeadSuite[]? Suites { get; set; } = new IAeadSuite[] { AesGcmSuite.Instance };

    // 握手超时时间（毫秒）；小于等于 0 表示不启用超时
    public int HandshakeTimeout { get; set; } = 5000;

    public SecurityOptions()
    {
    }

    public SecurityOptions(HandshakeVerifier verifier)
    {
        this.Verifier = verifier;
    }
}
