namespace Due.Security;

using System;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

// 服务端签名验证器；data 为待验证的原始数据，signature 为服务端签名
public delegate bool HandshakeVerifier(byte[] data, byte[]? signature);

// 内置的服务端公钥验证器，支持 due 的 ecc、rsa 签名实现
public static class Verifier
{
    // id-ecPublicKey
    private static readonly byte[] OID_EC_PUBLIC_KEY = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };

    // rsaEncryption
    private static readonly byte[] OID_RSA_ENCRYPTION = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

    // prime256v1 / secp256r1
    private static readonly byte[] OID_P256 = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

    // secp384r1
    private static readonly byte[] OID_P384 = { 0x2B, 0x81, 0x04, 0x00, 0x22 };

    // secp521r1
    private static readonly byte[] OID_P521 = { 0x2B, 0x81, 0x04, 0x00, 0x23 };

    // 默认签名分隔符与 due 的 ecc signer 保持一致
    private const string DEFAULT_DELIMITER = " ";

    // 创建 ECDSA 验证器。
    // publicKey 可以是 PEM 文件路径或 PEM 内容；delimiter 需与服务端配置一致。
    public static HandshakeVerifier Ecdsa(string publicKey, HashAlgorithmName? hash = null, string delimiter = DEFAULT_DELIMITER)
    {
        ECDsa ecdsa = LoadEcdsa(publicKey);
        HashAlgorithmName algorithm = hash ?? HashAlgorithmName.SHA256;
        string separator = string.IsNullOrEmpty(delimiter) ? DEFAULT_DELIMITER : delimiter;

        return (data, signature) => VerifyEcdsa(ecdsa, algorithm, separator, data, signature);
    }

    // 创建 RSA 验证器。
    // publicKey 可以是 PEM 文件路径或 PEM 内容；pss 为 false 时使用 PKCS#1 v1.5 填充。
    public static HandshakeVerifier Rsa(string publicKey, HashAlgorithmName? hash = null, bool pss = true)
    {
        RSA rsa = LoadRsa(publicKey);
        HashAlgorithmName algorithm = hash ?? HashAlgorithmName.SHA256;
        RSASignaturePadding padding = pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;

        return (data, signature) =>
        {
            if (signature == null)
            {
                return false;
            }

            try
            {
                lock (rsa)
                {
                    return rsa.VerifyData(data, signature, algorithm, padding);
                }
            }
            catch (CryptographicException)
            {
                return false;
            }
        };
    }

    // 验证 ECDSA 签名；服务端的签名为 r、s 的十进制字符串
    private static bool VerifyEcdsa(ECDsa ecdsa, HashAlgorithmName hash, string delimiter, byte[] data, byte[]? signature)
    {
        if (signature == null)
        {
            return false;
        }

        string text = Encoding.ASCII.GetString(signature);
        string[] parts = text.Split(new[] { delimiter }, StringSplitOptions.None);

        if (parts.Length != 2)
        {
            return false;
        }

        if (!BigInteger.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out BigInteger r))
        {
            return false;
        }

        if (!BigInteger.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out BigInteger s))
        {
            return false;
        }

        int size = (ecdsa.KeySize + 7) / 8;
        byte[] rs = new byte[size * 2];

        if (!WriteBigEndian(r, rs, 0, size) || !WriteBigEndian(s, rs, size, size))
        {
            return false;
        }

        try
        {
            lock (ecdsa)
            {
                return ecdsa.VerifyData(data, rs, hash);
            }
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    // 将非负整数按固定长度写入大端缓冲区
    private static bool WriteBigEndian(BigInteger value, byte[] buffer, int offset, int size)
    {
        if (value.Sign < 0)
        {
            return false;
        }

        byte[] bytes = value.ToByteArray();
        int index = bytes.Length - 1;

        while (index > 0 && bytes[index] == 0)
        {
            index--;
        }

        if (index + 1 > size)
        {
            return false;
        }

        for (int i = 0; i <= index; i++)
        {
            buffer[offset + size - 1 - i] = bytes[i];
        }

        return true;
    }

    // 从 PEM 公钥创建 ECDSA 实例
    private static ECDsa LoadEcdsa(string publicKey)
    {
        byte[] der = LoadDer(publicKey);
        int offset = 0;
        byte[] spki = ReadTlv(der, ref offset, 0x30);
        int spkiOffset = 0;
        byte[] algorithm = ReadTlv(spki, ref spkiOffset, 0x30);
        byte[] bits = ReadTlv(spki, ref spkiOffset, 0x03);

        int algorithmOffset = 0;
        byte[] algorithmOid = ReadTlv(algorithm, ref algorithmOffset, 0x06);

        if (!EqualOid(algorithmOid, OID_EC_PUBLIC_KEY))
        {
            throw new CryptographicException("unsupported public key algorithm");
        }

        byte[] curveOid = ReadTlv(algorithm, ref algorithmOffset, 0x06);
        ResolveCurve(curveOid, out ECCurve curve, out int fieldSize);

        if (bits.Length != 2 + fieldSize * 2 || bits[0] != 0 || bits[1] != 0x04)
        {
            throw new CryptographicException("invalid ec public key");
        }

        byte[] x = new byte[fieldSize];
        byte[] y = new byte[fieldSize];
        Buffer.BlockCopy(bits, 2, x, 0, fieldSize);
        Buffer.BlockCopy(bits, 2 + fieldSize, y, 0, fieldSize);

        ECParameters parameters = new ECParameters
        {
            Curve = curve,
            Q = new ECPoint { X = x, Y = y }
        };

        ECDsa ecdsa = ECDsa.Create();
        ecdsa.ImportParameters(parameters);

        return ecdsa;
    }

    // 从 PEM 公钥创建 RSA 实例；同时支持 PKIX 与 PKCS#1 两种格式
    private static RSA LoadRsa(string publicKey)
    {
        byte[] der = LoadDer(publicKey);
        int offset = 0;
        byte[] outer = ReadTlv(der, ref offset, 0x30);
        byte[] sequence;

        if (outer.Length > 0 && outer[0] == 0x30)
        {
            // PKIX SubjectPublicKeyInfo
            int outerOffset = 0;
            byte[] algorithm = ReadTlv(outer, ref outerOffset, 0x30);
            byte[] bits = ReadTlv(outer, ref outerOffset, 0x03);

            int algorithmOffset = 0;
            byte[] algorithmOid = ReadTlv(algorithm, ref algorithmOffset, 0x06);

            if (!EqualOid(algorithmOid, OID_RSA_ENCRYPTION))
            {
                throw new CryptographicException("unsupported public key algorithm");
            }

            if (bits.Length < 2 || bits[0] != 0)
            {
                throw new CryptographicException("invalid rsa public key");
            }

            byte[] rsaKey = new byte[bits.Length - 1];
            Buffer.BlockCopy(bits, 1, rsaKey, 0, rsaKey.Length);

            int rsaOffset = 0;
            sequence = ReadTlv(rsaKey, ref rsaOffset, 0x30);
        }
        else
        {
            // PKCS#1 RSAPublicKey，此时 outer 已经是 SEQUENCE 的内容
            sequence = outer;
        }

        int sequenceOffset = 0;
        byte[] modulus = TrimLeadingZeros(ReadTlv(sequence, ref sequenceOffset, 0x02));
        byte[] exponent = TrimLeadingZeros(ReadTlv(sequence, ref sequenceOffset, 0x02));

        RSA rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = exponent });

        return rsa;
    }

    // 将曲线 OID 解析为 .NET 曲线
    private static void ResolveCurve(byte[] oid, out ECCurve curve, out int fieldSize)
    {
        if (EqualOid(oid, OID_P256))
        {
            curve = ECCurve.NamedCurves.nistP256;
            fieldSize = 32;
            return;
        }

        if (EqualOid(oid, OID_P384))
        {
            curve = ECCurve.NamedCurves.nistP384;
            fieldSize = 48;
            return;
        }

        if (EqualOid(oid, OID_P521))
        {
            curve = ECCurve.NamedCurves.nistP521;
            fieldSize = 66;
            return;
        }

        throw new CryptographicException("unsupported elliptic curve");
    }

    // 比较两个 OID
    private static bool EqualOid(byte[] left, byte[] right)
    {
        if (left == null || right == null || left.Length != right.Length)
        {
            return false;
        }

        for (int i = 0; i < left.Length; i++)
        {
            if (left[i] != right[i])
            {
                return false;
            }
        }

        return true;
    }

    // 去除大端整数的前导零
    private static byte[] TrimLeadingZeros(byte[] value)
    {
        int offset = 0;

        while (offset < value.Length - 1 && value[offset] == 0)
        {
            offset++;
        }

        byte[] buffer = new byte[value.Length - offset];
        Buffer.BlockCopy(value, offset, buffer, 0, buffer.Length);

        return buffer;
    }

    // 加载 DER 数据；参数可以是文件路径或 PEM 内容
    private static byte[] LoadDer(string publicKey)
    {
        if (string.IsNullOrEmpty(publicKey))
        {
            throw new ArgumentException("public key must not be empty", nameof(publicKey));
        }

        string content = File.Exists(publicKey) ? File.ReadAllText(publicKey) : publicKey;
        StringBuilder builder = new StringBuilder();

        foreach (string line in content.Split('\n'))
        {
            string value = line.Trim();

            if (value.Length == 0 || value.StartsWith("-----", StringComparison.Ordinal))
            {
                continue;
            }

            builder.Append(value);
        }

        return Convert.FromBase64String(builder.ToString());
    }

    // 读取一个 DER TLV 的值
    private static byte[] ReadTlv(byte[] der, ref int offset, byte expectedTag)
    {
        if (der == null || offset >= der.Length || der[offset] != expectedTag)
        {
            throw new CryptographicException("invalid der encoding");
        }

        offset++;

        int length = ReadLength(der, ref offset);

        if (offset + length > der.Length)
        {
            throw new CryptographicException("invalid der encoding");
        }

        byte[] value = new byte[length];
        Buffer.BlockCopy(der, offset, value, 0, length);
        offset += length;

        return value;
    }

    // 读取 DER 长度
    private static int ReadLength(byte[] der, ref int offset)
    {
        if (offset >= der.Length)
        {
            throw new CryptographicException("invalid der encoding");
        }

        int value = der[offset++];

        if (value < 0x80)
        {
            return value;
        }

        int count = value & 0x7f;

        if (count == 0 || count > 4 || offset + count > der.Length)
        {
            throw new CryptographicException("invalid der encoding");
        }

        int length = 0;

        for (int i = 0; i < count; i++)
        {
            length = (length << 8) | der[offset++];
        }

        return length;
    }
}
