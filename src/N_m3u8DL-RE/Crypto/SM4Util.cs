using System.Buffers.Binary;

namespace N_m3u8DL_RE.Crypto;

/// <summary>
/// 国密 SM4 (GB/T 32907-2016) 纯 C# 实现，128 位分组 / 128 位密钥。
/// 移植自 stream-dl-builder 的 sm4_m3u8.py（零依赖 Pure-Python SM4），
/// 由下载器在分片下载完成后就地做 SM4-CBC 解密，无需外部 Python 依赖。
/// 主要用于优酷（Youku）等使用 SM4-CBC 的 HLS 流。
/// </summary>
internal static class SM4Util
{
    // S-box（与 gmssl 参考实现一致）
    private static readonly byte[] Sbox =
    [
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
        0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
        0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
        0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
        0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
        0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
        0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
        0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
        0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
        0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
        0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
        0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
    ];

    private static readonly uint[] FK = [0xA3B1BAC6u, 0x56AA3350u, 0x677D9197u, 0xB27022DCu];

    /// <summary>
    /// SM4-CBC 解密。行为与 N_m3u8DL-RE 内置 AES_128 解密一致：默认对每段做 PKCS7 去填充。
    /// key / iv 必须为 16 字节（由调用方从 --custom-hls-key / --custom-hls-iv 解码）。
    /// </summary>
    public static byte[] DecryptCbc(byte[] data, byte[] key, byte[] iv, bool unpad = true)
    {
        if (key == null || key.Length != 16)
            throw new Exception("SM4 解密需要提供 16 字节的 --custom-hls-key（HEX 或 Base64）");
        if (iv == null || iv.Length != 16)
            throw new Exception("SM4-CBC 解密需要提供 16 字节的 --custom-hls-iv（HEX 或 Base64）");
        if (data.Length % 16 != 0)
            throw new Exception($"SM4 CBC 密文长度必须是 16 字节整数倍，当前为 {data.Length} 字节");

        uint[] rk = ExpandKey(key);
        var outBuf = new byte[data.Length];
        byte[] prev = iv;
        for (int i = 0; i < data.Length; i += 16)
        {
            var block = new byte[16];
            Buffer.BlockCopy(data, i, block, 0, 16);
            byte[] dec = CryptBlock(block, rk, encrypt: false);
            for (int j = 0; j < 16; j++)
                outBuf[i + j] = (byte)(dec[j] ^ prev[j]);
            prev = block;
        }

        return unpad ? Pkcs7Unpad(outBuf) : outBuf;
    }

    /// <summary>
    /// SM4-CBC 加密（主要用于自测 / 与参考实现互验）。pad=true 时按 PKCS7 填充。
    /// </summary>
    public static byte[] EncryptCbc(byte[] data, byte[] key, byte[] iv, bool pad = true)
    {
        if (key == null || key.Length != 16)
            throw new Exception("SM4 加密需要提供 16 字节的密钥（HEX 或 Base64）");
        if (iv == null || iv.Length != 16)
            throw new Exception("SM4-CBC 加密需要提供 16 字节的 IV（HEX 或 Base64）");

        byte[] input = pad ? Pkcs7Pad(data) : data;
        if (input.Length % 16 != 0)
            throw new Exception($"SM4 CBC 明文长度必须是 16 字节整数倍，当前为 {input.Length} 字节");

        uint[] rk = ExpandKey(key);
        var outBuf = new byte[input.Length];
        byte[] prev = iv;
        for (int i = 0; i < input.Length; i += 16)
        {
            var block = new byte[16];
            for (int j = 0; j < 16; j++)
                block[j] = (byte)(input[i + j] ^ prev[j]);
            byte[] enc = CryptBlock(block, rk, encrypt: true);
            Buffer.BlockCopy(enc, 0, outBuf, i, 16);
            prev = enc;
        }
        return outBuf;
    }

    // ---------------------------------------------------------------------
    // 核心算法（逐行对应 sm4_m3u8.py）
    // ---------------------------------------------------------------------

    private static uint Rotl32(uint x, int n)
    {
        n &= 31;
        return (x << n) | (x >> (32 - n));
    }

    private static uint Tau(uint a)
    {
        uint r = 0;
        r |= (uint)Sbox[(a >> 24) & 0xFF] << 24;
        r |= (uint)Sbox[(a >> 16) & 0xFF] << 16;
        r |= (uint)Sbox[(a >> 8) & 0xFF] << 8;
        r |= (uint)Sbox[a & 0xFF];
        return r;
    }

    private static uint L(uint b) =>
        b ^ Rotl32(b, 2) ^ Rotl32(b, 10) ^ Rotl32(b, 18) ^ Rotl32(b, 24);

    private static uint LPrime(uint b) =>
        b ^ Rotl32(b, 13) ^ Rotl32(b, 23);

    private static uint T(uint x) => L(Tau(x));

    private static uint TPrime(uint x) => LPrime(Tau(x));

    private static uint Ck(int i)
    {
        int b = 4 * i;
        uint r = 0;
        r |= (uint)((7 * b) & 0xFF) << 24;
        r |= (uint)((7 * (b + 1)) & 0xFF) << 16;
        r |= (uint)((7 * (b + 2)) & 0xFF) << 8;
        r |= (uint)((7 * (b + 3)) & 0xFF);
        return r;
    }

    private static uint[] WordsFromBytes(byte[] data)
    {
        int n = data.Length / 4;
        var words = new uint[n];
        for (int i = 0; i < n; i++)
            words[i] = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(i * 4, 4));
        return words;
    }

    private static uint[] ExpandKey(byte[] key)
    {
        uint[] mk = WordsFromBytes(key);
        var k = new uint[36];
        for (int i = 0; i < 4; i++)
            k[i] = mk[i] ^ FK[i];
        var rk = new uint[32];
        for (int i = 0; i < 32; i++)
        {
            uint ki = k[i] ^ TPrime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ Ck(i));
            k[i + 4] = ki;
            rk[i] = ki;
        }
        return rk;
    }

    private static byte[] CryptBlock(byte[] block, uint[] rk, bool encrypt)
    {
        uint[] buf = WordsFromBytes(block); // buf[0..3]
        uint[] rks = encrypt ? rk : rk.Reverse().ToArray();
        for (int i = 0; i < 32; i++)
            buf = Append(buf, buf[i] ^ T(buf[i + 1] ^ buf[i + 2] ^ buf[i + 3] ^ rks[i]));
        uint[] y = [buf[35], buf[34], buf[33], buf[32]];
        var outBytes = new byte[16];
        BinaryPrimitives.WriteUInt32BigEndian(outBytes.AsSpan(0, 4), y[0]);
        BinaryPrimitives.WriteUInt32BigEndian(outBytes.AsSpan(4, 4), y[1]);
        BinaryPrimitives.WriteUInt32BigEndian(outBytes.AsSpan(8, 4), y[2]);
        BinaryPrimitives.WriteUInt32BigEndian(outBytes.AsSpan(12, 4), y[3]);
        return outBytes;
    }

    private static uint[] Append(uint[] arr, uint value)
    {
        var next = new uint[arr.Length + 1];
        Array.Copy(arr, next, arr.Length);
        next[arr.Length] = value;
        return next;
    }

    private static byte[] Pkcs7Unpad(byte[] data)
    {
        if (data.Length == 0)
            return data;
        int padLen = data[data.Length - 1];
        if (padLen >= 1 && padLen <= 16)
        {
            bool valid = true;
            for (int i = 0; i < padLen; i++)
            {
                if (data[data.Length - 1 - i] != padLen)
                {
                    valid = false;
                    break;
                }
            }
            if (valid)
                return data[..^padLen];
        }
        return data;
    }

    private static byte[] Pkcs7Pad(byte[] data)
    {
        int padLen = 16 - (data.Length % 16);
        if (padLen == 0)
            padLen = 16;
        var padded = new byte[data.Length + padLen];
        Buffer.BlockCopy(data, 0, padded, 0, data.Length);
        for (int i = data.Length; i < padded.Length; i++)
            padded[i] = (byte)padLen;
        return padded;
    }
}
